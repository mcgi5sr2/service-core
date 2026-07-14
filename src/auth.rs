//! OIDC/Dex bearer-token authentication, shared across the fleet.
//!
//! [`JwksStore`] owns the JWKS cache, the issuer, the HTTPS client, and the
//! single-flight + cooldown gate — one field on a service's `AppState` instead of
//! five, and the concurrency-subtle refresh logic lives in one place. The
//! [`AuthenticatedUser`] extractor is the gate: naming it in a handler's arguments
//! validates the token before the body is read.
//!
//! The request→identity boundary is [`JwksStore::validate`]. A future BFF-trust mode
//! (identity asserted by a trusted BFF over mTLS/a signed header) can be added here as
//! an alternative path without changing any consumer.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{FromRef, FromRequestParts};
use axum::http::{StatusCode, request::Parts};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

/// Minimum interval between JWKS refreshes. Caps a caller spraying unknown `kid`s to
/// one Dex fetch per interval regardless of load; a rotated key is picked up within it.
const REFRESH_COOLDOWN: Duration = Duration::from_secs(60);

/// Validated token claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: Option<String>,
    pub exp: usize,
}

/// A self-refreshing JWKS store with a DoS-hardened refresh path.
pub struct JwksStore {
    keys: RwLock<JwkSet>,
    issuer: String,
    audience: String,
    http: reqwest::Client,
    /// Single-flight + cooldown gate for refresh (holds the last successful refresh).
    last_refresh: Mutex<Option<Instant>>,
    dev_no_auth: bool,
}

impl JwksStore {
    /// Build the store, fetching the initial key set. Fails soft: if the fetch fails
    /// (Dex briefly unreachable) or auth is disabled, it starts empty and the on-miss
    /// refresh repopulates on the first authenticated request — startup never blocks.
    pub async fn new(issuer: String, audience: String, dev_no_auth: bool) -> anyhow::Result<Arc<Self>> {
        let http = reqwest::Client::builder().use_rustls_tls().build()?;
        let keys = if dev_no_auth || issuer.is_empty() {
            tracing::warn!("service-core auth: DISABLED (dev_no_auth or empty issuer)");
            JwkSet { keys: Vec::new() }
        } else {
            match Self::fetch_jwks(&http, &issuer).await {
                Ok(k) => {
                    tracing::info!("service-core auth: fetched JWKS from {issuer}");
                    k
                }
                Err(e) => {
                    tracing::warn!("service-core auth: initial JWKS fetch failed ({e}); lazy retry on first request");
                    JwkSet { keys: Vec::new() }
                }
            }
        };
        Ok(Arc::new(Self {
            keys: RwLock::new(keys),
            issuer,
            audience,
            http,
            last_refresh: Mutex::new(None),
            dev_no_auth,
        }))
    }

    /// True when auth is bypassed (local/offline dev).
    pub fn is_disabled(&self) -> bool {
        self.dev_no_auth
    }

    async fn fetch_jwks(http: &reqwest::Client, issuer: &str) -> anyhow::Result<JwkSet> {
        let discovery_url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
        let discovery: serde_json::Value = http.get(&discovery_url).send().await?.json().await?;
        let jwks_uri = discovery["jwks_uri"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("no jwks_uri in discovery document"))?;
        Ok(http.get(jwks_uri).send().await?.json().await?)
    }

    /// Validate a bearer token and return its claims. Handles the gated JWKS refresh
    /// internally. Returns `401` on any failure (fail-closed).
    pub async fn validate(&self, token: &str) -> Result<Claims, StatusCode> {
        let header = decode_header(token).map_err(|e| {
            tracing::warn!("auth: failed to decode JWT header: {e}");
            StatusCode::UNAUTHORIZED
        })?;
        let kid = header.kid.ok_or_else(|| {
            tracing::warn!("auth: JWT has no kid");
            StatusCode::UNAUTHORIZED
        })?;

        let found = self.keys.read().await.find(&kid).is_some();
        if !found {
            // Rate-limited + single-flight refresh: an attacker spraying unknown kids
            // can't amplify each request into a Dex fetch.
            let mut last = self.last_refresh.lock().await;
            let still_missing = self.keys.read().await.find(&kid).is_none();
            if still_missing {
                if matches!(*last, Some(t) if t.elapsed() < REFRESH_COOLDOWN) {
                    tracing::warn!("auth: kid '{kid}' unknown and refresh on cooldown — rejecting");
                    return Err(StatusCode::UNAUTHORIZED);
                }
                tracing::warn!("auth: kid '{kid}' not in cache — refreshing JWKS");
                *self.keys.write().await = Self::fetch_jwks(&self.http, &self.issuer).await.map_err(|e| {
                    tracing::warn!("auth: JWKS refresh failed: {e}");
                    StatusCode::UNAUTHORIZED
                })?;
                *last = Some(Instant::now());
            }
        }

        let keys = self.keys.read().await;
        let jwk = keys.find(&kid).ok_or_else(|| {
            tracing::warn!("auth: kid '{kid}' not found after refresh");
            StatusCode::UNAUTHORIZED
        })?;
        let decoding_key = DecodingKey::from_jwk(jwk).map_err(|e| {
            tracing::warn!("auth: failed to build decoding key: {e}");
            StatusCode::UNAUTHORIZED
        })?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        decode::<Claims>(token, &decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| {
                tracing::warn!("auth: token validation failed: {e}");
                StatusCode::UNAUTHORIZED
            })
    }
}

/// Proof that the request carried a valid Dex bearer token. Naming it in a handler
/// gates that handler. Works for any state from which an `Arc<JwksStore>` can be
/// extracted (derive `FromRef` on your `AppState` with an `Arc<JwksStore>` field).
pub struct AuthenticatedUser {
    pub claims: Claims,
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    Arc<JwksStore>: FromRef<S>,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = Arc::<JwksStore>::from_ref(state);

        if store.dev_no_auth {
            return Ok(AuthenticatedUser {
                claims: Claims { sub: "dev".into(), email: Some("dev@local".into()), exp: usize::MAX },
            });
        }

        let token = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| {
                tracing::warn!("auth: missing or malformed Authorization header");
                StatusCode::UNAUTHORIZED
            })?;

        let claims = store.validate(token).await?;
        Ok(AuthenticatedUser { claims })
    }
}
