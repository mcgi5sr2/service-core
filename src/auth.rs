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
use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::{HeaderMap, StatusCode, request::Parts};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

/// Minimum interval between JWKS refreshes. Caps a caller spraying unknown `kid`s to
/// one Dex fetch per interval regardless of load; a rotated key is picked up within it.
const REFRESH_COOLDOWN: Duration = Duration::from_secs(60);

/// Seconds since the Unix epoch (0 if the clock is before it).
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Validated token claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: Option<String>,
    pub exp: usize,
    /// When the user last actually authenticated (OIDC `auth_time`, seconds since epoch).
    ///
    /// The claim that makes **step-up re-auth** verifiable: a service can require that the
    /// password was entered within the last N seconds before allowing something
    /// destructive. `iat` cannot do this — it is refreshed on every silent token refresh,
    /// so a fresh `iat` says nothing about whether a human was present.
    ///
    /// `Option`, because a provider only has to emit it when the client asks (`max_age`
    /// or `prompt=login`), and not every provider emits it at all. Absent must therefore
    /// be treated as "cannot prove re-authentication" — never as "recently authenticated".
    #[serde(default)]
    pub auth_time: Option<usize>,
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
    /// Optional BFF-trust verifier. `None` (the default) leaves behaviour exactly as
    /// it was — bearer only. When `Some`, a request carrying a BFF assertion is
    /// accepted through it as an alternative to the bearer. Opt-in via
    /// [`JwksStore::with_bff_trust`], so no consumer that keeps calling [`new`]
    /// changes at all.
    bff: Option<crate::bff::BffTrust>,
    /// Optional browser sign-in: when set, a request carrying a live session
    /// cookie is accepted through it (feature `login`).
    #[cfg(feature = "login")]
    login: Option<Arc<crate::login::Login>>,
    /// Peers whose forwarded tokens [`JwksStore::peer_token`] accepts ([`crate::peer`]).
    peers: Vec<crate::peer::Peer>,
}

/// The optional identity paths a [`JwksStore`] accepts besides a bearer token, and
/// its other optional settings. Build with `..Default::default()` so a new field
/// never breaks a caller.
#[derive(Default)]
pub struct AuthOptions {
    /// Accept a BFF-signed assertion ([`crate::bff`]).
    pub bff: Option<crate::bff::BffTrust>,
    /// Accept the browser session cookie of this service's own sign-in.
    #[cfg(feature = "login")]
    pub login: Option<Arc<crate::login::Login>>,
    /// Peer services whose tokens an upstream may forward beside the request's own
    /// credential ([`crate::peer`]). Not an identity path: read only through
    /// [`JwksStore::peer_token`], after the request has authenticated.
    pub peers: Vec<crate::peer::Peer>,
}

impl JwksStore {
    /// Build the store, fetching the initial key set. Fails soft: if the fetch fails
    /// (Dex briefly unreachable) or auth is disabled, it starts empty and the on-miss
    /// refresh repopulates on the first authenticated request — startup never blocks.
    pub async fn new(
        issuer: String,
        audience: String,
        dev_no_auth: bool,
    ) -> anyhow::Result<Arc<Self>> {
        Self::with_options(issuer, audience, dev_no_auth, AuthOptions::default()).await
    }

    /// Like [`new`](Self::new), but also accepts BFF-signed assertions (BFF-trust). A request
    /// presenting the [`crate::bff::ASSERTION_HEADER`] is verified against `bff`
    /// instead of the IdP; a plain bearer still works, so this is additive during a
    /// transition.
    pub async fn with_bff_trust(
        issuer: String,
        audience: String,
        dev_no_auth: bool,
        bff: crate::bff::BffTrust,
    ) -> anyhow::Result<Arc<Self>> {
        let options = AuthOptions { bff: Some(bff), ..Default::default() };
        Self::with_options(issuer, audience, dev_no_auth, options).await
    }

    /// Like [`new`](Self::new), with any of the optional identity paths in [`AuthOptions`].
    /// Order of precedence in [`AuthenticatedUser`]: `dev_no_auth`, BFF assertion,
    /// bearer (when an `Authorization` header is present), session cookie.
    ///
    /// Each path is an `Option` here and an `if let` in the extractor. Should a
    /// third arrive, the shape to move to is a list of identity sources tried in
    /// order; `AuthOptions` keeps that change invisible to callers.
    pub async fn with_options(
        issuer: String,
        audience: String,
        dev_no_auth: bool,
        options: AuthOptions,
    ) -> anyhow::Result<Arc<Self>> {
        // One answer to "who is signed in" for the page and the API: a sign-in in
        // dev mode with real validation here (or the reverse) would show a user as
        // signed in while every API call failed.
        #[cfg(feature = "login")]
        if let Some(login) = &options.login
            && login.is_disabled() != dev_no_auth
        {
            anyhow::bail!("service-core auth: dev_no_auth is {dev_no_auth} but the login's is {}; they must match", login.is_disabled());
        }
        // A peer token's subject is compared with the request user's, so both must come from one provider.
        #[cfg(feature = "login")]
        if !options.peers.is_empty()
            && let Some(login_issuer) = options.login.as_ref().and_then(|login| login.issuer())
            && login_issuer.trim_end_matches('/') != issuer.trim_end_matches('/')
        {
            anyhow::bail!("service-core auth: the login's issuer {login_issuer} is not {issuer}; peer tokens need one provider");
        }
        for (i, peer) in options.peers.iter().enumerate() {
            if peer.audience.is_empty() || peer.audience == audience {
                // The service's own audience would make every ordinary token pass as a peer token.
                anyhow::bail!("service-core auth: peer '{}' needs an audience of its own, not empty or this service's", peer.name);
            }
            if options.peers[..i].iter().any(|other| other.name == peer.name || other.header == peer.header) {
                anyhow::bail!("service-core auth: peer '{}' repeats another peer's name or header", peer.name);
            }
            // A credential header would make the peer token double as the request's own credential.
            if [AUTHORIZATION, COOKIE].contains(&peer.header) || peer.header.as_str() == crate::bff::ASSERTION_HEADER.to_ascii_lowercase() {
                anyhow::bail!("service-core auth: peer '{}' header '{}' is a credential header", peer.name, peer.header);
            }
        }
        let http = crate::http::idp_client_builder().build()?;
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
                    tracing::warn!(
                        "service-core auth: initial JWKS fetch failed ({e}); lazy retry on first request"
                    );
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
            bff: options.bff,
            #[cfg(feature = "login")]
            login: options.login,
            peers: options.peers,
        }))
    }

    /// True when auth is bypassed (local/offline dev).
    pub fn is_disabled(&self) -> bool {
        self.dev_no_auth
    }

    async fn fetch_jwks(http: &reqwest::Client, issuer: &str) -> anyhow::Result<JwkSet> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let discovery: serde_json::Value = http.get(&discovery_url).send().await?.json().await?;
        let jwks_uri = discovery["jwks_uri"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("no jwks_uri in discovery document"))?;
        Ok(http.get(jwks_uri).send().await?.json().await?)
    }

    /// Validate a bearer token and return its claims. Handles the gated JWKS refresh
    /// internally. Returns `401` on any failure (fail-closed).
    pub async fn validate(&self, token: &str) -> Result<Claims, StatusCode> {
        let (claims, audiences) = self.validate_for(token, &self.audience).await?;
        // A token also issued for a peer is a peer token, not a credential here.
        if self.peers.iter().any(|peer| audiences.contains(&peer.audience)) {
            tracing::warn!("auth: bearer is also issued for a peer — rejecting");
            return Err(StatusCode::UNAUTHORIZED);
        }
        Ok(claims)
    }

    /// The peer token `peer` forwarded on this request, verified for `user`: `None`
    /// when the request carries none, `401` when it carries one that fails
    /// validation (issuer, keys, the peer's audience, expiry), is also issued for
    /// this service, or belongs to someone else. A `peer` this store wasn't built
    /// with is a programming error, answered `500`. See [`crate::peer`] for the
    /// trust model.
    ///
    /// `user` must be the claims of this request's [`AuthenticatedUser`]: the check
    /// binds the token to whoever `user` names, so claims from anywhere else bind it
    /// to nothing.
    ///
    /// With `dev_no_auth` the header is passed through unverified, as every other
    /// credential is.
    pub async fn peer_token(&self, headers: &HeaderMap, user: &Claims, peer: &str) -> Result<Option<crate::peer::PeerToken>, StatusCode> {
        let Some(config) = self.peers.iter().find(|candidate| candidate.name == peer) else {
            tracing::error!("auth: peer '{peer}' is not configured");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };
        let Some(value) = headers.get(&config.header) else {
            return Ok(None);
        };
        let token = value.to_str().map_err(|_| {
            tracing::warn!("auth: peer '{peer}' token header is not ASCII");
            StatusCode::UNAUTHORIZED
        })?;
        if self.dev_no_auth {
            return Ok(Some(crate::peer::PeerToken { token: token.to_owned(), claims: user.clone() }));
        }
        let (claims, audiences) = self.validate_for(token, &config.audience).await?;
        if audiences.contains(&self.audience) {
            tracing::warn!("auth: peer '{peer}' token is also issued for this service — rejecting");
            return Err(StatusCode::UNAUTHORIZED);
        }
        if claims.sub != user.sub {
            tracing::warn!("auth: peer '{peer}' token is for another subject than the request's user");
            return Err(StatusCode::UNAUTHORIZED);
        }
        Ok(Some(crate::peer::PeerToken { token: token.to_owned(), claims }))
    }

    /// [`validate`](Self::validate) for any audience this issuer serves: the claims
    /// and every audience the token names.
    async fn validate_for(&self, token: &str, audience: &str) -> Result<(Claims, Vec<String>), StatusCode> {
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
                    tracing::warn!("auth: kid {kid:?} unknown and refresh on cooldown — rejecting");
                    return Err(StatusCode::UNAUTHORIZED);
                }
                tracing::warn!("auth: kid {kid:?} not in cache — refreshing JWKS");
                let fetched = Self::fetch_jwks(&self.http, &self.issuer).await;
                // Arm the cooldown on BOTH success and failure so a down/hung Dex is
                // rate-limited too — not only a successful refresh.
                *last = Some(Instant::now());
                match fetched {
                    Ok(fresh) => *self.keys.write().await = fresh,
                    Err(e) => {
                        tracing::warn!("auth: JWKS refresh failed: {e}");
                        return Err(StatusCode::UNAUTHORIZED);
                    }
                }
            }
        }

        let keys = self.keys.read().await;
        let jwk = keys.find(&kid).ok_or_else(|| {
            tracing::warn!("auth: kid {kid:?} not found after refresh");
            StatusCode::UNAUTHORIZED
        })?;
        let decoding_key = DecodingKey::from_jwk(jwk).map_err(|e| {
            tracing::warn!("auth: failed to build decoding key: {e}");
            StatusCode::UNAUTHORIZED
        })?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[audience]);
        // The library checks iss and aud only when present; a token without them must not pass.
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        decode::<Validated>(token, &decoding_key, &validation)
            .map(|data| (data.claims.claims, data.claims.aud.into_vec()))
            .map_err(|e| {
                tracing::warn!("auth: token validation failed: {e}");
                StatusCode::UNAUTHORIZED
            })
    }
}

/// A validated token's claims with its audience, which [`Claims`] leaves out.
#[derive(Deserialize)]
struct Validated {
    #[serde(flatten)]
    claims: Claims,
    aud: Audience,
}

/// `aud`: one audience or several.
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn into_vec(self) -> Vec<String> {
        match self {
            Audience::One(one) => vec![one],
            Audience::Many(many) => many,
        }
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
                claims: Claims {
                    sub: "dev".into(),
                    email: Some("dev@local".into()),
                    exp: usize::MAX,
                    // "Just authenticated". dev_no_auth already disables validation
                    // entirely, so withholding this would only make step-up-gated actions
                    // untestable locally without adding any safety — it is the same
                    // loaded gun, not a second one.
                    auth_time: Some(unix_now() as usize),
                },
            });
        }

        // BFF-trust: if configured AND the request carries a BFF assertion, accept
        // it in place of a bearer. Absent the config or the header, nothing here
        // changes — the bearer path below runs exactly as before.
        if let Some(bff) = &store.bff
            && let Some(assertion) = parts
                .headers
                .get(crate::bff::ASSERTION_HEADER)
                .and_then(|v| v.to_str().ok())
        {
            return Ok(AuthenticatedUser {
                claims: bff.verify(assertion)?,
            });
        }

        // An explicit credential wins over an ambient one: a request that names
        // its bearer is judged on it alone, whatever cookies the browser attached.
        let authorization = parts.headers.get("Authorization");

        // Browser session: a live session cookie stands in for a bearer. No
        // cookie or no live session falls through, so an expired session ends as
        // the usual 401.
        #[cfg(feature = "login")]
        if authorization.is_none()
            && let Some(login) = &store.login
            && let Some(result) = login.authenticate(parts)
        {
            return result.map(|claims| AuthenticatedUser { claims });
        }

        let token = authorization
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
