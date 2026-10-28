//! The identity provider: the configured openidconnect client built from its
//! discovered metadata (endpoints and signing keys).
//!
//! Discovery is lazy. A service must start, serve `/health/live` and its public
//! routes while the provider is unreachable, so nothing here runs at startup:
//! the first sign-in discovers, and until that succeeds sign-in answers 503.
//! The same path re-fetches the signing keys when an ID token fails
//! verification (the provider rotated its keys), so a rotation heals itself
//! instead of failing every sign-in until a restart.
//!
//! Gating mirrors [`crate::auth::JwksStore`]'s key refresh: single-flight
//! (a tokio mutex held across the fetch) and a cooldown armed on failure too.
//! The two caches stay separate on purpose — this one is openidconnect's
//! metadata, verified the protocol's way; that one is a raw key set for bearer
//! tokens.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::{ClientId, IssuerUrl, RedirectUrl, Scope};

use super::http::Http;

/// Minimum interval between failed discoveries, and between key refreshes. A
/// burst of failed verifications triggers one refresh; while the provider is
/// down, one attempt per window and everyone else fails fast rather than
/// queueing behind a timeout each. A successful first discovery does NOT start
/// it, so a key rotation right after startup is still picked up.
const COOLDOWN: Duration = Duration::from_secs(30);

/// openidconnect's client with our endpoints materialised: authorization set;
/// token and userinfo present if discovered. Spelled out once because the
/// typestate is unwieldy to repeat.
pub(crate) type ConfiguredClient = openidconnect::Client<
    openidconnect::EmptyAdditionalClaims,
    openidconnect::core::CoreAuthDisplay,
    openidconnect::core::CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJsonWebKey,
    openidconnect::core::CoreAuthPrompt,
    openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
    openidconnect::core::CoreTokenResponse,
    openidconnect::core::CoreTokenIntrospectionResponse,
    openidconnect::core::CoreRevocableToken,
    openidconnect::core::CoreRevocationErrorResponse,
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

#[derive(Default)]
struct Attempts {
    failure: Option<Instant>,
    refresh: Option<Instant>,
}

pub(crate) struct Provider {
    issuer: IssuerUrl,
    client_id: ClientId,
    redirect_uri: RedirectUrl,
    pub scopes: Vec<Scope>,
    pub http: Http,
    /// Built once per discovery and shared, so a sign-in does not clone the
    /// metadata and key set to rebuild it.
    client: RwLock<Option<Arc<ConfiguredClient>>>,
    attempts: tokio::sync::Mutex<Attempts>,
}

impl Provider {
    pub fn new(issuer: IssuerUrl, client_id: ClientId, redirect_uri: RedirectUrl, scopes: Vec<Scope>) -> anyhow::Result<Self> {
        Ok(Self {
            issuer,
            client_id,
            redirect_uri,
            scopes,
            http: Http::new()?,
            client: RwLock::new(None),
            attempts: tokio::sync::Mutex::new(Attempts::default()),
        })
    }

    /// The configured client, discovering first if needed. `None` while the
    /// provider cannot be reached.
    pub async fn client(&self) -> Option<Arc<ConfiguredClient>> {
        if let Some(client) = self.current() {
            return Some(client);
        }
        self.discover(false).await;
        self.current()
    }

    /// Re-fetch metadata and keys after a verification failure, at most once
    /// per cooldown. Failure is logged and swallowed: the caller re-verifies with
    /// whatever keys are current, and a genuinely bad token still fails.
    pub async fn rediscover(&self) {
        self.discover(true).await;
    }

    fn current(&self) -> Option<Arc<ConfiguredClient>> {
        self.client.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    async fn discover(&self, refresh: bool) {
        let mut attempts = self.attempts.lock().await;
        // Someone else discovered while we waited for the lock.
        if !refresh && self.current().is_some() {
            return;
        }
        let recent = |t: Option<Instant>| t.is_some_and(|t| t.elapsed() < COOLDOWN);
        if recent(attempts.failure) || (refresh && recent(attempts.refresh)) {
            return;
        }
        if refresh {
            attempts.refresh = Some(Instant::now());
        }
        match CoreProviderMetadata::discover_async(self.issuer.clone(), &self.http).await {
            Ok(metadata) => {
                // Public client: no secret. PKCE secures the code exchange.
                let client = CoreClient::from_provider_metadata(metadata, self.client_id.clone(), None)
                    .set_redirect_uri(self.redirect_uri.clone());
                *self.client.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(client));
                attempts.failure = None;
                tracing::info!(refresh, "login: discovered the identity provider");
            }
            Err(e) => {
                attempts.failure = Some(Instant::now());
                tracing::warn!(refresh, "login: identity provider discovery failed: {e}");
            }
        }
    }
}
