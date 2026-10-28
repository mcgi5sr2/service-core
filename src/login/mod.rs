//! Browser sign-in for a service's own UI (feature `login`).
//!
//! A service that serves a UI on its own origin signs users in itself: the OIDC
//! authorization-code flow with PKCE against the identity provider, a
//! server-side session, and an opaque `HttpOnly` cookie. The browser never sees
//! a code verifier, a nonce or a token. The provider's own session makes a
//! sign-in after the first one silent, so moving between services' UIs does not
//! ask for a password again.
//!
//! [`Login::router`] serves the four routes a service UI calls (service-ui's
//! auth module speaks exactly these):
//!
//! | route | |
//! |---|---|
//! | `GET /auth/login?returnTo=/path&stepUp=1` | start a sign-in; `stepUp=1` forces real re-authentication |
//! | `GET /auth/callback` | the provider's redirect back |
//! | `POST /auth/logout` | end the session (same-origin only) |
//! | `GET /auth/me` | `{authenticated, sub, email, name}` |
//!
//! Wire it into [`crate::auth::JwksStore`] with
//! [`AuthOptions::login`](crate::auth::AuthOptions) and the existing
//! [`AuthenticatedUser`](crate::auth::AuthenticatedUser) extractor accepts the
//! session cookie too — handlers do not change. A request carrying an
//! `Authorization` header is judged on that alone. Cookie-authenticated requests
//! that change state must come from the service's own origin (see
//! [`same_origin`]), and cookie-authenticated reads are refused when a browser
//! says another site's page made them (anything but a top-level navigation).
//!
//! Consumers must still keep two rules the extractor cannot see: never change
//! state in a `GET` handler, and never combine sign-in with a CORS layer that
//! allows credentials. Gate routes with `AuthenticatedUser`, not with a
//! hand-rolled check on [`crate::auth::JwksStore::validate`], which knows
//! nothing of sessions.
//!
//! Sign-out is local: it ends this service's session, not the provider's.
//!
//! ```ignore
//! let login = Login::new(LoginConfig::from_env(dev_no_auth)?)?;
//! let jwks = JwksStore::with_options(issuer, audience, dev_no_auth,
//!     AuthOptions { login: Some(login.clone()), ..Default::default() }).await?;
//! let app = Router::new()
//!     .route("/api/things", get(things))
//!     .merge(login.router())
//!     .with_state(state);
//! ```

mod cookie;
mod flow;
mod handlers;
mod http;
#[cfg(feature = "openapi")]
pub mod openapi;
mod provider;
mod session;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use axum::Router;
use axum::http::header::ORIGIN;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::routing::{get, post};
use openidconnect::url::Url;
use openidconnect::{ClientId, IssuerUrl, RedirectUrl, Scope};

use crate::auth::Claims;
pub use session::Identity;

const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(8 * 3600);
const MIN_SESSION_TTL: Duration = Duration::from_secs(300);
const MAX_SESSION_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

/// How a service signs users in.
#[derive(Debug, Clone)]
pub struct LoginConfig {
    /// The identity provider's issuer URL.
    pub issuer: String,
    /// The OIDC client id. Several services may share one public client, each
    /// registering its own callback with it.
    pub client_id: String,
    /// This service's origin as browsers reach it, e.g. `https://tool.example.com`.
    /// The callback is `<public_url>/auth/callback`; it must be registered with
    /// the provider.
    pub public_url: String,
    pub scopes: Vec<String>,
    /// Absolute session lifetime; there is no sliding renewal.
    pub session_ttl: Duration,
    /// Local development without a provider: every caller is a stub user. Never
    /// set in a deployment.
    pub dev_no_auth: bool,
}

impl LoginConfig {
    pub fn new(issuer: impl Into<String>, client_id: impl Into<String>, public_url: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            client_id: client_id.into(),
            public_url: public_url.into(),
            scopes: ["openid", "email", "profile"].map(String::from).to_vec(),
            session_ttl: DEFAULT_SESSION_TTL,
            dev_no_auth: false,
        }
    }

    /// From the environment: `DEX_ISSUER_URL`, `OIDC_CLIENT_ID`, `PUBLIC_URL`,
    /// `LOGIN_SESSION_TTL_SECS` (default 8 h). `dev_no_auth` comes from the
    /// service, which already decides it.
    pub fn from_env(dev_no_auth: bool) -> anyhow::Result<Self> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let mut config = Self::new(
            var("DEX_ISSUER_URL").unwrap_or_default(),
            var("OIDC_CLIENT_ID").unwrap_or_default(),
            var("PUBLIC_URL").unwrap_or_default(),
        );
        if let Some(ttl) = var("LOGIN_SESSION_TTL_SECS") {
            config.session_ttl = Duration::from_secs(ttl.parse().context("LOGIN_SESSION_TTL_SECS must be whole seconds")?);
        }
        config.dev_no_auth = dev_no_auth;
        Ok(config)
    }
}

/// The sign-in machinery for one service: provider, flow sealer, sessions.
pub struct Login {
    /// `scheme://host[:port]` — what a same-origin request's `Origin` equals.
    origin: String,
    names: cookie::Names,
    /// `None` in `dev_no_auth`.
    provider: Option<provider::Provider>,
    flows: flow::FlowSealer,
    sessions: session::SessionStore,
}

impl Login {
    /// Validate the configuration. No network: the provider is discovered on
    /// the first sign-in, so the service starts whether or not it is reachable.
    pub fn new(config: LoginConfig) -> anyhow::Result<Arc<Self>> {
        let public = Url::parse(&config.public_url).context("PUBLIC_URL must be this service's origin, e.g. https://tool.example.com")?;
        let loopback = matches!(public.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if public.scheme() != "https" && !(public.scheme() == "http" && (loopback || config.dev_no_auth)) {
            bail!("PUBLIC_URL must be https (plain http only for localhost): {}", config.public_url);
        }
        if public.path() != "/" || public.query().is_some() || public.fragment().is_some() || !public.username().is_empty() {
            bail!("PUBLIC_URL must be an origin only, with no path, query or credentials: {}", config.public_url);
        }
        if !(MIN_SESSION_TTL..=MAX_SESSION_TTL).contains(&config.session_ttl) {
            bail!("session lifetime must be between 5 minutes and 7 days, got {:?}", config.session_ttl);
        }
        let origin = public.origin().ascii_serialization();
        let provider = if config.dev_no_auth {
            tracing::warn!("login: DISABLED (dev_no_auth) — every caller is a stub user");
            None
        } else {
            let issuer = IssuerUrl::new(config.issuer).context("DEX_ISSUER_URL must be the provider's issuer URL")?;
            if config.client_id.is_empty() {
                bail!("OIDC client id is empty");
            }
            Some(provider::Provider::new(
                issuer,
                ClientId::new(config.client_id),
                RedirectUrl::new(format!("{origin}/auth/callback")).context("callback URL")?,
                config.scopes.into_iter().map(Scope::new).collect(),
            )?)
        };
        Ok(Arc::new(Self {
            origin,
            names: cookie::Names::new(public.scheme() == "https"),
            provider,
            flows: flow::FlowSealer::new().context("no entropy for the sign-in key")?,
            sessions: session::SessionStore::new(config.session_ttl),
        }))
    }

    /// The `/auth/*` routes. Merge into the service's router; they carry their
    /// own state, so they fit any `Router<S>`.
    pub fn router<S: Clone + Send + Sync + 'static>(self: &Arc<Self>) -> Router<S> {
        Router::new()
            .route("/auth/login", get(handlers::login))
            .route("/auth/callback", get(handlers::callback))
            .route("/auth/logout", post(handlers::logout))
            .route("/auth/me", get(handlers::me))
            .with_state(self.clone())
    }

    /// True when sign-in is bypassed for local development.
    pub fn is_disabled(&self) -> bool {
        self.provider.is_none()
    }

    /// Live sessions, for a health endpoint.
    pub fn sessions_held(&self) -> usize {
        self.sessions.count()
    }

    /// The caller's identity from the session cookie, for the auth extractor.
    ///
    /// `None` when there is no cookie or no live session behind it — the
    /// extractor then answers 401. `Some(Err(403))` when the session is valid
    /// but a browser sent the cookie on another page's behalf: the browser
    /// attaches it on its own, so the cookie alone must never be enough.
    ///
    /// - A request that changes state must come from this origin
    ///   ([`same_origin`]).
    /// - A read is refused when the browser's Fetch Metadata says another site's
    ///   page made it — an `<img>`, `fetch` or WebSocket from a sibling host —
    ///   unless it is a top-level navigation, so ordinary links still work.
    ///   SameSite=Lax alone does not cover this: every host under the same
    ///   registrable domain is the same "site".
    pub(crate) fn authenticate(&self, parts: &Parts) -> Option<Result<Claims, StatusCode>> {
        let id = cookie::read(&parts.headers, self.names.session)?;
        let session = self.sessions.get(id)?;
        let safe = matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);
        if !safe && !same_origin(&parts.headers, &self.origin) {
            tracing::warn!(method = %parts.method, "login: refused a cookie-authenticated request from another origin");
            return Some(Err(StatusCode::FORBIDDEN));
        }
        if safe && embedded_by_another_site(&parts.headers) {
            tracing::warn!("login: refused a cookie-authenticated read embedded by another site");
            return Some(Err(StatusCode::FORBIDDEN));
        }
        Some(Ok(Claims {
            sub: session.identity.sub,
            email: session.identity.email,
            exp: session.expires_at as usize,
            auth_time: session.auth_time.map(|t| t as usize),
        }))
    }
}

/// Security logic with a twin: the fleet's BFF applies the same rule to the
/// sessions it proxies. Change both together.
///
/// Whether the browser says another site's page made this request — as a
/// subresource, or as a frame (frames are `navigate` too, so the destination
/// tells them apart from a top-level navigation). Browsers without Fetch
/// Metadata send none of these headers and pass: the check only ever refuses
/// on evidence.
fn embedded_by_another_site(headers: &HeaderMap) -> bool {
    let header = |name: &str| headers.get(name).map(|v| v.as_bytes());
    let top_level = header("sec-fetch-mode") == Some(b"navigate") && matches!(header("sec-fetch-dest"), None | Some(b"document"));
    matches!(header("sec-fetch-site"), Some(b"same-site" | b"cross-site")) && !top_level
}

/// Whether a request came from `origin` itself: its `Origin` header equals it,
/// or — when a browser omits `Origin` — `Sec-Fetch-Site` says `same-origin`. A
/// request with neither is refused: browsers send at least one on every
/// state-changing request, so its absence means something that is not a page of
/// ours.
pub fn same_origin(headers: &HeaderMap, origin: &str) -> bool {
    match headers.get(ORIGIN) {
        Some(o) => o.as_bytes() == origin.as_bytes(),
        None => headers.get("sec-fetch-site").is_some_and(|v| v.as_bytes() == b"same-origin"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn config(public_url: &str) -> LoginConfig {
        LoginConfig::new("https://idp.example.com", "client", public_url)
    }

    #[test]
    fn public_url_must_be_an_https_origin() {
        assert!(Login::new(config("https://tool.example.com")).is_ok());
        assert!(Login::new(config("https://tool.example.com/")).is_ok());
        assert!(Login::new(config("http://localhost:3000")).is_ok(), "plain http is fine on loopback");
        for bad in ["http://tool.example.com", "https://tool.example.com/app", "https://u:p@tool.example.com", "https://tool.example.com/?x=1", "tool.example.com", ""] {
            assert!(Login::new(config(bad)).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn session_lifetime_is_bounded() {
        let mut c = config("https://tool.example.com");
        c.session_ttl = Duration::from_secs(10);
        assert!(Login::new(c.clone()).is_err());
        c.session_ttl = Duration::from_secs(30 * 24 * 3600);
        assert!(Login::new(c).is_err());
    }

    #[test]
    fn https_deployments_use_host_locked_cookies() {
        assert_eq!(Login::new(config("https://tool.example.com")).unwrap().names.session, "__Host-session");
        assert_eq!(Login::new(config("http://localhost:3000")).unwrap().names.session, "session");
    }

    #[test]
    fn dev_no_auth_needs_no_provider() {
        let mut c = LoginConfig::new("", "", "http://localhost:3000");
        c.dev_no_auth = true;
        assert!(Login::new(c).unwrap().is_disabled());
    }

    #[test]
    fn reads_embedded_by_another_site_are_spotted_but_links_are_not() {
        let h = |site: Option<&'static str>, mode: Option<&'static str>| {
            let mut h = HeaderMap::new();
            if let Some(s) = site {
                h.insert("sec-fetch-site", HeaderValue::from_static(s));
            }
            if let Some(m) = mode {
                h.insert("sec-fetch-mode", HeaderValue::from_static(m));
            }
            h
        };
        let mut framed = h(Some("same-site"), Some("navigate"));
        framed.insert("sec-fetch-dest", HeaderValue::from_static("iframe"));
        assert!(embedded_by_another_site(&framed), "a frame on a sibling host");
        let mut linked = h(Some("same-site"), Some("navigate"));
        linked.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        assert!(!embedded_by_another_site(&linked));
        assert!(embedded_by_another_site(&h(Some("same-site"), Some("no-cors"))), "an <img> from a sibling host");
        assert!(embedded_by_another_site(&h(Some("cross-site"), Some("cors"))));
        assert!(embedded_by_another_site(&h(Some("same-site"), Some("websocket"))));
        assert!(!embedded_by_another_site(&h(Some("same-site"), Some("navigate"))), "a link is fine");
        assert!(!embedded_by_another_site(&h(Some("same-origin"), Some("cors"))));
        assert!(!embedded_by_another_site(&h(None, None)), "no metadata, no evidence");
    }

    #[test]
    fn same_origin_checks_origin_then_fetch_metadata() {
        let o = "https://tool.example.com";
        let mut h = HeaderMap::new();
        assert!(!same_origin(&h, o), "no headers at all is not a page of ours");
        h.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        assert!(same_origin(&h, o));
        h.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert!(!same_origin(&h, o));
        h.insert(ORIGIN, HeaderValue::from_static("https://tool.example.com"));
        assert!(same_origin(&h, o), "a matching Origin wins");
        for other in ["https://evil.example", "null", "https://tool.example.com.evil.example", "http://tool.example.com"] {
            h.insert(ORIGIN, HeaderValue::from_str(other).unwrap());
            assert!(!same_origin(&h, o), "{other} must not pass");
        }
    }
}
