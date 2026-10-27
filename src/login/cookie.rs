//! The cookies sign-in uses, read and written by hand. A cookie-jar crate would
//! be more surface than a few opaque values need.
//!
//! Every cookie is `HttpOnly` (never readable by page script), `SameSite=Lax`
//! and `Path=/`. Lax keeps the cookie off cross-SITE subrequests only — and a
//! site is the registrable domain, so every host under a shared parent counts
//! as the same site. The real CSRF guards are therefore in
//! [`super::Login::authenticate`], not here. Over HTTPS the names carry the
//! `__Host-` prefix: the browser then refuses the cookie unless it is `Secure`,
//! `Path=/` and has no `Domain`, which pins it to exactly this host — so a
//! sibling host can neither read nor plant one.

use axum::http::HeaderMap;
use axum::http::header::COOKIE;

/// The cookie names for one deployment. `__Host-` needs `Secure`, so a local
/// plain-HTTP run uses the bare names.
#[derive(Debug, Clone)]
pub(crate) struct Names {
    /// The opaque session id.
    pub session: &'static str,
    /// Marks a browser already sent round once after a failed callback.
    pub retry: &'static str,
    /// Prefix of each in-progress sign-in's sealed cookie; the flow's `state`
    /// completes the name, so concurrent sign-ins (two tabs) never collide.
    pub flow_prefix: &'static str,
    secure: bool,
}

impl Names {
    pub fn new(secure: bool) -> Self {
        if secure {
            Self { session: "__Host-session", retry: "__Host-login-retry", flow_prefix: "__Host-login-flow-", secure }
        } else {
            Self { session: "session", retry: "login-retry", flow_prefix: "login-flow-", secure }
        }
    }

    /// The cookie name for the sign-in with this `state`.
    pub fn flow(&self, state: &str) -> String {
        format!("{}{state}", self.flow_prefix)
    }

    /// A hardened `Set-Cookie` value.
    pub fn set(&self, name: &str, value: &str, max_age_secs: u64) -> String {
        let mut c = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}");
        if self.secure {
            c.push_str("; Secure");
        }
        c
    }

    /// A `Set-Cookie` that deletes the cookie.
    pub fn clear(&self, name: &str) -> String {
        self.set(name, "", 0)
    }
}

/// Every `name=value` pair in the request's cookies, in order. A request may
/// carry several `Cookie` headers (HTTP/2 splits them).
pub(crate) fn pairs(headers: &HeaderMap) -> impl Iterator<Item = (&str, &str)> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|raw| raw.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .map(|(k, v)| (k.trim(), v.trim()))
}

/// The value of cookie `name`, if present. Names match exactly (`session`
/// never matches `session_x`); the first match wins; values are taken verbatim —
/// every value we set is base64url or a literal, all cookie-safe.
pub(crate) fn read<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    pairs(headers).find(|(k, _)| *k == name).map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(COOKIE, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn reads_a_named_cookie_among_several_and_across_headers() {
        let h = headers(&["a=1; session=abc_def", "b=2"]);
        assert_eq!(read(&h, "session"), Some("abc_def"));
        assert_eq!(read(&h, "b"), Some("2"));
        assert_eq!(read(&h, "missing"), None);
        assert_eq!(read(&HeaderMap::new(), "session"), None);
    }

    #[test]
    fn does_not_prefix_match() {
        assert_eq!(read(&headers(&["session_x=nope"]), "session"), None);
    }

    #[test]
    fn https_names_are_host_locked_and_secure() {
        let n = Names::new(true);
        assert!(n.session.starts_with("__Host-") && n.retry.starts_with("__Host-") && n.flow("s").starts_with("__Host-"));
        let c = n.set(n.session, "v", 60);
        for flag in ["HttpOnly", "SameSite=Lax", "Path=/", "Secure", "Max-Age=60"] {
            assert!(c.contains(flag), "{flag} missing from {c}");
        }
        // __Host- cookies must not carry a Domain, or the browser drops them.
        assert!(!c.contains("Domain"));
    }

    #[test]
    fn plain_http_drops_only_the_prefix_and_secure() {
        let n = Names::new(false);
        assert_eq!(n.session, "session");
        assert_eq!(n.flow("abc"), "login-flow-abc");
        let c = n.set(n.session, "v", 60);
        assert!(!c.contains("Secure"));
        assert!(c.contains("HttpOnly") && c.contains("SameSite=Lax"));
    }

    #[test]
    fn clear_expires_immediately() {
        let n = Names::new(true);
        assert!(n.clear(n.session).contains("Max-Age=0"));
    }
}
