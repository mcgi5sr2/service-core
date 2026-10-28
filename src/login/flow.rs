//! In-progress sign-ins, each sealed into its own cookie.
//!
//! A sign-in has to remember, between `/auth/login` and the callback, what must
//! never travel in the URL: the PKCE verifier and the nonce, plus where to land
//! and whether it was a step-up. Holding that in a shared server-side map let
//! anyone evict real users' sign-ins by flooding `/auth/login` — and every host
//! under the same parent domain could make its visitors' browsers do the
//! flooding. So nothing is held server-side: the flow is encrypted and
//! authenticated (XChaCha20-Poly1305) under a per-process key and handed to the
//! browser that started it, in a cookie named after the flow's `state`.
//!
//! What that gives:
//! - **No shared state to exhaust.** A flood of sign-in starts costs CPU only.
//! - **Only the starting browser can finish.** The cookie is the binding: a
//!   callback URL handed to someone else arrives without it, so an attacker
//!   cannot sign a victim in as themselves.
//! - **Bound to its state.** The state is the AEAD's associated data, so one
//!   flow's cookie cannot complete another flow, and nothing in it can be read
//!   or altered without the key.
//! - **Expiring.** The sealed issue time is checked against `FLOW_TTL` as well
//!   as the cookie's own `Max-Age`.
//!
//! The key lives only in memory, so a restart invalidates sign-ins in progress;
//! the callback then sends the browser round once more, as it always has.

use std::time::Duration;

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use openidconnect::{Nonce, PkceCodeVerifier};

use crate::auth::unix_now;

/// How long a sign-in may sit half-finished. This is a human at a login page:
/// a password, very possibly MFA, and the ordinary chance of being interrupted.
/// Ten minutes did not cover an ordinary morning in production, and the reward
/// for finally signing in was an error page.
pub(crate) const FLOW_TTL: Duration = Duration::from_secs(1800);

/// Longest `returnTo` honoured. It rides in a cookie, and a browser may hold a
/// few sign-in cookies at once: kept small so they can never push the Cookie
/// header past a proxy's limit (8 KB on common defaults).
const MAX_RETURN_TO: usize = 256;

/// A `state` we minted: base64url. Checked before it names a cookie, since the
/// callback's copy comes from the URL.
pub(crate) fn valid_state(state: &str) -> bool {
    (16..=64).contains(&state.len()) && state.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub(crate) struct Flow {
    pub pkce_verifier: PkceCodeVerifier,
    pub nonce: Nonce,
    pub return_to: String,
    pub step_up: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Sealed {
    /// PKCE verifier.
    v: String,
    /// Nonce.
    n: String,
    /// Return-to path.
    r: String,
    /// Step-up.
    s: bool,
    /// Issued at, seconds since the epoch.
    t: u64,
}

pub(crate) struct FlowSealer {
    cipher: XChaCha20Poly1305,
}

impl FlowSealer {
    /// A sealer with a fresh random key.
    pub fn new() -> Result<Self, getrandom::Error> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key)?;
        Ok(Self { cipher: XChaCha20Poly1305::new(&Key::from(key)) })
    }

    /// The cookie value carrying `flow`, bound to `state`.
    pub fn seal(&self, state: &str, flow: &Flow) -> anyhow::Result<String> {
        let plain = serde_json::to_vec(&Sealed {
            v: flow.pkce_verifier.secret().clone(),
            n: flow.nonce.secret().clone(),
            r: flow.return_to.clone(),
            s: flow.step_up,
            t: unix_now(),
        })?;
        // A random 24-byte nonce: collisions are negligible at any volume.
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce)?;
        let sealed = self
            .cipher
            .encrypt(&XNonce::from(nonce), Payload { msg: &plain, aad: state.as_bytes() })
            .map_err(|_| anyhow::anyhow!("sealing a sign-in flow failed"))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&sealed);
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out))
    }

    /// The flow sealed in `value` for `state` — `None` if it was sealed under
    /// another key (a restart), for another state, altered, or is too old.
    pub fn open(&self, state: &str, value: &str) -> Option<Flow> {
        let (sealed, issued) = self.open_raw(state, value)?;
        (unix_now().saturating_sub(issued) < FLOW_TTL.as_secs()).then_some(sealed)
    }

    /// The issue time of a flow cookie, if it opens at all; used to prune the
    /// oldest when a browser holds too many.
    pub fn issued_at(&self, state: &str, value: &str) -> Option<u64> {
        self.open_raw(state, value).map(|(_, t)| t)
    }

    fn open_raw(&self, state: &str, value: &str) -> Option<(Flow, u64)> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value).ok()?;
        if bytes.len() <= 24 {
            return None;
        }
        let (nonce, sealed) = bytes.split_at(24);
        let nonce: [u8; 24] = nonce.try_into().ok()?;
        let plain = self.cipher.decrypt(&XNonce::from(nonce), Payload { msg: sealed, aad: state.as_bytes() }).ok()?;
        let s: Sealed = serde_json::from_slice(&plain).ok()?;
        let flow = Flow {
            pkce_verifier: PkceCodeVerifier::new(s.v),
            nonce: Nonce::new(s.n),
            return_to: s.r,
            step_up: s.s,
        };
        Some((flow, s.t))
    }
}

/// A `returnTo` is honoured only as a same-origin absolute path: one leading
/// `/`, so not `//host` or `https://host`. Backslashes are refused because
/// browsers resolve a `Location` with the WHATWG parser, where `/\evil.example`
/// lands on evil.example; control characters and whitespace are refused so no
/// other host-smuggling or header-splitting spelling gets through. `"` is
/// refused too: browsers always percent-encode it in a real path or query, and
/// unencoded it doubles in size inside the sealed flow. Anything else lands on `/`.
pub(crate) fn safe_return_to(raw: Option<&str>) -> String {
    match raw {
        Some(p)
            if p.len() <= MAX_RETURN_TO
                && p.starts_with('/')
                && !p.starts_with("//")
                && !p.contains(['\\', '"'])
                && !p.chars().any(|c| c.is_control() || c.is_whitespace()) =>
        {
            p.to_string()
        }
        _ => "/".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATE: &str = "abcdefghijklmnopqrstuv";

    fn flow() -> Flow {
        Flow {
            pkce_verifier: PkceCodeVerifier::new("verifier-123".into()),
            nonce: Nonce::new("nonce-456".into()),
            return_to: "/tool/7".into(),
            step_up: true,
        }
    }

    #[test]
    fn a_sealed_flow_opens_for_its_state_with_everything_intact() {
        let sealer = FlowSealer::new().unwrap();
        let value = sealer.seal(STATE, &flow()).unwrap();
        let opened = sealer.open(STATE, &value).unwrap();
        assert_eq!(opened.pkce_verifier.secret(), "verifier-123");
        assert_eq!(opened.nonce.secret(), "nonce-456");
        assert_eq!(opened.return_to, "/tool/7");
        assert!(opened.step_up);
        // Nothing secret is readable in the cookie value.
        assert!(!value.contains("verifier") && !String::from_utf8_lossy(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&value).unwrap()).contains("verifier"));
    }

    #[test]
    fn the_largest_flow_cookie_stays_small() {
        let sealer = FlowSealer::new().unwrap();
        let big = Flow { return_to: safe_return_to(Some(&format!("/{}", "é".repeat(127)))), ..flow() };
        let value = sealer.seal(STATE, &big).unwrap();
        // Five of these plus names must fit well inside an 8 KB header.
        assert!(value.len() < 1000, "flow cookie is {} bytes", value.len());
    }

    #[test]
    fn a_flow_does_not_open_for_another_state() {
        let sealer = FlowSealer::new().unwrap();
        let value = sealer.seal(STATE, &flow()).unwrap();
        assert!(sealer.open("zyxwvutsrqponmlkjihgfe", &value).is_none());
    }

    #[test]
    fn a_tampered_or_garbage_value_does_not_open() {
        let sealer = FlowSealer::new().unwrap();
        let value = sealer.seal(STATE, &flow()).unwrap();
        let mut bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&value).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        assert!(sealer.open(STATE, &tampered).is_none());
        for garbage in ["", "!!!", "AAAA", &"A".repeat(40)] {
            assert!(sealer.open(STATE, garbage).is_none(), "{garbage:?}");
        }
    }

    #[test]
    fn a_flow_from_before_a_restart_does_not_open() {
        let value = FlowSealer::new().unwrap().seal(STATE, &flow()).unwrap();
        assert!(FlowSealer::new().unwrap().open(STATE, &value).is_none());
    }

    #[test]
    fn an_old_flow_does_not_open() {
        let sealer = FlowSealer::new().unwrap();
        // Seal by hand with an issue time past the TTL.
        let plain = serde_json::to_vec(&Sealed { v: "v".into(), n: "n".into(), r: "/".into(), s: false, t: unix_now() - FLOW_TTL.as_secs() }).unwrap();
        let nonce = [7u8; 24];
        let sealed = sealer.cipher.encrypt(&XNonce::from(nonce), Payload { msg: &plain, aad: STATE.as_bytes() }).unwrap();
        let value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([nonce.to_vec(), sealed].concat());
        assert!(sealer.open(STATE, &value).is_none());
        assert!(sealer.issued_at(STATE, &value).is_some(), "still recognisable, so it can be pruned");
    }

    #[test]
    fn a_flow_outlives_a_human_at_a_login_page() {
        assert!(FLOW_TTL >= Duration::from_secs(900), "FLOW_TTL {FLOW_TTL:?} is too short for a real login");
    }

    #[test]
    fn only_minted_shaped_states_are_accepted() {
        assert!(valid_state(STATE));
        for bad in ["short", "has space in it xxxxxx", "semi;colon_xxxxxxxxxxx", "équivalentxxxxxxxxxxxx", &"a".repeat(65)] {
            assert!(!valid_state(bad), "{bad:?}");
        }
    }

    #[test]
    fn return_to_allows_only_same_origin_paths() {
        assert_eq!(safe_return_to(Some("/tool/7?tab=a#x")), "/tool/7?tab=a#x");
        assert_eq!(safe_return_to(Some("/")), "/");
        for bad in [
            "//evil.example",
            "https://evil.example",
            "javascript:alert(1)",
            "/\\evil.example",
            "/\\/evil.example",
            "/\r\nSet-Cookie: x=y",
            "/a b",
            "relative",
            "",
            "/\"quoted\"",
        ] {
            assert_eq!(safe_return_to(Some(bad)), "/", "{bad:?} must fall back to /");
        }
        assert_eq!(safe_return_to(None), "/");
        assert_eq!(safe_return_to(Some(&format!("/{}", "a".repeat(300)))), "/");
        assert_eq!(safe_return_to(Some(&format!("/{}", "a".repeat(255)))).len(), 256);
    }
}
