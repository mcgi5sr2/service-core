//! Server-side sessions. The browser holds only an opaque id in an `HttpOnly`
//! cookie; who the user is lives here and never reaches page script.
//!
//! A session holds the identity and when the user last actually authenticated —
//! nothing else. The identity provider's tokens are not kept: a service only
//! needs to know who is calling, and holding credentials it never uses would be
//! risk with no benefit.
//!
//! In memory, per process: a restart signs everyone out, and the identity
//! provider's own session makes the next sign-in silent. The map is behind a std
//! `Mutex` held only for the map operation, never across an `.await`.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;

use crate::auth::unix_now;

/// Ceiling on live sessions. Each is a few hundred bytes; at the cap the oldest
/// is evicted, so memory stays bounded however many sign-ins arrive.
const MAX_SESSIONS: usize = 10_000;
/// Ceiling per user. Without it, one person scripting sign-ins could push
/// everyone else's sessions out of the store; with it, they only evict their own.
const MAX_PER_SUBJECT: usize = 20;
/// How often an insert may sweep expired sessions. The sweep is O(n); doing it
/// at most this often keeps sign-in cheap without a background task.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// The signed-in user, safe to show to the page (no credentials).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Identity {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct Session {
    pub identity: Identity,
    /// When the user last entered credentials at the identity provider (OIDC
    /// `auth_time`, seconds since the epoch). What step-up checks read.
    pub auth_time: Option<u64>,
    /// Absolute expiry as seconds since the epoch — what `Claims::exp` carries.
    pub expires_at: u64,
    /// Monotonic creation time: what expiry is decided on.
    created: Instant,
    /// Wall-clock twin of `created`, kept only to notice the two clocks
    /// disagreeing (sessions reaped while young looked like user error once).
    created_wall: SystemTime,
}

struct Inner {
    map: HashMap<String, Session>,
    last_sweep: Instant,
}

pub(crate) struct SessionStore {
    inner: Mutex<Inner>,
    ttl: Duration,
}

/// 32 bytes from the OS CSPRNG, base64url without padding: an unguessable id.
/// A CSPRNG failure fails the one request that needed an id, never the process,
/// and never falls back to anything weaker.
pub(crate) fn new_id() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self { inner: Mutex::new(Inner { map: HashMap::new(), last_sweep: Instant::now() }), ttl }
    }

    /// The absolute session lifetime.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The map, recovering from a poisoned lock. It is a plain map with no
    /// cross-key invariant, so poisoning protects nothing here — while
    /// propagating the panic would refuse every request for everyone.
    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Store a new session and return its id. `Err` only if the CSPRNG failed.
    pub fn insert(&self, identity: Identity, auth_time: Option<u64>) -> Result<String, getrandom::Error> {
        let id = new_id()?;
        let mut inner = self.inner();
        if inner.last_sweep.elapsed() >= SWEEP_EVERY {
            self.sweep_locked(&mut inner);
        }
        // O(n) scans, only on sign-in (a human event), never on a request.
        let theirs: Vec<(&String, Instant)> =
            inner.map.iter().filter(|(_, s)| s.identity.sub == identity.sub).map(|(k, s)| (k, s.created)).collect();
        let evict = if theirs.len() >= MAX_PER_SUBJECT {
            theirs.into_iter().min_by_key(|(_, created)| *created).map(|(k, _)| k.clone())
        } else if inner.map.len() >= MAX_SESSIONS {
            let oldest = inner.map.iter().min_by_key(|(_, s)| s.created).map(|(k, _)| k.clone());
            tracing::warn!(held = inner.map.len(), "login: session store full — evicting the oldest session");
            oldest
        } else {
            None
        };
        if let Some(k) = evict {
            inner.map.remove(&k);
        }
        inner.map.insert(
            id.clone(),
            Session {
                identity,
                auth_time,
                expires_at: unix_now() + self.ttl.as_secs(),
                created: Instant::now(),
                created_wall: SystemTime::now(),
            },
        );
        Ok(id)
    }

    /// The session for `id` if it exists and is within its lifetime. An expired
    /// one is removed and treated as absent.
    pub fn get(&self, id: &str) -> Option<Session> {
        let mut inner = self.inner();
        match inner.map.get(id) {
            Some(s) if s.created.elapsed() < self.ttl => Some(s.clone()),
            Some(_) => {
                if let Some(s) = inner.map.remove(id)
                    && s.created_wall.elapsed().unwrap_or_default() < self.ttl
                {
                    tracing::error!("login: session expired by the monotonic clock while the wall clock says it is young — clock divergence");
                }
                None
            }
            None => None,
        }
    }

    pub fn remove(&self, id: &str) {
        self.inner().map.remove(id);
    }

    /// How many sessions are held. Worth surfacing on a health endpoint.
    pub fn count(&self) -> usize {
        self.inner().map.len()
    }

    fn sweep_locked(&self, inner: &mut Inner) {
        let before = inner.map.len();
        let ttl = self.ttl;
        let mut diverged = 0usize;
        inner.map.retain(|_, s| {
            let keep = s.created.elapsed() < ttl;
            if !keep && s.created_wall.elapsed().unwrap_or_default() < ttl {
                diverged += 1;
            }
            keep
        });
        inner.last_sweep = Instant::now();
        if diverged > 0 {
            tracing::error!(diverged, "login: sessions expired by the monotonic clock while the wall clock says they are young — clock divergence");
        }
        let removed = before - inner.map.len();
        if removed > 0 {
            tracing::info!(removed, remaining = inner.map.len(), "login: session sweep");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(sub: &str) -> Identity {
        Identity { sub: sub.into(), email: Some(format!("{sub}@example.com")), name: None }
    }

    #[test]
    fn ids_are_unique_url_safe_and_long() {
        let a = new_id().unwrap();
        let b = new_id().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 43); // 32 bytes, base64url, unpadded
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn insert_then_get_carries_identity_auth_time_and_expiry() {
        let store = SessionStore::new(Duration::from_secs(3600));
        let id = store.insert(ident("u1"), Some(1_700_000_000)).unwrap();
        let s = store.get(&id).unwrap();
        assert_eq!(s.identity, ident("u1"));
        assert_eq!(s.auth_time, Some(1_700_000_000));
        let now = unix_now();
        assert!(s.expires_at >= now + 3599 && s.expires_at <= now + 3600);
    }

    #[test]
    fn an_expired_session_is_gone() {
        let store = SessionStore::new(Duration::ZERO);
        let id = store.insert(ident("u1"), None).unwrap();
        assert!(store.get(&id).is_none());
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn remove_forgets_and_unknown_ids_are_harmless() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.insert(ident("u1"), None).unwrap();
        store.remove(&id);
        assert!(store.get(&id).is_none());
        store.remove("nonexistent");
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn the_store_is_bounded_and_evicts_the_oldest() {
        let store = SessionStore::new(Duration::from_secs(60));
        let first = store.insert(ident("first"), None).unwrap();
        for i in 1..MAX_SESSIONS {
            store.insert(ident(&format!("u{i}")), None).unwrap();
        }
        assert_eq!(store.count(), MAX_SESSIONS);
        let newest = store.insert(ident("newest"), None).unwrap();
        assert_eq!(store.count(), MAX_SESSIONS);
        assert!(store.get(&first).is_none(), "the oldest session should have been evicted");
        assert!(store.get(&newest).is_some());
    }

    #[test]
    fn one_user_signing_in_repeatedly_only_evicts_their_own_sessions() {
        let store = SessionStore::new(Duration::from_secs(60));
        let bystander = store.insert(ident("bystander"), None).unwrap();
        let first_of_theirs = store.insert(ident("busy"), None).unwrap();
        for _ in 0..(MAX_PER_SUBJECT * 3) {
            store.insert(ident("busy"), None).unwrap();
        }
        assert_eq!(store.count(), MAX_PER_SUBJECT + 1);
        assert!(store.get(&bystander).is_some(), "someone else's session survives");
        assert!(store.get(&first_of_theirs).is_none(), "their own oldest went first");
    }

    #[test]
    fn inserts_sweep_expired_sessions_periodically() {
        let store = SessionStore::new(Duration::ZERO);
        store.insert(ident("a"), None).unwrap();
        store.inner().last_sweep = Instant::now() - SWEEP_EVERY;
        store.insert(ident("b"), None).unwrap();
        // "a" was swept by the second insert; "b" is expired but not yet swept.
        assert_eq!(store.count(), 1);
    }
}
