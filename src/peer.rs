//! Peer tokens: an identity-provider token that a trusted upstream obtained for
//! ANOTHER service (a peer) on the user's behalf, forwarded beside the request's
//! own credential so this service can call the peer as that user.
//!
//! The problem it solves: a backend-for-frontend signs the user in once, and some
//! services behind it must call a peer service as the user. The peer only accepts
//! tokens issued for its own audience, and the BFF's ordinary token must not be one
//! (every service it forwards to could then act at the peer). So the BFF keeps a
//! separate grant for the peer and forwards that token, in its own header, only to
//! the services allowed to use it. This module is the receiving end.
//!
//! Trust model: the header is not trusted because of where it came from (a service
//! is usually reachable without the BFF too). [`crate::auth::JwksStore::peer_token`]
//! verifies it against the same issuer and keys as the request's own credential,
//! insists on the peer's audience, and requires the SAME subject as the user the
//! request already authenticated as. A mismatched pair is refused: otherwise a
//! caller could pair their own sign-in with someone else's peer token and have this
//! service act on the peer's data under the wrong user. What the peer allows the
//! token to do (how old it may be, which client obtained it) is the peer's to
//! enforce; this check only decides whether this service may use it for this user.
//!
//! The raw token is only ever handed to the caller to forward to the peer. It is
//! never logged, and [`PeerToken`]'s `Debug` leaves it out.

use axum::http::HeaderName;

use crate::auth::Claims;

/// A peer service whose tokens this service accepts in a header.
#[derive(Debug, Clone)]
pub struct Peer {
    /// What callers name the peer by in [`crate::auth::JwksStore::peer_token`].
    pub name: String,
    /// The request header the upstream forwards the peer's token in.
    pub header: HeaderName,
    /// The audience the peer's tokens are issued for (the peer's client id).
    pub audience: String,
}

/// A verified peer token: the bearer to send the peer, and its claims.
pub struct PeerToken {
    pub(crate) token: String,
    pub(crate) claims: Claims,
}

impl PeerToken {
    /// The token to send the peer as `Authorization: Bearer <token>`.
    pub fn bearer(&self) -> &str {
        &self.token
    }

    /// The token's claims. `sub` always equals the request's user.
    pub fn claims(&self) -> &Claims {
        &self.claims
    }
}

impl std::fmt::Debug for PeerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerToken").field("claims", &self.claims).finish_non_exhaustive()
    }
}
