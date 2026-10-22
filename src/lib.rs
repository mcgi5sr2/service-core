//! service-core — shared building blocks for a small Rust service fleet.
//!
//! One audited home for the OIDC bearer extractor, a bounded async-job store, and
//! size-capped body reads, instead of copy-pasting them per service. Consumed as a git
//! dependency (like `rust-ldap`) so each service's container build stays self-contained.
//!
//! - [`auth`] — OIDC/Dex bearer validation: a self-refreshing [`auth::JwksStore`]
//!   (single-flight + cooldown) and the [`auth::AuthenticatedUser`] extractor. The
//!   request→identity boundary lives here, so a future BFF-trust mode can slot in
//!   without touching consumers.
//! - [`jobs`] — a bounded, TTL-swept [`jobs::JobStore`] for async job APIs.
//! - [`http`] — [`http::read_body_capped`], a size-capped response-body reader.
//! - [`wg`] (feature `wg`) — an in-process userspace WireGuard transport with a
//!   handshake watchdog and a `/health`-ready [`wg::forward::WgHealth`] handle.
//!   Feature-gated: boringtun + smoltcp are heavy, and non-tunnel consumers must
//!   not pay for them.
//! - [`llm`] (feature `llm`) — a bounded client for an OpenAI-compatible
//!   chat-completion service, typically reached through the [`wg`] loopback.

pub mod auth;
pub mod bff;
pub mod http;
pub mod jobs;
#[cfg(feature = "llm")]
pub mod llm;
#[cfg(feature = "wg")]
pub mod wg;
