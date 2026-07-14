//! service-core — shared building blocks for the internal-tools service fleet.
//!
//! Extracted because the per-service copies had drifted: the gated JWKS refresh
//! (DoS hardening) shipped in only 2 of ~9 services. Consumed as a git dependency,
//! like `rust-ldap`, so each service's container build stays self-contained.
//!
//! - [`auth`] — OIDC/Dex bearer validation: a self-refreshing [`auth::JwksStore`]
//!   (single-flight + cooldown) and the [`auth::AuthenticatedUser`] extractor. The
//!   request→identity boundary lives here, so a future BFF-trust mode can slot in
//!   without touching consumers.
//! - [`jobs`] — a bounded, TTL-swept [`jobs::JobStore`] for async job APIs.
//! - [`http`] — [`http::read_body_capped`], a size-capped response-body reader.

pub mod auth;
pub mod http;
pub mod jobs;
