# service-core

Shared building blocks for a small Rust service fleet: OIDC bearer validation, a bounded
async-job store, and size-capped body reads.

These three pieces were being copy-pasted into every service. Each copy drifted, and a fix to
one (say, a JWKS refresh hardening) never reached the others. This crate gives them one audited
home. It is deliberately small — it is not a framework, and it holds only the code that was
genuinely duplicated.

Consumed as a git dependency, so each service's container build stays self-contained with no
registry dependency.

```toml
[dependencies]
service-core = { git = "https://github.com/mcgi5sr2/service-core.git", tag = "v0.1.0" }
```

Pin a `tag` or `rev`. Tracking a branch makes builds non-reproducible.

## `auth` — OIDC bearer validation

The request→identity boundary. `JwksStore` fetches and caches an issuer's JWKS, refreshing
itself when it sees an unknown key ID.

- **Single-flight refresh** — concurrent requests carrying an unknown `kid` trigger one fetch,
  not a thundering herd against the issuer.
- **Cooldown on failure** — a failing issuer does not get hammered once per request.
- **HTTP timeouts** — a hung issuer cannot stall the store indefinitely.
- **Fails closed** — validation errors yield `401`/`403`, never an authenticated request.

```rust
use service_core::auth::{AuthenticatedUser, JwksStore};

let jwks = JwksStore::new(issuer, audience, /* dev_no_auth */ false).await?;
let app = Router::new().route("/api/thing", get(handler)).with_state(jwks);

async fn handler(user: AuthenticatedUser) -> impl IntoResponse {
    // Only reached with a valid token; `user` carries the verified claims.
    Json(json!({ "sub": user.claims.sub }))
}
```

`AuthenticatedUser` is an axum extractor, so an endpoint that takes one cannot be reached
unauthenticated — the type system enforces it rather than a convention.

### `dev_no_auth`

`JwksStore::new(.., dev_no_auth: true)` disables validation for local development. It is a
loaded gun: it makes every extractor succeed. Gate it behind an explicit environment variable
that is never set in a deployed environment, and treat `is_disabled()` as something worth
surfacing on a health endpoint.

## `jobs` — bounded async-job store

An in-memory store for the submit-then-poll pattern, built so a job API cannot become an
unbounded memory leak.

- `try_create_under(limit)` returns `None` once `limit` jobs are live, giving callers a
  backpressure signal (`429`) instead of growing without limit.
- `evict_terminal_older_than(ttl)` sweeps finished jobs. Call it periodically; nothing reaps
  automatically.

```rust
let store = JobStore::new();
let Some(id) = store.try_create_under(64) else {
    return StatusCode::TOO_MANY_REQUESTS.into_response();
};
store.set(&id, JobStatus::Running);
```

State is per-process and lost on restart. That is a deliberate fit for jobs that are
re-runnable, not a durable queue.

## `http` — capped body reads

```rust
let bytes = read_body_capped(resp, 8 * 1024 * 1024, "issuer JWKS").await?;
```

Reads a response body while enforcing a byte ceiling, so a remote that streams unboundedly
cannot exhaust memory. The `what` argument names the source in the error. Prefer this over
`resp.bytes()` for any response from a host you do not control.

## Versioning

Pre-1.0: minor version may break. Consumers pin a tag, so nothing updates without an explicit
bump.

## Licence

Not yet chosen. Until one is added, default copyright applies and the code is not licensed for
reuse by others.
