# service-core

Shared building blocks for a small Rust service fleet: OIDC bearer validation, a bounded
async-job store, size-capped body reads, and (opt-in) browser sign-in for a service's own UI.

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

## `login` — browser sign-in (feature `login`)

For a service that serves its own UI: the OIDC authorization-code flow with PKCE against the
identity provider, a server-side session, and an opaque `HttpOnly` cookie. The browser never
holds a token, code verifier or nonce.

```toml
service-core = { git = "…", tag = "…", features = ["login", "openapi"] }
```

```rust
use service_core::auth::{AuthOptions, AuthenticatedUser, JwksStore};
use service_core::login::{Login, LoginConfig};

let login = Login::new(LoginConfig::from_env(dev_no_auth)?)?;
let jwks = JwksStore::with_options(issuer, audience, dev_no_auth,
    AuthOptions { login: Some(login.clone()), ..Default::default() }).await?;

let app = Router::new()
    .route("/api/things", get(things))   // `AuthenticatedUser` now accepts the session too
    .merge(login.router())               // /auth/login, /auth/callback, /auth/logout, /auth/me
    .with_state(state);
```

`LoginConfig::from_env` reads `DEX_ISSUER_URL`, `OIDC_CLIENT_ID`, `PUBLIC_URL` (this service's
origin, e.g. `https://tool.example.com`) and `LOGIN_SESSION_TTL_SECS` (default 8 h). Register
`<PUBLIC_URL>/auth/callback` with the provider; several services can share one public client,
each registering its own callback.

| route | |
|---|---|
| `GET /auth/login?returnTo=/path&stepUp=1` | start a sign-in; `stepUp=1` forces the user to re-enter credentials |
| `GET /auth/callback` | the provider's redirect back |
| `POST /auth/logout` | end the session; same-origin only |
| `GET /auth/me` | `{authenticated, sub, email, name}` |

What it guarantees:

- **Host-only cookies.** Over HTTPS every cookie is `__Host-`prefixed, so the browser itself
  refuses one that is not `Secure`, `Path=/` and domain-less. Services sharing a parent domain
  never see each other's sessions.
- **No ambient writes.** A cookie-authenticated `POST`/`PUT`/`PATCH`/`DELETE` must carry this
  origin's `Origin` (or `Sec-Fetch-Site: same-origin`), or it gets `403`. Bearer requests are
  unaffected.
- **A callback finishes only in the browser that started it.** Each sign-in's PKCE verifier,
  nonce and destination are sealed (XChaCha20-Poly1305, per-process key) into a short-lived
  cookie for that browser, bound to the flow's `state`. Nothing is held server-side, so a flood
  of sign-in starts cannot evict anyone's sign-in; a browser keeps at most five such cookies.
- **Explicit credentials win.** A request with an `Authorization` header is judged on its bearer
  alone, whatever cookies ride along.
- **No embedded reads from sibling hosts.** A cookie-authenticated read that the browser marks as
  made by another site's page (an `<img>`, `fetch`, WebSocket or frame — anything but a top-level
  navigation) gets `403`. `SameSite=Lax` alone does not cover this: every host under the same
  registrable domain is the same site.
- **Starts without the provider.** Discovery happens on the first sign-in; until the provider
  answers, `/auth/login` returns `503` and everything else keeps working. Key rotations are
  picked up by re-fetching keys when an ID token fails verification.
- **Bounded.** Sessions are capped overall and at 20 per user, oldest evicted first, so one
  person cannot sign everyone else out; responses from the provider are size-capped and never
  followed through a redirect. A failed callback is retried once, to the same destination and
  step-up.
- **Step-up.** The session keeps the ID token's `auth_time`, so `AuthenticatedUser`'s
  `claims.auth_time` works for a cookie exactly as it does for a bearer.

Sessions and the sign-in key live in one process's memory, so run one replica (or pin each
browser to one). Sessions hold identity only — no provider tokens — and live in memory: a restart signs
everyone out, and the provider's own session makes the next sign-in silent. Sign-out is local:
it ends this service's session, not the provider's. With `dev_no_auth` there is no provider and
every caller is a stub user; `JwksStore` refuses to start if its `dev_no_auth` and the login's
disagree.

Two rules the extractor cannot enforce for you:

- **Never change state in a `GET` handler.** Cookie-authenticated reads are allowed from links.
- **Never combine `login` with a CORS layer that allows credentials** (`allow_credentials(true)`
  with a mirrored or wildcard origin): it would let other sites read responses with the user's
  session.

Gate routes with `AuthenticatedUser`. A hand-rolled check on `JwksStore::validate` sees only
bearers, not sessions, and none of the protections above.

Feature `openapi` adds `login::openapi::LoginApi` (utoipa 6) to merge into the service's spec.

## Versioning

Pre-1.0: minor version may break. Consumers pin a tag, so nothing updates without an explicit
bump.

## Licence

Not yet chosen. Until one is added, default copyright applies and the code is not licensed for
reuse by others.
