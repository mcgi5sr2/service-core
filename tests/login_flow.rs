//! End-to-end sign-in against a fake identity provider on a local port.
//!
//! The provider serves discovery, a key set and a token endpoint, and checks
//! PKCE the way a real one does. Each test drives the service's real router —
//! `/auth/*` plus routes behind `AuthenticatedUser` — through a whole sign-in
//! and then attacks one step of it.
#![cfg(feature = "login")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, COOKIE, LOCATION, ORIGIN, SET_COOKIE};
use axum::http::{Request, Response, StatusCode};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use service_core::auth::{AuthOptions, AuthenticatedUser, JwksStore};
use service_core::login::{Login, LoginConfig};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const PUBLIC: &str = "https://tool.example.com";
const CLIENT_ID: &str = "test-client";
const KEY_PEM: &str = include_str!("fixtures/test-only-idp-signing-key.pem");
/// Modulus of the fixture key, base64url — what the fake provider publishes.
const KEY_N: &str = "sC266YSK7l34lFj1Z5DSRt0cbrNinMqqXJvc8K-NDggPFEn1TYdlT1y6XAxILhz9phJo1RUigKz9Zw_1mTTciL8At0Liiy6PxmwS2tn4I6CJBwmw9f-5XQQA-qKuDrFjmUMoNaXE6RNwHenH2mfx_uq7OJiC4H2l32306_LzxaWVjq2doKEd35ElSlIzH1KMARKom_ZTpthJADv2QZr7uyqJxfJciWwlsdkEMgpCbS2gJ2t3hZNl1rFi8rk4WYcZjTd6nO_TQqcPYucloDcAvL3mxMxH7vFdX6xONJujSKyvYJ7VRMM02_jLBasi1664Uy7JDu1_QbeVsrcp-67ltQ";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn sign(kid: &str, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    jsonwebtoken::encode(&header, claims, &EncodingKey::from_rsa_pem(KEY_PEM.as_bytes()).unwrap()).unwrap()
}

// ── the fake identity provider ──────────────────────────────────────────────

/// What the user "did" at the provider for one authorization code.
#[derive(Clone)]
struct Grant {
    nonce: String,
    challenge: String,
    auth_time: u64,
    /// Sign the ID token with this kid.
    kid: &'static str,
}

struct IdpState {
    issuer: String,
    /// The kid the key set publishes the fixture key under (a rotation changes it).
    published_kid: &'static str,
    grants: HashMap<String, Grant>,
    exchanged: Vec<String>,
}

type Idp = Arc<Mutex<IdpState>>;

async fn discovery(State(idp): State<Idp>) -> Json<Value> {
    let iss = idp.lock().unwrap().issuer.clone();
    Json(json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/auth"),
        "token_endpoint": format!("{iss}/token"),
        "jwks_uri": format!("{iss}/keys"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
}

async fn keys(State(idp): State<Idp>) -> Json<Value> {
    let kid = idp.lock().unwrap().published_kid;
    Json(json!({ "keys": [{ "kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid, "n": KEY_N, "e": "AQAB" }] }))
}

async fn token(State(idp): State<Idp>, Form(form): Form<HashMap<String, String>>) -> Result<Json<Value>, StatusCode> {
    let mut idp = idp.lock().unwrap();
    let code = form.get("code").ok_or(StatusCode::BAD_REQUEST)?;
    let grant = idp.grants.remove(code).ok_or(StatusCode::BAD_REQUEST)?;
    idp.exchanged.push(code.clone());
    // PKCE: the verifier must hash to the challenge the browser carried.
    let verifier = form.get("code_verifier").ok_or(StatusCode::BAD_REQUEST)?;
    let hashed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    if hashed != grant.challenge || form.get("redirect_uri").map(String::as_str) != Some(&format!("{PUBLIC}/auth/callback")) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let id_token = sign(
        grant.kid,
        &json!({
            "iss": idp.issuer, "sub": "user-1", "aud": CLIENT_ID,
            "iat": now(), "exp": now() + 3600, "auth_time": grant.auth_time,
            "nonce": grant.nonce, "email": "ada@example.com", "name": "Ada Lovelace",
        }),
    );
    Ok(Json(json!({ "access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": id_token })))
}

async fn start_idp() -> (String, Idp) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let issuer = format!("http://{addr}");
    let idp: Idp = Arc::new(Mutex::new(IdpState { issuer: issuer.clone(), published_kid: "k1", grants: HashMap::new(), exchanged: Vec::new() }));
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/keys", get(keys))
        .route("/token", post(token))
        .with_state(idp.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (issuer, idp)
}

// ── the service under test ──────────────────────────────────────────────────

async fn whoami(user: AuthenticatedUser) -> Json<Value> {
    Json(json!({ "sub": user.claims.sub, "email": user.claims.email, "auth_time": user.claims.auth_time }))
}

async fn act(user: AuthenticatedUser) -> String {
    format!("done for {}", user.claims.sub)
}

async fn service(issuer: &str) -> (Router, Arc<Login>) {
    let login = Login::new(LoginConfig::new(issuer, CLIENT_ID, PUBLIC)).unwrap();
    let jwks = JwksStore::with_options(issuer.into(), CLIENT_ID.into(), false, AuthOptions { login: Some(login.clone()), ..Default::default() })
        .await
        .unwrap();
    let app = Router::new()
        .route("/api/whoami", get(whoami))
        .route("/api/act", post(act))
        .merge(login.router())
        .with_state(jwks);
    (app, login)
}

/// A browser: a cookie jar and the router to talk to.
struct Browser {
    app: Router,
    jar: HashMap<String, String>,
}

impl Browser {
    fn new(app: Router) -> Self {
        Self { app, jar: HashMap::new() }
    }

    async fn send(&mut self, req: axum::http::request::Builder) -> Response<Body> {
        let cookie = self.jar.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        let req = if cookie.is_empty() { req } else { req.header(COOKIE, cookie) };
        let resp = self.app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
        for set in resp.headers().get_all(SET_COOKIE) {
            let set = set.to_str().unwrap();
            let (pair, attrs) = set.split_once(';').unwrap_or((set, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if attrs.contains("Max-Age=0") {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.into(), value.into());
            }
        }
        resp
    }

    async fn get(&mut self, uri: &str) -> Response<Body> {
        self.send(Request::get(uri)).await
    }

    async fn post(&mut self, uri: &str, origin: Option<&str>) -> Response<Body> {
        let mut req = Request::post(uri);
        if let Some(o) = origin {
            req = req.header(ORIGIN, o);
        }
        self.send(req).await
    }

    fn flow_cookies(&self) -> usize {
        self.jar.keys().filter(|k| k.starts_with("__Host-login-flow-")).count()
    }
}

fn location(resp: &Response<Body>) -> String {
    resp.headers()[LOCATION].to_str().unwrap().to_string()
}

async fn json_body(resp: Response<Body>) -> Value {
    serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap()
}

async fn text_body(resp: Response<Body>) -> String {
    String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap()
}

/// The parameters the service sent the browser to the provider with.
fn authorize_params(url: &str) -> HashMap<String, String> {
    let url = openidconnect::url::Url::parse(url).unwrap();
    url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect()
}

/// Begin a sign-in and play the user at the provider: returns the callback URL
/// the provider would send the browser back to, and the authorize parameters.
async fn sign_in_at_provider(
    browser: &mut Browser,
    idp: &Idp,
    login_uri: &str,
    grant: impl FnOnce(&HashMap<String, String>) -> Grant,
) -> (String, HashMap<String, String>) {
    let resp = browser.get(login_uri).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{login_uri}");
    let params = authorize_params(&location(&resp));
    let code = format!("code-{}", params["state"]);
    idp.lock().unwrap().grants.insert(code.clone(), grant(&params));
    (format!("/auth/callback?code={code}&state={}", params["state"]), params)
}

fn honest(params: &HashMap<String, String>) -> Grant {
    Grant { nonce: params["nonce"].clone(), challenge: params["code_challenge"].clone(), auth_time: now(), kid: "k1" }
}

async fn signed_in(issuer: &str, idp: &Idp) -> Browser {
    let (app, _) = service(issuer).await;
    let mut browser = Browser::new(app);
    let (callback, _) = sign_in_at_provider(&mut browser, idp, "/auth/login", honest).await;
    assert_eq!(browser.get(&callback).await.status(), StatusCode::SEE_OTHER);
    assert!(browser.jar.contains_key("__Host-session"));
    browser
}

// ── tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_full_sign_in_session_and_sign_out() {
    let (issuer, idp) = start_idp().await;
    let (app, login) = service(&issuer).await;
    let mut browser = Browser::new(app);

    // Signed out: /auth/me says so and protected routes refuse.
    assert_eq!(json_body(browser.get("/auth/me").await).await, json!({ "authenticated": false }));
    assert_eq!(browser.get("/api/whoami").await.status(), StatusCode::UNAUTHORIZED);

    // The authorize request is PKCE-protected and asks for exactly the client and callback.
    let (callback, params) = sign_in_at_provider(&mut browser, &idp, "/auth/login?returnTo=/tool/7%3Ftab%3Da", honest).await;
    assert_eq!(params["client_id"], CLIENT_ID);
    assert_eq!(params["redirect_uri"], format!("{PUBLIC}/auth/callback"));
    assert_eq!(params["code_challenge_method"], "S256");
    assert_eq!(params["response_type"], "code");
    assert!(params["scope"].split(' ').any(|s| s == "openid"));
    assert!(!params.contains_key("prompt"), "an ordinary sign-in must not force re-authentication");
    let flow_cookie = format!("__Host-login-flow-{}", params["state"]);
    let sealed = browser.jar.get(&flow_cookie).expect("the sign-in is sealed into a cookie for this browser").clone();
    assert!(!sealed.contains(&params["nonce"]), "the cookie does not reveal the nonce");

    let resp = browser.get(&callback).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/tool/7?tab=a");
    let set = resp.headers().get_all(SET_COOKIE).iter().map(|v| v.to_str().unwrap()).collect::<Vec<_>>().join(" | ");
    assert!(set.contains("__Host-session=") && set.contains("HttpOnly") && set.contains("Secure") && set.contains("SameSite=Lax"), "{set}");
    assert!(!browser.jar.contains_key(&flow_cookie), "the used sign-in cookie is cleared");
    assert_eq!(login.sessions_held(), 1);

    // Signed in: the page and the API both see the user.
    assert_eq!(
        json_body(browser.get("/auth/me").await).await,
        json!({ "authenticated": true, "sub": "user-1", "email": "ada@example.com", "name": "Ada Lovelace" })
    );
    let who = json_body(browser.get("/api/whoami").await).await;
    assert_eq!(who["sub"], "user-1");
    assert!(who["auth_time"].as_u64().unwrap() >= now() - 5, "auth_time travels into the claims for step-up checks");

    // State changes need this origin; the cookie alone is not enough.
    assert_eq!(browser.post("/api/act", None).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(browser.post("/api/act", Some("https://evil.example")).await.status(), StatusCode::FORBIDDEN);
    let resp = browser.post("/api/act", Some(PUBLIC)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(text_body(resp).await, "done for user-1");

    // Sign-out: cross-site refused, same-origin ends the session for good.
    assert_eq!(browser.post("/auth/logout", Some("https://evil.example")).await.status(), StatusCode::FORBIDDEN);
    let stolen = browser.jar.get("__Host-session").cloned().unwrap();
    assert_eq!(browser.post("/auth/logout", Some(PUBLIC)).await.status(), StatusCode::NO_CONTENT);
    assert!(!browser.jar.contains_key("__Host-session"), "the cookie is cleared");
    assert_eq!(json_body(browser.get("/auth/me").await).await, json!({ "authenticated": false }));
    browser.jar.insert("__Host-session".into(), stolen);
    assert_eq!(browser.get("/api/whoami").await.status(), StatusCode::UNAUTHORIZED, "the server forgot the session too");
}

#[tokio::test]
async fn a_replayed_callback_signs_nobody_in() {
    let (issuer, idp) = start_idp().await;
    let (app, login) = service(&issuer).await;
    let mut browser = Browser::new(app);
    let (callback, _) = sign_in_at_provider(&mut browser, &idp, "/auth/login", honest).await;
    assert_eq!(browser.get(&callback).await.status(), StatusCode::SEE_OTHER);
    browser.jar.remove("__Host-session");

    // The same callback again: its sign-in cookie is spent, so it goes round once more…
    let resp = browser.get(&callback).await;
    assert_eq!(location(&resp), "/auth/login");
    assert!(!browser.jar.contains_key("__Host-session"));
    // …and a second failure in a row is refused rather than looping.
    let resp = browser.get(&callback).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(text_body(resp).await.contains("[flow-unknown]"));
    assert_eq!(login.sessions_held(), 1, "only the original sign-in made a session");
}

#[tokio::test]
async fn a_callback_url_handed_to_another_browser_is_useless() {
    let (issuer, idp) = start_idp().await;
    let (app, _) = service(&issuer).await;
    let mut attacker = Browser::new(app.clone());
    let (callback, _) = sign_in_at_provider(&mut attacker, &idp, "/auth/login", honest).await;

    // The victim follows the attacker's callback URL.
    let mut victim = Browser::new(app);
    let resp = victim.get(&callback).await;
    assert_eq!(location(&resp), "/auth/login", "sent to sign in as themselves");
    assert!(!victim.jar.contains_key("__Host-session"), "never signed in as the attacker");
    assert!(idp.lock().unwrap().exchanged.is_empty(), "the attacker's code was never even exchanged");
}

#[tokio::test]
async fn a_flood_of_sign_in_starts_cannot_evict_a_real_one() {
    let (issuer, idp) = start_idp().await;
    let (app, _) = service(&issuer).await;
    let mut user = Browser::new(app.clone());
    let (callback, _) = sign_in_at_provider(&mut user, &idp, "/auth/login", honest).await;

    // More cookieless sign-in starts than any server-side store would hold.
    for _ in 0..5000 {
        let resp = app.clone().oneshot(Request::get("/auth/login").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }
    let resp = user.get(&callback).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(user.jar.contains_key("__Host-session"), "the real sign-in still completes");
}

#[tokio::test]
async fn a_browser_keeps_only_a_few_sign_in_cookies() {
    let (issuer, _) = start_idp().await;
    let (app, _) = service(&issuer).await;
    let mut browser = Browser::new(app);
    for _ in 0..12 {
        browser.get("/auth/login").await;
    }
    assert_eq!(browser.flow_cookies(), 5, "older sign-in cookies are pruned so the Cookie header stays small");
}

#[tokio::test]
async fn a_token_for_another_sign_in_is_refused() {
    let (issuer, idp) = start_idp().await;
    let (app, _) = service(&issuer).await;
    let mut browser = Browser::new(app);
    // The provider hands back an ID token minted for a different nonce.
    let (callback, _) = sign_in_at_provider(&mut browser, &idp, "/auth/login", |p| Grant { nonce: "someone-else".into(), ..honest(p) }).await;
    let resp = browser.get(&callback).await;
    assert_eq!(location(&resp), "/auth/login?returnTo=%2F");
    assert!(!browser.jar.contains_key("__Host-session"));
}

#[tokio::test]
async fn a_token_signed_with_an_unknown_key_is_refused() {
    let (issuer, idp) = start_idp().await;
    let (app, _) = service(&issuer).await;
    let mut browser = Browser::new(app);
    let (callback, _) = sign_in_at_provider(&mut browser, &idp, "/auth/login", |p| Grant { kid: "nobody-publishes-this", ..honest(p) }).await;
    let resp = browser.get(&callback).await;
    assert!(location(&resp).starts_with("/auth/login"));
    assert!(!browser.jar.contains_key("__Host-session"));
}

#[tokio::test]
async fn a_key_rotation_right_after_discovery_is_picked_up() {
    let (issuer, idp) = start_idp().await;
    let (app, _) = service(&issuer).await;
    let mut browser = Browser::new(app);
    // This sign-in discovers the provider (and its k1 key).
    let (callback, _) = sign_in_at_provider(&mut browser, &idp, "/auth/login", honest).await;
    // The provider rotates to k2 before the callback, within the cooldown window.
    idp.lock().unwrap().published_kid = "k2";
    idp.lock().unwrap().grants.values_mut().for_each(|g| g.kid = "k2");
    let resp = browser.get(&callback).await;
    assert_eq!(location(&resp), "/", "the new key was fetched and the sign-in completed");
    assert!(browser.jar.contains_key("__Host-session"));
}

#[tokio::test]
async fn a_failed_exchange_retries_the_same_sign_in() {
    let (issuer, idp) = start_idp().await;
    let (app, _) = service(&issuer).await;
    let mut browser = Browser::new(app);
    let (callback, _) = sign_in_at_provider(&mut browser, &idp, "/auth/login?stepUp=1&returnTo=/danger", honest).await;
    idp.lock().unwrap().grants.clear(); // the provider rejects the code: a transient blip
    let resp = browser.get(&callback).await;
    assert_eq!(location(&resp), "/auth/login?returnTo=%2Fdanger&stepUp=1", "same destination, still a step-up");
}

#[tokio::test]
async fn step_up_forces_re_authentication() {
    let (issuer, idp) = start_idp().await;
    let (app, _) = service(&issuer).await;
    let mut browser = Browser::new(app);
    let (callback, params) =
        sign_in_at_provider(&mut browser, &idp, "/auth/login?stepUp=1&returnTo=/danger", |p| Grant { auth_time: 1_700_000_000, ..honest(p) }).await;
    assert_eq!(params["prompt"], "login");
    assert_eq!(params["max_age"], "0");
    let resp = browser.get(&callback).await;
    assert_eq!(location(&resp), "/danger");
    assert_eq!(json_body(browser.get("/api/whoami").await).await["auth_time"], 1_700_000_000);
}

#[tokio::test]
async fn a_bearer_is_judged_on_its_own_even_with_a_session_cookie() {
    let (issuer, idp) = start_idp().await;
    let mut browser = signed_in(&issuer, &idp).await;
    let bearer = sign("k1", &json!({ "iss": issuer, "sub": "service-account", "aud": CLIENT_ID, "exp": now() + 300 }));
    // Cross-origin with both: the bearer decides, so no CSRF refusal…
    let resp = browser
        .send(Request::post("/api/act").header(ORIGIN, "https://other.example.com").header(AUTHORIZATION, format!("Bearer {bearer}")))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(text_body(resp).await, "done for service-account");
    // …and the identity is the bearer's, not the cookie's.
    let resp = browser.send(Request::get("/api/whoami").header(AUTHORIZATION, format!("Bearer {bearer}"))).await;
    assert_eq!(json_body(resp).await["sub"], "service-account");
    // A bad bearer is not rescued by the cookie.
    let resp = browser.send(Request::get("/api/whoami").header(AUTHORIZATION, "Bearer nonsense")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn reads_embedded_by_another_site_are_refused_but_links_work() {
    let (issuer, idp) = start_idp().await;
    let mut browser = signed_in(&issuer, &idp).await;
    let fetch = |site: &str, mode: &str| Request::get("/api/whoami").header("sec-fetch-site", site).header("sec-fetch-mode", mode);
    assert_eq!(browser.send(fetch("same-site", "no-cors")).await.status(), StatusCode::FORBIDDEN, "an <img> on a sibling host");
    assert_eq!(browser.send(fetch("cross-site", "cors")).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        browser.send(fetch("same-site", "navigate").header("sec-fetch-dest", "document")).await.status(),
        StatusCode::OK,
        "a link from a sibling host"
    );
    assert_eq!(
        browser.send(fetch("same-site", "navigate").header("sec-fetch-dest", "iframe")).await.status(),
        StatusCode::FORBIDDEN,
        "a frame on a sibling host"
    );
    assert_eq!(browser.send(fetch("same-origin", "cors")).await.status(), StatusCode::OK, "our own page");
}

#[tokio::test]
async fn return_to_never_leaves_the_site() {
    let (issuer, idp) = start_idp().await;
    let (app, _) = service(&issuer).await;
    // Query-encoded: //evil.example, https://evil.example, /\evil.example.
    for evil in ["%2F%2Fevil.example", "https%3A%2F%2Fevil.example", "%2F%5Cevil.example"] {
        let mut browser = Browser::new(app.clone());
        let (callback, _) = sign_in_at_provider(&mut browser, &idp, &format!("/auth/login?returnTo={evil}"), honest).await;
        assert_eq!(location(&browser.get(&callback).await), "/", "{evil} must land on /");
    }
}

#[tokio::test]
async fn the_service_runs_while_the_provider_is_down() {
    // A port nothing listens on.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let (app, _) = service(&issuer).await;
    let mut browser = Browser::new(app);
    let resp = browser.get("/auth/login").await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(text_body(resp).await.contains("[idp-unavailable]"));
    // Everything that doesn't need the provider still answers.
    assert_eq!(json_body(browser.get("/auth/me").await).await, json!({ "authenticated": false }));
    assert_eq!(browser.get("/api/whoami").await.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_provider_error_is_shown_but_not_reflected_raw() {
    let (issuer, _) = start_idp().await;
    let (app, _) = service(&issuer).await;
    let mut browser = Browser::new(app);
    let resp = browser.get("/auth/callback?error=redirect_uri_mismatch%3Cscript%3E").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = text_body(resp).await;
    assert!(body.contains("(redirect_uri_mismatchscript)"), "{body}");
    assert!(!body.contains('<'));
}

#[tokio::test]
async fn dev_no_auth_signs_everyone_in_as_the_stub() {
    let mut config = LoginConfig::new("", "", "http://localhost:3000");
    config.dev_no_auth = true;
    let login = Login::new(config).unwrap();
    let mut browser = Browser::new(login.router());
    assert_eq!(json_body(browser.get("/auth/me").await).await["authenticated"], true);
    assert_eq!(location(&browser.get("/auth/login?returnTo=/x").await), "/x");
}

#[tokio::test]
async fn sign_in_and_api_must_agree_on_dev_mode() {
    let mut config = LoginConfig::new("", "", "http://localhost:3000");
    config.dev_no_auth = true;
    let login = Login::new(config).unwrap();
    let mismatched = JwksStore::with_options(String::new(), CLIENT_ID.into(), false, AuthOptions { login: Some(login), ..Default::default() }).await;
    assert!(mismatched.is_err(), "the page would say signed in while every API call failed");
}
