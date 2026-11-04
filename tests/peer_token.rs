//! `JwksStore::peer_token` against a fake identity provider on a local port: a
//! forwarded token for a peer service is handed back only when the provider
//! signed it for that peer and for the request's own user.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use service_core::auth::{AuthOptions, Claims, JwksStore};
use service_core::peer::Peer;

use common::{KEY_N, now, sign};

const AUDIENCE: &str = "this-service";
const PEER_AUDIENCE: &str = "peer-service";
const PEER_HEADER: &str = "x-peer-token";

/// A provider serving discovery and a key set, at `issuer`.
async fn start_idp() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let issuer = format!("http://{addr}");
    let discovery = json!({ "issuer": issuer, "jwks_uri": format!("{issuer}/keys") });
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(move || async move { Json(discovery) }))
        .route("/keys", get(|| async { Json(json!({ "keys": [{ "kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1", "n": KEY_N, "e": "AQAB" }] })) }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    issuer
}

fn peer() -> Peer {
    Peer::new("peer", HeaderName::from_static(PEER_HEADER), PEER_AUDIENCE)
}

async fn store(issuer: &str, dev_no_auth: bool) -> Arc<JwksStore> {
    JwksStore::with_options(issuer.into(), AUDIENCE.into(), dev_no_auth, AuthOptions { peers: vec![peer()], ..Default::default() })
        .await
        .unwrap()
}

fn token(issuer: &str, sub: &str, aud: &str, exp: u64) -> String {
    sign("k1", &json!({ "iss": issuer, "sub": sub, "aud": aud, "iat": now(), "exp": exp, "azp": "the-bff" }))
}

fn user(sub: &str) -> Claims {
    Claims { sub: sub.into(), email: None, exp: usize::MAX, auth_time: None }
}

fn forwarded(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(PEER_HEADER, HeaderValue::from_str(token).unwrap());
    headers
}

#[tokio::test]
async fn hands_back_the_users_own_peer_token() {
    let issuer = start_idp().await;
    let store = store(&issuer, false).await;
    let sent = token(&issuer, "user-1", PEER_AUDIENCE, now() + 600);
    let got = store.peer_token(&forwarded(&sent), &user("user-1"), "peer").await.unwrap().unwrap();
    assert_eq!(got.bearer(), sent);
    assert_eq!(got.claims().sub, "user-1");
    // The token is only for sending on: never in Debug output.
    assert!(!format!("{got:?}").contains(&sent));
}

#[tokio::test]
async fn is_none_without_the_header() {
    let issuer = start_idp().await;
    let store = store(&issuer, false).await;
    assert!(store.peer_token(&HeaderMap::new(), &user("user-1"), "peer").await.unwrap().is_none());
}

#[tokio::test]
async fn refuses_someone_elses_peer_token() {
    let issuer = start_idp().await;
    let store = store(&issuer, false).await;
    let theirs = token(&issuer, "user-2", PEER_AUDIENCE, now() + 600);
    assert_eq!(store.peer_token(&forwarded(&theirs), &user("user-1"), "peer").await.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refuses_a_token_for_another_audience_an_expired_one_and_another_issuer() {
    let issuer = start_idp().await;
    let store = store(&issuer, false).await;
    let cases = [
        // This service's own token is not a peer token.
        ("own audience", token(&issuer, "user-1", AUDIENCE, now() + 600)),
        ("expired", token(&issuer, "user-1", PEER_AUDIENCE, now() - 120)),
        ("other issuer", token("http://elsewhere.example", "user-1", PEER_AUDIENCE, now() + 600)),
    ];
    for (what, sent) in cases {
        let result = store.peer_token(&forwarded(&sent), &user("user-1"), "peer").await;
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED, "{what}");
    }
    assert_eq!(store.peer_token(&forwarded("not-a-jwt"), &user("user-1"), "peer").await.unwrap_err(), StatusCode::UNAUTHORIZED);
    let mut not_ascii = HeaderMap::new();
    not_ascii.insert(PEER_HEADER, HeaderValue::from_bytes("tök".as_bytes()).unwrap());
    assert_eq!(store.peer_token(&not_ascii, &user("user-1"), "peer").await.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn keeps_the_two_audiences_apart_and_needs_both_claims() {
    let issuer = start_idp().await;
    let store = store(&issuer, false).await;
    let both = sign("k1", &json!({ "iss": issuer, "sub": "user-1", "aud": [AUDIENCE, PEER_AUDIENCE], "exp": now() + 600 }));
    // Issued for both: neither a peer token nor a credential here.
    assert_eq!(store.peer_token(&forwarded(&both), &user("user-1"), "peer").await.unwrap_err(), StatusCode::UNAUTHORIZED);
    assert_eq!(store.validate(&both).await.unwrap_err(), StatusCode::UNAUTHORIZED);
    // An ordinary token is still a credential, and a peer token isn't one.
    assert_eq!(store.validate(&token(&issuer, "user-1", AUDIENCE, now() + 600)).await.unwrap().sub, "user-1");
    assert_eq!(store.validate(&token(&issuer, "user-1", PEER_AUDIENCE, now() + 600)).await.unwrap_err(), StatusCode::UNAUTHORIZED);
    // The library would skip the audience check on a token without one.
    let no_audience = sign("k1", &json!({ "iss": issuer, "sub": "user-1", "exp": now() + 600 }));
    assert_eq!(store.peer_token(&forwarded(&no_audience), &user("user-1"), "peer").await.unwrap_err(), StatusCode::UNAUTHORIZED);
    assert_eq!(store.validate(&no_audience).await.unwrap_err(), StatusCode::UNAUTHORIZED);
    let no_issuer = sign("k1", &json!({ "sub": "user-1", "aud": PEER_AUDIENCE, "exp": now() + 600 }));
    assert_eq!(store.peer_token(&forwarded(&no_issuer), &user("user-1"), "peer").await.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refuses_a_bad_signature_and_an_unknown_key() {
    let issuer = start_idp().await;
    let store = store(&issuer, false).await;
    let good = token(&issuer, "user-1", PEER_AUDIENCE, now() + 600);
    let (body, signature) = good.rsplit_once('.').unwrap();
    let flipped = if signature.starts_with('A') { "B" } else { "A" };
    let forged = format!("{body}.{flipped}{}", &signature[1..]);
    assert_eq!(store.peer_token(&forwarded(&forged), &user("user-1"), "peer").await.unwrap_err(), StatusCode::UNAUTHORIZED);
    let unknown_key = sign("k9", &json!({ "iss": issuer, "sub": "user-1", "aud": PEER_AUDIENCE, "exp": now() + 600 }));
    assert_eq!(store.peer_token(&forwarded(&unknown_key), &user("user-1"), "peer").await.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_unknown_peer_is_a_server_error() {
    let issuer = start_idp().await;
    let store = store(&issuer, false).await;
    let sent = token(&issuer, "user-1", PEER_AUDIENCE, now() + 600);
    assert_eq!(store.peer_token(&forwarded(&sent), &user("user-1"), "other").await.unwrap_err(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn dev_mode_passes_the_header_through() {
    let store = store("", true).await;
    let got = store.peer_token(&forwarded("anything"), &user("dev"), "peer").await.unwrap().unwrap();
    assert_eq!(got.bearer(), "anything");
    assert_eq!(got.claims().sub, "dev");
}

#[tokio::test]
async fn refuses_a_peer_that_would_accept_ordinary_tokens_repeats_another_or_takes_a_credential_header() {
    let refusal = async |peers: Vec<Peer>| {
        match JwksStore::with_options(String::new(), AUDIENCE.into(), true, AuthOptions { peers, ..Default::default() }).await {
            Ok(_) => String::from("accepted"),
            Err(error) => error.to_string(),
        }
    };
    let header = || HeaderName::from_static(PEER_HEADER);
    assert!(refusal(vec![Peer::new("peer", header(), AUDIENCE)]).await.contains("audience of its own"));
    assert!(refusal(vec![Peer::new("peer", header(), "")]).await.contains("audience of its own"));
    assert!(refusal(vec![peer(), Peer::new("peer", HeaderName::from_static("x-other"), "third-service")]).await.contains("repeats"));
    assert!(refusal(vec![peer(), Peer::new("other", header(), "third-service")]).await.contains("repeats"));
    for credential in ["authorization", "cookie", "x-bff-assertion"] {
        assert!(refusal(vec![Peer::new("peer", HeaderName::from_static(credential), PEER_AUDIENCE)]).await.contains("credential header"), "{credential}");
    }
    assert_eq!(refusal(vec![peer()]).await, "accepted");
}

#[cfg(feature = "login")]
#[tokio::test]
async fn refuses_peers_when_the_login_has_another_provider() {
    use service_core::login::{Login, LoginConfig};
    let login = Login::new(LoginConfig::new("https://other-provider.example", "client", "https://tool.example.com")).unwrap();
    let options = AuthOptions { peers: vec![peer()], login: Some(login), ..Default::default() };
    let error = JwksStore::with_options("https://provider.example".into(), AUDIENCE.into(), false, options).await.err().unwrap();
    assert!(error.to_string().contains("one provider"));
}
