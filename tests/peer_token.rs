//! `JwksStore::peer_token` against a fake identity provider on a local port: a
//! forwarded token for a peer service is handed back only when the provider
//! signed it for that peer and for the request's own user.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};
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
    Peer { name: "peer".into(), header: HeaderName::from_static(PEER_HEADER), audience: PEER_AUDIENCE.into() }
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
    let cases: [(&str, Value); 3] = [
        // This service's own token is not a peer token.
        ("own audience", json!(token(&issuer, "user-1", AUDIENCE, now() + 600))),
        ("expired", json!(token(&issuer, "user-1", PEER_AUDIENCE, now() - 120))),
        ("other issuer", json!(token("http://elsewhere.example", "user-1", PEER_AUDIENCE, now() + 600))),
    ];
    for (what, sent) in cases {
        let result = store.peer_token(&forwarded(sent.as_str().unwrap()), &user("user-1"), "peer").await;
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED, "{what}");
    }
    assert_eq!(store.peer_token(&forwarded("not-a-jwt"), &user("user-1"), "peer").await.unwrap_err(), StatusCode::UNAUTHORIZED);
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
}

#[tokio::test]
async fn refuses_a_peer_that_would_accept_ordinary_tokens_or_repeats_another() {
    let build = |peers: Vec<Peer>| JwksStore::with_options(String::new(), AUDIENCE.into(), true, AuthOptions { peers, ..Default::default() });
    let own = Peer { audience: AUDIENCE.into(), ..peer() };
    assert!(build(vec![own]).await.is_err());
    assert!(build(vec![Peer { audience: String::new(), ..peer() }]).await.is_err());
    let again = Peer { audience: "third-service".into(), ..peer() };
    assert!(build(vec![peer(), again]).await.is_err());
    assert!(build(vec![peer()]).await.is_ok());
}
