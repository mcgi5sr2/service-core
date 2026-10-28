//! The `/auth/*` handlers. Lifted from a BFF's sign-in, where most of these
//! branches were learned in production; the comments keep the reasons.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::header::{CACHE_CONTROL, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use openidconnect::core::{CoreAuthPrompt, CoreAuthenticationFlow, CoreIdToken, CoreIdTokenClaims};
use openidconnect::url::form_urlencoded;
use openidconnect::{AuthorizationCode, CsrfToken, Nonce, PkceCodeChallenge, TokenResponse};

use super::cookie::{self, Names};
use super::flow::{FLOW_TTL, Flow, safe_return_to, valid_state};
use super::provider::{ConfiguredClient, Provider};
use super::session::Identity;
use super::{Login, same_origin};

/// How long the one-retry marker suppresses a second automatic retry.
const RETRY_TTL: Duration = Duration::from_secs(300);
/// Most sign-in cookies a browser keeps at once (several tabs signing in). A
/// page that starts sign-ins in a loop — or another site making a browser do so
/// — would otherwise grow the Cookie header until proxies reject it.
const MAX_FLOW_COOKIES: usize = 5;

#[derive(serde::Deserialize)]
pub(crate) struct LoginQuery {
    #[serde(rename = "returnTo")]
    return_to: Option<String>,
    /// `1` forces real re-authentication (`prompt=login`, `max_age=0`) even with
    /// a live session: the provider asks for credentials again and issues a
    /// fresh `auth_time`, which is what a step-up check reads.
    #[serde(rename = "stepUp")]
    step_up: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /auth/me`. No credentials, just who is signed in.
#[derive(serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Me {
    pub authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Start a sign-in: mint PKCE, CSRF state and nonce, seal them into a cookie
/// for this browser, and send it to the provider.
#[cfg_attr(feature = "openapi", utoipa::path(
    get, path = "/auth/login", tag = "auth",
    params(
        ("returnTo" = Option<String>, Query, description = "Same-origin path to land on afterwards; anything else lands on /"),
        ("stepUp" = Option<String>, Query, description = "1 forces the user to re-enter credentials"),
    ),
    responses(
        (status = 303, description = "To the identity provider"),
        (status = 503, description = "The identity provider cannot be reached"),
    )
))]
pub(crate) async fn login(State(login): State<Arc<Login>>, Query(q): Query<LoginQuery>, headers: HeaderMap) -> Response {
    let return_to = safe_return_to(q.return_to.as_deref());
    let Some(provider) = &login.provider else {
        return redirect(&return_to); // dev_no_auth: already "signed in"
    };
    let Some(client) = provider.client().await else {
        return text(
            StatusCode::SERVICE_UNAVAILABLE,
            "Sign-in is unavailable right now: the identity provider cannot be reached. Try again shortly. [idp-unavailable]",
        );
    };

    let step_up = q.step_up.as_deref() == Some("1");
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut req = client.authorize_url(CoreAuthenticationFlow::AuthorizationCode, CsrfToken::new_random, Nonce::new_random);
    for scope in &provider.scopes {
        req = req.add_scope(scope.clone());
    }
    if step_up {
        req = req.add_prompt(CoreAuthPrompt::Login).set_max_age(Duration::ZERO);
    }
    let (auth_url, csrf, nonce) = req.set_pkce_challenge(challenge).url();
    let state = csrf.secret();

    let flow = Flow { pkce_verifier: verifier, nonce, return_to, step_up };
    let sealed = match login.flows.seal(state, &flow) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("login: could not seal the sign-in: {e}");
            return text(StatusCode::INTERNAL_SERVER_ERROR, "Sign-in could not start. [flow-seal]");
        }
    };

    let mut resp = redirect(auth_url.as_str());
    prune_flow_cookies(&login, &headers, &mut resp);
    // Without this cookie the callback cannot be completed, so the sign-in is
    // already doomed: say so now, not after the round trip.
    if !append_cookie(&mut resp, login.names.set(&login.names.flow(state), &sealed, FLOW_TTL.as_secs())) {
        return text(StatusCode::INTERNAL_SERVER_ERROR, "Sign-in could not start. [flow-cookie]");
    }
    resp
}

/// Keep at most `MAX_FLOW_COOKIES - 1` existing sign-in cookies (the new one
/// makes up the rest), newest first; drop any that no longer open at all.
fn prune_flow_cookies(login: &Login, headers: &HeaderMap, resp: &mut Response) {
    let mut held: Vec<(&str, Option<u64>)> = cookie::pairs(headers)
        .filter_map(|(name, value)| {
            let state = name.strip_prefix(login.names.flow_prefix)?;
            Some((name, valid_state(state).then(|| login.flows.issued_at(state, value)).flatten()))
        })
        .collect();
    held.sort_by_key(|(_, issued)| std::cmp::Reverse(*issued));
    let mut kept = 0;
    for (name, issued) in held {
        if issued.is_some() && kept < MAX_FLOW_COOKIES - 1 {
            kept += 1;
        } else {
            append_cookie(resp, login.names.clear(name));
        }
    }
}

/// Finish a sign-in: open this browser's sealed flow for the callback's state,
/// exchange the code with its PKCE verifier, verify the ID token against its
/// nonce, then replace any old session with a new one.
#[cfg_attr(feature = "openapi", utoipa::path(
    get, path = "/auth/callback", tag = "auth",
    params(
        ("code" = Option<String>, Query, description = "Authorization code from the provider"),
        ("state" = Option<String>, Query, description = "The sign-in this callback completes"),
        ("error" = Option<String>, Query, description = "The provider's OAuth error code"),
    ),
    responses(
        (status = 303, description = "Signed in, to returnTo; or sent round once more after a recoverable failure"),
        (status = 400, description = "The provider refused the sign-in"),
        (status = 403, description = "A sign-in failed twice in a row"),
    )
))]
pub(crate) async fn callback(State(login): State<Arc<Login>>, Query(q): Query<CallbackQuery>, headers: HeaderMap) -> Response {
    let Some(provider) = &login.provider else {
        return redirect("/");
    };
    if let Some(err) = q.error {
        // The provider's error code names a misconfiguration on our side
        // (invalid_client, redirect_uri_mismatch) and is worth showing. It came
        // through the URL, so only a short plain token of it is echoed.
        let err: String = err.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(64).collect();
        tracing::warn!("login: provider returned error: {err}");
        return text(StatusCode::BAD_REQUEST, &format!("Sign-in was refused by the identity provider ({err}). [callback-error]"));
    }
    let (Some(code), Some(state)) = (q.code, q.state) else {
        return text(StatusCode::BAD_REQUEST, "Sign-in callback is missing its code or state. [callback-params]");
    };

    // The sealed flow is the binding to the browser that started the sign-in: a
    // callback URL handed to anyone else arrives without it, so an attacker
    // cannot sign a victim in as themselves. No flow is overwhelmingly routine
    // — it expired at the login page, the process restarted, the callback was
    // reloaded — so the browser goes round again rather than hitting a wall.
    // Going round is safe even when it is an attack: the code is discarded
    // unused, and a victim who then signs in as themselves is the outcome we want.
    let flow_cookie = valid_state(&state).then(|| login.names.flow(&state));
    let flow = flow_cookie
        .as_deref()
        .and_then(|name| cookie::read(&headers, name))
        .and_then(|value| login.flows.open(&state, value));
    let Some(flow) = flow else {
        let state_prefix: String = state.chars().take(8).collect();
        tracing::warn!(state = state_prefix, "login: callback without a matching sign-in cookie");
        return done(restart_or_refuse(&login.names, &headers, "flow-unknown", None), &login.names, flow_cookie.as_deref());
    };
    // Single use: every answer from here clears it.
    let finish = |resp: Response| done(resp, &login.names, flow_cookie.as_deref());

    let Some(client) = provider.client().await else {
        return finish(restart_or_refuse(&login.names, &headers, "idp-unavailable", Some(&flow)));
    };
    let request = match client.exchange_code(AuthorizationCode::new(code)) {
        Ok(req) => req.set_pkce_verifier(openidconnect::PkceCodeVerifier::new(flow.pkce_verifier.secret().clone())),
        Err(e) => {
            tracing::error!("login: provider metadata has no token endpoint: {e}");
            return finish(text(StatusCode::INTERNAL_SERVER_ERROR, "Sign-in failed preparing the token request. [exchange-setup]"));
        }
    };
    let tokens = match request.request_async(&provider.http).await {
        Ok(t) => t,
        Err(e) => {
            // Seen in production as an intermittent blip talking to the
            // provider. The code is spent either way, so the only way on is a
            // fresh sign-in: go round once, which makes a transient failure
            // invisible.
            tracing::warn!("login: code exchange failed: {e}");
            return finish(restart_or_refuse(&login.names, &headers, "token-exchange", Some(&flow)));
        }
    };
    let Some(id_token) = tokens.id_token() else {
        tracing::warn!("login: token response had no ID token");
        return finish(text(StatusCode::BAD_GATEWAY, "The identity provider returned no identity token. [no-id-token]"));
    };
    let Some((identity, auth_time)) = verify_id_token(provider, client, id_token, &flow.nonce).await else {
        return finish(restart_or_refuse(&login.names, &headers, "id-token-verify", Some(&flow)));
    };

    let id = match login.sessions.insert(identity, auth_time) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("login: could not mint a session id: {e}");
            return finish(text(StatusCode::INTERNAL_SERVER_ERROR, "Signed in, but the session could not be created. [session-id]"));
        }
    };
    // A sign-in over an existing session (step-up, or signing in again)
    // replaces it — retired only now that the replacement exists, so a failure
    // above never logs the user out of the session they had.
    if let Some(old) = cookie::read(&headers, login.names.session) {
        login.sessions.remove(old);
    }

    let mut resp = redirect(&flow.return_to);
    if !append_cookie(&mut resp, login.names.set(login.names.session, &id, login.sessions.ttl().as_secs())) {
        login.sessions.remove(&id);
        return finish(text(StatusCode::INTERNAL_SERVER_ERROR, "Signed in, but the session could not be set. [session-cookie]"));
    }
    // Spend the retry marker, so a genuine failure later still gets its one
    // automatic retry. Failing to clear it only means that retry is skipped.
    append_cookie(&mut resp, login.names.clear(login.names.retry));
    finish(resp)
}

/// Verify the ID token against our nonce, which binds it to this sign-in and
/// defeats token substitution. A failure is almost always a signature failure
/// after the provider rotated its keys, so refresh the keys and verify once
/// more before giving up.
async fn verify_id_token(
    provider: &Provider,
    client: Arc<ConfiguredClient>,
    id_token: &CoreIdToken,
    nonce: &Nonce,
) -> Option<(Identity, Option<u64>)> {
    match id_token.claims(&client.id_token_verifier(), nonce) {
        Ok(claims) => return Some(from_claims(claims)),
        Err(e) => tracing::warn!("login: ID token verification failed ({e}); refreshing keys and retrying once"),
    }
    provider.rediscover().await;
    let client = provider.client().await?;
    match id_token.claims(&client.id_token_verifier(), nonce) {
        Ok(claims) => Some(from_claims(claims)),
        Err(e) => {
            tracing::warn!("login: ID token verification failed after a key refresh: {e}");
            None
        }
    }
}

/// End the session. POST and same-origin only: a cross-site page must not be
/// able to sign users out. Local only: the provider's session is not ended.
#[cfg_attr(feature = "openapi", utoipa::path(
    post, path = "/auth/logout", tag = "auth",
    responses(
        (status = 204, description = "Signed out"),
        (status = 403, description = "Not from this origin"),
    )
))]
pub(crate) async fn logout(State(login): State<Arc<Login>>, headers: HeaderMap) -> Response {
    if !login.is_disabled() && !same_origin(&headers, &login.origin) {
        return text(StatusCode::FORBIDDEN, "Sign-out must come from this site. [cross-origin]");
    }
    if let Some(id) = cookie::read(&headers, login.names.session) {
        login.sessions.remove(id);
    }
    let mut resp = no_store(StatusCode::NO_CONTENT.into_response());
    append_cookie(&mut resp, login.names.clear(login.names.session));
    resp
}

/// Who is signed in, for the page. Never a credential.
#[cfg_attr(feature = "openapi", utoipa::path(
    get, path = "/auth/me", tag = "auth",
    responses((status = 200, description = "The signed-in user, or authenticated: false", body = Me))
))]
pub(crate) async fn me(State(login): State<Arc<Login>>, headers: HeaderMap) -> Response {
    let me = if login.is_disabled() {
        Me { authenticated: true, sub: Some("dev".into()), email: Some("dev@local".into()), name: Some("Local dev".into()) }
    } else {
        match cookie::read(&headers, login.names.session).and_then(|id| login.sessions.get(id)) {
            Some(s) => Me { authenticated: true, sub: Some(s.identity.sub), email: s.identity.email, name: s.identity.name },
            None => Me { authenticated: false, sub: None, email: None, name: None },
        }
    };
    no_store(Json(me).into_response())
}

fn from_claims(claims: &CoreIdTokenClaims) -> (Identity, Option<u64>) {
    let identity = Identity {
        sub: claims.subject().as_str().to_string(),
        email: claims.email().map(|e| e.as_str().to_string()),
        name: claims.name().and_then(|n| n.get(None)).map(|n| n.as_str().to_string()),
    };
    // Absent means "cannot prove re-authentication", never "just authenticated".
    let auth_time = claims.auth_time().and_then(|t| u64::try_from(t.timestamp()).ok());
    (identity, auth_time)
}

/// After a recoverable callback failure: start the same sign-in again — same
/// destination, same step-up — marked so a structural failure cannot bounce
/// the browser off the provider forever. A second failure inside the marker's
/// lifetime is refused, naming which failure class it was: one generic message
/// for every class once cost hours chasing the wrong one.
fn restart_or_refuse(names: &Names, headers: &HeaderMap, reason: &'static str, flow: Option<&Flow>) -> Response {
    if cookie::read(headers, names.retry).is_some() {
        tracing::warn!(reason, "login: sign-in failed again after a retry — refusing");
        return text(
            StatusCode::FORBIDDEN,
            &format!("Sign-in could not be completed. Close this tab and open the app again. [{reason}]"),
        );
    }
    tracing::info!(reason, "login: sign-in attempt failed — restarting once");
    let mut again = form_urlencoded::Serializer::new(String::new());
    if let Some(flow) = flow {
        again.append_pair("returnTo", &flow.return_to);
        if flow.step_up {
            again.append_pair("stepUp", "1");
        }
    }
    let query = again.finish();
    let mut resp = redirect(&if query.is_empty() { "/auth/login".to_string() } else { format!("/auth/login?{query}") });
    append_cookie(&mut resp, names.set(names.retry, "1", RETRY_TTL.as_secs()));
    resp
}

/// Clear a used sign-in cookie on the way out.
fn done(mut resp: Response, names: &Names, flow_cookie: Option<&str>) -> Response {
    if let Some(name) = flow_cookie {
        append_cookie(&mut resp, names.clear(name));
    }
    resp
}

/// A 303 to `location`: a provider URL we built or a checked same-origin path.
fn redirect(location: &str) -> Response {
    let mut resp = no_store(StatusCode::SEE_OTHER.into_response());
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(LOCATION, v);
    }
    resp
}

fn text(status: StatusCode, body: &str) -> Response {
    no_store((status, body.to_string()).into_response())
}

/// Sign-in responses carry cookies and one-time redirects: never cache them.
fn no_store(mut resp: Response) -> Response {
    resp.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// Append a `Set-Cookie`, reporting whether it was a valid header value. Every
/// value we set is base64url or a literal, so `false` is unreachable today —
/// but a cookie that silently never reached the browser is not a session.
fn append_cookie(resp: &mut Response, cookie: String) -> bool {
    match HeaderValue::from_str(&cookie) {
        Ok(v) => {
            resp.headers_mut().append(SET_COOKIE, v);
            true
        }
        Err(e) => {
            tracing::error!("login: cookie was not a valid header value: {e}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::COOKIE;
    use openidconnect::PkceCodeVerifier;

    fn names() -> Names {
        Names::new(true)
    }

    fn headers(cookie: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(c) = cookie {
            h.insert(COOKIE, HeaderValue::from_str(c).unwrap());
        }
        h
    }

    fn set_cookies(resp: &Response) -> String {
        resp.headers().get_all(SET_COOKIE).iter().map(|v| v.to_str().unwrap().to_string()).collect::<Vec<_>>().join(" | ")
    }

    #[test]
    fn a_failed_callback_goes_round_once_marked_against_looping() {
        let resp = restart_or_refuse(&names(), &headers(None), "flow-unknown", None);
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers()[LOCATION], "/auth/login");
        let set = set_cookies(&resp);
        assert!(set.contains("__Host-login-retry=1") && set.contains("HttpOnly") && set.contains("Secure"), "{set}");
    }

    #[test]
    fn the_retry_keeps_the_destination_and_the_step_up() {
        let flow = Flow {
            pkce_verifier: PkceCodeVerifier::new("v".into()),
            nonce: Nonce::new("n".into()),
            return_to: "/danger?x=1&y=2".into(),
            step_up: true,
        };
        let resp = restart_or_refuse(&names(), &headers(None), "token-exchange", Some(&flow));
        assert_eq!(resp.headers()[LOCATION], "/auth/login?returnTo=%2Fdanger%3Fx%3D1%26y%3D2&stepUp=1");
    }

    #[test]
    fn a_second_failure_is_refused_with_its_reason() {
        let resp = restart_or_refuse(&names(), &headers(Some("__Host-login-retry=1")), "id-token-verify", None);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(resp.headers().get(LOCATION).is_none());
    }

    #[test]
    fn auth_responses_are_never_cached() {
        assert_eq!(redirect("/x").headers()[CACHE_CONTROL], "no-store");
        assert_eq!(text(StatusCode::FORBIDDEN, "x").headers()[CACHE_CONTROL], "no-store");
    }
}
