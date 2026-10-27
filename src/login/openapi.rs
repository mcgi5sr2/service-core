//! OpenAPI description of the `/auth/*` routes (feature `openapi`), so a
//! service's spec documents its sign-in from the same source as the code:
//!
//! ```ignore
//! let mut api = ApiDoc::openapi();
//! api.merge(service_core::login::openapi::LoginApi::openapi());
//! ```

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(super::handlers::login, super::handlers::callback, super::handlers::logout, super::handlers::me),
    components(schemas(super::handlers::Me)),
    tags((name = "auth", description = "Browser sign-in: OIDC authorization code + PKCE, server-side session, HttpOnly cookie"))
)]
pub struct LoginApi;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documents_every_login_route() {
        let spec = serde_json::to_value(LoginApi::openapi()).unwrap();
        let paths = spec["paths"].as_object().unwrap();
        for (path, method) in [("/auth/login", "get"), ("/auth/callback", "get"), ("/auth/logout", "post"), ("/auth/me", "get")] {
            assert!(paths[path][method].is_object(), "{method} {path} missing from {paths:?}");
        }
        assert!(spec["components"]["schemas"]["Me"].is_object());
    }
}
