//! The HTTP client openidconnect talks to the identity provider through.
//!
//! openidconnect ships its own reqwest adapter, but for reqwest 0.12; this crate
//! is on 0.13, so it would mean two HTTP stacks in every service that signs
//! users in. This adapter is the same few lines over the crate's own client,
//! with two hardenings the stock one leaves to the caller:
//!
//! - **no redirects** — a discovery or token response that redirects is refused
//!   rather than followed, so a compromised or misconfigured provider cannot
//!   bounce this service's requests (and the auth code) somewhere else;
//! - **capped responses** — read through [`crate::http::read_body_capped`], so an
//!   oversized answer cannot exhaust memory.

use std::future::Future;
use std::io;
use std::pin::Pin;

use openidconnect::{AsyncHttpClient, HttpRequest, HttpResponse};

/// Largest identity-provider response accepted. Discovery documents, key sets
/// and token responses are a few KB.
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

pub(crate) struct Http {
    client: reqwest::Client,
}

impl Http {
    pub fn new() -> anyhow::Result<Self> {
        let client = crate::http::idp_client_builder().redirect(reqwest::redirect::Policy::none()).build()?;
        Ok(Self { client })
    }
}

impl<'c> AsyncHttpClient<'c> for Http {
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, io::Error>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let request: reqwest::Request = request.try_into().map_err(io::Error::other)?;
            let url = request.url().clone();
            let fail = |e: &dyn std::fmt::Display| io::Error::other(format!("{url}: {e}"));
            let response = self.client.execute(request).await.map_err(|e| fail(&e))?;
            let status = response.status();
            if status.is_redirection() {
                return Err(fail(&format!("refused to follow a redirect ({status})")));
            }
            let headers = response.headers().clone();
            let body = crate::http::read_body_capped(response, MAX_RESPONSE_BYTES, "identity provider response")
                .await
                .map_err(|e| fail(&e))?;
            let mut out = HttpResponse::new(body);
            *out.status_mut() = status;
            *out.headers_mut() = headers;
            Ok(out)
        })
    }
}
