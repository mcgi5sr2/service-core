//! Size-capped response-body reading.

use anyhow::{Context, Result};

/// Read a response body as bytes, refusing anything over `max` so an attacker-sized
/// response can't OOM the service. The declared Content-Length is checked first for a
/// fast reject, then the cap is enforced while streaming so a missing or lying length
/// can't defeat it. Callers decode the returned bytes (`String::from_utf8`,
/// `serde_json::from_slice`, …) and choose whether an over-cap body is fatal or best-effort.
pub async fn read_body_capped(mut resp: reqwest::Response, max: u64, what: &str) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len > max {
            anyhow::bail!("{what} is {len} bytes, over the {max}-byte cap");
        }
    }
    let mut buf: Vec<u8> = Vec::with_capacity(resp.content_length().map_or(0, |l| l.min(max) as usize));
    while let Some(chunk) = resp.chunk().await.context("reading response body")? {
        if buf.len() as u64 + chunk.len() as u64 > max {
            anyhow::bail!("{what} exceeds the {max}-byte cap");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}
