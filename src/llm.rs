//! A minimal client for an OpenAI-compatible chat-completion service — typically
//! a llama.cpp server reached through the [`crate::wg`] tunnel's loopback port,
//! though nothing here requires the tunnel. One bounded, time-limited completion
//! call and one cheap reachability probe; prompt construction stays with the
//! consumer.

use std::time::Duration;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<Message<'a>>,
    stream: bool,
    /// Hard cap on generated tokens. Must be generous: Gemma 4's thinking mode
    /// spends tokens on `reasoning_content` *before* the answer, so a tight cap
    /// truncates mid-reasoning and `content` comes back empty.
    max_tokens: u32,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: AssistantMessage,
}

#[derive(Deserialize)]
struct AssistantMessage {
    content: String,
}

/// Run one chat completion against the OpenAI-compatible inference service.
///
/// `timeout` bounds the *entire* call (connect + generate + read body) via
/// reqwest's per-request timeout — a single authoritative mechanism, so a
/// wedged inference box surfaces as an error instead of leaking a task forever.
/// `api_key`, when present, is sent as `Authorization: Bearer <key>`.
pub async fn complete(
    client: &reqwest::Client,
    base_url: &str,
    model: &str,
    api_key: Option<&str>,
    prompt: &str,
    max_tokens: u32,
    timeout: Duration,
) -> anyhow::Result<String> {
    let body = ChatRequest {
        model,
        messages: vec![Message { role: "user", content: prompt }],
        stream: false,
        max_tokens,
    };

    let mut req = client
        .post(format!("{base_url}/v1/chat/completions"))
        .timeout(timeout)
        .json(&body);
    if let Some(key) = api_key {
        req = req.bearer_auth(key);
    }

    // Cap the inference response before buffering it: a misbehaving or compromised
    // inference box (or anything on the WG-inner path) must not be able to OOM the
    // consumer with an arbitrarily large body. `max_tokens` bounds generation, not
    // wire bytes.
    const MAX_INFERENCE_BYTES: u64 = 32 * 1024 * 1024; // 32 MiB — generous for any completion
    let mut http = req.send().await?.error_for_status()?;
    if let Some(len) = http.content_length()
        && len > MAX_INFERENCE_BYTES
    {
        anyhow::bail!("inference response is {len} bytes, over the {MAX_INFERENCE_BYTES}-byte cap");
    }
    let mut body: Vec<u8> =
        Vec::with_capacity(http.content_length().map_or(0, |l| l.min(MAX_INFERENCE_BYTES) as usize));
    while let Some(chunk) = http.chunk().await? {
        if body.len() as u64 + chunk.len() as u64 > MAX_INFERENCE_BYTES {
            anyhow::bail!("inference response exceeds the {MAX_INFERENCE_BYTES}-byte cap");
        }
        body.extend_from_slice(&chunk);
    }
    let resp: ChatResponse = serde_json::from_slice(&body)?;

    resp.choices
        .into_iter()
        .next()
        .map(|c| c.message.content)
        .ok_or_else(|| anyhow::anyhow!("empty response from inference service"))
}

/// Lightweight reachability probe for the inference backend, used by the
/// background health poller (never on the request path). Short, fixed timeout
/// so it can't stall the caller regardless of the configured generation timeout.
pub async fn reachable(client: &reqwest::Client, base_url: &str, api_key: Option<&str>) -> bool {
    let mut req = client
        .get(format!("{base_url}/health"))
        .timeout(Duration::from_secs(3));
    if let Some(key) = api_key {
        req = req.bearer_auth(key);
    }
    req.send().await.map(|r| r.status().is_success()).unwrap_or(false)
}
