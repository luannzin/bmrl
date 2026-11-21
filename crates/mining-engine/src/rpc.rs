//! Minimal Bitcoin Core JSON-RPC 2.0 client (HTTP basic auth, cookie file).

use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::path::Path;
use std::time::Duration;

/// A JSON-RPC error object returned by the node.
#[derive(Debug, Clone)]
pub struct RpcError {
    pub method: String,
    pub code: i64,
    pub message: String,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed ({}): {}", self.method, self.code, self.message)
    }
}

impl std::error::Error for RpcError {}

pub struct Rpc {
    url: String,
    auth: String,
    agent: ureq::Agent,
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

impl Rpc {
    pub fn new(url: impl Into<String>, user: &str, password: &str) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(300)))
            .build()
            .into();
        Self { url: url.into(), auth: format!("Basic {}", base64(format!("{user}:{password}").as_bytes())), agent }
    }

    /// Authenticate with the node's `.cookie` file (`user:password`).
    pub fn from_cookie(url: impl Into<String>, cookie: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(cookie).with_context(|| format!("reading {}", cookie.display()))?;
        let (user, password) = text.trim().split_once(':').context("malformed cookie file")?;
        Ok(Self::new(url, user, password))
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let mut resp = self
            .agent
            .post(&self.url)
            .header("Authorization", &self.auth)
            .send_json(&body)
            .with_context(|| format!("{method}: transport error"))?;
        let status = resp.status();
        let v: Value = resp.body_mut().read_json().with_context(|| format!("{method}: HTTP {status}, unreadable body"))?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return Err(RpcError {
                method: method.into(),
                code: err["code"].as_i64().unwrap_or(0),
                message: err["message"].as_str().unwrap_or("").into(),
            }
            .into());
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_rfc4648_vectors() {
        let cases = [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")];
        for (i, o) in cases {
            assert_eq!(super::base64(i.as_bytes()), o);
        }
    }
}
