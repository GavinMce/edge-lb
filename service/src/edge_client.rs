//! Controller-side client for an edge's management API (mTLS + certificate pinning).

use crate::config::Route;
use crate::{pki, tls};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The edge understood us and rejected the config (HTTP 422).
    #[error("edge rejected the configuration: {}", .0.join("; "))]
    Rejected(Vec<String>),
    #[error("{0}")]
    Other(String),
}

#[derive(Clone)]
pub struct EdgeClient {
    http: reqwest::Client,
    base: String,
}

fn fmt_host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => format!("[{v}]"),
    }
}

impl EdgeClient {
    pub fn new(ip: IpAddr, port: u16, pinned_fingerprint: &str, client: &pki::Pem) -> Result<Self> {
        tls::init();
        let cfg = tls::pinned_client_config(pinned_fingerprint, &client.cert, &client.key)?;
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(cfg)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| anyhow!("building client: {e}"))?;
        Ok(Self { http, base: format!("https://{}:{port}", fmt_host(ip)) })
    }

    async fn get(&self, path: &str) -> Result<Value, ClientError> {
        let r = self.http.get(format!("{}{path}", self.base)).send().await.map_err(|e| ClientError::Other(chain(&e)))?;
        if !r.status().is_success() {
            return Err(ClientError::Other(format!("HTTP {}", r.status())));
        }
        r.json().await.map_err(|e| ClientError::Other(e.to_string()))
    }

    pub async fn info(&self) -> Result<Value, ClientError> {
        self.get("/v1/info").await
    }

    pub async fn status(&self) -> Result<Value, ClientError> {
        self.get("/v1/status").await
    }

    pub async fn put_config(&self, generation: u64, routes: &[Route]) -> Result<(), ClientError> {
        let r = self
            .http
            .put(format!("{}/v1/config", self.base))
            .json(&json!({ "generation": generation, "routes": routes }))
            .send()
            .await
            .map_err(|e| ClientError::Other(chain(&e)))?;
        match r.status().as_u16() {
            200..=299 => Ok(()),
            422 => {
                let body: Value = r.json().await.unwrap_or_default();
                let details = body["details"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
                Err(ClientError::Rejected(details))
            }
            s => Err(ClientError::Other(format!("HTTP {s}"))),
        }
    }
}

/// reqwest hides the useful part of a connection error in its source chain.
fn chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
}
