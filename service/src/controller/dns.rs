//! DNS: keep a set of names pointing at exactly the healthy edges (Cloudflare, DNS-only).
//!
//! We only ever touch records we created (tagged with a comment), so existing records in the
//! zone are safe. And we never withdraw the *last* records: with no healthy edge, stale DNS
//! beats an empty answer.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::time::Duration;

pub const MARKER: &str = "edge-lb:managed";

#[derive(Debug, Clone)]
pub struct Record {
    pub id: String,
    pub ip: Ipv4Addr,
}

pub struct Cloudflare {
    http: reqwest::Client,
    base: String,
    token: String,
    zone: String,
}

impl Cloudflare {
    pub fn new(base: &str, token: &str, zone: &str) -> Result<Self> {
        crate::tls::init();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| anyhow!("building HTTP client: {e}"))?;
        Ok(Self { http, base: base.trim_end_matches('/').to_string(), token: token.into(), zone: zone.into() })
    }

    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<Value> {
        let mut req = self.http.request(method, format!("{}/zones/{}/dns_records{path}", self.base, self.zone)).bearer_auth(&self.token);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|e| anyhow!("Cloudflare API unreachable: {e}"))?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if status.is_success() && body["success"] != json!(false) {
            return Ok(body);
        }
        let msg = body["errors"][0]["message"].as_str().unwrap_or("no detail");
        bail!("Cloudflare API error {status}: {msg}")
    }

    /// A records for `name` that we created.
    pub async fn managed_records(&self, name: &str) -> Result<Vec<Record>> {
        let body = self.call(reqwest::Method::GET, &format!("?type=A&name={name}&per_page=100"), None).await?;
        Ok(body["result"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| r["comment"].as_str() == Some(MARKER))
            .filter_map(|r| Some(Record { id: r["id"].as_str()?.to_string(), ip: r["content"].as_str()?.parse().ok()? }))
            .collect())
    }

    pub async fn create(&self, name: &str, ip: Ipv4Addr, ttl: u32) -> Result<()> {
        // proxied:false is essential: Cloudflare's proxy would terminate TLS and break passthrough.
        self.call(
            reqwest::Method::POST,
            "",
            Some(json!({ "type": "A", "name": name, "content": ip.to_string(), "ttl": ttl, "proxied": false, "comment": MARKER })),
        )
        .await?;
        Ok(())
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        self.call(reqwest::Method::DELETE, &format!("/{id}"), None).await?;
        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub created: usize,
    pub deleted: usize,
    /// There were no healthy edges, so existing records were left alone.
    pub held: bool,
}

/// Make `names` resolve to exactly `desired` (among records we manage).
pub async fn reconcile(cf: &Cloudflare, names: &[String], desired: &BTreeSet<Ipv4Addr>, ttl: u32) -> Result<Report> {
    let mut report = Report::default();
    if desired.is_empty() {
        report.held = true;
        return Ok(report);
    }
    for name in names {
        let have = cf.managed_records(name).await?;
        let have_ips: BTreeSet<Ipv4Addr> = have.iter().map(|r| r.ip).collect();
        for ip in desired.difference(&have_ips) {
            cf.create(name, *ip, ttl).await?;
            report.created += 1;
        }
        for r in have.iter().filter(|r| !desired.contains(&r.ip)) {
            cf.delete(&r.id).await?;
            report.deleted += 1;
        }
    }
    Ok(report)
}
