//! Cloud providers that can create and destroy edge machines.
//!
//! Only Hetzner is implemented. Creation is idempotent: every server carries an `edge-lb-id`
//! label, so a crash between "ask for a server" and "record its id" can't leave an orphaned,
//! still-billing machine that we've forgotten about.

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct CreateServer {
    pub edge_id: String,
    pub name: String,
    pub location: String,
    pub server_type: String,
    pub image: String,
    pub ssh_key_id: String,
}

#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub id: String,
    pub ipv4: Option<IpAddr>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Location {
    pub name: String,
    pub description: String,
    pub city: String,
    pub country: String,
    pub network_zone: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Price {
    pub location: String,
    pub monthly: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerType {
    pub name: String,
    pub description: String,
    pub cores: u64,
    pub memory_gb: f64,
    pub disk_gb: u64,
    pub architecture: String,
    pub prices: Vec<Price>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Catalog {
    pub locations: Vec<Location>,
    pub server_types: Vec<ServerType>,
}

pub struct Hetzner {
    http: reqwest::Client,
    base: String,
    token: String,
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

impl Hetzner {
    pub fn new(base: &str, token: &str) -> Result<Self> {
        crate::tls::init();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| anyhow!("building HTTP client: {e}"))?;
        Ok(Self { http, base: base.trim_end_matches('/').to_string(), token: token.to_string() })
    }

    /// Returns (status, body). Non-2xx is an error except where `allow` lists the status.
    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>, allow: &[u16]) -> Result<(u16, Value)> {
        let mut req = self.http.request(method, format!("{}{path}", self.base)).bearer_auth(&self.token);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|e| anyhow!("Hetzner API unreachable: {e}"))?;
        let status = resp.status().as_u16();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if (200..300).contains(&status) || allow.contains(&status) {
            return Ok((status, body));
        }
        let msg = body["error"]["message"].as_str().unwrap_or("no detail");
        let code = body["error"]["code"].as_str().unwrap_or("");
        match status {
            401 | 403 => bail!("Hetzner rejected the API token ({status}): {msg}"),
            _ => bail!("Hetzner API error {status} {code}: {msg}"),
        }
    }

    /// Register our SSH public key with the project (once) and return its id.
    pub async fn ensure_ssh_key(&self, name: &str, public_key: &str) -> Result<String> {
        let wanted = public_key.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        let (_, list) = self.call(reqwest::Method::GET, "/ssh_keys?per_page=50", None, &[]).await?;
        for k in list["ssh_keys"].as_array().into_iter().flatten() {
            let have = s(&k["public_key"]).split_whitespace().take(2).collect::<Vec<_>>().join(" ");
            if have == wanted {
                return Ok(k["id"].to_string());
            }
        }
        let (_, created) = self
            .call(reqwest::Method::POST, "/ssh_keys", Some(json!({ "name": name, "public_key": public_key, "labels": {"managed-by": "edge-lb"} })), &[])
            .await?;
        Ok(created["ssh_key"]["id"].to_string())
    }

    fn parse_server(v: &Value) -> ServerInfo {
        ServerInfo {
            id: v["id"].to_string(),
            ipv4: v["public_net"]["ipv4"]["ip"].as_str().and_then(|x| x.parse().ok()),
            status: s(&v["status"]),
        }
    }

    pub async fn find_by_edge_id(&self, edge_id: &str) -> Result<Option<ServerInfo>> {
        let sel = format!("edge-lb-id%3D{edge_id}");
        let (_, body) = self.call(reqwest::Method::GET, &format!("/servers?label_selector={sel}"), None, &[]).await?;
        Ok(body["servers"].as_array().and_then(|a| a.first()).map(Self::parse_server))
    }

    pub async fn get_server(&self, id: &str) -> Result<Option<ServerInfo>> {
        let (status, body) = self.call(reqwest::Method::GET, &format!("/servers/{id}"), None, &[404]).await?;
        Ok(if status == 404 { None } else { Some(Self::parse_server(&body["server"])) })
    }

    /// Create the server, or return the one already carrying this edge's label.
    pub async fn create_server(&self, req: &CreateServer) -> Result<ServerInfo> {
        if let Some(existing) = self.find_by_edge_id(&req.edge_id).await? {
            return Ok(existing);
        }
        let (_, body) = self
            .call(
                reqwest::Method::POST,
                "/servers",
                Some(json!({
                    "name": req.name,
                    "server_type": req.server_type,
                    "image": req.image,
                    "location": req.location,
                    "ssh_keys": [req.ssh_key_id.parse::<u64>().map(Value::from).unwrap_or(Value::from(req.ssh_key_id.clone()))],
                    "start_after_create": true,
                    "public_net": { "enable_ipv4": true, "enable_ipv6": true },
                    "labels": { "managed-by": "edge-lb", "edge-lb-id": req.edge_id },
                })),
                &[],
            )
            .await
            .context("creating server")?;
        Ok(Self::parse_server(&body["server"]))
    }

    /// Destroy a server. Already gone counts as success.
    pub async fn delete_server(&self, id: &str) -> Result<()> {
        self.call(reqwest::Method::DELETE, &format!("/servers/{id}"), None, &[404]).await?;
        Ok(())
    }

    pub async fn catalog(&self) -> Result<Catalog> {
        let (_, locs) = self.call(reqwest::Method::GET, "/locations?per_page=50", None, &[]).await?;
        let (_, types) = self.call(reqwest::Method::GET, "/server_types?per_page=50", None, &[]).await?;
        let locations = locs["locations"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|l| Location {
                name: s(&l["name"]),
                description: s(&l["description"]),
                city: s(&l["city"]),
                country: s(&l["country"]),
                network_zone: s(&l["network_zone"]),
            })
            .collect();
        let server_types = types["server_types"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|t| t["deprecation"].is_null() && t["deprecated"] != json!(true))
            .map(|t| ServerType {
                name: s(&t["name"]),
                description: s(&t["description"]),
                cores: t["cores"].as_u64().unwrap_or(0),
                memory_gb: t["memory"].as_f64().unwrap_or(0.0),
                disk_gb: t["disk"].as_u64().unwrap_or(0),
                architecture: s(&t["architecture"]),
                prices: t["prices"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|p| Price {
                        location: s(&p["location"]),
                        monthly: p["price_monthly"]["gross"].as_str().and_then(|x| x.parse().ok()).unwrap_or(0.0),
                    })
                    .collect(),
            })
            .collect();
        Ok(Catalog { locations, server_types })
    }
}
