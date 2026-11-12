//! Everything the controller persists.

use crate::config::Route;
use crate::pki::Pem;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub type Ts = u64;

pub fn now() -> Ts {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// How an edge machine comes to exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderSpec {
    /// Created (and later destroyed) through the Hetzner Cloud API.
    Hetzner { location: String, server_type: String },
    /// A machine you already have. We install onto it over SSH and never destroy it.
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeStatus {
    /// Asking the provider for a machine.
    Creating,
    WaitingForSsh,
    /// Copying the binary over and starting it.
    Bootstrapping,
    /// Installed; pushing the first config.
    Joining,
    Healthy,
    /// Was healthy, controller can no longer reach it. Traffic may still be flowing.
    Unreachable,
    /// Removed from DNS, letting connections finish before deletion.
    Draining,
    Deleting,
    Failed,
}

impl EdgeStatus {
    /// Statuses in which the edge should be receiving traffic / listed in DNS.
    pub fn serving(self) -> bool {
        matches!(self, EdgeStatus::Healthy)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub ts: Ts,
    pub msg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub id: String,
    pub name: String,
    /// Free-form label such as "us-east". Shown in the UI; the first step toward geo DNS.
    #[serde(default)]
    pub region: String,
    pub provider: ProviderSpec,
    pub server_id: Option<String>,
    pub ip: Option<IpAddr>,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub mgmt_port: u16,
    /// SHA-256 of the edge's management certificate, pinned when we installed it.
    pub mgmt_fingerprint: Option<String>,
    pub status: EdgeStatus,
    pub error: Option<String>,
    pub created_at: Ts,
    pub status_since: Ts,
    /// Hash of the route set last applied to this edge.
    pub applied_hash: Option<String>,
    #[serde(default)]
    pub attempts: u32,
    pub drain_started: Option<Ts>,
    #[serde(default)]
    pub log: Vec<LogEntry>,
}

/// A route plus which edges serve it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CRoute {
    #[serde(flatten)]
    pub route: Route,
    /// Edge ids. Empty means every edge.
    #[serde(default)]
    pub edges: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSettings {
    pub cloudflare_token: String,
    pub zone_id: String,
    /// Fully-qualified names that should resolve to every healthy edge, e.g. "app.example.com".
    pub names: Vec<String>,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Hard cap on edges (each one is a billed server).
    pub max_edges: u32,
    pub hetzner_token: Option<String>,
    pub hetzner_image: String,
    pub dns: Option<DnsSettings>,
    /// How long a draining edge keeps its connections before it is deleted.
    pub drain_seconds: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self { max_edges: 5, hetzner_token: None, hetzner_image: "debian-12".into(), dns: None, drain_seconds: 60 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Admin {
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    /// Signs the client certificate edges accept. The CA key never leaves this file.
    pub ca: Pem,
    pub client: Pem,
    pub admin: Option<Admin>,
    pub settings: Settings,
    pub edges: Vec<Edge>,
    pub routes: Vec<CRoute>,
    /// Bumped on every route change.
    pub generation: u64,
}

impl State {
    pub fn fresh() -> anyhow::Result<State> {
        let ca = crate::pki::new_ca()?;
        let client = crate::pki::issue_client(&ca.key, "edge-lb controller")?;
        Ok(State { version: 1, ca, client, admin: None, settings: Settings::default(), edges: vec![], routes: vec![], generation: 0 })
    }

    pub fn edge(&self, id: &str) -> Option<&Edge> {
        self.edges.iter().find(|e| e.id == id)
    }

    /// The routes a given edge should be running.
    pub fn routes_for(&self, edge_id: &str) -> Vec<Route> {
        self.routes
            .iter()
            .filter(|r| r.edges.is_empty() || r.edges.iter().any(|e| e == edge_id))
            .map(|r| r.route.clone())
            .collect()
    }
}

pub fn routes_hash(routes: &[Route]) -> String {
    use sha2::{Digest, Sha256};
    let json = serde_json::to_vec(routes).unwrap_or_default();
    Sha256::digest(json).iter().map(|b| format!("{b:02x}")).collect()
}
