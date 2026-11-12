//! The controller: owns desired state (edges, routes, settings), creates and destroys edge
//! machines, and keeps every edge's running config and DNS in step with it.
//!
//! The data plane never depends on the controller being up: edges keep serving from their
//! last applied config.

pub mod api;
pub mod audit;
pub mod auth;
pub mod bootstrap;
pub mod dns;
pub mod lifecycle;
pub mod model;
pub mod providers;
pub mod store;

use crate::config::{self, Route};
use audit::Audit;
use auth::Sessions;
use bootstrap::{Bootstrapper, SshBootstrapper, SshKey};
use model::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use store::Store;
use tokio::sync::OnceCell;

pub const DEFAULT_MGMT_PORT: u16 = 7443;

pub struct Options {
    pub data_dir: PathBuf,
    /// The edge binary pushed to new machines. Must match their OS and CPU (static musl builds
    /// run anywhere; a glibc build only runs on equal-or-newer glibc).
    pub edge_binary: PathBuf,
    /// Override how machines are bootstrapped (tests). Default: the system `ssh`.
    pub bootstrapper: Option<Arc<dyn Bootstrapper>>,
    pub hetzner_base: String,
    pub cloudflare_base: String,
    /// Lifecycle loop period.
    pub tick: Duration,
    /// How often a healthy edge's status is polled.
    pub poll_every: Duration,
    pub default_mgmt_port: u16,
    /// Ports routes may never use on any edge (SSH).
    pub reserved_ports: Vec<u16>,
    /// Retry delay after a transient failure doubles from `.0` up to `.1`.
    pub retry_backoff: (Duration, Duration),
}

impl Options {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            edge_binary: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("edge-lbd")),
            bootstrapper: None,
            hetzner_base: std::env::var("EDGE_LB_HETZNER_URL").unwrap_or_else(|_| "https://api.hetzner.cloud/v1".into()),
            cloudflare_base: std::env::var("EDGE_LB_CLOUDFLARE_URL").unwrap_or_else(|_| "https://api.cloudflare.com/client/v4".into()),
            tick: Duration::from_secs(1),
            poll_every: Duration::from_secs(5),
            default_mgmt_port: DEFAULT_MGMT_PORT,
            reserved_ports: vec![22],
            retry_backoff: (Duration::from_secs(2), Duration::from_secs(30)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CtlError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("invalid request")]
    Invalid(Vec<String>),
    #[error("{0}")]
    Internal(String),
}

impl From<anyhow::Error> for CtlError {
    fn from(e: anyhow::Error) -> Self {
        CtlError::Internal(format!("{e:#}"))
    }
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, CtlError> {
    Err(CtlError::Invalid(vec![msg.into()]))
}

/// What the controller last learned from an edge. Memory only.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Live {
    pub reachable: bool,
    pub last_seen: Option<Ts>,
    pub version: Option<String>,
    pub generation: Option<u64>,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    /// The edge's own `/v1/status` (listeners, per-route health and traffic).
    pub status: Option<serde_json::Value>,
    #[serde(skip)]
    pub last_poll: Option<Instant>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsStatus {
    pub last_sync: Option<Ts>,
    pub last_error: Option<String>,
    /// No healthy edge, so existing records were deliberately left in place.
    pub held: bool,
}

#[derive(Default)]
pub(crate) struct DnsRun {
    pub key: String,
    pub at: Option<Instant>,
    pub status: DnsStatus,
}

pub struct Controller {
    pub store: Store,
    pub audit: Audit,
    pub sessions: Sessions,
    pub opts: Options,
    ssh_key: OnceCell<SshKey>,
    bootstrapper: OnceCell<Arc<dyn Bootstrapper>>,
    pub(crate) live: RwLock<HashMap<String, Live>>,
    pub(crate) inflight: Mutex<HashSet<String>>,
    pub(crate) backoff: Mutex<HashMap<String, Instant>>,
    pub(crate) dns_run: Mutex<DnsRun>,
    /// First-run proof of physical/shell access: needed to create the admin account.
    pub setup_code: Mutex<Option<String>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

// ---- API-facing types ------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct NewEdge {
    pub name: String,
    #[serde(default)]
    pub region: String,
    pub provider: ProviderSpec,
    /// Required for `manual`; assigned by the provider otherwise.
    pub ip: Option<IpAddr>,
    pub ssh_user: Option<String>,
    pub ssh_port: Option<u16>,
    pub mgmt_port: Option<u16>,
}

#[derive(Debug, Serialize)]
pub struct EdgeView {
    #[serde(flatten)]
    pub edge: Edge,
    pub live: Option<Live>,
}

#[derive(Debug, Deserialize, Default)]
pub struct DnsUpdate {
    /// Omit to keep the stored token.
    pub cloudflare_token: Option<String>,
    pub zone_id: String,
    pub names: Vec<String>,
    pub ttl: u32,
}

#[derive(Debug, Deserialize, Default)]
pub struct SettingsUpdate {
    pub max_edges: Option<u32>,
    /// Omit to keep; empty string clears.
    pub hetzner_token: Option<String>,
    pub hetzner_image: Option<String>,
    pub drain_seconds: Option<u64>,
    pub dns: Option<DnsUpdate>,
    #[serde(default)]
    pub clear_dns: bool,
}

#[derive(Debug, Serialize)]
pub struct DnsView {
    pub zone_id: String,
    pub names: Vec<String>,
    pub ttl: u32,
    pub token_set: bool,
}

/// Settings as shown to the UI: secrets are write-only.
#[derive(Debug, Serialize)]
pub struct SettingsView {
    pub max_edges: u32,
    pub hetzner_token_set: bool,
    pub hetzner_image: String,
    pub drain_seconds: u64,
    pub dns: Option<DnsView>,
}

fn safe_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

impl Controller {
    pub async fn start(opts: Options) -> anyhow::Result<Arc<Controller>> {
        crate::tls::init();
        let store = Store::open(&opts.data_dir)?;
        let c = Arc::new(Controller {
            audit: Audit::new(&opts.data_dir),
            sessions: Sessions::default(),
            store,
            ssh_key: OnceCell::new(),
            bootstrapper: OnceCell::new(),
            live: RwLock::new(HashMap::new()),
            inflight: Mutex::new(HashSet::new()),
            backoff: Mutex::new(HashMap::new()),
            dns_run: Mutex::new(DnsRun::default()),
            setup_code: Mutex::new(None),
            task: Mutex::new(None),
            opts,
        });
        if c.store.read(|s| s.admin.is_none()) {
            use rand::Rng;
            const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
            let code: String = (0..12).map(|_| ALPHABET[rand::rngs::OsRng.gen_range(0..ALPHABET.len())] as char).collect();
            let path = c.opts.data_dir.join("setup-code");
            let _ = std::fs::write(&path, format!("{code}\n"));
            *c.setup_code.lock().unwrap() = Some(code);
        }
        let runner = c.clone();
        *c.task.lock().unwrap() = Some(tokio::spawn(async move { runner.run().await }));
        Ok(c)
    }

    /// Stop the lifecycle loop. Edges keep running; nothing is torn down.
    pub fn stop(&self) {
        if let Some(t) = self.task.lock().unwrap().take() {
            t.abort();
        }
    }

    pub async fn ssh_key(&self) -> anyhow::Result<&SshKey> {
        self.ssh_key.get_or_try_init(|| SshKey::ensure(&self.opts.data_dir, "ssh-keygen")).await
    }

    pub(crate) async fn bootstrapper(&self) -> anyhow::Result<Arc<dyn Bootstrapper>> {
        let b = self
            .bootstrapper
            .get_or_try_init(|| async {
                if let Some(b) = &self.opts.bootstrapper {
                    return Ok::<_, anyhow::Error>(b.clone());
                }
                let key = self.ssh_key().await?.clone();
                Ok(Arc::new(SshBootstrapper::new(key, &self.opts.data_dir)) as Arc<dyn Bootstrapper>)
            })
            .await?;
        Ok(b.clone())
    }

    // ---- reads -------------------------------------------------------------------------------

    pub fn edges(&self) -> Vec<EdgeView> {
        let live = self.live.read().unwrap();
        self.store.read(|s| s.edges.iter().map(|e| EdgeView { edge: e.clone(), live: live.get(&e.id).cloned() }).collect())
    }

    pub fn routes(&self) -> Vec<CRoute> {
        self.store.read(|s| s.routes.clone())
    }

    pub fn settings_view(&self) -> SettingsView {
        self.store.read(|s| SettingsView {
            max_edges: s.settings.max_edges,
            hetzner_token_set: s.settings.hetzner_token.is_some(),
            hetzner_image: s.settings.hetzner_image.clone(),
            drain_seconds: s.settings.drain_seconds,
            dns: s.settings.dns.as_ref().map(|d| DnsView { zone_id: d.zone_id.clone(), names: d.names.clone(), ttl: d.ttl, token_set: !d.cloudflare_token.is_empty() }),
        })
    }

    /// Locations and server types for the "add edge" form. `compatible` marks types whose CPU
    /// architecture matches the edge binary this controller can install.
    pub async fn catalog(&self) -> Result<serde_json::Value, CtlError> {
        let (h, _) = self.hetzner().map_err(|e| CtlError::Invalid(vec![e.to_string()]))?;
        let cat = h.catalog().await.map_err(|e| CtlError::Internal(format!("{e:#}")))?;
        let mine = match std::env::consts::ARCH {
            "x86_64" => "x86",
            "aarch64" => "arm",
            other => other,
        };
        let types: Vec<serde_json::Value> = cat
            .server_types
            .iter()
            .map(|t| {
                let mut v = serde_json::to_value(t).unwrap_or_default();
                v["compatible"] = serde_json::json!(t.architecture == mine);
                v
            })
            .collect();
        Ok(serde_json::json!({ "locations": cat.locations, "server_types": types, "edge_binary_arch": mine }))
    }

    pub fn dns_status(&self) -> DnsStatus {
        self.dns_run.lock().unwrap().status.clone()
    }

    // ---- settings ----------------------------------------------------------------------------

    pub fn update_settings(&self, actor: &str, u: SettingsUpdate) -> Result<SettingsView, CtlError> {
        let mut errs = Vec::new();
        if let Some(n) = u.max_edges {
            if !(1..=50).contains(&n) {
                errs.push("max_edges must be between 1 and 50".to_string());
            }
        }
        if let Some(i) = &u.hetzner_image {
            if !safe_ident(i) {
                errs.push("hetzner_image contains unsupported characters".into());
            }
        }
        if let Some(d) = u.drain_seconds {
            if d > 3600 {
                errs.push("drain_seconds must be at most 3600".into());
            }
        }
        let mut dns_names = Vec::new();
        if let Some(d) = &u.dns {
            if !safe_ident(&d.zone_id) {
                errs.push("zone_id looks invalid".into());
            }
            if d.names.is_empty() {
                errs.push("add at least one DNS name".into());
            }
            for n in &d.names {
                match config::normalize_domain(n) {
                    Ok(x) if !x.starts_with("*.") => dns_names.push(x),
                    Ok(_) => errs.push(format!("DNS name '{n}': wildcards are not supported here")),
                    Err(e) => errs.push(format!("DNS name '{n}': {e}")),
                }
            }
            if !(d.ttl == 1 || (60..=86400).contains(&d.ttl)) {
                errs.push("ttl must be 1 (automatic) or between 60 and 86400".into());
            }
        }
        if !errs.is_empty() {
            return Err(CtlError::Invalid(errs));
        }
        self.store.try_update(|s| {
            let st = &mut s.settings;
            if let Some(n) = u.max_edges {
                st.max_edges = n;
            }
            if let Some(t) = &u.hetzner_token {
                st.hetzner_token = if t.trim().is_empty() { None } else { Some(t.trim().to_string()) };
            }
            if let Some(i) = &u.hetzner_image {
                st.hetzner_image = i.clone();
            }
            if let Some(d) = u.drain_seconds {
                st.drain_seconds = d;
            }
            if u.clear_dns {
                st.dns = None;
            }
            if let Some(d) = &u.dns {
                let token = match (&d.cloudflare_token, &st.dns) {
                    (Some(t), _) if !t.trim().is_empty() => t.trim().to_string(),
                    (_, Some(old)) => old.cloudflare_token.clone(),
                    _ => return Err(CtlError::Invalid(vec!["a Cloudflare API token is required".into()])),
                };
                st.dns = Some(DnsSettings { cloudflare_token: token, zone_id: d.zone_id.clone(), names: dns_names.clone(), ttl: d.ttl });
            }
            Ok::<_, CtlError>(())
        })?;
        self.audit.record(actor, "settings.update", "settings changed (secrets not logged)");
        Ok(self.settings_view())
    }

    // ---- edges -------------------------------------------------------------------------------

    pub fn create_edge(&self, actor: &str, n: NewEdge) -> Result<Edge, CtlError> {
        let mut errs = Vec::new();
        let name = n.name.trim().to_string();
        if name.is_empty() || name.chars().count() > 60 {
            errs.push("name is required (max 60 characters)".to_string());
        }
        let user = n.ssh_user.clone().unwrap_or_else(|| "root".into());
        if !bootstrap::valid_ssh_user(&user) {
            errs.push("ssh_user is not a valid user name".into());
        }
        let mgmt_port = n.mgmt_port.unwrap_or(self.opts.default_mgmt_port);
        let ssh_port = n.ssh_port.unwrap_or(22);
        if mgmt_port == 0 || ssh_port == 0 {
            errs.push("ports must be 1-65535".into());
        }
        let ip = match &n.provider {
            ProviderSpec::Manual => match n.ip {
                Some(ip) if !ip.is_unspecified() && !ip.is_multicast() => Some(ip),
                _ => {
                    errs.push("a manual edge needs the machine's IP address".into());
                    None
                }
            },
            ProviderSpec::Hetzner { location, server_type } => {
                if !safe_ident(location) || !safe_ident(server_type) {
                    errs.push("choose a location and a server type".into());
                }
                None
            }
        };
        if !errs.is_empty() {
            return Err(CtlError::Invalid(errs));
        }

        let edge = self.store.try_update(|s| {
            if matches!(n.provider, ProviderSpec::Hetzner { .. }) && s.settings.hetzner_token.is_none() {
                return invalid("set the Hetzner API token in Settings first");
            }
            let active = s.edges.iter().filter(|e| e.status != EdgeStatus::Deleting).count() as u32;
            if active >= s.settings.max_edges {
                return invalid(format!("edge limit reached ({} of {}); raise it in Settings if you really want more servers", active, s.settings.max_edges));
            }
            if let Some(ip) = ip {
                if s.edges.iter().any(|e| e.ip == Some(ip) && e.mgmt_port == mgmt_port) {
                    return Err(CtlError::Conflict(format!("an edge for {ip}:{mgmt_port} already exists")));
                }
            }
            let base = config::slugify(&name);
            let id = (1..).map(|i| if i == 1 { base.clone() } else { format!("{base}-{i}") }).find(|c| s.edge(c).is_none()).unwrap();
            let edge = Edge {
                id,
                name: name.clone(),
                region: n.region.trim().to_string(),
                provider: n.provider.clone(),
                server_id: None,
                ip,
                ssh_user: user.clone(),
                ssh_port,
                mgmt_port,
                mgmt_fingerprint: None,
                status: EdgeStatus::Creating,
                error: None,
                created_at: now(),
                status_since: now(),
                applied_hash: None,
                attempts: 0,
                drain_started: None,
                log: vec![LogEntry { ts: now(), msg: "edge requested".into() }],
            };
            s.edges.push(edge.clone());
            Ok(edge)
        })?;
        self.audit.record(actor, "edge.create", &format!("{} ({:?})", edge.id, edge.provider));
        Ok(edge)
    }

    /// Start deleting an edge. Serving edges are drained first. Refuses to remove the last
    /// healthy edge unless `force`.
    pub fn delete_edge(&self, actor: &str, id: &str, force: bool) -> Result<(), CtlError> {
        self.store.try_update(|s| {
            let healthy = s.edges.iter().filter(|e| e.status == EdgeStatus::Healthy).count();
            let e = s.edges.iter_mut().find(|e| e.id == id).ok_or_else(|| CtlError::NotFound(id.into()))?;
            let next = match e.status {
                EdgeStatus::Draining | EdgeStatus::Deleting => return Ok(()),
                EdgeStatus::Healthy | EdgeStatus::Unreachable => {
                    if e.status == EdgeStatus::Healthy && healthy == 1 && !force {
                        return Err(CtlError::Conflict(
                            "this is the last healthy edge; deleting it takes your service offline. Pass force to do it anyway".into(),
                        ));
                    }
                    EdgeStatus::Draining
                }
                _ => EdgeStatus::Deleting,
            };
            e.status = next;
            e.status_since = now();
            e.attempts = 0;
            e.error = None;
            e.log.push(LogEntry { ts: now(), msg: format!("delete requested ({next:?})") });
            Ok(())
        })?;
        self.audit.record(actor, "edge.delete", &format!("{id}{}", if force { " (forced)" } else { "" }));
        Ok(())
    }

    /// Resume a failed edge from where it left off.
    pub fn retry_edge(&self, actor: &str, id: &str) -> Result<(), CtlError> {
        self.store.try_update(|s| {
            let e = s.edges.iter_mut().find(|e| e.id == id).ok_or_else(|| CtlError::NotFound(id.into()))?;
            if e.status != EdgeStatus::Failed {
                return Err(CtlError::Conflict("only a failed edge can be retried".into()));
            }
            e.status = if e.mgmt_fingerprint.is_some() {
                EdgeStatus::Joining
            } else if e.ip.is_some() {
                EdgeStatus::WaitingForSsh
            } else {
                EdgeStatus::Creating
            };
            e.status_since = now();
            e.attempts = 0;
            e.error = None;
            e.log.push(LogEntry { ts: now(), msg: "retry requested".into() });
            Ok(())
        })?;
        self.audit.record(actor, "edge.retry", id);
        Ok(())
    }

    // ---- routes ------------------------------------------------------------------------------

    /// Every edge must end up with a valid route set, so validate each edge's slice (and the
    /// slice that applies to every edge, for edges that don't exist yet).
    fn validate_routes(&self, s: &State, routes: &[CRoute]) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        let ids: HashSet<&str> = s.edges.iter().map(|e| e.id.as_str()).collect();
        for r in routes {
            for e in &r.edges {
                if !ids.contains(e.as_str()) {
                    errs.push(format!("route '{}': unknown edge '{e}'", r.route.name));
                }
            }
        }
        if !errs.is_empty() {
            return Err(errs);
        }
        let mut reserved = self.opts.reserved_ports.clone();
        reserved.push(self.opts.default_mgmt_port);
        reserved.extend(s.edges.iter().map(|e| e.mgmt_port));

        let slice = |edge: Option<&str>| -> Vec<Route> {
            routes
                .iter()
                .filter(|r| r.edges.is_empty() || edge.is_some_and(|e| r.edges.iter().any(|x| x == e)))
                .map(|r| r.route.clone())
                .collect()
        };
        let mut check = |label: &str, set: Vec<Route>| {
            if let Err(e) = config::validate_set(&set, &reserved) {
                errs.extend(e.into_iter().map(|m| if label.is_empty() { m } else { format!("on edge '{label}': {m}") }));
            }
        };
        check("", slice(None));
        for e in s.edges.iter().filter(|e| e.status != EdgeStatus::Deleting) {
            check(&e.name, slice(Some(&e.id)));
        }
        errs.dedup();
        if errs.is_empty() { Ok(()) } else { Err(errs) }
    }

    fn commit_routes(&self, s: &mut State, next: Vec<CRoute>) -> Result<(), CtlError> {
        self.validate_routes(s, &next).map_err(CtlError::Invalid)?;
        s.routes = next;
        s.generation += 1;
        Ok(())
    }

    pub fn create_route(&self, actor: &str, mut r: CRoute) -> Result<CRoute, CtlError> {
        r.route.normalize().map_err(CtlError::Invalid)?;
        let out = self.store.try_update(|s| -> Result<CRoute, CtlError> {
            if r.route.id.is_empty() {
                r.route.id = config::unique_id(&s.routes.iter().map(|x| x.route.clone()).collect::<Vec<_>>(), &config::slugify(&r.route.name));
            } else if s.routes.iter().any(|x| x.route.id == r.route.id) {
                return Err(CtlError::Conflict(format!("route '{}' already exists", r.route.id)));
            }
            let mut next = s.routes.clone();
            next.push(r.clone());
            self.commit_routes(s, next)?;
            Ok(r.clone())
        })?;
        self.audit.record(actor, "route.create", &out.route.id);
        Ok(out)
    }

    pub fn update_route(&self, actor: &str, id: &str, mut r: CRoute) -> Result<CRoute, CtlError> {
        r.route.id = id.to_string();
        r.route.normalize().map_err(CtlError::Invalid)?;
        let out = self.store.try_update(|s| -> Result<CRoute, CtlError> {
            let pos = s.routes.iter().position(|x| x.route.id == id).ok_or_else(|| CtlError::NotFound(id.into()))?;
            let mut next = s.routes.clone();
            next[pos] = r.clone();
            self.commit_routes(s, next)?;
            Ok(r.clone())
        })?;
        self.audit.record(actor, "route.update", id);
        Ok(out)
    }

    pub fn delete_route(&self, actor: &str, id: &str) -> Result<(), CtlError> {
        self.store.try_update(|s| -> Result<(), CtlError> {
            if !s.routes.iter().any(|x| x.route.id == id) {
                return Err(CtlError::NotFound(id.into()));
            }
            let next = s.routes.iter().filter(|x| x.route.id != id).cloned().collect();
            self.commit_routes(s, next)
        })?;
        self.audit.record(actor, "route.delete", id);
        Ok(())
    }
}
