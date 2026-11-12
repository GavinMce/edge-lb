//! The control core: owns the route set, persists it, and reconciles running listeners
//! and health checkers to match — live, without dropping existing connections.

use crate::config::{self, Route, Store};
use crate::firewall::NftSet;
use crate::proxy::{spawn_listener, RouteRt, RouteStats, TargetState, Table, Tunables};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex, Semaphore};
use tokio::task::JoinHandle;
use tracing::{info, warn};

#[derive(Clone)]
pub struct Options {
    pub data_dir: PathBuf,
    /// Ports routes may not listen on (the management API, SSH, ...).
    pub reserved_ports: Vec<u16>,
    pub peek_timeout: Duration,
    pub connect_timeout: Duration,
    pub health_interval: Duration,
    /// How often to retry failed binds and re-assert the firewall set.
    pub maintenance_interval: Duration,
    pub max_conns: usize,
    pub nft_set: Option<NftSet>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/edge-lb"),
            reserved_ports: vec![22],
            peek_timeout: Duration::from_secs(3),
            connect_timeout: Duration::from_secs(5),
            health_interval: Duration::from_secs(5),
            maintenance_interval: Duration::from_secs(15),
            max_conns: 20_000,
            nft_set: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid route configuration")]
    Invalid(Vec<String>),
    #[error("{0}")]
    Internal(String),
}

type Key = (IpAddr, u16);

struct Listener {
    tx: watch::Sender<Arc<Table>>,
    task: JoinHandle<()>,
}

impl Listener {
    /// Abort and wait until the socket is actually closed, so the port can be rebound.
    async fn stop(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Health {
    state: Arc<TargetState>,
    task: JoinHandle<()>,
}
impl Drop for Health {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
struct State {
    routes: Vec<Route>,
    listeners: BTreeMap<Key, Listener>,
    bind_errors: BTreeMap<Key, String>,
    health: BTreeMap<SocketAddr, Health>,
    stats: BTreeMap<String, Arc<RouteStats>>,
    fw_error: Option<String>,
}

struct Inner {
    state: Mutex<State>,
    store: Store,
    opts: Options,
    started: Instant,
    sem: Arc<Semaphore>,
}

#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

// ---- views (what the API returns) -----------------------------------------------------

#[derive(Debug, Serialize)]
pub struct TargetView {
    pub address: IpAddr,
    pub port: u16,
    /// `null` when the route is disabled and the target isn't being checked.
    pub healthy: Option<bool>,
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RouteStatus {
    /// `listening`, `disabled`, `error` (could not bind) or `pending`.
    pub state: &'static str,
    pub error: Option<String>,
    pub active_connections: i64,
    pub total_connections: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub connect_failures: u64,
    pub targets: Vec<TargetView>,
}

#[derive(Debug, Serialize)]
pub struct RouteView {
    #[serde(flatten)]
    pub route: Route,
    pub status: RouteStatus,
}

#[derive(Debug, Serialize)]
pub struct StatusView {
    pub version: &'static str,
    pub uptime_secs: u64,
    pub active_connections: i64,
    pub listeners: usize,
    pub firewall_error: Option<String>,
    pub routes: Vec<RouteView>,
}

fn route_view(st: &State, r: &Route) -> RouteView {
    let key = (r.listen.ip, r.listen.port);
    let (state, error) = if !r.enabled {
        ("disabled", None)
    } else if st.listeners.contains_key(&key) {
        ("listening", None)
    } else if let Some(e) = st.bind_errors.get(&key) {
        ("error", Some(e.clone()))
    } else {
        ("pending", None)
    };
    let zero = RouteStats::default();
    let stats = st.stats.get(&r.id).map(|s| s.as_ref()).unwrap_or(&zero);
    RouteView {
        route: r.clone(),
        status: RouteStatus {
            state,
            error,
            active_connections: stats.active.load(Relaxed),
            total_connections: stats.total.load(Relaxed),
            bytes_up: stats.bytes_up.load(Relaxed),
            bytes_down: stats.bytes_down.load(Relaxed),
            connect_failures: stats.connect_failures.load(Relaxed),
            targets: r
                .targets
                .iter()
                .map(|t| {
                    let h = st.health.get(&SocketAddr::new(t.address, t.port));
                    TargetView {
                        address: t.address,
                        port: t.port,
                        healthy: h.map(|h| h.state.healthy()),
                        last_error: h.and_then(|h| h.state.last_error()),
                    }
                })
                .collect(),
        },
    }
}

fn spawn_health(addr: SocketAddr, every: Duration, connect_timeout: Duration) -> Health {
    let state = Arc::new(TargetState::new(addr));
    let s = state.clone();
    let task = tokio::spawn(async move {
        loop {
            match tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(addr)).await {
                Ok(Ok(_)) => s.set(true, None),
                Ok(Err(e)) => s.set(false, Some(e.to_string())),
                Err(_) => s.set(false, Some("connect timed out".into())),
            }
            tokio::time::sleep(every).await;
        }
    });
    Health { state, task }
}

impl Engine {
    pub async fn start(opts: Options) -> anyhow::Result<Engine> {
        let store = Store::new(opts.data_dir.join("routes.json"));
        let routes = store.load()?;
        if let Err(errs) = config::validate_set(&routes, &opts.reserved_ports) {
            // Don't refuse to boot over a bad stored config; run what is valid is unsafe,
            // so run nothing from it and say why.
            for e in &errs {
                warn!("stored routes invalid: {e}");
            }
            anyhow::bail!(
                "{} contains an invalid route set ({} problem(s)); fix or remove it",
                opts.data_dir.join("routes.json").display(),
                errs.len()
            );
        }
        let engine = Engine {
            inner: Arc::new(Inner {
                sem: Arc::new(Semaphore::new(opts.max_conns)),
                state: Mutex::new(State { routes, ..Default::default() }),
                store,
                started: Instant::now(),
                opts,
            }),
        };
        {
            let mut st = engine.inner.state.lock().await;
            engine.reconcile(&mut st).await;
            engine.sync_firewall(&mut st).await;
        }
        let e = engine.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(e.inner.opts.maintenance_interval);
            tick.tick().await;
            loop {
                tick.tick().await;
                e.maintain().await;
            }
        });
        Ok(engine)
    }

    async fn maintain(&self) {
        let mut st = self.inner.state.lock().await;
        let wanted: HashSet<Key> =
            st.routes.iter().filter(|r| r.enabled).map(|r| (r.listen.ip, r.listen.port)).collect();
        if wanted.iter().any(|k| !st.listeners.contains_key(k)) {
            self.reconcile(&mut st).await;
        }
        self.sync_firewall(&mut st).await;
    }

    /// Make listeners, health checkers and stats match `st.routes`.
    async fn reconcile(&self, st: &mut State) {
        let opts = &self.inner.opts;
        let enabled: Vec<Route> = st.routes.iter().filter(|r| r.enabled).cloned().collect();

        let ids: HashSet<&str> = st.routes.iter().map(|r| r.id.as_str()).collect();
        st.stats.retain(|id, _| ids.contains(id.as_str()));
        for r in &st.routes {
            st.stats.entry(r.id.clone()).or_insert_with(|| Arc::new(RouteStats::default()));
        }

        let wanted_targets: HashSet<SocketAddr> = enabled
            .iter()
            .flat_map(|r| r.targets.iter().map(|t| SocketAddr::new(t.address, t.port)))
            .collect();
        st.health.retain(|a, _| wanted_targets.contains(a));
        for a in &wanted_targets {
            st.health
                .entry(*a)
                .or_insert_with(|| spawn_health(*a, opts.health_interval, opts.connect_timeout));
        }

        let mut groups: BTreeMap<Key, Vec<Arc<RouteRt>>> = BTreeMap::new();
        for r in enabled {
            let targets = r
                .targets
                .iter()
                .map(|t| st.health[&SocketAddr::new(t.address, t.port)].state.clone())
                .collect();
            let stats = st.stats[&r.id].clone();
            groups.entry((r.listen.ip, r.listen.port)).or_default().push(Arc::new(RouteRt::new(r, stats, targets)));
        }

        // Close removed listeners first so a port that moved can be rebound immediately.
        let gone: Vec<Key> = st.listeners.keys().filter(|k| !groups.contains_key(k)).copied().collect();
        for k in gone {
            if let Some(l) = st.listeners.remove(&k) {
                l.stop().await;
                info!("closed listener {}:{}", k.0, k.1);
            }
        }
        st.bind_errors.retain(|k, _| groups.contains_key(k));

        let tunables = Tunables { peek_timeout: opts.peek_timeout, connect_timeout: opts.connect_timeout };
        for (key, routes) in groups {
            let table = Arc::new(Table::new(routes));
            if let Some(l) = st.listeners.get(&key) {
                l.tx.send_replace(table);
                continue;
            }
            match TcpListener::bind(SocketAddr::new(key.0, key.1)).await {
                Ok(sock) => {
                    let (tx, rx) = watch::channel(table);
                    let task = spawn_listener(sock, rx, tunables.clone(), self.inner.sem.clone());
                    st.listeners.insert(key, Listener { tx, task });
                    st.bind_errors.remove(&key);
                    info!("listening on {}:{}", key.0, key.1);
                }
                Err(e) => {
                    if st.bind_errors.get(&key).map(String::as_str) != Some(&e.to_string()) {
                        warn!("cannot listen on {}:{}: {e}", key.0, key.1);
                    }
                    st.bind_errors.insert(key, e.to_string());
                }
            }
        }
    }

    async fn sync_firewall(&self, st: &mut State) {
        let Some(set) = &self.inner.opts.nft_set else { return };
        let ports: BTreeSet<u16> = st.listeners.keys().map(|k| k.1).collect();
        match set.sync(&ports).await {
            Ok(()) => st.fw_error = None,
            Err(e) => {
                let msg = e.to_string();
                if st.fw_error.as_deref() != Some(&msg) {
                    warn!("firewall sync: {msg}");
                }
                st.fw_error = Some(msg);
            }
        }
    }

    async fn commit(&self, st: &mut State, next: Vec<Route>) -> Result<(), EngineError> {
        config::validate_set(&next, &self.inner.opts.reserved_ports).map_err(EngineError::Invalid)?;
        self.inner.store.save(&next).map_err(|e| EngineError::Internal(format!("saving routes: {e}")))?;
        st.routes = next;
        self.reconcile(st).await;
        self.sync_firewall(st).await;
        Ok(())
    }

    // ---- public API -------------------------------------------------------------------

    /// Close every listener and stop health checks. Existing connections finish on their own.
    pub async fn shutdown(&self) {
        let mut st = self.inner.state.lock().await;
        for (_, l) in std::mem::take(&mut st.listeners) {
            l.stop().await;
        }
        st.health.clear();
    }

    pub async fn status(&self) -> StatusView {
        let st = self.inner.state.lock().await;
        StatusView {
            version: env!("CARGO_PKG_VERSION"),
            uptime_secs: self.inner.started.elapsed().as_secs(),
            active_connections: st.stats.values().map(|s| s.active.load(Relaxed)).sum(),
            listeners: st.listeners.len(),
            firewall_error: st.fw_error.clone(),
            routes: st.routes.iter().map(|r| route_view(&st, r)).collect(),
        }
    }

    pub async fn list(&self) -> Vec<RouteView> {
        let st = self.inner.state.lock().await;
        st.routes.iter().map(|r| route_view(&st, r)).collect()
    }

    pub async fn get(&self, id: &str) -> Result<RouteView, EngineError> {
        let st = self.inner.state.lock().await;
        st.routes
            .iter()
            .find(|r| r.id == id)
            .map(|r| route_view(&st, r))
            .ok_or_else(|| EngineError::NotFound(id.into()))
    }

    pub async fn create(&self, mut r: Route) -> Result<RouteView, EngineError> {
        r.normalize().map_err(EngineError::Invalid)?;
        let mut st = self.inner.state.lock().await;
        if r.id.is_empty() {
            r.id = config::unique_id(&st.routes, &config::slugify(&r.name));
        } else if st.routes.iter().any(|x| x.id == r.id) {
            return Err(EngineError::Conflict(format!("route '{}' already exists", r.id)));
        }
        let mut next = st.routes.clone();
        next.push(r.clone());
        self.commit(&mut st, next).await?;
        Ok(route_view(&st, &r))
    }

    pub async fn update(&self, id: &str, mut r: Route) -> Result<RouteView, EngineError> {
        r.id = id.to_string();
        r.normalize().map_err(EngineError::Invalid)?;
        let mut st = self.inner.state.lock().await;
        let pos = st
            .routes
            .iter()
            .position(|x| x.id == id)
            .ok_or_else(|| EngineError::NotFound(id.into()))?;
        let mut next = st.routes.clone();
        next[pos] = r.clone();
        self.commit(&mut st, next).await?;
        Ok(route_view(&st, &r))
    }

    pub async fn delete(&self, id: &str) -> Result<(), EngineError> {
        let mut st = self.inner.state.lock().await;
        if !st.routes.iter().any(|x| x.id == id) {
            return Err(EngineError::NotFound(id.into()));
        }
        let next: Vec<Route> = st.routes.iter().filter(|r| r.id != id).cloned().collect();
        self.commit(&mut st, next).await
    }

    /// Replace the entire route set (import / bulk edit). All-or-nothing.
    pub async fn replace_all(&self, routes: Vec<Route>) -> Result<Vec<RouteView>, EngineError> {
        let mut errs = Vec::new();
        let mut next: Vec<Route> = Vec::new();
        for mut r in routes {
            if let Err(e) = r.normalize() {
                errs.extend(e.into_iter().map(|m| format!("route '{}': {m}", r.name)));
                continue;
            }
            if r.id.is_empty() {
                r.id = config::unique_id(&next, &config::slugify(&r.name));
            }
            next.push(r);
        }
        if !errs.is_empty() {
            return Err(EngineError::Invalid(errs));
        }
        let mut st = self.inner.state.lock().await;
        self.commit(&mut st, next).await?;
        Ok(st.routes.iter().map(|r| route_view(&st, r)).collect())
    }
}
