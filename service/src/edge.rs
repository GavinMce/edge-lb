//! Edge node: the data-plane engine plus a mutual-TLS management API the controller drives.
//!
//! The edge keeps working from its last applied config if the controller disappears.

use crate::api::ApiError;
use crate::config::Route;
use crate::engine::{Engine, Options, StatusView};
use crate::{pki, tls};
use anyhow::{Context, Result};
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::info;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct EdgeOptions {
    pub mgmt: SocketAddr,
    pub controller_ca_pem: String,
    /// Engine settings. `data_dir` is shared: routes.json, generation and the mgmt cert live there.
    pub engine: Options,
}

pub struct EdgeHandle {
    pub addr: SocketAddr,
    pub cert_pem: String,
    pub fingerprint: String,
    pub engine: Engine,
    task: JoinHandle<()>,
}

impl EdgeHandle {
    pub async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
        self.engine.shutdown().await;
    }
}

struct EdgeState {
    engine: Engine,
    data_dir: PathBuf,
    generation: Mutex<u64>,
    started: Instant,
}

#[derive(Deserialize)]
pub struct ConfigPush {
    pub generation: u64,
    pub routes: Vec<Route>,
    /// WireGuard state for this edge. Absent from controllers that predate gateways; absent also
    /// when the edge has no WireGuard, in which case any previous state is left untouched.
    #[serde(default)]
    pub wg: Option<crate::wg::Desired>,
}

#[derive(Serialize)]
struct Info {
    version: &'static str,
    uptime_secs: u64,
    generation: u64,
}

#[derive(Serialize)]
struct StatusResp {
    generation: u64,
    #[serde(flatten)]
    status: StatusView,
}

fn write_secret(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

/// Load the edge's management certificate, generating it on first start.
fn load_or_create_identity(dir: &Path) -> Result<pki::Pem> {
    let (cp, kp) = (dir.join("mgmt-cert.pem"), dir.join("mgmt-key.pem"));
    if let (Ok(cert), Ok(key)) = (std::fs::read_to_string(&cp), std::fs::read_to_string(&kp)) {
        return Ok(pki::Pem { cert, key });
    }
    let pem = pki::self_signed_server()?;
    write_secret(&kp, &pem.key)?;
    std::fs::write(&cp, &pem.cert)?;
    Ok(pem)
}

pub async fn start(mut opts: EdgeOptions) -> Result<EdgeHandle> {
    tls::init();
    let dir = opts.engine.data_dir.clone();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let identity = load_or_create_identity(&dir)?;
    let fingerprint = pki::fingerprint_pem(&identity.cert)?;
    let cfg = tls::edge_server_config(&identity.cert, &identity.key, &opts.controller_ca_pem)
        .context("building mTLS config")?;

    let listener = TcpListener::bind(opts.mgmt).await.with_context(|| format!("binding management API on {}", opts.mgmt))?;
    let addr = listener.local_addr()?;
    opts.engine.reserved_ports.push(addr.port());
    let engine = Engine::start(opts.engine).await?;

    let generation = std::fs::read_to_string(dir.join("generation")).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    let state = Arc::new(EdgeState { engine: engine.clone(), data_dir: dir, generation: Mutex::new(generation), started: Instant::now() });
    let app = Router::new()
        .route("/v1/info", get(info))
        .route("/v1/status", get(status))
        .route("/v1/config", axum::routing::put(put_config))
        .with_state(state);

    info!("management API (mTLS) on {addr}, certificate {fingerprint}");
    let task = tokio::spawn(tls::serve(listener, cfg, app));
    Ok(EdgeHandle { addr, cert_pem: identity.cert, fingerprint, engine, task })
}

async fn info(State(s): State<Arc<EdgeState>>) -> Json<Info> {
    Json(Info { version: VERSION, uptime_secs: s.started.elapsed().as_secs(), generation: *s.generation.lock().await })
}

async fn status(State(s): State<Arc<EdgeState>>) -> Json<StatusResp> {
    Json(StatusResp { generation: *s.generation.lock().await, status: s.engine.status().await })
}

/// Hand the validated WireGuard state to the root applier by writing it where that daemon looks.
/// The edge itself has no privileges and never touches the interface.
fn write_wg_state(dir: &Path, wg: &crate::wg::Desired) -> Result<()> {
    let tmp = dir.join("wg.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(wg)?)?;
    std::fs::rename(&tmp, dir.join("wg.json"))?;
    Ok(())
}

async fn put_config(State(s): State<Arc<EdgeState>>, Json(push): Json<ConfigPush>) -> Result<Json<serde_json::Value>, ApiError> {
    let mut gen = s.generation.lock().await;
    if let Some(wg) = &push.wg {
        crate::wg::validate(wg).map_err(|e| ApiError::from(crate::engine::EngineError::Invalid(e)))?;
        if !wg.forward_to.is_empty() {
            return Err(crate::engine::EngineError::Invalid(vec!["an edge may not forward traffic".into()]).into());
        }
    }
    let applied = s.engine.replace_all(push.routes).await?;
    if let Some(wg) = &push.wg {
        write_wg_state(&s.data_dir, wg).map_err(|e| ApiError::from(crate::engine::EngineError::Internal(format!("saving WireGuard state: {e:#}"))))?;
    }
    *gen = push.generation;
    let _ = std::fs::write(s.data_dir.join("generation"), gen.to_string());
    Ok(Json(serde_json::json!({ "generation": *gen, "routes": applied.len() })))
}
