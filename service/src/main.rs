// Edge, gateway and standalone modes are Linux-only; on other platforms their code is compiled but unused.
#![cfg_attr(not(unix), allow(dead_code))]
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use edge_lbd::engine::{Engine, Options};
use edge_lbd::firewall::NftSet;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

/// Configurable L4 edge load balancer: routes (domain, listen ip:port) -> targets, with a web UI.
///
/// Hostname matching works on TLS SNI, HTTP Host and the Minecraft handshake; nothing is
/// terminated or decrypted.
#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the fleet controller: web UI + API that creates and manages edges.
    Controller(ControllerArgs),
    /// Run as a managed edge node (installed and driven by the controller).
    Edge(EdgeArgs),
    /// Single machine: proxy and web UI together, no controller.
    Standalone(StandaloneArgs),
    /// Run as a site's WireGuard gateway on the home network (installed by the controller's enrol command).
    Gateway(GatewayArgs),
    /// Root helper on an edge: applies the WireGuard state the edge writes. Installed by the controller.
    WgApply(WgApplyArgs),
}

#[derive(Parser, Debug)]
struct GatewayArgs {
    /// The controller's gateway listener, as host:port.
    #[arg(long)]
    controller: String,

    /// SHA-256 fingerprint (hex) of the controller's gateway certificate.
    #[arg(long)]
    pin: String,

    /// Holds the WireGuard key, enrolment token and identity. Root only.
    #[arg(long, default_value = "/var/lib/edge-lb-gateway")]
    data_dir: PathBuf,

    #[arg(long, default_value_t = 5)]
    interval_secs: u64,
}

#[derive(Parser, Debug)]
struct WgApplyArgs {
    /// State file the edge process writes (validated JSON).
    #[arg(long, default_value = "/var/lib/edge-lb/wg.json")]
    state: PathBuf,

    /// The edge's WireGuard private key (root only).
    #[arg(long, default_value = "/etc/edge-lb/wg.key")]
    key: PathBuf,

    #[arg(long, default_value_t = 2000)]
    interval_ms: u64,
}

#[derive(Parser, Debug)]
struct ControllerArgs {
    /// Address for the web UI and API.
    #[arg(long, env = "EDGE_LB_LISTEN", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Allow binding a non-private address. The UI is plain HTTP: put a TLS-terminating
    /// reverse proxy in front, and pass --secure-cookies.
    #[arg(long)]
    allow_public: bool,

    /// Mark session cookies Secure (set this when served over HTTPS).
    #[arg(long)]
    secure_cookies: bool,

    /// State directory: controller.json (holds secrets), SSH key, audit log.
    /// Default: %APPDATA%\edge-lb on Windows, /var/lib/edge-lb-controller elsewhere.
    #[arg(long, env = "EDGE_LB_CONTROLLER_DIR", default_value_os_t = default_controller_dir())]
    data_dir: PathBuf,

    /// The edge binary installed on machines with this controller's own CPU (default: this
    /// executable, on Linux). It must be a Linux build; a static (musl) build runs anywhere.
    #[arg(long, env = "EDGE_LB_EDGE_BINARY")]
    edge_binary: Option<PathBuf>,

    /// Directory with Linux builds to install, named edge-lbd-x86_64 and edge-lbd-aarch64.
    /// Default: `agents` next to this executable. The Windows app ships its builds there.
    #[arg(long, env = "EDGE_LB_AGENTS_DIR")]
    agents_dir: Option<PathBuf>,

    /// Where WireGuard gateways connect (TLS, pinned by them; only enrolment and sync live here).
    /// Off unless set. Typically 0.0.0.0:7444 on a public machine.
    #[arg(long, env = "EDGE_LB_GATEWAY_LISTEN", requires = "gateway_host")]
    gateway_listen: Option<SocketAddr>,

    /// The hostname or IPv4 address gateways use to reach --gateway-listen (host or host:port).
    #[arg(long, env = "EDGE_LB_GATEWAY_HOST")]
    gateway_host: Option<String>,
}

#[derive(Parser, Debug)]
struct EdgeArgs {
    /// Management API (mutual TLS). Only the controller's certificate is accepted.
    #[arg(long, default_value = "0.0.0.0:7443")]
    mgmt: SocketAddr,

    #[arg(long, default_value = "/var/lib/edge-lb")]
    data_dir: PathBuf,

    /// PEM file with the controller's CA certificate.
    #[arg(long, default_value = "/etc/edge-lb/controller-ca.pem")]
    controller_ca: PathBuf,

    #[arg(long, default_value_t = 20_000)]
    max_conns: usize,

    #[arg(long, default_value_t = 3000)]
    peek_timeout_ms: u64,
}

#[derive(Parser, Debug)]
struct StandaloneArgs {
    /// Address for the web UI and API. Keep this on loopback or the WireGuard address.
    #[arg(long, env = "EDGE_LB_API", default_value = "127.0.0.1:9090")]
    api: SocketAddr,

    /// Allow the API on a public address. The API can open ports on this machine; don't.
    #[arg(long)]
    allow_public_api: bool,

    /// Where routes.json lives.
    #[arg(long, env = "EDGE_LB_DATA_DIR", default_value = "/var/lib/edge-lb")]
    data_dir: PathBuf,

    /// File holding the API token (created with a random value on first start).
    /// The EDGE_LB_TOKEN environment variable overrides it.
    #[arg(long, env = "EDGE_LB_TOKEN_FILE", default_value = "/etc/edge-lb/token")]
    token_file: PathBuf,

    /// Ports routes may not listen on. The API port is always reserved.
    #[arg(long = "reserve-port", default_values_t = [22u16])]
    reserve_port: Vec<u16>,

    /// Keep an nftables set in sync with the listening ports, as family:table:set
    /// (e.g. inet:edge_lb:routes). Needs the set to exist and CAP_NET_ADMIN.
    #[arg(long, env = "EDGE_LB_NFT_SET")]
    nft_set: Option<String>,

    /// Max simultaneous proxied connections.
    #[arg(long, default_value_t = 20_000)]
    max_conns: usize,

    /// How long to wait for the first bytes (to read the hostname) on a listener with domain routes.
    #[arg(long, default_value_t = 3000)]
    peek_timeout_ms: u64,

    #[arg(long, default_value_t = 5000)]
    connect_timeout_ms: u64,

    #[arg(long, default_value_t = 5000)]
    health_interval_ms: u64,
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_loopback() || v.is_private() || v.is_link_local() || (v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v) => {
            v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn load_token(path: &Path) -> Result<String> {
    if let Ok(t) = std::env::var("EDGE_LB_TOKEN") {
        let t = t.trim().to_string();
        if t.len() < 16 {
            bail!("EDGE_LB_TOKEN must be at least 16 characters");
        }
        return Ok(t);
    }
    match std::fs::read_to_string(path) {
        Ok(t) => {
            let t = t.trim().to_string();
            if t.len() < 16 {
                bail!("{} holds a token shorter than 16 characters", path.display());
            }
            Ok(t)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            use rand::RngCore;
            let mut raw = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut raw);
            let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let mut f = edge_lbd::fsutil::private_options()
                .write(true)
                .create_new(true)
                .open(path)
                .with_context(|| format!("creating {}", path.display()))?;
            writeln!(f, "{token}")?;
            info!("generated a new API token in {}", path.display());
            Ok(token)
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

async fn standalone(args: StandaloneArgs) -> Result<()> {

    if !args.allow_public_api && !is_private(args.api.ip()) {
        bail!(
            "refusing to serve the API on public address {}: it can open ports on this host. \
             Use loopback or the WireGuard address, or pass --allow-public-api if you really mean it.",
            args.api.ip()
        );
    }
    let token = load_token(&args.token_file)?;

    let mut reserved = args.reserve_port.clone();
    reserved.push(args.api.port());
    let opts = Options {
        data_dir: args.data_dir.clone(),
        reserved_ports: reserved,
        peek_timeout: Duration::from_millis(args.peek_timeout_ms),
        connect_timeout: Duration::from_millis(args.connect_timeout_ms),
        health_interval: Duration::from_millis(args.health_interval_ms),
        max_conns: args.max_conns,
        nft_set: args.nft_set.as_deref().map(NftSet::parse).transpose()?,
        ..Default::default()
    };
    let engine = Engine::start(opts).await?;

    let app = edge_lbd::api::router(engine.clone(), Arc::from(token.as_str()));
    let listener = tokio::net::TcpListener::bind(args.api)
        .await
        .with_context(|| format!("binding API on {}", args.api))?;
    info!("web UI and API on http://{}", args.api);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    engine.shutdown().await;
    Ok(())
}

/// Resolves on Ctrl+C, and on SIGTERM (Unix) or the console being closed (Windows).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async { match term.as_mut() { Some(t) => { t.recv().await; } None => std::future::pending().await } } => {}
        }
    }
    #[cfg(windows)]
    {
        let mut close = tokio::signal::windows::ctrl_close().ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async { match close.as_mut() { Some(c) => { c.recv().await; } None => std::future::pending().await } } => {}
        }
    }
    info!("shutting down");
}

/// Where the controller keeps its state when `--data-dir` isn't given.
fn default_controller_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return PathBuf::from(appdata).join("edge-lb");
        }
    }
    PathBuf::from("/var/lib/edge-lb-controller")
}

async fn edge(args: EdgeArgs) -> Result<()> {
    let ca = std::fs::read_to_string(&args.controller_ca)
        .with_context(|| format!("reading the controller CA from {}", args.controller_ca.display()))?;
    let handle = edge_lbd::edge::start(edge_lbd::edge::EdgeOptions {
        mgmt: args.mgmt,
        controller_ca_pem: ca,
        engine: Options {
            data_dir: args.data_dir,
            reserved_ports: vec![22],
            peek_timeout: Duration::from_millis(args.peek_timeout_ms),
            max_conns: args.max_conns,
            ..Default::default()
        },
    })
    .await?;
    shutdown_signal().await;
    handle.stop().await;
    Ok(())
}

async fn controller(args: ControllerArgs) -> Result<()> {
    if !args.allow_public && !is_private(args.listen.ip()) {
        bail!(
            "refusing to serve the controller on public address {}: the UI is plain HTTP and can create servers. \
             Bind a private address, or pass --allow-public behind a TLS-terminating reverse proxy.",
            args.listen.ip()
        );
    }
    let mut opts = edge_lbd::controller::Options::new(args.data_dir);
    if let Some(b) = args.edge_binary {
        opts.agents.insert(std::env::consts::ARCH, b);
    }
    if let Some(d) = &args.agents_dir {
        opts.agents.discover(d);
    }
    if opts.agents.is_empty() {
        tracing::warn!("no Linux edge binaries found (looked for `agents/edge-lbd-<arch>` beside this program): edges and gateways can't be installed until you pass --agents-dir or --edge-binary");
    } else {
        info!("can install edges and gateways for: {}", opts.agents.archs().join(", "));
    }
    if let (Some(listen), Some(host)) = (args.gateway_listen, args.gateway_host) {
        opts.gateway = Some(edge_lbd::controller::sites::GatewayListen { listen, host });
    }
    let ctl = edge_lbd::controller::Controller::start(opts).await?;
    if let Some(code) = ctl.setup_code.lock().unwrap().clone() {
        info!("FIRST RUN: open the UI and create the admin account with setup code {code}");
    }
    let app = edge_lbd::controller::api::router(ctl.clone(), args.secure_cookies);
    let listener = tokio::net::TcpListener::bind(args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    info!("controller UI on http://{}", args.listen);
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    ctl.stop();
    Ok(())
}

async fn gateway(args: GatewayArgs) -> Result<()> {
    if !edge_lbd::gateway::valid_pin(&args.pin) {
        bail!("--pin must be the 64-character hex SHA-256 fingerprint of the controller's gateway certificate");
    }
    if !edge_lbd::controller::sites::valid_hostport(&args.controller) {
        bail!("--controller must be host:port");
    }
    let run = edge_lbd::gateway::run(edge_lbd::gateway::Options {
        controller: args.controller,
        pin: args.pin,
        data_dir: args.data_dir,
        interval: Duration::from_secs(args.interval_secs.clamp(1, 300)),
        host: Arc::new(edge_lbd::gateway::RealHost),
    });
    tokio::select! {
        r = run => r,
        _ = shutdown_signal() => Ok(()),
    }
}

async fn wg_apply(args: WgApplyArgs) -> Result<()> {
    info!("watching {} and keeping {} in step with it", args.state.display(), edge_lbd::wg::IFACE);
    tokio::select! {
        r = edge_lbd::wg::watch_and_apply(&args.state, &args.key, Duration::from_millis(args.interval_ms.max(200))) => r,
        _ = shutdown_signal() => Ok(()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    match Cli::parse().cmd {
        Cmd::Controller(a) => controller(a).await,
        #[cfg(unix)]
        Cmd::Edge(a) => edge(a).await,
        #[cfg(unix)]
        Cmd::Standalone(a) => standalone(a).await,
        #[cfg(unix)]
        Cmd::Gateway(a) => gateway(a).await,
        #[cfg(unix)]
        Cmd::WgApply(a) => wg_apply(a).await,
        #[cfg(not(unix))]
        _ => bail!("only `controller` runs on this platform: edges, gateways and standalone mode are Linux-only. The controller installs them on your Linux machines for you."),
    }
}
