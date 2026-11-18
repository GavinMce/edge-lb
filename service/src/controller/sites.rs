//! Sites and gateways: the controller's half of managed WireGuard.
//!
//! A *site* is a network the edges can reach (a home LAN). Its *gateway* is a machine there that
//! dials out to every edge. The controller allocates tunnel addresses, exchanges **public** keys,
//! and tells every edge and gateway what its tunnel should look like. Private keys are generated on
//! the machines that use them and never travel.
//!
//! Gateways reach the controller on a separate TLS listener (self-signed, pinned by the gateway):
//! admin credentials and the admin UI are never exposed there.

use super::model::*;
use super::{invalid, Controller, CtlError};
use crate::gateway::{EnrolReq, EnrolResp, Handshake, SyncReq, SyncResp};
use crate::wg::{self, Cidr};
use crate::{config, pki, tls};
use axum::extract::{DefaultBodyLimit, Path, State as Ax};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tracing::warn;

pub const ENROL_TTL_SECS: u64 = 3600;
/// A gateway polls every few seconds; this long without a poll and it is shown as offline.
pub const ONLINE_WITHIN_SECS: u64 = 30;
const MAX_SITES: usize = 20;
const MAX_LAN_RANGES: usize = 16;

/// Where the gateway listener binds and how gateways are told to reach it.
#[derive(Debug, Clone)]
pub struct GatewayListen {
    pub listen: SocketAddr,
    /// Hostname or IPv4 address gateways connect to; `host:port` if the public port differs.
    pub host: String,
}

#[derive(Debug, Clone)]
pub struct GatewayEndpoint {
    pub addr: SocketAddr,
    /// `host:port` as a gateway should dial it.
    pub hostport: String,
}

pub fn valid_hostport(s: &str) -> bool {
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (s, None),
    };
    !host.is_empty()
        && host.len() <= 253
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !host.starts_with(['.', '-'])
        && port.is_none_or(|p| p.parse::<u16>().is_ok_and(|n| n > 0))
}

// ---- views ----------------------------------------------------------------------------------------

/// What the controller last heard from a gateway. Memory only.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GwLive {
    pub last_seen: Ts,
    pub version: String,
    pub applied_hash: Option<String>,
    pub error: Option<String>,
    pub handshakes: Vec<Handshake>,
}

#[derive(Debug, Serialize)]
pub struct TunnelView {
    pub edge: String,
    pub edge_name: String,
    /// A handshake completed within the last few minutes. `None` = unknown (gateway offline).
    pub up: Option<bool>,
    pub handshake_age_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct GatewayView {
    pub tunnel_ip: Option<std::net::Ipv4Addr>,
    pub public_key: Option<String>,
    pub enrolled: bool,
    pub enrolled_at: Option<Ts>,
    /// An enrolment token has been issued and hasn't expired or been used.
    pub enrol_pending_until: Option<Ts>,
    pub online: bool,
    pub last_seen: Option<Ts>,
    pub version: Option<String>,
    /// The gateway has applied the config the controller currently wants.
    pub in_sync: Option<bool>,
    pub error: Option<String>,
    pub tunnels: Vec<TunnelView>,
}

#[derive(Debug, Serialize)]
pub struct SiteView {
    pub id: String,
    pub name: String,
    pub lan_cidrs: Vec<String>,
    pub created_at: Ts,
    pub routes: usize,
    pub gateway: GatewayView,
}

#[derive(Debug, Deserialize)]
pub struct NewSite {
    pub name: String,
    pub lan_cidrs: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct SiteUpdate {
    pub name: Option<String>,
    pub lan_cidrs: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct EnrolInfo {
    /// Paste this on the gateway machine.
    pub command: String,
    pub expires: Ts,
}

// ---- helpers -------------------------------------------------------------------------------------

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha256_hex(s: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(s))
}

fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex(&b)
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn parse_cidrs(list: &[String]) -> (Vec<Cidr>, Vec<String>) {
    let mut errs = Vec::new();
    let mut ok = Vec::new();
    for s in list {
        match wg::parse_lan(s) {
            Ok(c) => ok.push(c),
            Err(e) => errs.push(e),
        }
    }
    (ok, errs)
}

impl State {
    /// Why this set of LAN ranges can't be used for `site_id` (a new site if `None`).
    pub fn check_lan_ranges(&self, site_id: Option<&str>, ranges: &[String]) -> Vec<String> {
        let mut errs = Vec::new();
        if ranges.is_empty() {
            errs.push("a site needs at least one LAN range, e.g. 192.168.1.0/24".into());
        }
        if ranges.len() > MAX_LAN_RANGES {
            errs.push(format!("at most {MAX_LAN_RANGES} LAN ranges per site"));
        }
        let (parsed, perrs) = parse_cidrs(ranges);
        errs.extend(perrs);
        let net = self.wg_net();
        for (i, c) in parsed.iter().enumerate() {
            if net.overlaps(*c) {
                errs.push(format!("{c} overlaps the tunnel network {}/{}; pick a different tunnel network in Settings", net.network(), net.prefix));
            }
            if parsed[..i].iter().any(|o| o.overlaps(*c)) {
                errs.push(format!("{c} overlaps another range in this site"));
            }
            for other in self.sites.iter().filter(|o| Some(o.id.as_str()) != site_id) {
                if other.lan_cidrs.iter().filter_map(|x| Cidr::parse(x).ok()).any(|o| o.overlaps(*c)) {
                    errs.push(format!("{c} overlaps site '{}'. Two sites can't share addresses, because the edge picks a tunnel by destination", other.name));
                }
            }
            for e in &self.edges {
                if let Some(std::net::IpAddr::V4(ip)) = e.ip {
                    if c.contains(ip) {
                        errs.push(format!("{c} contains the public address of edge '{}' ({ip}); traffic to it would loop into the tunnel", e.name));
                    }
                }
            }
        }
        errs.dedup();
        errs
    }
}

// ---- admin operations --------------------------------------------------------------------------------

impl Controller {
    pub(crate) fn ensure_addresses(&self) {
        if self.store.read(|s| s.needs_addresses()) {
            if let Err(e) = self.store.update(|s| s.assign_addresses()) {
                warn!("allocating tunnel addresses: {e:#}");
            }
        }
    }

    pub fn gateway_endpoint(&self) -> Option<GatewayEndpoint> {
        self.gateway.lock().unwrap().clone()
    }

    pub fn sites(&self) -> Vec<SiteView> {
        let live = self.gw_live.read().unwrap();
        let t = now();
        self.store.read(|s| {
            s.sites
                .iter()
                .map(|site| {
                    let l = live.get(&site.id);
                    let g = &site.gateway;
                    let online = l.is_some_and(|l| t.saturating_sub(l.last_seen) <= ONLINE_WITHIN_SECS);
                    let want = s.wg_for_gateway(site).map(|d| d.hash());
                    let tunnels = s
                        .edges
                        .iter()
                        .filter(|e| e.wg_public_key.is_some() && matches!(e.status, EdgeStatus::Healthy | EdgeStatus::Unreachable | EdgeStatus::Draining | EdgeStatus::Joining))
                        .map(|e| {
                            let age = l.filter(|_| online).and_then(|l| l.handshakes.iter().find(|h| Some(&h.public_key) == e.wg_public_key.as_ref())).and_then(|h| h.age_secs);
                            TunnelView { edge: e.id.clone(), edge_name: e.name.clone(), up: online.then_some(age.is_some_and(|a| a < 300)), handshake_age_secs: age }
                        })
                        .collect();
                    SiteView {
                        id: site.id.clone(),
                        name: site.name.clone(),
                        lan_cidrs: site.lan_cidrs.clone(),
                        created_at: site.created_at,
                        routes: s.routes.iter().filter(|r| r.site.as_deref() == Some(&site.id)).count(),
                        gateway: GatewayView {
                            tunnel_ip: g.tunnel_ip,
                            public_key: g.public_key.clone(),
                            enrolled: g.public_key.is_some(),
                            enrolled_at: g.enrolled_at,
                            enrol_pending_until: g.enrol.as_ref().filter(|e| e.expires > t).map(|e| e.expires),
                            online,
                            last_seen: l.map(|l| l.last_seen),
                            version: l.map(|l| l.version.clone()),
                            in_sync: l.filter(|_| online).map(|l| l.applied_hash.is_some() && l.applied_hash == want),
                            error: l.filter(|_| online).and_then(|l| l.error.clone()),
                            tunnels,
                        },
                    }
                })
                .collect()
        })
    }

    pub fn create_site(&self, actor: &str, n: NewSite) -> Result<SiteView, CtlError> {
        let name = n.name.trim().to_string();
        let mut errs = Vec::new();
        if name.is_empty() || name.chars().count() > 60 {
            errs.push("name is required (max 60 characters)".to_string());
        }
        let id = self.store.try_update(|s| {
            if s.sites.len() >= MAX_SITES {
                return invalid(format!("at most {MAX_SITES} sites"));
            }
            errs.extend(s.check_lan_ranges(None, &n.lan_cidrs));
            if !errs.is_empty() {
                return Err(CtlError::Invalid(errs.clone()));
            }
            let base = config::slugify(&name);
            let id = (1..).map(|i| if i == 1 { base.clone() } else { format!("{base}-{i}") }).find(|c| s.site(c).is_none()).unwrap();
            s.sites.push(Site { id: id.clone(), name: name.clone(), lan_cidrs: n.lan_cidrs.clone(), gateway: Gateway::default(), created_at: now() });
            s.assign_addresses();
            Ok(id)
        })?;
        self.audit.record(actor, "site.create", &id);
        Ok(self.sites().into_iter().find(|v| v.id == id).expect("just created"))
    }

    pub fn update_site(&self, actor: &str, id: &str, u: SiteUpdate) -> Result<SiteView, CtlError> {
        self.store.try_update(|s| {
            let pos = s.sites.iter().position(|x| x.id == id).ok_or_else(|| CtlError::NotFound(id.into()))?;
            if let Some(n) = &u.name {
                let n = n.trim();
                if n.is_empty() || n.chars().count() > 60 {
                    return invalid("name is required (max 60 characters)");
                }
                s.sites[pos].name = n.to_string();
            }
            if let Some(r) = &u.lan_cidrs {
                let errs = s.check_lan_ranges(Some(id), r);
                if !errs.is_empty() {
                    return Err(CtlError::Invalid(errs));
                }
                s.sites[pos].lan_cidrs = r.clone();
                // Routes into this site must still land inside it.
                let routes = s.routes.clone();
                self.validate_routes(s, &routes).map_err(CtlError::Invalid)?;
            }
            Ok(())
        })?;
        self.audit.record(actor, "site.update", id);
        Ok(self.sites().into_iter().find(|v| v.id == id).expect("exists"))
    }

    pub fn delete_site(&self, actor: &str, id: &str) -> Result<(), CtlError> {
        self.store.try_update(|s| {
            if s.site(id).is_none() {
                return Err(CtlError::NotFound(id.into()));
            }
            let using: Vec<&str> = s.routes.iter().filter(|r| r.site.as_deref() == Some(id)).map(|r| r.route.name.as_str()).collect();
            if !using.is_empty() {
                return Err(CtlError::Conflict(format!("routes still use this site: {}. Delete or change them first", using.join(", "))));
            }
            s.sites.retain(|x| x.id != id);
            Ok(())
        })?;
        self.gw_live.write().unwrap().remove(id);
        self.audit.record(actor, "site.delete", id);
        Ok(())
    }

    /// Issue a one-time token and the command that installs and enrols a gateway with it.
    pub fn start_enrolment(&self, actor: &str, id: &str) -> Result<EnrolInfo, CtlError> {
        let ep = self.gateway_endpoint().ok_or_else(|| {
            CtlError::Invalid(vec!["gateways can't connect yet: start the controller with --gateway-listen <addr> --gateway-host <public hostname or IP>".into()])
        })?;
        let pin = self.store.read(|s| s.gateway_tls.as_ref().map(|p| pki::spki_pin(&p.key))).ok_or_else(|| CtlError::Internal("no gateway certificate".into()))??;
        let token = random_hex(32);
        let expires = now() + ENROL_TTL_SECS;
        self.store.try_update(|s| {
            let site = s.sites.iter_mut().find(|x| x.id == id).ok_or_else(|| CtlError::NotFound(id.into()))?;
            site.gateway.enrol = Some(Enrolment { token_hash: sha256_hex(token.as_bytes()), expires });
            Ok::<_, CtlError>(())
        })?;
        self.audit.record(actor, "site.enrol", id);
        // `-k` skips CA validation (there is none); `--pinnedpubkey` is what authenticates the controller.
        let command = format!("curl -fsS -k --pinnedpubkey '{pin}' 'https://{}/gw/install/{token}' | sudo sh", ep.hostport);
        Ok(EnrolInfo { command, expires })
    }

    // ---- what gateways call -------------------------------------------------------------------------

    fn site_for_token(&self, token: &str) -> Option<String> {
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let h = sha256_hex(token.as_bytes());
        let t = now();
        self.store.read(|s| s.sites.iter().find(|x| x.gateway.enrol.as_ref().is_some_and(|e| e.expires > t && ct_eq(&e.token_hash, &h))).map(|x| x.id.clone()))
    }

    fn site_for_secret(&self, secret: &str) -> Option<String> {
        let h = sha256_hex(secret.as_bytes());
        self.store.read(|s| s.sites.iter().find(|x| x.gateway.secret_hash.as_ref().is_some_and(|sh| ct_eq(sh, &h))).map(|x| x.id.clone()))
    }

    pub fn gw_enrol(&self, req: EnrolReq) -> Result<EnrolResp, GwError> {
        let id = self.site_for_token(&req.token).ok_or(GwError::Unauthorized)?;
        if !wg::is_key(&req.public_key) {
            return Err(GwError::Invalid("public_key is not a WireGuard key".into()));
        }
        let secret = random_hex(32);
        let secret_hash = sha256_hex(secret.as_bytes());
        let h = sha256_hex(req.token.as_bytes());
        let site = self
            .store
            .try_update(|s| {
                if s.edges.iter().any(|e| e.wg_public_key.as_deref() == Some(&req.public_key)) || s.sites.iter().any(|x| x.id != id && x.gateway.public_key.as_deref() == Some(&req.public_key)) {
                    return Err(GwError::Invalid("that WireGuard key is already in use by another node".into()));
                }
                let site = s.sites.iter_mut().find(|x| x.id == id).ok_or(GwError::Unauthorized)?;
                // Re-check under the lock: the token is single-use.
                if !site.gateway.enrol.as_ref().is_some_and(|e| e.expires > now() && ct_eq(&e.token_hash, &h)) {
                    return Err(GwError::Unauthorized);
                }
                site.gateway.enrol = None;
                site.gateway.public_key = Some(req.public_key.clone());
                site.gateway.secret_hash = Some(secret_hash.clone());
                site.gateway.enrolled_at = Some(now());
                Ok(site.name.clone())
            })?;
        self.gw_live.write().unwrap().remove(&id);
        self.audit.record("gateway", "site.enrolled", &format!("{id} ({site})"));
        Ok(EnrolResp { secret, site })
    }

    pub fn gw_sync(&self, secret: &str, req: SyncReq) -> Result<SyncResp, GwError> {
        let id = self.site_for_secret(secret).ok_or(GwError::Unauthorized)?;
        let desired = self.store.read(|s| s.site(&id).and_then(|site| s.wg_for_gateway(site))).ok_or_else(|| GwError::Internal("no tunnel address allocated yet".into()))?;
        let hash = desired.hash();
        self.gw_live.write().unwrap().insert(
            id,
            GwLive {
                last_seen: now(),
                version: req.version.chars().take(32).collect(),
                applied_hash: req.applied_hash.filter(|h| h.len() <= 64),
                error: req.error.map(|e| e.chars().take(300).collect()),
                handshakes: req.handshakes.into_iter().filter(|h| wg::is_key(&h.public_key)).take(wg::MAX_PEERS).collect(),
            },
        );
        Ok(SyncResp { hash, desired })
    }

    /// The installer a gateway machine runs. Needs a live token but doesn't use it up.
    pub fn gw_install_script(&self, token: &str) -> Result<String, GwError> {
        self.site_for_token(token).ok_or(GwError::Unauthorized)?;
        let ep = self.gateway_endpoint().ok_or_else(|| GwError::Internal("gateway listener is not running".into()))?;
        let (pin, fp) = self
            .store
            .read(|s| s.gateway_tls.as_ref().map(|p| (pki::spki_pin(&p.key), pki::fingerprint_pem(&p.cert))))
            .ok_or_else(|| GwError::Internal("no gateway certificate".into()))?;
        let (pin, fp) = (pin.map_err(|e| GwError::Internal(e.to_string()))?, fp.map_err(|e| GwError::Internal(e.to_string()))?);
        let mut bins = Vec::new();
        for arch in self.opts.agents.archs() {
            let path = self.opts.agents.get(arch).expect("listed architecture");
            let bin = std::fs::read(path).map_err(|e| GwError::Internal(format!("reading the {arch} binary to serve: {e}")))?;
            bins.push((arch, sha256_hex(&bin)));
        }
        if bins.is_empty() {
            return Err(GwError::Internal("this controller has no Linux gateway binary to serve (see the agents directory)".into()));
        }
        render_install_script(&ep.hostport, token, &pin, &fp, &bins).map_err(|e| GwError::Internal(e.to_string()))
    }

    /// The gateway binary for a CPU architecture. `arch` is only ever looked up, never used as a path.
    pub async fn gw_binary(&self, token: &str, arch: &str) -> Result<Vec<u8>, GwError> {
        self.site_for_token(token).ok_or(GwError::Unauthorized)?;
        let path = self.opts.agents.get(arch).ok_or_else(|| GwError::Invalid("no binary for that architecture".into()))?;
        tokio::fs::read(path).await.map_err(|e| GwError::Internal(format!("reading the binary to serve: {e}")))
    }

    pub(crate) async fn start_gateway_listener(self: &Arc<Self>, g: &GatewayListen) -> anyhow::Result<()> {
        use anyhow::Context;
        if !valid_hostport(&g.host) {
            anyhow::bail!("--gateway-host '{}' must be a hostname or IPv4 address, optionally with :port", g.host);
        }
        let (cert, key) = self.store.read(|s| s.gateway_tls.as_ref().map(|p| (p.cert.clone(), p.key.clone()))).context("no gateway certificate")?;
        let cfg = tls::gateway_server_config(&cert, &key)?;
        let listener = tokio::net::TcpListener::bind(g.listen).await.with_context(|| format!("binding the gateway listener on {}", g.listen))?;
        let addr = listener.local_addr()?;
        let hostport = if g.host.contains(':') { g.host.clone() } else { format!("{}:{}", g.host, addr.port()) };
        *self.gateway.lock().unwrap() = Some(GatewayEndpoint { addr, hostport });
        let task = tokio::spawn(tls::serve(listener, cfg, gateway_router(self.clone())));
        *self.gateway_task.lock().unwrap() = Some(task);
        Ok(())
    }
}

// ---- the gateway-facing HTTP surface -----------------------------------------------------------------

#[derive(Debug)]
pub enum GwError {
    /// Deliberately uninformative: don't reveal whether a token exists, expired or was used.
    Unauthorized,
    Invalid(String),
    Internal(String),
}

impl From<anyhow::Error> for GwError {
    fn from(e: anyhow::Error) -> Self {
        GwError::Internal(format!("{e:#}"))
    }
}

impl IntoResponse for GwError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            GwError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            GwError::Invalid(m) => (StatusCode::UNPROCESSABLE_ENTITY, m),
            GwError::Internal(m) => {
                warn!("gateway request failed: {m}");
                (StatusCode::INTERNAL_SERVER_ERROR, m)
            }
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

type Ctl = Ax<Arc<Controller>>;

pub fn gateway_router(ctl: Arc<Controller>) -> Router {
    Router::new()
        .route("/gw/install/:token", get(h_script))
        .route("/gw/binary/:token/:arch", get(h_binary))
        .route("/gw/v1/enroll", post(h_enroll))
        .route("/gw/v1/sync", post(h_sync))
        .layer(DefaultBodyLimit::max(256 * 1024))
        .with_state(ctl)
}

async fn h_script(Ax(c): Ctl, Path(token): Path<String>) -> Result<Response, GwError> {
    let s = c.gw_install_script(&token)?;
    Ok(([(header::CONTENT_TYPE, "text/x-shellscript"), (header::CACHE_CONTROL, "no-store")], s).into_response())
}

async fn h_binary(Ax(c): Ctl, Path((token, arch)): Path<(String, String)>) -> Result<Response, GwError> {
    let b = c.gw_binary(&token, &arch).await?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream"), (header::CACHE_CONTROL, "no-store")], b).into_response())
}

async fn h_enroll(Ax(c): Ctl, Json(req): Json<EnrolReq>) -> Result<Json<EnrolResp>, GwError> {
    Ok(Json(c.gw_enrol(req)?))
}

async fn h_sync(Ax(c): Ctl, headers: HeaderMap, Json(req): Json<SyncReq>) -> Result<Json<SyncResp>, GwError> {
    let secret = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).ok_or(GwError::Unauthorized)?;
    Ok(Json(c.gw_sync(secret, req)?))
}

// ---- the installer served to a gateway machine -----------------------------------------------------------

const INSTALL_SH: &str = r#"#!/bin/sh
# edge-lb gateway installer, served by your controller. Safe to run again.
set -eu
HOST='@HOST@'
TOKEN='@TOKEN@'
PIN='@PIN@'
DIR=/var/lib/edge-lb-gateway
log() { printf 'edge-lb: %s\n' "$*" >&2; }
[ "$(id -u)" -eq 0 ] || { log "run as root:  curl ... | sudo sh"; exit 1; }
for c in systemctl curl sha256sum; do command -v "$c" >/dev/null 2>&1 || { log "$c is required"; exit 1; }; done
case "$(uname -m)" in
@BINARIES@
  *) log "this controller has no gateway binary for $(uname -m)"; exit 1 ;;
esac

if ! command -v wg >/dev/null 2>&1 || ! command -v nft >/dev/null 2>&1 || ! command -v ip >/dev/null 2>&1; then
  log "installing wireguard-tools, nftables and iproute2"
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools nftables iproute2 >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q wireguard-tools nftables iproute >/dev/null
  else
    log "install wireguard-tools, nftables and iproute2, then run this again"; exit 1
  fi
fi
modprobe wireguard >/dev/null 2>&1 || true
if ! ip link add edgelb-probe type wireguard >/dev/null 2>&1; then
  log "this machine can't create WireGuard interfaces. Unprivileged LXC containers usually can't: use a VM or a privileged container with the wireguard module loaded on the host"
  exit 1
fi
ip link del edgelb-probe >/dev/null 2>&1 || true

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
log "downloading the gateway binary (certificate pinned)"
curl -fsS -k --pinnedpubkey "$PIN" -o "$tmp/edge-lbd" "https://$HOST/gw/binary/$TOKEN/$ARCH"
echo "$BINSHA  $tmp/edge-lbd" | sha256sum -c - >/dev/null 2>&1 || { log "the downloaded binary does not match what the controller advertised"; exit 1; }
install -d -m 0755 /usr/local/bin
install -m 0755 "$tmp/edge-lbd" /usr/local/bin/edge-lbd.new
mv -f /usr/local/bin/edge-lbd.new /usr/local/bin/edge-lbd

install -d -m 0700 "$DIR"
( umask 077; printf '%s\n' "$TOKEN" > "$DIR/enrol-token" )
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-edge-lb-gateway.conf
sysctl -q -p /etc/sysctl.d/99-edge-lb-gateway.conf >/dev/null 2>&1 || sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || log "could not enable IP forwarding; set net.ipv4.ip_forward=1"

cat > /etc/systemd/system/edge-lb-gateway.service <<'UNIT'
[Unit]
Description=edge-lb gateway
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/edge-lbd gateway --controller @HOST@ --pin @FP@ --data-dir /var/lib/edge-lb-gateway
Restart=always
RestartSec=3
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/edge-lb-gateway
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable edge-lb-gateway >/dev/null 2>&1
systemctl restart edge-lb-gateway

i=0
while [ "$i" -lt 30 ]; do
  [ -s "$DIR/identity.json" ] && [ ! -e "$DIR/enrol-token" ] && break
  sleep 1; i=$((i+1))
done
if [ -s "$DIR/identity.json" ] && [ ! -e "$DIR/enrol-token" ]; then
  log "gateway enrolled. It now appears in the controller; add routes for this site there."
else
  journalctl -u edge-lb-gateway -n 15 --no-pager >&2 || true
  log "the gateway did not enrol; see the log above"
  exit 1
fi
"#;

/// `bins` is one `(architecture, sha256 of that binary)` per CPU the controller can serve.
pub fn render_install_script(hostport: &str, token: &str, pin: &str, fp: &str, bins: &[(&str, String)]) -> anyhow::Result<String> {
    let hexn = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit());
    anyhow::ensure!(valid_hostport(hostport), "unsafe controller address");
    anyhow::ensure!(hexn(token, 64) && hexn(fp, 64), "unsafe token or fingerprint");
    anyhow::ensure!(!bins.is_empty(), "no binaries to serve");
    anyhow::ensure!(
        pin.strip_prefix("sha256//").is_some_and(|b| b.len() == 44 && b.bytes().all(|c| c.is_ascii_alphanumeric() || b"+/=".contains(&c))),
        "unsafe pin"
    );
    // One `case` branch per architecture. Only canonical names and hex digests can get in here.
    let mut arms = Vec::new();
    for (arch, sha) in bins {
        anyhow::ensure!(super::agents::normalize_arch(arch) == Some(*arch) && hexn(sha, 64), "unsafe binary entry");
        let uname = if *arch == super::agents::AARCH64 { "aarch64|arm64" } else { "x86_64|amd64" };
        arms.push(format!("  {uname}) ARCH={arch}; BINSHA={sha} ;;"));
    }
    Ok(INSTALL_SH
        .replace("@BINARIES@", &arms.join("\n"))
        .replace("@HOST@", hostport)
        .replace("@TOKEN@", token)
        .replace("@PIN@", pin)
        .replace("@FP@", fp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostport_validation() {
        for ok in ["ctl.example.com", "ctl.example.com:7444", "203.0.113.5", "203.0.113.5:7444", "a-b.c"] {
            assert!(valid_hostport(ok), "{ok}");
        }
        for bad in ["", ":7444", "ctl.example.com:", "ctl.example.com:0", "ctl.example.com:99999", "-x.com", ".x", "a b", "a;b", "a'b", "a$(id)", "a/b", "[::1]:7444"] {
            assert!(!valid_hostport(bad), "{bad:?}");
        }
    }

    fn script() -> String {
        let c = pki::self_signed_controller().unwrap();
        render_install_script(
            "ctl.example.com:7444",
            &"ab".repeat(32),
            &pki::spki_pin(&c.key).unwrap(),
            &pki::fingerprint_pem(&c.cert).unwrap(),
            &[("x86_64", "cd".repeat(32)), ("aarch64", "ef".repeat(32))],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn install_script_is_valid_sh_with_everything_filled_in() {
        let s = script();
        assert!(!s.contains('@'), "unreplaced placeholder");
        for must in [
            "--pinnedpubkey \"$PIN\"",
            "sha256sum -c",
            "CapabilityBoundingSet=CAP_NET_ADMIN",
            "--controller ctl.example.com:7444",
            "x86_64|amd64) ARCH=x86_64;",
            "aarch64|arm64) ARCH=aarch64;",
            "/gw/binary/$TOKEN/$ARCH",
        ] {
            assert!(s.contains(must), "{must}");
        }
        let dir = std::env::temp_dir().join(format!("gwscript-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("install.sh");
        std::fs::write(&p, &s).unwrap();
        match tokio::process::Command::new("sh").arg("-n").arg(&p).output().await {
            Ok(out) => assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr)),
            // The script only ever runs on Linux; on Windows `sh` exists only with Git for Windows on PATH.
            Err(e) if cfg!(windows) => eprintln!("skipping the shell syntax check: no `sh` on PATH ({e})"),
            Err(e) => panic!("running sh: {e}"),
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn install_script_refuses_unsafe_values() {
        let c = pki::self_signed_controller().unwrap();
        let (pin, fp) = (pki::spki_pin(&c.key).unwrap(), pki::fingerprint_pem(&c.cert).unwrap());
        let (tok, sha) = ("ab".repeat(32), "cd".repeat(32));
        let ok = [("x86_64", sha.clone())];
        assert!(render_install_script("h:1", &tok, &pin, &fp, &ok).is_ok());
        assert!(render_install_script("h:1'; rm -rf /; '", &tok, &pin, &fp, &ok).is_err());
        assert!(render_install_script("h:1", &format!("{}'", &tok[..63]), &pin, &fp, &ok).is_err());
        assert!(render_install_script("h:1", &tok, "sha256//x'y", &fp, &ok).is_err());
        assert!(render_install_script("h:1", &tok, &pin, &fp, &[("x86; id", sha.clone())]).is_err());
        assert!(render_install_script("h:1", &tok, &pin, &fp, &[("x86_64", format!("{}'", &sha[..63]))]).is_err());
        assert!(render_install_script("h:1", &tok, &pin, &fp, &[]).is_err());
    }

    fn state() -> State {
        let mut s = State::fresh().unwrap();
        s.sites.push(Site { id: "home".into(), name: "Home".into(), lan_cidrs: vec!["192.168.1.0/24".into()], gateway: Gateway::default(), created_at: 0 });
        s
    }

    #[test]
    fn lan_range_checks() {
        let s = state();
        assert!(s.check_lan_ranges(None, &["192.168.2.0/24".into()]).is_empty());
        assert!(s.check_lan_ranges(Some("home"), &["192.168.1.0/24".into()]).is_empty(), "a site may keep its own ranges");
        let bad = |r: &[&str]| s.check_lan_ranges(None, &r.iter().map(|x| x.to_string()).collect::<Vec<_>>());
        assert!(!bad(&[]).is_empty(), "needs a range");
        assert!(!bad(&["192.168.1.0/25"]).is_empty(), "overlaps the other site");
        assert!(!bad(&["10.100.0.0/24"]).is_empty(), "overlaps the tunnel network");
        assert!(!bad(&["192.168.5.0/24", "192.168.5.0/25"]).is_empty(), "overlap inside one site");
        assert!(!bad(&["0.0.0.0/0"]).is_empty() && !bad(&["169.254.169.254/32"]).is_empty());
    }

    #[test]
    fn a_lan_range_may_not_contain_an_edges_public_ip() {
        let mut s = state();
        s.edges.push(edge("e1", Some("192.168.50.7")));
        assert!(!s.check_lan_ranges(None, &["192.168.50.0/24".into()]).is_empty());
        assert!(s.check_lan_ranges(None, &["192.168.51.0/24".into()]).is_empty());
    }

    pub(crate) fn edge(id: &str, ip: Option<&str>) -> Edge {
        Edge {
            id: id.into(),
            name: id.into(),
            region: String::new(),
            provider: ProviderSpec::Manual,
            server_id: None,
            ip: ip.map(|i| i.parse().unwrap()),
            ssh_user: "root".into(),
            ssh_port: 22,
            mgmt_port: 7443,
            mgmt_fingerprint: None,
            status: EdgeStatus::Healthy,
            error: None,
            created_at: 0,
            status_since: 0,
            applied_hash: None,
            attempts: 0,
            drain_started: None,
            log: vec![],
            tunnel_ip: None,
            wg_public_key: None,
        }
    }

    const K_EDGE: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const K_GW: &str = "gN8FfqbA3XQ2o6a0lYtB5g2f6Tn9m7yV1m0zq3K4s2A=";

    #[test]
    fn addresses_are_unique_stable_and_skip_the_network_address() {
        let mut s = state();
        s.edges.push(edge("e1", Some("203.0.113.1")));
        s.edges.push(edge("e2", Some("203.0.113.2")));
        assert!(s.needs_addresses() && s.assign_addresses() && !s.needs_addresses());
        let mut ips: Vec<_> = s.edges.iter().filter_map(|e| e.tunnel_ip).chain(s.sites[0].gateway.tunnel_ip).collect();
        assert_eq!(ips.len(), 3);
        ips.sort();
        ips.dedup();
        assert_eq!(ips.len(), 3, "no duplicates");
        assert!(!ips.contains(&"10.100.0.0".parse().unwrap()) && !ips.contains(&"10.100.0.255".parse().unwrap()));
        let before = s.edges[0].tunnel_ip;
        assert!(!s.assign_addresses(), "idempotent");
        assert_eq!(s.edges[0].tunnel_ip, before);
        // A freed address is reused, others never move.
        s.edges.remove(1);
        s.edges.push(edge("e3", Some("203.0.113.3")));
        s.assign_addresses();
        assert_eq!(s.edges[0].tunnel_ip, before);
    }

    #[test]
    fn address_pool_exhaustion_leaves_nodes_unaddressed_rather_than_duplicating() {
        let mut s = state();
        s.settings.wg_network = "10.100.0.0/27".into(); // 30 hosts
        for i in 0..40 {
            s.edges.push(edge(&format!("e{i}"), Some(&format!("203.0.113.{i}"))));
        }
        s.assign_addresses();
        let mut ips: Vec<_> = s.edges.iter().filter_map(|e| e.tunnel_ip).chain(s.sites[0].gateway.tunnel_ip).collect();
        assert_eq!(ips.len(), 30);
        ips.sort();
        ips.dedup();
        assert_eq!(ips.len(), 30);
    }

    #[test]
    fn desired_state_wires_edges_and_gateway_to_each_other() {
        let mut s = state();
        let mut e = edge("e1", Some("203.0.113.1"));
        e.wg_public_key = Some(K_EDGE.into());
        s.edges.push(e);
        s.edges.push(edge("no-wg", Some("203.0.113.2"))); // installed without WireGuard
        s.sites[0].gateway.public_key = Some(K_GW.into());
        s.assign_addresses();
        let (e, site) = (&s.edges[0], &s.sites[0]);

        let ed = s.wg_for_edge(e).unwrap();
        wg::validate(&ed).unwrap();
        assert_eq!(ed.listen_port, Some(51820));
        assert_eq!(ed.peers.len(), 1);
        assert_eq!(ed.peers[0].public_key, K_GW);
        assert_eq!(ed.peers[0].allowed_ips, vec![format!("{}/32", site.gateway.tunnel_ip.unwrap()), "192.168.1.0/24".to_string()]);
        assert!(ed.peers[0].endpoint.is_none(), "the gateway dials us");
        assert!(s.wg_for_edge(&s.edges[1]).is_none(), "an edge without WireGuard gets no tunnel");

        let gd = s.wg_for_gateway(site).unwrap();
        wg::validate(&gd).unwrap();
        assert_eq!(gd.peers.len(), 1, "only edges that have WireGuard");
        assert_eq!(gd.peers[0].endpoint.as_deref(), Some("203.0.113.1:51820"));
        assert_eq!(gd.peers[0].keepalive, Some(25));
        assert_eq!(gd.peers[0].allowed_ips, vec![format!("{}/32", e.tunnel_ip.unwrap())]);
        assert_eq!(gd.forward_to, vec!["192.168.1.0/24"]);
        assert_eq!(gd.listen_port, None);
    }

    #[test]
    fn an_unenrolled_gateway_adds_no_peer_to_edges() {
        let mut s = state();
        let mut e = edge("e1", Some("203.0.113.1"));
        e.wg_public_key = Some(K_EDGE.into());
        s.edges.push(e);
        s.assign_addresses();
        assert!(s.wg_for_edge(&s.edges[0]).unwrap().peers.is_empty());
    }

    #[test]
    fn edges_being_torn_down_leave_the_gateway() {
        let mut s = state();
        let mut e = edge("e1", Some("203.0.113.1"));
        e.wg_public_key = Some(K_EDGE.into());
        e.status = EdgeStatus::Deleting;
        s.edges.push(e);
        s.assign_addresses();
        assert!(s.wg_for_gateway(&s.sites[0]).unwrap().peers.is_empty());
    }

    #[test]
    fn tunnel_network_rules() {
        use super::super::model::parse_wg_network as p;
        assert!(p("10.100.0.0/24").is_ok() && p("172.31.0.0/16").is_ok() && p("100.64.8.0/22").is_ok() && p("100.96.0.0/16").is_ok());
        for bad in ["8.8.8.0/24", "10.0.0.0/8", "10.100.0.0/30", "10.100.0.5/24", "0.0.0.0/0"] {
            assert!(p(bad).is_err(), "{bad}");
        }
    }
}
