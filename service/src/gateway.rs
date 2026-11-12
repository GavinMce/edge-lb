//! The gateway: a small machine on the home network that dials *out* to every edge over
//! WireGuard and forwards tunnel traffic into the LAN. It never accepts a connection from the
//! internet, so CGNAT and closed router ports don't matter.
//!
//! It talks to the controller over TLS pinned to the controller's certificate, with no public CA:
//!
//! 1. **Enrol** once with a one-time token. The gateway generates its own WireGuard key and sends
//!    only the public half; the controller returns a long-lived secret.
//! 2. **Sync** every few seconds: report tunnel health, receive the desired tunnel config, apply it.
//!
//! If the controller is unreachable the gateway keeps its current tunnels (and re-applies its last
//! config after a reboot): the data path never depends on the controller being up.

use crate::wg::{self, Desired};
use crate::{pki, tls};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---- wire types shared with the controller ----------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrolReq {
    pub token: String,
    pub public_key: String,
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrolResp {
    pub secret: String,
    pub site: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    pub public_key: String,
    /// Seconds since the last completed handshake; `None` if there has never been one.
    pub age_secs: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SyncReq {
    #[serde(default)]
    pub version: String,
    /// The `hash` of the last config this gateway applied successfully.
    #[serde(default)]
    pub applied_hash: Option<String>,
    /// Why the last apply failed, if it did.
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub handshakes: Vec<Handshake>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncResp {
    /// Opaque; echoed back as `applied_hash` once applied.
    pub hash: String,
    pub desired: Desired,
}

// ---- how the gateway touches the host (replaceable in tests) --------------------------------------

#[async_trait]
pub trait HostWg: Send + Sync {
    /// Create the private key if needed and return the public key.
    async fn ensure_key(&self, path: &Path) -> Result<String>;
    async fn apply(&self, d: &Desired, key: &Path) -> Result<()>;
    async fn handshakes(&self) -> Vec<Handshake>;
    /// Send a tiny data packet into the tunnel towards each address (see `STALE_AFTER_SECS`).
    async fn probe(&self, targets: &[std::net::Ipv4Addr]);
}

/// A peer whose last handshake is older than this gets probed.
///
/// WireGuard's keepalives never make it re-handshake with a peer that silently lost its session
/// (an edge that rebooted): the gateway would keep sending into the void until its keys expire, up to
/// 180 s later. A *data* packet with no reply makes the kernel start a new handshake after ~15 s, so
/// we send one. A live peer answers it (an ICMP port-unreachable is enough) and nothing else happens.
pub const STALE_AFTER_SECS: u64 = 30;
/// The discard port. Nothing listens; the point is the packet, and the ICMP error that comes back.
const PROBE_PORT: u16 = 9;

/// The real thing: `wg`, `ip` and `nft`.
pub struct RealHost;

#[async_trait]
impl HostWg for RealHost {
    async fn ensure_key(&self, path: &Path) -> Result<String> {
        wg::ensure_key(path).await
    }

    async fn apply(&self, d: &Desired, key: &Path) -> Result<()> {
        wg::apply(d, key, wg::Role::Gateway).await
    }

    async fn handshakes(&self) -> Vec<Handshake> {
        wg::handshakes().await.into_iter().map(|(public_key, age_secs)| Handshake { public_key, age_secs }).collect()
    }

    async fn probe(&self, targets: &[std::net::Ipv4Addr]) {
        if let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            for t in targets {
                let _ = sock.send_to(&[0], (*t, PROBE_PORT)).await;
            }
        }
    }
}

/// Tunnel addresses of peers that haven't completed a handshake recently.
fn stale_peers(desired: &Desired, handshakes: &[Handshake]) -> Vec<std::net::Ipv4Addr> {
    desired
        .peers
        .iter()
        .filter(|p| handshakes.iter().find(|h| h.public_key == p.public_key).is_none_or(|h| h.age_secs.is_none_or(|a| a >= STALE_AFTER_SECS)))
        .filter_map(|p| p.allowed_ips.iter().find_map(|a| wg::Cidr::parse(a).ok().filter(|c| c.prefix == 32).map(|c| c.addr)))
        .collect()
}

// ---- the agent ---------------------------------------------------------------------------------

pub struct Options {
    /// `host:port` of the controller's gateway listener.
    pub controller: String,
    /// SHA-256 (hex) of the controller's certificate.
    pub pin: String,
    pub data_dir: PathBuf,
    pub interval: Duration,
    pub host: Arc<dyn HostWg>,
}

#[derive(Serialize, Deserialize)]
struct Identity {
    secret: String,
    site: String,
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn client(pin: &str) -> Result<reqwest::Client> {
    tls::init();
    let cfg = tls::pinned_client_config_no_auth(pin)?;
    reqwest::Client::builder()
        .use_preconfigured_tls(cfg)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| anyhow!("building HTTP client: {e}"))
}

enum Failure {
    /// The controller said no (bad token, unknown secret).
    Rejected(String),
    /// Couldn't talk to it; try again later.
    Unreachable(String),
}

async fn post<T: Serialize, R: for<'a> Deserialize<'a>>(c: &reqwest::Client, url: &str, bearer: Option<&str>, body: &T) -> std::result::Result<R, Failure> {
    let mut req = c.post(url).json(body);
    if let Some(b) = bearer {
        req = req.bearer_auth(b);
    }
    let resp = req.send().await.map_err(|e| {
        let mut s = e.to_string();
        let mut cur = std::error::Error::source(&e);
        while let Some(c) = cur {
            s.push_str(&format!(": {c}"));
            cur = c.source();
        }
        Failure::Unreachable(s)
    })?;
    let status = resp.status();
    if status.is_success() {
        return resp.json().await.map_err(|e| Failure::Unreachable(format!("bad response: {e}")));
    }
    let text = resp.text().await.unwrap_or_default();
    let msg = serde_json::from_str::<serde_json::Value>(&text).ok().and_then(|v| v["error"].as_str().map(String::from)).unwrap_or(text);
    if status.is_client_error() {
        Err(Failure::Rejected(format!("HTTP {status}: {msg}")))
    } else {
        Err(Failure::Unreachable(format!("HTTP {status}: {msg}")))
    }
}

/// Run until cancelled. Enrols first if an enrolment token is waiting in the data directory.
pub async fn run(opts: Options) -> Result<()> {
    std::fs::create_dir_all(&opts.data_dir).with_context(|| format!("creating {}", opts.data_dir.display()))?;
    let (key_path, id_path, token_path, last_path) = (
        opts.data_dir.join("wg.key"),
        opts.data_dir.join("identity.json"),
        opts.data_dir.join("enrol-token"),
        opts.data_dir.join("desired.json"),
    );
    let http = client(&opts.pin)?;
    let base = format!("https://{}", opts.controller);
    let public_key = opts.host.ensure_key(&key_path).await?;

    // A token file means "enrol now" — also when already enrolled, which is how re-enrolment works.
    let mut identity: Option<Identity> = std::fs::read(&id_path).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let mut warned = false;
    while token_path.exists() {
        let token = std::fs::read_to_string(&token_path).unwrap_or_default().trim().to_string();
        let req = EnrolReq { token, public_key: public_key.clone(), version: VERSION.into() };
        match post::<_, EnrolResp>(&http, &format!("{base}/gw/v1/enroll"), None, &req).await {
            Ok(r) => {
                write_private(&id_path, &serde_json::to_vec(&Identity { secret: r.secret.clone(), site: r.site.clone() })?)?;
                let _ = std::fs::remove_file(&token_path);
                info!("enrolled with the controller as the gateway for site '{}'", r.site);
                identity = Some(Identity { secret: r.secret, site: r.site });
            }
            Err(Failure::Rejected(m)) => {
                let _ = std::fs::remove_file(&token_path);
                error!("the controller rejected the enrolment token ({m}). It may have expired or been used; create a new one in the UI");
            }
            Err(Failure::Unreachable(m)) => {
                if !warned {
                    warn!("cannot reach the controller to enrol yet ({m}); retrying");
                    warned = true;
                }
                tokio::time::sleep(opts.interval).await;
            }
        }
    }
    let Some(identity) = identity else {
        bail!("this gateway is not enrolled and has no enrolment token; create one for the site in the controller UI");
    };

    // After a reboot, bring the tunnels back from the last known config without waiting for the controller.
    let mut applied_hash: Option<String> = None;
    if let Some(d) = std::fs::read(&last_path).ok().and_then(|b| serde_json::from_slice::<Desired>(&b).ok()) {
        match opts.host.apply(&d, &key_path).await {
            Ok(()) => info!("restored the last known tunnel config ({} peer(s))", d.peers.len()),
            Err(e) => warn!("could not restore the last tunnel config: {e:#}"),
        }
    }

    let mut last_error: Option<String> = None;
    let mut reachable = true;
    let mut rejected = false;
    let mut current: Option<Desired> = std::fs::read(&last_path).ok().and_then(|b| serde_json::from_slice(&b).ok());
    loop {
        let handshakes = opts.host.handshakes().await;
        if let Some(d) = &current {
            let stale = stale_peers(d, &handshakes);
            if !stale.is_empty() {
                opts.host.probe(&stale).await;
            }
        }
        let req = SyncReq { version: VERSION.into(), applied_hash: applied_hash.clone(), error: last_error.clone(), handshakes };
        match post::<_, SyncResp>(&http, &format!("{base}/gw/v1/sync"), Some(&identity.secret), &req).await {
            Ok(resp) => {
                if !reachable || rejected {
                    info!("connected to the controller again");
                }
                reachable = true;
                rejected = false;
                if applied_hash.as_deref() != Some(resp.hash.as_str()) || last_error.is_some() {
                    match opts.host.apply(&resp.desired, &key_path).await {
                        Ok(()) => {
                            info!("applied tunnel config: {} peer(s), forwarding to {}", resp.desired.peers.len(), resp.desired.forward_to.join(", "));
                            let _ = write_private(&last_path, &serde_json::to_vec(&resp.desired)?);
                            current = Some(resp.desired.clone());
                            applied_hash = Some(resp.hash);
                            last_error = None;
                        }
                        Err(e) => {
                            let m = format!("{e:#}");
                            if last_error.as_deref() != Some(&m) {
                                error!("could not apply the tunnel config: {m}");
                            }
                            last_error = Some(m);
                        }
                    }
                }
            }
            Err(Failure::Rejected(m)) => {
                if !rejected {
                    error!("the controller no longer accepts this gateway ({m}); it was probably re-enrolled elsewhere or the site was deleted. Tunnels are left as they are");
                }
                rejected = true;
            }
            Err(Failure::Unreachable(m)) => {
                if reachable {
                    warn!("cannot reach the controller ({m}); keeping the current tunnels and retrying");
                }
                reachable = false;
            }
        }
        tokio::time::sleep(opts.interval).await;
    }
}

/// `--pin` accepts the certificate fingerprint exactly as the controller prints it.
pub fn valid_pin(p: &str) -> bool {
    p.len() == 64 && p.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn fingerprint_of(cert_pem: &str) -> Result<String> {
    pki::fingerprint_pem(cert_pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "gN8FfqbA3XQ2o6a0lYtB5g2f6Tn9m7yV1m0zq3K4s2A=";
    const K2: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";

    fn desired() -> Desired {
        let peer = |k: &str, ip: &str| wg::Peer { public_key: k.into(), allowed_ips: vec![ip.into()], endpoint: None, keepalive: None };
        Desired { address: "10.100.0.9/24".into(), listen_port: None, peers: vec![peer(K1, "10.100.0.1/32"), peer(K2, "10.100.0.2/32")], forward_to: vec![] }
    }

    #[test]
    fn only_peers_without_a_fresh_handshake_are_probed() {
        let hs = |a: Option<u64>, b: Option<u64>| vec![Handshake { public_key: K1.into(), age_secs: a }, Handshake { public_key: K2.into(), age_secs: b }];
        let ips = |v: Vec<std::net::Ipv4Addr>| v.iter().map(|i| i.to_string()).collect::<Vec<_>>();
        assert!(stale_peers(&desired(), &hs(Some(3), Some(29))).is_empty(), "fresh tunnels are left alone");
        assert_eq!(ips(stale_peers(&desired(), &hs(Some(3), Some(30)))), ["10.100.0.2"]);
        assert_eq!(ips(stale_peers(&desired(), &hs(None, Some(5)))), ["10.100.0.1"], "never handshaken");
        assert_eq!(ips(stale_peers(&desired(), &[])), ["10.100.0.1", "10.100.0.2"], "no information at all");
    }

    #[test]
    fn pins_are_the_hex_fingerprint() {
        assert!(valid_pin(&"ab".repeat(32)));
        for bad in ["", "ab", &"zz".repeat(32), &"ab".repeat(33)] {
            assert!(!valid_pin(bad));
        }
    }
}
