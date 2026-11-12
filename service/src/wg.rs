//! WireGuard: the desired-state type shared by controller, edge and gateway, strict validation,
//! config rendering, and the code that applies it to the host with `wg`, `ip` and `nft`.
//!
//! Private keys never leave the machine that generated them. A desired state only ever holds
//! public keys; the private key is read from a root-only file at apply time and piped to `wg`
//! over stdin, so it is never written anywhere else or put on a command line.
//!
//! Everything that reaches a root process is validated here first: keys, addresses and CIDRs are
//! parsed into typed values and re-rendered, never interpolated as received.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Name of the WireGuard interface. Deliberately not `wg0`, so we never collide with one the
/// machine's owner already has.
pub const IFACE: &str = "wg-edge";
pub const DEFAULT_PORT: u16 = 51820;
/// WireGuard's default of 1420 stalls large responses behind PPPoE and IPv6 underlays.
pub const MTU: u32 = 1380;
pub const GATEWAY_NFT_TABLE: &str = "edge_lb_gw";
pub const MAX_PEERS: usize = 256;
pub const MAX_ALLOWED_IPS: usize = 32;

// ---- CIDRs ---------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Cidr, String> {
        let (a, p) = s.trim().split_once('/').ok_or_else(|| format!("'{s}' must look like 192.168.1.0/24"))?;
        let addr: Ipv4Addr = a.parse().map_err(|_| format!("'{a}' is not an IPv4 address"))?;
        let prefix: u8 = p.parse().map_err(|_| format!("'{p}' is not a prefix length"))?;
        if prefix > 32 {
            return Err(format!("prefix length /{prefix} is out of range"));
        }
        Ok(Cidr { addr, prefix })
    }

    pub fn host(addr: Ipv4Addr) -> Cidr {
        Cidr { addr, prefix: 32 }
    }

    fn mask(self) -> u32 {
        if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) }
    }

    pub fn network(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) & self.mask())
    }

    pub fn is_canonical(self) -> bool {
        self.network() == self.addr
    }

    pub fn contains(self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.network())
    }

    pub fn contains_cidr(self, o: Cidr) -> bool {
        o.prefix >= self.prefix && self.contains(o.network())
    }

    pub fn overlaps(self, o: Cidr) -> bool {
        self.contains_cidr(o) || o.contains_cidr(self)
    }

    /// First and last usable host addresses (the whole range for /31 and /32).
    pub fn host_range(self) -> (u32, u32) {
        let n = u32::from(self.network());
        let size = 1u64 << (32 - self.prefix as u64);
        let last = (n as u64 + size - 1) as u32;
        if self.prefix >= 31 { (n, last) } else { (n + 1, last - 1) }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Ranges that must never be routed through a tunnel: this host, loopback, link-local (cloud
/// metadata lives at 169.254.169.254), multicast and reserved space.
fn forbidden(c: Cidr) -> Option<&'static str> {
    const BAD: [(&str, [u8; 4], u8); 4] = [
        ("this-network (0.0.0.0/8)", [0, 0, 0, 0], 8),
        ("loopback (127.0.0.0/8)", [127, 0, 0, 0], 8),
        ("link-local (169.254.0.0/16)", [169, 254, 0, 0], 16),
        ("multicast and reserved (224.0.0.0/3)", [224, 0, 0, 0], 3),
    ];
    BAD.iter().find(|(_, o, p)| Cidr { addr: Ipv4Addr::from(*o), prefix: *p }.overlaps(c)).map(|(n, _, _)| *n)
}

/// A LAN range a site exposes: canonical, at least a /8 (so nobody routes "the internet"),
/// and not one of the forbidden ranges.
pub fn parse_lan(s: &str) -> Result<Cidr, String> {
    let c = Cidr::parse(s)?;
    if !c.is_canonical() {
        return Err(format!("'{s}' has host bits set; did you mean {}/{}?", c.network(), c.prefix));
    }
    if c.prefix < 8 {
        return Err(format!("'{s}' is too broad (the smallest allowed prefix is /8)"));
    }
    if let Some(n) = forbidden(c) {
        return Err(format!("'{s}' overlaps {n}, which can't be routed through a tunnel"));
    }
    Ok(c)
}

// ---- keys ----------------------------------------------------------------------------------

/// A WireGuard key is 32 bytes in standard base64: 43 characters plus `=`, where the last data
/// character can only carry 4 bits.
pub fn is_key(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 44
        && b[43] == b'='
        && b[..43].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/')
        && b"AEIMQUYcgkosw048".contains(&b[42])
}

// ---- desired state -------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub public_key: String,
    /// What this peer may send us and what we route to it. Doubles as the routing table.
    pub allowed_ips: Vec<String>,
    /// `ip:port`. Absent for a peer that dials us (the gateway, from an edge's point of view).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Seconds. Keeps a NAT mapping open; set on the side that is behind NAT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Desired {
    /// Our tunnel address with the network prefix, e.g. `10.100.0.1/24`.
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    /// No peers means no tunnel: the interface is removed.
    pub peers: Vec<Peer>,
    /// Gateway only: the LAN ranges tunnel traffic may be forwarded into. Everything else
    /// arriving from the tunnel is dropped, so a compromised edge can reach only these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forward_to: Vec<String>,
}

impl Desired {
    pub fn hash(&self) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(serde_json::to_vec(self).unwrap_or_default()).iter().map(|b| format!("{b:02x}")).collect()
    }

    fn address_cidr(&self) -> Result<Cidr, String> {
        let c = Cidr::parse(&self.address)?;
        if !(8..=30).contains(&c.prefix) {
            return Err(format!("tunnel address {} must have a prefix between /8 and /30", self.address));
        }
        if forbidden(Cidr::host(c.addr)).is_some() || c.addr == c.network() {
            return Err(format!("tunnel address {} is not usable", self.address));
        }
        Ok(c)
    }
}

/// Every problem with a desired state, or `Ok` if it is safe to apply.
pub fn validate(d: &Desired) -> Result<(), Vec<String>> {
    let mut errs = Vec::new();
    let net = match d.address_cidr() {
        Ok(c) => Some(c),
        Err(e) => {
            errs.push(e);
            None
        }
    };
    if d.listen_port == Some(0) {
        errs.push("listen_port must be 1-65535".into());
    }
    if d.peers.len() > MAX_PEERS {
        errs.push(format!("too many peers (max {MAX_PEERS})"));
    }
    let mut keys = HashSet::new();
    let mut claimed: Vec<Cidr> = Vec::new();
    for p in &d.peers {
        let who = if is_key(&p.public_key) { format!("peer {}…", &p.public_key[..8]) } else { "a peer".to_string() };
        if !is_key(&p.public_key) {
            errs.push("a peer has a malformed public key".into());
        } else if !keys.insert(p.public_key.as_str()) {
            errs.push(format!("{who} is listed twice"));
        }
        if p.allowed_ips.is_empty() || p.allowed_ips.len() > MAX_ALLOWED_IPS {
            errs.push(format!("{who}: allowed_ips must have 1-{MAX_ALLOWED_IPS} entries"));
        }
        for s in &p.allowed_ips {
            let c = match Cidr::parse(s) {
                Ok(c) if c.is_canonical() && c.prefix >= 8 => c,
                Ok(_) => {
                    errs.push(format!("{who}: allowed IP '{s}' must be a canonical range of at least /8"));
                    continue;
                }
                Err(e) => {
                    errs.push(format!("{who}: {e}"));
                    continue;
                }
            };
            if let Some(n) = forbidden(c) {
                errs.push(format!("{who}: allowed IP '{s}' overlaps {n}"));
            }
            // A host inside the tunnel network is a peer's own address; anything else overlapping
            // the tunnel network would shadow it.
            if let Some(net) = net {
                if net.overlaps(c) && !(c.prefix == 32 && net.contains(c.addr)) {
                    errs.push(format!("{who}: allowed IP '{s}' overlaps the tunnel network {}/{}", net.network(), net.prefix));
                }
            }
            if let Some(o) = claimed.iter().find(|o| o.overlaps(c)) {
                errs.push(format!("allowed IP '{s}' overlaps '{o}', which belongs to another peer"));
            }
            claimed.push(c);
        }
        if let Some(e) = &p.endpoint {
            match e.parse::<SocketAddr>() {
                Ok(SocketAddr::V4(a)) if a.port() != 0 && !a.ip().is_unspecified() && !a.ip().is_multicast() && !a.ip().is_loopback() => {}
                _ => errs.push(format!("{who}: endpoint '{e}' must be an IPv4 address and port")),
            }
        }
        if p.keepalive.is_some_and(|k| k == 0 || k > 300) {
            errs.push(format!("{who}: keepalive must be 1-300 seconds"));
        }
    }
    for s in &d.forward_to {
        match parse_lan(s) {
            Ok(c) => {
                if let Some(net) = net {
                    if net.overlaps(c) {
                        errs.push(format!("forward range '{s}' overlaps the tunnel network"));
                    }
                }
            }
            Err(e) => errs.push(format!("forward range: {e}")),
        }
    }
    if errs.is_empty() { Ok(()) } else { Err(errs) }
}

// ---- rendering (pure; unit-tested) ------------------------------------------------------------

/// The native `wg` config for `wg syncconf`. Only validated values are interpolated.
pub fn render_conf(d: &Desired, private_key: &str) -> Result<String> {
    validate(d).map_err(|e| anyhow!("invalid WireGuard config: {}", e.join("; ")))?;
    if !is_key(private_key) {
        bail!("the private key is malformed");
    }
    let mut s = format!("[Interface]\nPrivateKey = {private_key}\n");
    if let Some(p) = d.listen_port {
        s.push_str(&format!("ListenPort = {p}\n"));
    }
    for p in &d.peers {
        s.push_str(&format!("\n[Peer]\nPublicKey = {}\nAllowedIPs = {}\n", p.public_key, p.allowed_ips.join(", ")));
        if let Some(e) = &p.endpoint {
            s.push_str(&format!("Endpoint = {e}\n"));
        }
        if let Some(k) = p.keepalive {
            s.push_str(&format!("PersistentKeepalive = {k}\n"));
        }
    }
    Ok(s)
}

/// Gateway firewall: its own table (never `flush ruleset`), replaced atomically.
///
/// * forward: tunnel traffic may go only to the declared LAN ranges.
/// * input: the tunnel may ping the gateway but not reach any service on it.
/// * postrouting: masquerade, because the edge connects from its tunnel address and LAN hosts
///   would otherwise reply through the router, which knows nothing about 10.100.x.x.
pub fn render_gateway_nft(d: &Desired) -> Result<String> {
    validate(d).map_err(|e| anyhow!("invalid WireGuard config: {}", e.join("; ")))?;
    let t = GATEWAY_NFT_TABLE;
    let lan: Vec<String> = d.forward_to.iter().map(|s| parse_lan(s).map(|c| c.to_string()).map_err(|e| anyhow!(e))).collect::<Result<_>>()?;
    let forward_rule = if lan.is_empty() {
        String::new()
    } else {
        format!("    iifname \"{IFACE}\" ip daddr {{ {} }} accept\n", lan.join(", "))
    };
    Ok(format!(
        "add table inet {t}\n\
         delete table inet {t}\n\
         table inet {t} {{\n\
         \x20 chain forward {{\n\
         \x20   type filter hook forward priority -10; policy accept;\n\
         {forward_rule}\
         \x20   iifname \"{IFACE}\" drop\n\
         \x20 }}\n\
         \x20 chain input {{\n\
         \x20   type filter hook input priority -10; policy accept;\n\
         \x20   iifname \"{IFACE}\" ct state established,related accept\n\
         \x20   iifname \"{IFACE}\" icmp type echo-request accept\n\
         \x20   iifname \"{IFACE}\" drop\n\
         \x20 }}\n\
         \x20 chain postrouting {{\n\
         \x20   type nat hook postrouting priority 100; policy accept;\n\
         \x20   iifname \"{IFACE}\" oifname != \"{IFACE}\" masquerade\n\
         \x20 }}\n\
         }}\n"
    ))
}

/// Routes the interface needs: every allowed range that isn't just a host inside the tunnel
/// network (that one is covered by the interface's own connected route).
pub fn desired_routes(d: &Desired) -> Result<Vec<Cidr>> {
    let net = d.address_cidr().map_err(|e| anyhow!(e))?;
    let mut out = Vec::new();
    for p in &d.peers {
        for s in &p.allowed_ips {
            let c = Cidr::parse(s).map_err(|e| anyhow!(e))?;
            if !(c.prefix == 32 && net.contains(c.addr)) {
                out.push(c);
            }
        }
    }
    out.sort_by_key(|c| (u32::from(c.addr), c.prefix));
    Ok(out)
}

// ---- running commands ---------------------------------------------------------------------------

async fn run(prog: &str, args: &[&str], stdin: Option<&str>) -> Result<String> {
    let mut cmd = Command::new(prog);
    cmd.args(args).stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow!("`{prog}` is not installed (needs wireguard-tools, iproute2 and, on a gateway, nftables)")
        } else {
            anyhow!("running {prog}: {e}")
        }
    })?;
    if let Some(input) = stdin {
        let mut w = child.stdin.take().ok_or_else(|| anyhow!("no stdin"))?;
        w.write_all(input.as_bytes()).await.ok();
        drop(w);
    }
    let out = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
        .await
        .map_err(|_| anyhow!("`{prog} {}` timed out", args.first().copied().unwrap_or("")))??;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("`{prog} {}` failed: {}", args.join(" "), err.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

async fn ip(args: &[&str]) -> Result<String> {
    run("ip", &[&["-4"], args].concat(), None).await
}

async fn iface_exists() -> bool {
    run("ip", &["link", "show", "dev", IFACE], None).await.is_ok()
}

/// Read the private key at `path`, creating it (mode 0600, via `wg genkey`) if it doesn't exist.
/// Returns the public key.
pub async fn ensure_key(path: &Path) -> Result<String> {
    use std::os::unix::fs::OpenOptionsExt;
    if !path.exists() {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let key = run("wg", &["genkey"], None).await?;
        let key = key.trim();
        if !is_key(key) {
            bail!("`wg genkey` returned something that isn't a key");
        }
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).with_context(|| format!("creating {}", path.display()))?;
        std::io::Write::write_all(&mut f, format!("{key}\n").as_bytes())?;
    }
    public_key(path).await
}

pub async fn public_key(path: &Path) -> Result<String> {
    let key = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let key = key.trim();
    if !is_key(key) {
        bail!("{} does not hold a WireGuard private key", path.display());
    }
    let publ = run("wg", &["pubkey"], Some(key)).await?;
    let publ = publ.trim().to_string();
    if !is_key(&publ) {
        bail!("`wg pubkey` returned something that isn't a key");
    }
    Ok(publ)
}

/// `(peer public key, seconds since last handshake)`; `None` if it has never completed one.
pub async fn handshakes() -> Vec<(String, Option<u64>)> {
    let Ok(out) = run("wg", &["show", IFACE, "latest-handshakes"], None).await else { return vec![] };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    out.lines()
        .filter_map(|l| {
            let (k, t) = l.split_once('\t')?;
            let t: u64 = t.trim().parse().ok()?;
            is_key(k).then(|| (k.to_string(), if t == 0 { None } else { Some(now.saturating_sub(t)) }))
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Edge,
    Gateway,
}

/// Make the host match `d`. Idempotent, and changes only what differs: peers are synced in place
/// (existing sessions survive), the address and routes are reconciled, and nothing outside our own
/// interface and nft table is touched.
pub async fn apply(d: &Desired, key_path: &Path, role: Role) -> Result<()> {
    if role == Role::Edge && !d.forward_to.is_empty() {
        bail!("an edge may not forward traffic");
    }
    if d.peers.is_empty() {
        return teardown(role).await;
    }
    validate(d).map_err(|e| anyhow!("refusing to apply: {}", e.join("; ")))?;
    let key = std::fs::read_to_string(key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let conf = render_conf(d, key.trim())?;
    let net = d.address_cidr().map_err(|e| anyhow!(e))?;

    if !iface_exists().await {
        run("ip", &["link", "add", "dev", IFACE, "type", "wireguard"], None)
            .await
            .context("creating the WireGuard interface (is the kernel module available? try `modprobe wireguard`)")?;
    }
    run("wg", &["syncconf", IFACE, "/dev/stdin"], Some(&conf)).await?;

    // Address: replace unless it's already exactly right.
    let want_addr = format!("{}/{}", d.address.split('/').next().unwrap_or(""), net.prefix);
    let have = ip(&["-o", "addr", "show", "dev", IFACE]).await?;
    let have_addrs: Vec<&str> = have.lines().filter_map(|l| l.split_whitespace().nth(3)).collect();
    if have_addrs != [want_addr.as_str()] {
        ip(&["addr", "flush", "dev", IFACE]).await?;
        ip(&["addr", "add", &want_addr, "dev", IFACE]).await?;
    }
    run("ip", &["link", "set", "dev", IFACE, "mtu", &MTU.to_string(), "up"], None).await?;

    // Routes: add what's missing, drop what is no longer wanted. The connected route for the
    // tunnel network is the kernel's and is left alone.
    let want: Vec<Cidr> = desired_routes(d)?;
    let routes = ip(&["-o", "route", "show", "dev", IFACE]).await?;
    let mut have_routes = Vec::new();
    for l in routes.lines() {
        if l.contains("proto kernel") {
            continue;
        }
        if let Some(Ok(c)) = l.split_whitespace().next().map(|d| Cidr::parse(&if d.contains('/') { d.to_string() } else { format!("{d}/32") })) {
            have_routes.push(c);
        }
    }
    for c in &want {
        if !have_routes.contains(c) {
            ip(&["route", "replace", &c.to_string(), "dev", IFACE]).await?;
        }
    }
    for c in &have_routes {
        if !want.contains(c) {
            ip(&["route", "del", &c.to_string(), "dev", IFACE]).await?;
        }
    }

    if role == Role::Gateway {
        enable_forwarding().await?;
        run("nft", &["-f", "-"], Some(&render_gateway_nft(d)?)).await?;
    }
    Ok(())
}

async fn enable_forwarding() -> Result<()> {
    const P: &str = "/proc/sys/net/ipv4/ip_forward";
    if std::fs::read_to_string(P).map(|s| s.trim() == "1").unwrap_or(false) {
        return Ok(());
    }
    std::fs::write(P, "1\n").with_context(|| format!("enabling IPv4 forwarding ({P}); set net.ipv4.ip_forward=1 in /etc/sysctl.d"))
}

/// Remove the interface (and the gateway's firewall table). Absent things are fine.
pub async fn teardown(role: Role) -> Result<()> {
    if iface_exists().await {
        run("ip", &["link", "del", "dev", IFACE], None).await?;
    }
    if role == Role::Gateway {
        let _ = run("nft", &["delete", "table", "inet", GATEWAY_NFT_TABLE], None).await;
    }
    Ok(())
}

// ---- the edge-side applier daemon ----------------------------------------------------------------

/// Run as root next to the unprivileged edge process: whenever the edge writes a new desired
/// state to `state`, validate it and apply it. This is the only privileged piece on an edge, and
/// all it will ever do is configure `wg-edge`.
pub async fn watch_and_apply(state: &Path, key: &Path, interval: Duration) -> Result<()> {
    let mut last: Option<String> = None;
    let mut failing = false;
    loop {
        match std::fs::metadata(state) {
            Ok(m) if m.is_file() && m.len() <= 1 << 20 => match std::fs::read(state) {
                Ok(bytes) => {
                    let sig = format!("{:x}", sha2_hash(&bytes));
                    if last.as_deref() != Some(&sig) || failing {
                        let result = match serde_json::from_slice::<Desired>(&bytes) {
                            Ok(d) => apply(&d, key, Role::Edge).await,
                            Err(e) => Err(anyhow!("{} is not a valid WireGuard state: {e}", state.display())),
                        };
                        match result {
                            Ok(()) => {
                                tracing::info!("applied WireGuard state {}", &sig[..12]);
                                failing = false;
                            }
                            Err(e) => {
                                if !failing {
                                    tracing::error!("could not apply WireGuard state: {e:#}");
                                }
                                failing = true;
                            }
                        }
                        last = Some(sig);
                    }
                }
                Err(e) => tracing::warn!("reading {}: {e}", state.display()),
            },
            _ => {}
        }
        tokio::time::sleep(interval).await;
    }
}

fn sha2_hash(b: &[u8]) -> u128 {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(b);
    u128::from_be_bytes(d[..16].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "gN8FfqbA3XQ2o6a0lYtB5g2f6Tn9m7yV1m0zq3K4s2A=";
    const K2: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";

    fn peer(key: &str, ips: &[&str]) -> Peer {
        Peer { public_key: key.into(), allowed_ips: ips.iter().map(|s| s.to_string()).collect(), endpoint: None, keepalive: None }
    }

    fn edge_side() -> Desired {
        Desired { address: "10.100.0.1/24".into(), listen_port: Some(51820), peers: vec![peer(K2, &["10.100.0.2/32", "192.168.1.0/24"])], forward_to: vec![] }
    }

    #[test]
    fn cidr_math() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(c.is_canonical() && c.contains("192.168.1.77".parse().unwrap()) && !c.contains("192.168.2.1".parse().unwrap()));
        assert!(!Cidr::parse("192.168.1.5/24").unwrap().is_canonical());
        assert!(c.overlaps(Cidr::parse("192.168.0.0/16").unwrap()) && !c.overlaps(Cidr::parse("192.168.2.0/24").unwrap()));
        assert_eq!(Cidr::parse("10.100.0.0/24").unwrap().host_range(), (u32::from(Ipv4Addr::new(10, 100, 0, 1)), u32::from(Ipv4Addr::new(10, 100, 0, 254))));
        assert!(Cidr::parse("1.2.3.4").is_err() && Cidr::parse("1.2.3.4/33").is_err() && Cidr::parse("x/24").is_err());
    }

    #[test]
    fn lan_ranges_are_restricted() {
        assert!(parse_lan("192.168.1.0/24").is_ok());
        assert!(parse_lan("10.0.0.0/8").is_ok());
        for bad in ["0.0.0.0/0", "0.0.0.0/1", "192.168.1.5/24", "127.0.0.0/8", "169.254.169.254/32", "169.254.0.0/16", "224.0.0.0/4", "8.0.0.0/7"] {
            assert!(parse_lan(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn key_format() {
        assert!(is_key(K1) && is_key(K2));
        for bad in ["", "short", &K1[..43], &format!("{K1}A"), "gN8FfqbA3XQ2o6a0lYtB5g2f6Tn9m7yV1m0zq3K4s2B=", "gN8FfqbA3XQ2o6a0lYtB5g2f6Tn9m7yV1m0zq3K4s\n=="] {
            assert!(!is_key(bad), "{bad:?}");
        }
    }

    #[test]
    fn valid_state_passes_and_renders() {
        let d = edge_side();
        validate(&d).unwrap();
        let conf = render_conf(&d, K1).unwrap();
        assert!(conf.contains("ListenPort = 51820"));
        assert!(conf.contains(&format!("PublicKey = {K2}")));
        assert!(conf.contains("AllowedIPs = 10.100.0.2/32, 192.168.1.0/24"));
        assert!(!conf.contains("Endpoint"));
        assert_eq!(desired_routes(&d).unwrap().iter().map(|c| c.to_string()).collect::<Vec<_>>(), ["192.168.1.0/24"]);
    }

    #[test]
    fn gateway_side_renders_endpoint_keepalive_and_firewall() {
        let d = Desired {
            address: "10.100.0.2/24".into(),
            listen_port: None,
            peers: vec![Peer { endpoint: Some("203.0.113.9:51820".into()), keepalive: Some(25), ..peer(K1, &["10.100.0.1/32"]) }],
            forward_to: vec!["192.168.1.0/24".into(), "192.168.2.0/24".into()],
        };
        validate(&d).unwrap();
        let conf = render_conf(&d, K2).unwrap();
        assert!(conf.contains("Endpoint = 203.0.113.9:51820") && conf.contains("PersistentKeepalive = 25") && !conf.contains("ListenPort"));
        let nft = render_gateway_nft(&d).unwrap();
        assert!(nft.contains("ip daddr { 192.168.1.0/24, 192.168.2.0/24 } accept"));
        assert!(nft.contains("masquerade") && nft.starts_with("add table inet edge_lb_gw\ndelete table inet edge_lb_gw\n"));
        // Anything else from the tunnel is dropped, in both forward and input.
        assert_eq!(nft.matches("iifname \"wg-edge\" drop").count(), 2);
    }

    #[test]
    fn nft_forwards_nothing_without_ranges() {
        let mut d = edge_side();
        d.peers[0].allowed_ips = vec!["10.100.0.2/32".into()];
        let nft = render_gateway_nft(&d).unwrap();
        assert!(!nft.contains("ip daddr"));
    }

    #[test]
    fn rejects_hostile_or_broken_input() {
        type Mutation = Box<dyn Fn(&mut Desired)>;
        let cases: Vec<(&str, Mutation)> = vec![
            ("default route", Box::new(|d| d.peers[0].allowed_ips.push("0.0.0.0/0".into()))),
            ("metadata service", Box::new(|d| d.peers[0].allowed_ips.push("169.254.169.254/32".into()))),
            ("loopback", Box::new(|d| d.peers[0].allowed_ips = vec!["127.0.0.0/8".into()])),
            ("overlaps tunnel net", Box::new(|d| d.peers[0].allowed_ips = vec!["10.100.0.0/16".into()])),
            ("no allowed ips", Box::new(|d| d.peers[0].allowed_ips.clear())),
            ("bad key", Box::new(|d| d.peers[0].public_key = "abc\nPostUp = rm -rf /".into())),
            ("duplicate peer", Box::new(|d| d.peers.push(d.peers[0].clone()))),
            ("overlapping peers", Box::new(|d| d.peers.push(peer(K1, &["192.168.1.0/25"])))),
            ("bad endpoint", Box::new(|d| d.peers[0].endpoint = Some("example.com:51820".into()))),
            ("loopback endpoint", Box::new(|d| d.peers[0].endpoint = Some("127.0.0.1:51820".into()))),
            ("zero keepalive", Box::new(|d| d.peers[0].keepalive = Some(0))),
            ("bad address", Box::new(|d| d.address = "10.100.0.1".into())),
            ("network address", Box::new(|d| d.address = "10.100.0.0/24".into())),
            ("huge prefix", Box::new(|d| d.address = "10.100.0.1/31".into())),
            ("zero port", Box::new(|d| d.listen_port = Some(0))),
            ("forward overlaps tunnel", Box::new(|d| d.forward_to = vec!["10.100.0.0/24".into()])),
            ("forward default", Box::new(|d| d.forward_to = vec!["0.0.0.0/0".into()])),
        ];
        for (name, mutate) in cases {
            let mut d = edge_side();
            mutate(&mut d);
            assert!(validate(&d).is_err(), "{name} should be rejected");
            assert!(render_conf(&d, K1).is_err(), "{name} must not render");
        }
        assert!(render_conf(&edge_side(), "not a key").is_err());
    }

    #[test]
    fn json_roundtrip_and_hash_stability() {
        let d = edge_side();
        let back: Desired = serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert_eq!(d, back);
        assert_eq!(d.hash(), back.hash());
        let mut e = d.clone();
        e.peers[0].allowed_ips.push("192.168.5.0/24".into());
        assert_ne!(d.hash(), e.hash());
        // Unknown fields from a newer controller are ignored rather than fatal.
        let _: Desired = serde_json::from_str(r#"{"address":"10.100.0.1/24","peers":[],"future":1}"#).unwrap();
    }
}
