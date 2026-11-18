//! The data plane: accept, (maybe) sniff the hostname, pick a target, forward bytes.

use crate::accesslog::{AccessLog, Closed, Outcome};
use crate::config::{domain_matches, Route};
use crate::sniff::{sniff, Sniffed};
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, warn};

const MAX_PEEK: usize = 16 * 1024;

#[derive(Clone)]
pub struct Tunables {
    /// How long to wait for a client to send enough bytes to identify the hostname.
    pub peek_timeout: Duration,
    pub connect_timeout: Duration,
    /// Where each finished connection is written down.
    pub log: Arc<AccessLog>,
}

/// One connection's entry in the access log. It is written when this is dropped, so every way out
/// of `handle_conn` (including a task being cancelled) leaves exactly one record.
struct ConnLog {
    log: Arc<AccessLog>,
    started: Instant,
    client: IpAddr,
    port: u16,
    route: Option<String>,
    host: Option<String>,
    target: Option<String>,
    outcome: Outcome,
    up: AtomicU64,
    down: AtomicU64,
}

impl ConnLog {
    fn new(log: Arc<AccessLog>, client: IpAddr, port: u16) -> Self {
        Self { log, started: Instant::now(), client, port, route: None, host: None, target: None, outcome: Outcome::Aborted, up: AtomicU64::new(0), down: AtomicU64::new(0) }
    }
}

impl Drop for ConnLog {
    fn drop(&mut self) {
        self.log.record(Closed {
            client: self.client,
            port: self.port,
            route: self.route.take(),
            host: self.host.take(),
            target: self.target.take(),
            outcome: self.outcome,
            bytes_up: self.up.load(Relaxed),
            bytes_down: self.down.load(Relaxed),
            duration_ms: self.started.elapsed().as_millis() as u64,
        });
    }
}

pub struct TargetState {
    pub addr: SocketAddr,
    healthy: AtomicBool,
    last_error: Mutex<Option<String>>,
}

impl TargetState {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr, healthy: AtomicBool::new(true), last_error: Mutex::new(None) }
    }
    pub fn healthy(&self) -> bool {
        self.healthy.load(Relaxed)
    }
    pub fn set(&self, ok: bool, err: Option<String>) {
        self.healthy.store(ok, Relaxed);
        *self.last_error.lock().unwrap() = if ok { None } else { err };
    }
    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }
}

#[derive(Default)]
pub struct RouteStats {
    pub active: AtomicI64,
    pub total: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub connect_failures: AtomicU64,
}

struct ActiveGuard(Arc<RouteStats>);
impl ActiveGuard {
    fn new(s: &Arc<RouteStats>) -> Self {
        s.active.fetch_add(1, Relaxed);
        s.total.fetch_add(1, Relaxed);
        Self(s.clone())
    }
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Relaxed);
    }
}

pub struct RouteRt {
    pub route: Route,
    pub stats: Arc<RouteStats>,
    pub targets: Vec<Arc<TargetState>>,
    rr: AtomicUsize,
}

impl RouteRt {
    pub fn new(route: Route, stats: Arc<RouteStats>, targets: Vec<Arc<TargetState>>) -> Self {
        Self { route, stats, targets, rr: AtomicUsize::new(0) }
    }

    /// Targets to try, in order: round-robin start, healthy ones first, unhealthy last
    /// (so that a wrongly-failing health check never blackholes a route).
    fn attempt_order(&self) -> Vec<Arc<TargetState>> {
        let n = self.targets.len();
        if n == 0 {
            return Vec::new();
        }
        let start = self.rr.fetch_add(1, Relaxed) % n;
        let rotated = (0..n).map(|i| self.targets[(start + i) % n].clone());
        let (mut up, down): (Vec<_>, Vec<_>) = rotated.partition(|t| t.healthy());
        up.extend(down);
        up
    }
}

/// Everything one listening socket needs to route a connection.
pub struct Table {
    pub routes: Vec<Arc<RouteRt>>,
    /// True if any route filters on domain, so connections must be sniffed first.
    pub needs_sniff: bool,
}

impl Table {
    pub fn new(routes: Vec<Arc<RouteRt>>) -> Self {
        let needs_sniff = routes.iter().any(|r| !r.route.domains.is_empty());
        Self { routes, needs_sniff }
    }

    /// Exact domain beats wildcard (longest suffix first), which beats the catch-all.
    pub fn resolve(&self, host: Option<&str>) -> Option<Arc<RouteRt>> {
        if let Some(host) = host {
            if let Some(r) = self
                .routes
                .iter()
                .find(|r| r.route.domains.iter().any(|d| !d.starts_with("*.") && d == host))
            {
                return Some(r.clone());
            }
            let mut best: Option<(usize, &Arc<RouteRt>)> = None;
            for r in &self.routes {
                for d in r.route.domains.iter().filter(|d| d.starts_with("*.")) {
                    if domain_matches(d, host) && best.is_none_or(|(l, _)| d.len() > l) {
                        best = Some((d.len(), r));
                    }
                }
            }
            if let Some((_, r)) = best {
                return Some(r.clone());
            }
        }
        self.routes.iter().find(|r| r.route.domains.is_empty()).cloned()
    }
}

/// PROXY protocol v2 header (PROXY command, TCP).
pub fn proxy_v2_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    fn v6(ip: IpAddr) -> Ipv6Addr {
        match ip {
            IpAddr::V4(v) => v.to_ipv6_mapped(),
            IpAddr::V6(v) => v,
        }
    }
    let mut h = Vec::with_capacity(52);
    h.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
    h.push(0x21);
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            h.push(0x11);
            h.extend(12u16.to_be_bytes());
            h.extend(s.octets());
            h.extend(d.octets());
        }
        (s, d) => {
            h.push(0x21);
            h.extend(36u16.to_be_bytes());
            h.extend(v6(s).octets());
            h.extend(v6(d).octets());
        }
    }
    h.extend(src.port().to_be_bytes());
    h.extend(dst.port().to_be_bytes());
    h
}

async fn peek(c: &mut TcpStream, head: &mut Vec<u8>) -> io::Result<Option<String>> {
    let mut buf = [0u8; 4096];
    loop {
        let n = c.read(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        head.extend_from_slice(&buf[..n]);
        match sniff(head) {
            Sniffed::Host(h) => return Ok(Some(h)),
            Sniffed::NoHost | Sniffed::Unknown => return Ok(None),
            Sniffed::NeedMore if head.len() >= MAX_PEEK => return Ok(None),
            Sniffed::NeedMore => {}
        }
    }
}

fn keepalive(s: &TcpStream) {
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(20));
    let _ = socket2::SockRef::from(s).set_tcp_keepalive(&ka);
}

/// Copy until EOF, counting bytes both on the route (`total`) and on this one connection (`mine`).
async fn pump<R, W>(mut r: R, mut w: W, total: &AtomicU64, mine: &AtomicU64) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n]).await?;
        total.fetch_add(n as u64, Relaxed);
        mine.fetch_add(n as u64, Relaxed);
    }
    w.shutdown().await
}

pub async fn handle_conn(mut client: TcpStream, peer: SocketAddr, tbl: Arc<Table>, t: Tunables) {
    let local = client.local_addr().unwrap_or(peer);
    let _ = client.set_nodelay(true);
    // Written to the access log when this function ends, however it ends.
    let mut cl = ConnLog::new(t.log.clone(), peer.ip(), local.port());

    let mut head = Vec::new();
    let mut host = None;
    if tbl.needs_sniff {
        // A timeout leaves whatever was read in `head`; we route it as "no hostname".
        if let Ok(res) = timeout(t.peek_timeout, peek(&mut client, &mut head)).await {
            match res {
                Ok(h) => host = h,
                Err(_) => return,
            }
        }
    }
    cl.host = host.clone();
    let Some(rt) = tbl.resolve(host.as_deref()) else {
        debug!(%peer, ?host, "no matching route; closing");
        // If nothing arrived at all the client never asked for anything (a port probe, say).
        cl.outcome = if head.is_empty() { Outcome::Aborted } else { Outcome::NoRoute };
        return;
    };
    cl.route = Some(rt.route.id.clone());

    let _active = ActiveGuard::new(&rt.stats);
    let mut upstream = None;
    for tg in rt.attempt_order() {
        cl.target = Some(tg.addr.to_string());
        match timeout(t.connect_timeout, TcpStream::connect(tg.addr)).await {
            Ok(Ok(s)) => {
                upstream = Some(s);
                break;
            }
            Ok(Err(e)) => {
                tg.set(false, Some(e.to_string()));
                rt.stats.connect_failures.fetch_add(1, Relaxed);
            }
            Err(_) => {
                tg.set(false, Some("connect timed out".into()));
                rt.stats.connect_failures.fetch_add(1, Relaxed);
            }
        }
    }
    let Some(mut up) = upstream else {
        warn!(route = %rt.route.id, %peer, "all targets unreachable");
        cl.outcome = Outcome::Unreachable;
        return;
    };
    cl.outcome = Outcome::Ok;
    let _ = up.set_nodelay(true);
    keepalive(&client);
    keepalive(&up);

    if rt.route.proxy_protocol && up.write_all(&proxy_v2_header(peer, local)).await.is_err() {
        return;
    }
    if !head.is_empty() {
        if up.write_all(&head).await.is_err() {
            return;
        }
        rt.stats.bytes_up.fetch_add(head.len() as u64, Relaxed);
        cl.up.fetch_add(head.len() as u64, Relaxed);
    }

    let (cr, cw) = client.into_split();
    let (ur, uw) = up.into_split();
    let _ = tokio::try_join!(pump(cr, uw, &rt.stats.bytes_up, &cl.up), pump(ur, cw, &rt.stats.bytes_down, &cl.down));
}

/// Run the accept loop for one bound socket. Routes can be swapped live via the watch channel.
pub fn spawn_listener(
    l: TcpListener,
    rx: watch::Receiver<Arc<Table>>,
    t: Tunables,
    sem: Arc<Semaphore>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match l.accept().await {
                Ok((s, peer)) => {
                    let Ok(permit) = sem.clone().try_acquire_owned() else {
                        debug!(%peer, "connection limit reached; dropping");
                        continue;
                    };
                    let tbl = rx.borrow().clone();
                    let t = t.clone();
                    tokio::spawn(async move {
                        handle_conn(s, peer, tbl, t).await;
                        drop(permit);
                    });
                }
                Err(e) => {
                    warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_header_v4_layout() {
        let h = proxy_v2_header("203.0.113.9:51234".parse().unwrap(), "192.0.2.1:443".parse().unwrap());
        assert_eq!(&h[..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(h[12], 0x21);
        assert_eq!(h[13], 0x11);
        assert_eq!(u16::from_be_bytes([h[14], h[15]]), 12);
        assert_eq!(&h[16..20], &[203, 0, 113, 9]);
        assert_eq!(&h[20..24], &[192, 0, 2, 1]);
        assert_eq!(u16::from_be_bytes([h[24], h[25]]), 51234);
        assert_eq!(u16::from_be_bytes([h[26], h[27]]), 443);
        assert_eq!(h.len(), 28);
    }

    #[test]
    fn proxy_header_mixed_families_use_v6() {
        let h = proxy_v2_header("[2001:db8::1]:1000".parse().unwrap(), "192.0.2.1:443".parse().unwrap());
        assert_eq!(h[13], 0x21);
        assert_eq!(h.len(), 16 + 36);
    }

    fn rt(domains: &[&str]) -> Arc<RouteRt> {
        use crate::config::{Listen, Target};
        let route = Route {
            id: domains.first().copied().unwrap_or("any").to_string(),
            name: "t".into(),
            enabled: true,
            listen: Listen { ip: "0.0.0.0".parse().unwrap(), port: 1 },
            domains: domains.iter().map(|s| s.to_string()).collect(),
            targets: vec![Target { address: "10.0.0.1".parse().unwrap(), port: 1 }],
            proxy_protocol: false,
        };
        Arc::new(RouteRt::new(route, Default::default(), vec![]))
    }

    #[test]
    fn resolve_prefers_exact_then_longest_wildcard_then_catch_all() {
        let t = Table::new(vec![
            rt(&["*.example.com"]),
            rt(&["*.a.example.com"]),
            rt(&["www.example.com"]),
            rt(&[]),
        ]);
        assert!(t.needs_sniff);
        let id = |h: Option<&str>| t.resolve(h).map(|r| r.route.id.clone());
        assert_eq!(id(Some("www.example.com")).as_deref(), Some("www.example.com"));
        assert_eq!(id(Some("x.a.example.com")).as_deref(), Some("*.a.example.com"));
        assert_eq!(id(Some("other.example.com")).as_deref(), Some("*.example.com"));
        assert_eq!(id(Some("unrelated.org")).as_deref(), Some("any"));
        assert_eq!(id(None).as_deref(), Some("any"));
    }

    #[test]
    fn no_catch_all_means_no_match() {
        let t = Table::new(vec![rt(&["a.example.com"])]);
        assert!(t.resolve(Some("b.example.com")).is_none());
        assert!(t.resolve(None).is_none());
    }

    #[test]
    fn attempt_order_round_robins_and_demotes_unhealthy() {
        let a = Arc::new(TargetState::new("10.0.0.1:1".parse().unwrap()));
        let b = Arc::new(TargetState::new("10.0.0.2:1".parse().unwrap()));
        let r = RouteRt::new(rt(&[]).route.clone(), Default::default(), vec![a.clone(), b.clone()]);
        let first = |o: Vec<Arc<TargetState>>| o[0].addr;
        assert_eq!(first(r.attempt_order()), a.addr);
        assert_eq!(first(r.attempt_order()), b.addr);
        a.set(false, Some("down".into()));
        let o = r.attempt_order();
        assert_eq!(o[0].addr, b.addr);
        assert_eq!(o[1].addr, a.addr, "unhealthy targets stay as a last resort");
    }
}
