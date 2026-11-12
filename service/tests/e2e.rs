//! End-to-end: real engine, real sockets on loopback, real backends.

use edge_lbd::config::Route;
use edge_lbd::engine::{Engine, EngineError, Options};
use edge_lbd::sniff::testutil::{client_hello, http_request, mc_handshake};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

static N: AtomicU32 = AtomicU32::new(0);

fn opts() -> Options {
    let dir = std::env::temp_dir().join(format!(
        "edge-lbd-e2e-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    Options {
        data_dir: dir,
        reserved_ports: vec![],
        peek_timeout: Duration::from_millis(300),
        connect_timeout: Duration::from_millis(500),
        health_interval: Duration::from_millis(100),
        maintenance_interval: Duration::from_millis(100),
        ..Default::default()
    }
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
}

/// Backend that collects what it receives until the client goes quiet, then replies
/// `tag:` + the bytes it received, and closes.
async fn backend(tag: &'static str) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    match timeout(Duration::from_millis(120), s.read(&mut buf)).await {
                        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                        Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let mut reply = format!("{tag}:").into_bytes();
                reply.extend(got);
                let _ = s.write_all(&reply).await;
            });
        }
    });
    port
}

/// Backend that speaks first (like SSH/SMTP/Postgres-over-TLS-less banners).
async fn banner_backend(banner: &'static str) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let _ = s.write_all(banner.as_bytes()).await;
        }
    });
    port
}

fn route(name: &str, port: u16, domains: &[&str], targets: &[u16]) -> Route {
    serde_json::from_value(json!({
        "name": name,
        "listen": { "ip": "127.0.0.1", "port": port },
        "domains": domains,
        "targets": targets.iter().map(|p| json!({"address": "127.0.0.1", "port": p})).collect::<Vec<_>>(),
    }))
    .unwrap()
}

async fn send(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(payload).await.unwrap();
    let mut out = Vec::new();
    let _ = timeout(Duration::from_secs(3), c.read_to_end(&mut out)).await;
    out
}

fn tag(reply: &[u8]) -> String {
    String::from_utf8_lossy(reply.split(|b| *b == b':').next().unwrap_or(&[])).into_owned()
}

async fn wait_until<F: FnMut() -> Fut, Fut: std::future::Future<Output = bool>>(mut f: F) {
    for _ in 0..60 {
        if f().await {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not reached in time");
}

#[tokio::test]
async fn plain_l4_forward() {
    let a = backend("A").await;
    let e = Engine::start(opts()).await.unwrap();
    let p = free_port().await;
    e.create(route("db", p, &[], &[a])).await.unwrap();
    assert_eq!(send(p, b"hello").await, b"A:hello");
    let v = e.get("db").await.unwrap();
    assert_eq!(v.status.state, "listening");
    assert_eq!(v.status.total_connections, 1);
    assert!(v.status.bytes_up >= 5 && v.status.bytes_down >= 7);
}

#[tokio::test]
async fn routes_by_sni_host_and_minecraft_with_catch_all() {
    let (a, b, c) = (backend("A").await, backend("B").await, backend("C").await);
    let e = Engine::start(opts()).await.unwrap();
    let p = free_port().await;
    e.create(route("a", p, &["a.test"], &[a])).await.unwrap();
    e.create(route("b", p, &["*.b.test"], &[b])).await.unwrap();
    e.create(route("fallback", p, &[], &[c])).await.unwrap();

    // TLS SNI, and the ClientHello must arrive at the backend byte-for-byte.
    let hello = client_hello(Some("a.test"));
    let r = send(p, &hello).await;
    assert_eq!(tag(&r), "A");
    assert_eq!(&r[2..], &hello[..]);
    assert_eq!(tag(&send(p, &client_hello(Some("x.b.test"))).await), "B");
    assert_eq!(tag(&send(p, &client_hello(Some("nope.test"))).await), "C");
    assert_eq!(tag(&send(p, &client_hello(None)).await), "C");

    // HTTP Host header
    assert_eq!(tag(&send(p, &http_request("A.test:8080")).await), "A");
    assert_eq!(tag(&send(p, &http_request("deep.x.b.test")).await), "B");

    // Minecraft handshake
    assert_eq!(tag(&send(p, &mc_handshake("a.test", 2)).await), "A");
    assert_eq!(tag(&send(p, &mc_handshake("a.test\0FML\0", 2)).await), "A");
    assert_eq!(tag(&send(p, &mc_handshake("who.b.test", 1)).await), "B");

    // Garbage goes to the catch-all too.
    assert_eq!(tag(&send(p, b"\x00\x01\x02 binary").await), "C");
}

#[tokio::test]
async fn unmatched_domain_without_catch_all_is_closed() {
    let a = backend("A").await;
    let e = Engine::start(opts()).await.unwrap();
    let p = free_port().await;
    e.create(route("a", p, &["a.test"], &[a])).await.unwrap();
    assert_eq!(tag(&send(p, &client_hello(Some("a.test"))).await), "A");
    assert!(send(p, &client_hello(Some("other.test"))).await.is_empty());
}

#[tokio::test]
async fn silent_client_falls_through_to_catch_all_for_server_first_protocols() {
    let a = backend("A").await;
    let banner = banner_backend("SSH-2.0-test\r\n").await;
    let e = Engine::start(opts()).await.unwrap();
    let p = free_port().await;
    e.create(route("web", p, &["a.test"], &[a])).await.unwrap();
    e.create(route("ssh", p, &[], &[banner])).await.unwrap();
    // Client sends nothing; after the peek timeout it is routed to the catch-all.
    let r = send(p, b"").await;
    assert_eq!(r, b"SSH-2.0-test\r\n");
}

#[tokio::test]
async fn proxy_protocol_v2_carries_client_address() {
    let a = backend("A").await;
    let e = Engine::start(opts()).await.unwrap();
    let p = free_port().await;
    let mut r = route("pp", p, &[], &[a]);
    r.proxy_protocol = true;
    e.create(r).await.unwrap();

    let mut c = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    let client_port = c.local_addr().unwrap().port();
    c.write_all(b"payload").await.unwrap();
    let mut out = Vec::new();
    let _ = timeout(Duration::from_secs(3), c.read_to_end(&mut out)).await;

    let body = &out[2..]; // strip "A:"
    assert_eq!(&body[..12], b"\r\n\r\n\0\r\nQUIT\n");
    assert_eq!(&body[12..14], &[0x21, 0x11]);
    assert_eq!(&body[16..20], &[127, 0, 0, 1]);
    assert_eq!(u16::from_be_bytes([body[24], body[25]]), client_port);
    assert_eq!(u16::from_be_bytes([body[26], body[27]]), p);
    assert_eq!(&body[28..], b"payload");
}

#[tokio::test]
async fn round_robin_and_failover() {
    let (a, b) = (backend("A").await, backend("B").await);
    let dead = free_port().await;
    let e = Engine::start(opts()).await.unwrap();

    let p = free_port().await;
    e.create(route("rr", p, &[], &[a, b])).await.unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..6 {
        seen.insert(tag(&send(p, b"x").await));
    }
    assert_eq!(seen, ["A", "B"].map(String::from).into());

    let p2 = free_port().await;
    e.create(route("fo", p2, &[], &[dead, a])).await.unwrap();
    for _ in 0..4 {
        assert_eq!(tag(&send(p2, b"x").await), "A", "must skip the dead target");
    }
    // The health checker should mark the dead target down.
    wait_until(|| async {
        let v = e.get("fo").await.unwrap();
        v.status.targets[0].healthy == Some(false) && v.status.targets[1].healthy == Some(true)
    })
    .await;
    let v = e.get("fo").await.unwrap();
    assert!(v.status.targets[0].last_error.is_some());
}

#[tokio::test]
async fn all_targets_down_closes_the_connection() {
    let dead = free_port().await;
    let e = Engine::start(opts()).await.unwrap();
    let p = free_port().await;
    e.create(route("x", p, &[], &[dead])).await.unwrap();
    assert!(send(p, b"hi").await.is_empty());
    assert!(e.get("x").await.unwrap().status.connect_failures >= 1);
}

#[tokio::test]
async fn live_reconfiguration() {
    let (a, b) = (backend("A").await, backend("B").await);
    let e = Engine::start(opts()).await.unwrap();
    let p = free_port().await;
    let id = e.create(route("svc", p, &[], &[a])).await.unwrap().route.id;
    assert_eq!(id, "svc");
    assert_eq!(tag(&send(p, b"x").await), "A");

    // Retarget in place.
    e.update(&id, route("svc", p, &[], &[b])).await.unwrap();
    assert_eq!(tag(&send(p, b"x").await), "B");

    // Move to another port: the old one must close and the new one open.
    let p2 = free_port().await;
    e.update(&id, route("svc", p2, &[], &[b])).await.unwrap();
    assert!(TcpStream::connect(("127.0.0.1", p)).await.is_err());
    assert_eq!(tag(&send(p2, b"x").await), "B");

    // Disable / enable.
    let mut r = route("svc", p2, &[], &[b]);
    r.enabled = false;
    let v = e.update(&id, r.clone()).await.unwrap();
    assert_eq!(v.status.state, "disabled");
    assert!(TcpStream::connect(("127.0.0.1", p2)).await.is_err());
    r.enabled = true;
    e.update(&id, r).await.unwrap();
    assert_eq!(tag(&send(p2, b"x").await), "B");

    // Delete.
    e.delete(&id).await.unwrap();
    assert!(TcpStream::connect(("127.0.0.1", p2)).await.is_err());
    assert!(matches!(e.delete(&id).await, Err(EngineError::NotFound(_))));
}

#[tokio::test]
async fn existing_connections_survive_reconfiguration() {
    let a = backend("A").await;
    let e = Engine::start(opts()).await.unwrap();
    let p = free_port().await;
    e.create(route("svc", p, &[], &[a])).await.unwrap();

    let mut c = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    c.write_all(b"before").await.unwrap();
    // Unrelated change while the connection is open.
    let q = free_port().await;
    e.create(route("other", q, &[], &[a])).await.unwrap();
    sleep(Duration::from_millis(50)).await;
    c.write_all(b"+after").await.unwrap();
    let mut out = Vec::new();
    let _ = timeout(Duration::from_secs(3), c.read_to_end(&mut out)).await;
    assert_eq!(out, b"A:before+after");
}

#[tokio::test]
async fn bind_failure_is_reported_then_recovers() {
    let a = backend("A").await;
    let squatter = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = squatter.local_addr().unwrap().port();
    let e = Engine::start(opts()).await.unwrap();
    let v = e.create(route("svc", p, &[], &[a])).await.unwrap();
    assert_eq!(v.status.state, "error");
    assert!(v.status.error.unwrap().to_lowercase().contains("in use"));

    drop(squatter);
    wait_until(|| async { e.get("svc").await.unwrap().status.state == "listening" }).await;
    assert_eq!(tag(&send(p, b"x").await), "A");
}

#[tokio::test]
async fn validation_is_enforced_by_the_engine() {
    let a = backend("A").await;
    let mut o = opts();
    o.reserved_ports = vec![22];
    let e = Engine::start(o).await.unwrap();
    let p = free_port().await;
    e.create(route("one", p, &["x.test"], &[a])).await.unwrap();

    let dup = e.create(route("two", p, &["x.test"], &[a])).await;
    assert!(matches!(dup, Err(EngineError::Invalid(ref m)) if m[0].contains("x.test")), "{dup:?}");
    let same_id = e.create(route("one", free_port().await, &[], &[a])).await;
    // Same *name* gets a unique id rather than failing.
    assert_eq!(same_id.unwrap().route.id, "one-2");
    let reserved = e.create(route("ssh", 22, &[], &[a])).await;
    assert!(matches!(reserved, Err(EngineError::Invalid(_))));
    // Nothing invalid was persisted or half-applied.
    assert_eq!(e.list().await.len(), 2);
}

#[tokio::test]
async fn replace_all_is_atomic() {
    let a = backend("A").await;
    let e = Engine::start(opts()).await.unwrap();
    let (p1, p2) = (free_port().await, free_port().await);
    e.replace_all(vec![route("one", p1, &[], &[a]), route("two", p2, &[], &[a])]).await.unwrap();
    assert_eq!(e.list().await.len(), 2);

    let bad = e.replace_all(vec![route("ok", free_port().await, &[], &[a]), route("bad", 0, &[], &[a])]).await;
    assert!(matches!(bad, Err(EngineError::Invalid(_))));
    let ids: Vec<_> = e.list().await.into_iter().map(|r| r.route.id).collect();
    assert_eq!(ids, ["one", "two"], "failed import must leave the old config untouched");
    assert_eq!(tag(&send(p1, b"x").await), "A");
}

#[tokio::test]
async fn routes_persist_across_restart() {
    let a = backend("A").await;
    let o = opts();
    let p = free_port().await;
    let e = Engine::start(o.clone()).await.unwrap();
    e.create(route("keep", p, &["k.test"], &[a])).await.unwrap();
    e.shutdown().await;
    drop(e);

    let e2 = Engine::start(o).await.unwrap();
    let v = e2.get("keep").await.unwrap();
    assert_eq!(v.route.domains, ["k.test"]);
    assert_eq!(v.status.state, "listening");
    assert_eq!(tag(&send(p, &client_hello(Some("k.test"))).await), "A");
}

#[tokio::test]
async fn specific_listen_ip_is_honored() {
    // 127.0.0.2 is also loopback on Linux; a route bound there must not answer on 127.0.0.1.
    let a = backend("A").await;
    let e = Engine::start(opts()).await.unwrap();
    let p = free_port().await;
    let mut r = route("ip", p, &[], &[a]);
    r.listen.ip = "127.0.0.2".parse().unwrap();
    e.create(r).await.unwrap();
    let addr: SocketAddr = format!("127.0.0.2:{p}").parse().unwrap();
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(b"x").await.unwrap();
    let mut out = Vec::new();
    let _ = timeout(Duration::from_secs(3), c.read_to_end(&mut out)).await;
    assert_eq!(tag(&out), "A");
    assert!(TcpStream::connect(("127.0.0.1", p)).await.is_err());
}
