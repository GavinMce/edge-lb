//! The controller <-> edge channel: who may talk to an edge, and whom the controller will trust.

use edge_lbd::config::Route;
use edge_lbd::edge::{self, EdgeHandle, EdgeOptions};
use edge_lbd::edge_client::{ClientError, EdgeClient};
use edge_lbd::engine::Options;
use edge_lbd::{pki, tls};
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("edge-lbd-mtls-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

async fn start_edge(ca: &pki::Pem, data_dir: std::path::PathBuf) -> EdgeHandle {
    edge::start(EdgeOptions {
        mgmt: "127.0.0.1:0".parse().unwrap(),
        controller_ca_pem: ca.cert.clone(),
        engine: Options {
            data_dir,
            reserved_ports: vec![],
            health_interval: Duration::from_millis(100),
            maintenance_interval: Duration::from_millis(100),
            ..Default::default()
        },
    })
    .await
    .unwrap()
}

fn client(e: &EdgeHandle, pin: &str, c: &pki::Pem) -> EdgeClient {
    EdgeClient::new(e.addr.ip(), e.addr.port(), pin, c).unwrap()
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
}

fn route(name: &str, port: u16, target: u16) -> Route {
    serde_json::from_value(json!({
        "id": name, "name": name,
        "listen": {"ip": "127.0.0.1", "port": port},
        "targets": [{"address": "127.0.0.1", "port": target}],
    }))
    .unwrap()
}

#[tokio::test]
async fn only_the_enrolled_controller_can_talk_to_the_edge() {
    let ca = pki::new_ca().unwrap();
    let me = pki::issue_client(&ca.key, "controller").unwrap();
    let edge = start_edge(&ca, dir("auth")).await;

    // Right CA + right pin: works.
    let info = client(&edge, &edge.fingerprint, &me).info().await.unwrap();
    assert_eq!(info["version"], edge::VERSION);

    // Wrong pin: the controller refuses to talk to an impostor edge.
    let wrong_pin = "00".repeat(32);
    let err = client(&edge, &wrong_pin, &me).info().await.unwrap_err().to_string();
    assert!(err.contains("pinned"), "{err}");

    // A client certificate from some other CA is rejected by the edge.
    let other_ca = pki::new_ca().unwrap();
    let rogue = pki::issue_client(&other_ca.key, "rogue").unwrap();
    assert!(client(&edge, &edge.fingerprint, &rogue).info().await.is_err());

    // No client certificate at all is rejected too.
    let cfg = tls::pinned_client_config_no_auth(&edge.fingerprint).unwrap();
    let http = reqwest::Client::builder().use_preconfigured_tls(cfg).build().unwrap();
    let res = http.get(format!("https://{}/v1/info", edge.addr)).send().await;
    assert!(res.is_err(), "edge answered a client with no certificate: {res:?}");

    // Plain HTTP (no TLS) gets nothing useful either.
    let mut tcp = TcpStream::connect(edge.addr).await.unwrap();
    tcp.write_all(b"GET /v1/info HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), tcp.read_to_end(&mut buf)).await;
    assert!(!String::from_utf8_lossy(&buf).contains("version"), "plaintext request was served");
}

#[tokio::test]
async fn config_push_applies_validates_and_persists() {
    let ca = pki::new_ca().unwrap();
    let me = pki::issue_client(&ca.key, "controller").unwrap();
    let data = dir("cfg");
    let edge = start_edge(&ca, data.clone()).await;
    let c = client(&edge, &edge.fingerprint, &me);

    // A real backend and a route to it.
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = backend.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = backend.accept().await else { return };
            let _ = s.write_all(b"hello from backend").await;
        }
    });
    let p = free_port().await;
    c.put_config(7, &[route("web", p, bport)], None).await.unwrap();

    let mut conn = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut got)).await;
    assert_eq!(got, b"hello from backend");

    let st = c.status().await.unwrap();
    assert_eq!(st["generation"], 7);
    assert_eq!(st["routes"].as_array().unwrap().len(), 1);

    // An invalid push is rejected with details and leaves the running config alone.
    let bad = c.put_config(8, &[route("web", p, bport), route("dup", p, bport)], None).await.unwrap_err();
    assert!(matches!(bad, ClientError::Rejected(ref d) if !d.is_empty()), "{bad:?}");
    assert_eq!(c.status().await.unwrap()["generation"], 7);
    assert!(TcpStream::connect(("127.0.0.1", p)).await.is_ok());

    // The management port itself cannot be used as a route port.
    let reserved = c.put_config(9, &[route("evil", edge.addr.port(), bport)], None).await.unwrap_err();
    assert!(matches!(reserved, ClientError::Rejected(_)), "{reserved:?}");

    // Restart from the same data dir: same identity (so the pin still holds), same routes, same generation.
    let fp = edge.fingerprint.clone();
    edge.stop().await;
    let edge2 = start_edge(&ca, data).await;
    assert_eq!(edge2.fingerprint, fp, "edge identity must survive restarts");
    let c2 = client(&edge2, &fp, &me);
    assert_eq!(c2.info().await.unwrap()["generation"], 7);
    assert_eq!(c2.status().await.unwrap()["routes"].as_array().unwrap().len(), 1);
}

// ---- the access log ----------------------------------------------------------------------------------------

/// Connect, say `send`, then read until the other side is done.
async fn talk(port: u16, send: &[u8]) -> Vec<u8> {
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    if !send.is_empty() {
        c.write_all(send).await.unwrap();
    }
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), c.read_to_end(&mut out)).await;
    out
}

/// Poll until the edge has logged at least `n` entries of `kind`.
async fn entries(c: &EdgeClient, kind: &str, n: usize) -> Vec<serde_json::Value> {
    for _ in 0..60 {
        let page = c.connections(0, 100, kind).await.unwrap();
        let list = page["entries"].as_array().unwrap().clone();
        if list.len() >= n {
            return list;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the edge never logged {n} {kind} entries");
}

#[tokio::test]
async fn the_edge_logs_every_connection_and_the_controller_can_read_it() {
    let ca = pki::new_ca().unwrap();
    let me = pki::issue_client(&ca.key, "controller").unwrap();
    let edge = start_edge(&ca, dir("log")).await;
    let c = client(&edge, &edge.fingerprint, &me);

    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = backend.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = backend.accept().await else { return };
            let _ = s.write_all(b"hello from backend").await;
        }
    });
    let dead = free_port().await; // nothing listens here
    let (p_web, p_api, p_dead) = (free_port().await, free_port().await, free_port().await);
    let api: Route = serde_json::from_value(json!({
        "id": "api", "name": "api", "domains": ["api.test"],
        "listen": {"ip": "127.0.0.1", "port": p_api},
        "targets": [{"address": "127.0.0.1", "port": bport}],
    }))
    .unwrap();
    c.put_config(1, &[route("web", p_web, bport), api, route("down", p_dead, dead)], None).await.unwrap();

    // A normal connection, a request for a hostname nobody serves, a client that connects and
    // leaves, and a route whose target is down.
    assert_eq!(talk(p_web, b"").await, b"hello from backend");
    let _ = talk(p_api, b"GET / HTTP/1.1\r\nHost: other.test\r\n\r\n").await;
    drop(TcpStream::connect(("127.0.0.1", p_api)).await.unwrap());
    let _ = talk(p_dead, b"").await;

    let traffic = entries(&c, "traffic", 2).await;
    assert_eq!(traffic.len(), 2, "{traffic:?}");
    let ok = traffic.iter().find(|e| e["outcome"] == "ok").expect("a forwarded connection");
    assert_eq!(ok["route"], "web");
    assert_eq!(ok["client"], "127.0.0.1");
    assert_eq!(ok["port"], p_web);
    assert_eq!(ok["target"], format!("127.0.0.1:{bport}"));
    assert_eq!(ok["bytes_down"], "hello from backend".len());
    assert_eq!(ok["bytes_up"], 0);
    assert!(ok["ts_ms"].as_u64().unwrap() > 1_600_000_000_000, "a real timestamp: {ok}");
    let down = traffic.iter().find(|e| e["outcome"] == "unreachable").expect("a connection to a dead target");
    assert_eq!(down["route"], "down");
    assert_eq!(down["target"], format!("127.0.0.1:{dead}"), "the target that was tried is recorded");

    let rejects = entries(&c, "rejects", 2).await;
    let no_route = rejects.iter().find(|e| e["outcome"] == "no_route").expect("a hostname with no route");
    assert_eq!(no_route["host"], "other.test");
    assert!(no_route["route"].is_null());
    let aborted = rejects.iter().find(|e| e["outcome"] == "aborted").expect("a client that said nothing");
    assert!(aborted["host"].is_null());

    // `kind` selects a ring; `all` merges both in order.
    let all = c.connections(0, 100, "all").await.unwrap();
    let seqs: Vec<u64> = all["entries"].as_array().unwrap().iter().map(|e| e["seq"].as_u64().unwrap()).collect();
    assert_eq!(seqs.len(), 4);
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "oldest first: {seqs:?}");

    // The cursor returns only what is new.
    let next = all["next"].as_u64().unwrap();
    assert_eq!(next, 4);
    assert!(c.connections(next, 100, "all").await.unwrap()["entries"].as_array().unwrap().is_empty());
    let _ = talk(p_web, b"").await;
    let fresh = loop {
        let page = c.connections(next, 100, "all").await.unwrap();
        if !page["entries"].as_array().unwrap().is_empty() {
            break page;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(fresh["entries"].as_array().unwrap().len(), 1);
    assert_eq!(fresh["entries"][0]["seq"], 5);

    // A limit keeps the newest.
    let last = c.connections(0, 1, "all").await.unwrap();
    assert_eq!(last["entries"][0]["seq"], 5);

    // Nonsense is refused, and the log is not reachable without the controller's certificate.
    assert!(c.connections(0, 10, "bogus").await.is_err());
    let cfg = tls::pinned_client_config_no_auth(&edge.fingerprint).unwrap();
    let http = reqwest::Client::builder().use_preconfigured_tls(cfg).build().unwrap();
    assert!(http.get(format!("https://{}/v1/connections", edge.addr)).send().await.is_err(), "client addresses are not public");
}
