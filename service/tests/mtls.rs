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
    c.put_config(7, &[route("web", p, bport)]).await.unwrap();

    let mut conn = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut got)).await;
    assert_eq!(got, b"hello from backend");

    let st = c.status().await.unwrap();
    assert_eq!(st["generation"], 7);
    assert_eq!(st["routes"].as_array().unwrap().len(), 1);

    // An invalid push is rejected with details and leaves the running config alone.
    let bad = c.put_config(8, &[route("web", p, bport), route("dup", p, bport)]).await.unwrap_err();
    assert!(matches!(bad, ClientError::Rejected(ref d) if !d.is_empty()), "{bad:?}");
    assert_eq!(c.status().await.unwrap()["generation"], 7);
    assert!(TcpStream::connect(("127.0.0.1", p)).await.is_ok());

    // The management port itself cannot be used as a route port.
    let reserved = c.put_config(9, &[route("evil", edge.addr.port(), bport)]).await.unwrap_err();
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
