//! HTTP API tests: real server on loopback, raw HTTP/1.1 client.

use edge_lbd::api::router;
use edge_lbd::engine::{Engine, Options};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const TOKEN: &str = "test-token-0123456789abcdef";

async fn start() -> (SocketAddr, Engine) {
    let dir = std::env::temp_dir().join(format!("edge-lbd-api-{}-{:?}", std::process::id(), std::thread::current().id()));
    let _ = std::fs::remove_dir_all(&dir);
    let engine = Engine::start(Options {
        data_dir: dir,
        reserved_ports: vec![22],
        health_interval: Duration::from_millis(100),
        ..Default::default()
    })
    .await
    .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let app = router(engine.clone(), Arc::from(TOKEN));
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (addr, engine)
}

struct Resp {
    status: u16,
    headers: String,
    body: String,
}
impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("not json ({e}): {}", self.body))
    }
}

async fn http(addr: SocketAddr, method: &str, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
    let mut c = TcpStream::connect(addr).await.unwrap();
    let body = body.map(|b| b.to_string());
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n");
    if let Some(t) = token {
        req += &format!("Authorization: Bearer {t}\r\n");
    }
    if let Some(b) = &body {
        req += &format!("Content-Type: application/json\r\nContent-Length: {}\r\n", b.len());
    }
    req += "\r\n";
    c.write_all(req.as_bytes()).await.unwrap();
    if let Some(b) = &body {
        c.write_all(b.as_bytes()).await.unwrap();
    }
    let mut raw = Vec::new();
    timeout(Duration::from_secs(5), c.read_to_end(&mut raw)).await.unwrap().unwrap();
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    Resp { status, headers: head.to_ascii_lowercase(), body: body.to_string() }
}

async fn echo_backend() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let mut b = [0u8; 64];
                if let Ok(n) = s.read(&mut b).await {
                    let _ = s.write_all(&b[..n]).await;
                }
            });
        }
    });
    port
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
}

#[tokio::test]
async fn api_requires_the_token() {
    let (a, _e) = start().await;
    for (m, p) in [("GET", "/api/status"), ("GET", "/api/routes"), ("DELETE", "/api/routes/x")] {
        assert_eq!(http(a, m, p, None, None).await.status, 401, "{m} {p}");
        assert_eq!(http(a, m, p, Some("wrong"), None).await.status, 401, "{m} {p}");
        assert_eq!(http(a, m, p, Some("test-token-0123456789abcdeX"), None).await.status, 401);
    }
    // A write without a token must not have any effect.
    let body = json!({"name":"x","listen":{"port":1},"targets":[{"address":"10.0.0.1","port":1}]});
    assert_eq!(http(a, "POST", "/api/routes", None, Some(body)).await.status, 401);
    let list = http(a, "GET", "/api/routes", Some(TOKEN), None).await;
    assert_eq!(list.status, 200);
    assert_eq!(list.json(), json!([]));
}

#[tokio::test]
async fn ui_assets_are_served_with_a_strict_csp() {
    let (a, _e) = start().await;
    for (path, ct) in [("/", "text/html"), ("/app.js", "text/javascript"), ("/app.css", "text/css")] {
        let r = http(a, "GET", path, None, None).await;
        assert_eq!(r.status, 200, "{path}");
        assert!(r.headers.contains(ct), "{path}: {}", r.headers);
        assert!(r.headers.contains("content-security-policy: default-src 'none'"), "{path}");
        assert!(r.headers.contains("x-content-type-options: nosniff"));
        assert!(r.headers.contains("cache-control: no-store"));
    }
    assert!(http(a, "GET", "/", None, None).await.body.contains("edge-lb"));
    assert_eq!(http(a, "GET", "/healthz", None, None).await.body, "ok");
    // The page must not rely on inline script or style (the CSP would block it).
    let html = http(a, "GET", "/", None, None).await.body;
    assert!(!html.contains("<script>") && !html.contains("style="), "inline script/style found");
}

#[tokio::test]
async fn crud_and_real_traffic_through_the_api() {
    let (a, _e) = start().await;
    let backend = echo_backend().await;
    let port = free_port().await;

    let create = http(
        a,
        "POST",
        "/api/routes",
        Some(TOKEN),
        Some(json!({
            "name": "My Service",
            "listen": { "ip": "127.0.0.1", "port": port },
            "domains": ["Svc.Example.com"],
            "targets": [{ "address": "127.0.0.1", "port": backend }],
        })),
    )
    .await;
    assert_eq!(create.status, 201, "{}", create.body);
    let v = create.json();
    assert_eq!(v["id"], "my-service");
    assert_eq!(v["domains"], json!(["svc.example.com"]), "domains are normalized");
    assert_eq!(v["enabled"], true);
    assert_eq!(v["status"]["state"], "listening");

    // Traffic flows: an HTTP request for the right Host reaches the echo backend.
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let req = b"GET / HTTP/1.1\r\nHost: svc.example.com\r\n\r\n";
    c.write_all(req).await.unwrap();
    let mut got = vec![0u8; 64];
    let n = timeout(Duration::from_secs(3), c.read(&mut got)).await.unwrap().unwrap();
    assert_eq!(&got[..n], &req[..n.min(req.len())]);

    // Duplicate explicit id -> 409; invalid -> 422 with every problem listed.
    let dup = http(
        a, "POST", "/api/routes", Some(TOKEN),
        Some(json!({"id":"my-service","name":"b","listen":{"port":1},"targets":[{"address":"10.0.0.1","port":1}]})),
    ).await;
    assert_eq!(dup.status, 409);
    let bad = http(
        a, "POST", "/api/routes", Some(TOKEN),
        Some(json!({"name":" ","listen":{"port":0},"domains":["not a domain"],"targets":[]})),
    ).await;
    assert_eq!(bad.status, 422);
    assert!(bad.json()["details"].as_array().unwrap().len() >= 4, "{}", bad.body);

    // Conflict across routes is a 422 naming the domain.
    let conflict = http(
        a, "POST", "/api/routes", Some(TOKEN),
        Some(json!({"name":"other","listen":{"ip":"127.0.0.1","port":port},"domains":["svc.example.com"],
                    "targets":[{"address":"127.0.0.1","port":backend}]})),
    ).await;
    assert_eq!(conflict.status, 422);
    assert!(conflict.body.contains("svc.example.com"));

    // Update: disable -> port closes.
    let upd = http(
        a, "PUT", "/api/routes/my-service", Some(TOKEN),
        Some(json!({"name":"My Service","enabled":false,"listen":{"ip":"127.0.0.1","port":port},
                    "domains":["svc.example.com"],"targets":[{"address":"127.0.0.1","port":backend}]})),
    ).await;
    assert_eq!(upd.status, 200, "{}", upd.body);
    assert_eq!(upd.json()["status"]["state"], "disabled");
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());

    // Status endpoint and GET one.
    let st = http(a, "GET", "/api/status", Some(TOKEN), None).await.json();
    assert_eq!(st["routes"].as_array().unwrap().len(), 1);
    assert_eq!(st["listeners"], 0);
    assert_eq!(http(a, "GET", "/api/routes/my-service", Some(TOKEN), None).await.status, 200);
    assert_eq!(http(a, "GET", "/api/routes/nope", Some(TOKEN), None).await.status, 404);

    // Delete.
    assert_eq!(http(a, "DELETE", "/api/routes/my-service", Some(TOKEN), None).await.status, 204);
    assert_eq!(http(a, "DELETE", "/api/routes/my-service", Some(TOKEN), None).await.status, 404);
    assert_eq!(http(a, "GET", "/api/routes", Some(TOKEN), None).await.json(), json!([]));
}

#[tokio::test]
async fn bulk_replace_via_put() {
    let (a, _e) = start().await;
    let p = free_port().await;
    let ok = json!([{"name":"a","listen":{"ip":"127.0.0.1","port":p},"targets":[{"address":"127.0.0.1","port":9}]}]);
    let r = http(a, "PUT", "/api/routes", Some(TOKEN), Some(ok)).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json().as_array().unwrap().len(), 1);

    let bad = json!([{"name":"a","listen":{"port":0},"targets":[]}]);
    assert_eq!(http(a, "PUT", "/api/routes", Some(TOKEN), Some(bad)).await.status, 422);
    assert_eq!(http(a, "GET", "/api/routes", Some(TOKEN), None).await.json().as_array().unwrap().len(), 1);

    // Reserved port 22 is refused.
    let ssh = json!([{"name":"ssh","listen":{"port":22},"targets":[{"address":"127.0.0.1","port":9}]}]);
    assert_eq!(http(a, "PUT", "/api/routes", Some(TOKEN), Some(ssh)).await.status, 422);
}
