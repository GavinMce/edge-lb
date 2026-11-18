#![allow(clippy::cmp_owned)] // comparing JSON ids as strings keeps the mocks simple
//! Development harness: a real controller + web UI backed by a *mock* Hetzner API and in-process
//! "machines" (real edges on 127.0.0.N). Nothing leaves this computer and nothing is billed.
//!
//!   cargo run --example ui_demo -- /tmp/edge-lb-demo 8099
//!
//! The setup code is written to <dir>/setup-code. The mock API accepts any token.

use async_trait::async_trait;
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use edge_lbd::controller::bootstrap::{Bootstrapper, InstallCtx, Installed, Target};
use edge_lbd::controller::sites::{GatewayListen, NewSite};
use edge_lbd::controller::{Controller, Options};
use edge_lbd::gateway::{self, Handshake, HostWg};
use edge_lbd::wg::Desired;
use edge_lbd::edge::{self, EdgeHandle, EdgeOptions};
use edge_lbd::engine::Options as EngineOptions;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[derive(Default)]
struct Mock {
    servers: Vec<Value>,
    keys: Vec<Value>,
    next: u64,
}
type M = Arc<Mutex<Mock>>;

async fn mock_hetzner() -> String {
    let m: M = Arc::new(Mutex::new(Mock { next: 100, ..Default::default() }));
    let app = Router::new()
        .route("/ssh_keys", get(|State(m): State<M>| async move { Json(json!({"ssh_keys": m.lock().unwrap().keys.clone()})) })
            .post(|State(m): State<M>, Json(b): Json<Value>| async move {
                let mut s = m.lock().unwrap();
                s.next += 1;
                let k = json!({"id": s.next, "public_key": b["public_key"]});
                s.keys.push(k.clone());
                Json(json!({"ssh_key": k}))
            }))
        .route("/servers", get(|State(m): State<M>, Query(q): Query<HashMap<String, String>>| async move {
            let want = q.get("label_selector").cloned().unwrap_or_default();
            let (k, v) = want.split_once('=').unwrap_or(("", ""));
            Json(json!({"servers": m.lock().unwrap().servers.iter().filter(|x| want.is_empty() || x["labels"][k] == json!(v)).cloned().collect::<Vec<_>>()}))
        }).post(|State(m): State<M>, Json(b): Json<Value>| async move {
            let mut s = m.lock().unwrap();
            s.next += 1;
            let ip = format!("127.0.0.{}", s.servers.len() + 1);
            let srv = json!({"id": s.next, "status": "running", "labels": b["labels"], "public_net": {"ipv4": {"ip": ip}}});
            s.servers.push(srv.clone());
            Json(json!({"server": srv}))
        }))
        .route("/servers/:id", get(|State(m): State<M>, Path(id): Path<String>| async move {
            let s = m.lock().unwrap();
            Json(json!({"server": s.servers.iter().find(|x| x["id"].to_string() == id)}))
        }).delete(|State(m): State<M>, Path(id): Path<String>| async move {
            m.lock().unwrap().servers.retain(|x| x["id"].to_string() != id);
            Json(json!({"action": {"id": 1}}))
        }))
        .route("/locations", get(|| async { Json(json!({"locations": [
            {"name": "ash", "description": "Ashburn, VA", "city": "Ashburn", "country": "US", "network_zone": "us-east"},
            {"name": "hil", "description": "Hillsboro, OR", "city": "Hillsboro", "country": "US", "network_zone": "us-west"},
            {"name": "fsn1", "description": "Falkenstein", "city": "Falkenstein", "country": "DE", "network_zone": "eu-central"}]})) }))
        .route("/server_types", get(|| async { Json(json!({"server_types": [
            {"name": "cpx11", "description": "CPX 11", "cores": 2, "memory": 2.0, "disk": 40, "architecture": "x86", "deprecation": null,
             "prices": [{"location": "ash", "price_monthly": {"gross": "5.49"}}, {"location": "hil", "price_monthly": {"gross": "5.49"}}, {"location": "fsn1", "price_monthly": {"gross": "4.99"}}]},
            {"name": "cpx21", "description": "CPX 21", "cores": 3, "memory": 4.0, "disk": 80, "architecture": "x86", "deprecation": null,
             "prices": [{"location": "ash", "price_monthly": {"gross": "9.99"}}]},
            {"name": "cax11", "description": "CAX 11", "cores": 2, "memory": 4.0, "disk": 40, "architecture": "arm", "deprecation": null,
             "prices": [{"location": "fsn1", "price_monthly": {"gross": "3.79"}}]}]})) }))
        .with_state(m);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    url
}

struct Machines {
    edges: tokio::sync::Mutex<HashMap<String, EdgeHandle>>,
    dir: PathBuf,
}

#[async_trait]
impl Bootstrapper for Machines {
    async fn probe(&self, _: &Target) -> anyhow::Result<()> {
        tokio::time::sleep(Duration::from_millis(1500)).await; // make the lifecycle visible
        Ok(())
    }
    async fn install(&self, t: &Target, ctx: &InstallCtx) -> anyhow::Result<Installed> {
        tokio::time::sleep(Duration::from_millis(2000)).await;
        let h = edge::start(EdgeOptions {
            mgmt: SocketAddr::new(t.ip, 0),
            controller_ca_pem: ctx.ca_pem.clone(),
            engine: EngineOptions { data_dir: self.dir.join(&t.edge_id), reserved_ports: vec![], ..Default::default() },
        })
        .await?;
        let out = Installed { cert_pem: h.cert_pem.clone(), mgmt_port: h.addr.port(), wg_public_key: Some(demo_key(&t.edge_id)) };
        self.edges.lock().await.insert(t.edge_id.clone(), h);
        Ok(out)
    }
    async fn uninstall(&self, t: &Target) -> anyhow::Result<()> {
        if let Some(h) = self.edges.lock().await.remove(&t.edge_id) {
            h.stop().await;
        }
        Ok(())
    }
    async fn forget(&self, _: &Target) {}
}

/// A valid WireGuard key that is different for every demo edge (nothing secret: no real tunnel exists).
fn demo_key(seed: &str) -> String {
    use sha2::{Digest, Sha256};
    edge_lbd::pki::base64_encode(&Sha256::digest(seed.as_bytes()))
}

/// Pretends to be a gateway host: accepts every config and reports a healthy handshake with each peer.
struct DemoHost(Mutex<Vec<String>>);

#[async_trait]
impl HostWg for DemoHost {
    async fn ensure_key(&self, _: &std::path::Path) -> anyhow::Result<String> {
        Ok(demo_key("demo-gateway"))
    }
    async fn apply(&self, d: &Desired, _: &std::path::Path) -> anyhow::Result<()> {
        *self.0.lock().unwrap() = d.peers.iter().map(|p| p.public_key.clone()).collect();
        Ok(())
    }
    async fn handshakes(&self) -> Vec<Handshake> {
        self.0.lock().unwrap().iter().enumerate().map(|(i, k)| Handshake { public_key: k.clone(), age_secs: Some(8 + i as u64 * 31) }).collect()
    }
    async fn probe(&self, _: &[std::net::Ipv4Addr]) {}
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("warn").init();
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().expect("usage: ui_demo <dir> [port]"));
    let port: u16 = args.next().and_then(|p| p.parse().ok()).unwrap_or(8099);
    let _ = std::fs::remove_dir_all(&dir);

    // A little backend the demo routes can point at.
    let backend = TcpListener::bind("127.0.0.1:19000").await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = backend.accept().await else { return };
            let _ = s.write_all(b"hello from the demo backend\n").await;
        }
    });

    let hz = mock_hetzner().await;
    let mut o = Options::new(dir.join("controller"));
    o.hetzner_base = hz;
    o.bootstrapper = Some(Arc::new(Machines { edges: Default::default(), dir: dir.join("machines") }));
    o.default_mgmt_port = 7443;
    o.gateway = Some(GatewayListen { listen: "127.0.0.1:0".parse().unwrap(), host: "127.0.0.1".into() });
    let ctl = Controller::start(o).await.unwrap();

    // Two demo sites: "Home" gets a live in-process gateway agent, "Cabin" is waiting for one.
    ctl.create_site("demo", NewSite { name: "Home".into(), lan_cidrs: vec!["192.168.1.0/24".into()] }).unwrap();
    ctl.create_site("demo", NewSite { name: "Cabin".into(), lan_cidrs: vec!["192.168.50.0/24".into(), "192.168.51.0/24".into()] }).unwrap();
    let token = ctl.start_enrolment("demo", "home").unwrap().command.split("/gw/install/").nth(1).unwrap().split('\'').next().unwrap().to_string();
    let gwdir = dir.join("gateway");
    std::fs::create_dir_all(&gwdir).unwrap();
    std::fs::write(gwdir.join("enrol-token"), &token).unwrap();
    let pem = ctl.store.read(|s| s.gateway_tls.clone().unwrap());
    tokio::spawn(gateway::run(gateway::Options {
        controller: ctl.gateway_endpoint().unwrap().hostport,
        pin: edge_lbd::pki::fingerprint_pem(&pem.cert).unwrap(),
        data_dir: gwdir,
        interval: Duration::from_secs(2),
        host: Arc::new(DemoHost(Mutex::new(vec![]))),
        self_update: false,
    }));
    ctl.start_enrolment("demo", "cabin").unwrap();
    let l = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    println!("demo controller: http://127.0.0.1:{port}  (setup code in {}/controller/setup-code)", dir.display());
    axum::serve(l, edge_lbd::controller::api::router(ctl, false).into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}
