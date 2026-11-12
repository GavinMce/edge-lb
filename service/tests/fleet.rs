#![allow(clippy::cmp_owned)] // comparing JSON ids as strings keeps the mocks simple
//! Fleet lifecycle, end to end: the real controller creating "servers" through a mock Hetzner
//! API, installing real edges (in-process) over the real mTLS channel, pushing routes, moving
//! traffic, publishing DNS to a mock Cloudflare, and tearing everything down again.

use async_trait::async_trait;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use edge_lbd::config::Route;
use edge_lbd::controller::bootstrap::{Bootstrapper, InstallCtx, Installed, Target};
use edge_lbd::controller::model::{EdgeStatus, ProviderSpec};
use edge_lbd::controller::{Controller, CtlError, NewEdge, Options, SettingsUpdate};
use edge_lbd::edge::{self, EdgeHandle, EdgeOptions};
use edge_lbd::engine::Options as EngineOptions;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

const TOKEN: &str = "tok-123";

// ---- mock Hetzner -------------------------------------------------------------------------------

#[derive(Default)]
struct HState {
    servers: Vec<Value>,
    ssh_keys: Vec<Value>,
    post_servers: Vec<Value>,
    deleted: Vec<String>,
    next_id: u64,
    next_ip: u8,
    reject_auth: bool,
}
type H = Arc<Mutex<HState>>;

fn authed(h: &HeaderMap, s: &H) -> Result<(), (StatusCode, Json<Value>)> {
    let ok = h.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}"));
    if ok && !s.lock().unwrap().reject_auth {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, Json(json!({"error": {"code": "unauthorized", "message": "unable to authenticate"}}))))
    }
}

type R = Result<Json<Value>, (StatusCode, Json<Value>)>;

async fn post_server(State(s): State<H>, h: HeaderMap, Json(b): Json<Value>) -> R {
    authed(&h, &s)?;
    let mut st = s.lock().unwrap();
    st.post_servers.push(b.clone());
    st.next_id += 1;
    let ip = format!("127.0.0.{}", st.next_ip);
    st.next_ip += 1;
    let srv = json!({"id": st.next_id, "name": b["name"], "status": "initializing", "labels": b["labels"], "public_net": {"ipv4": {"ip": ip}}});
    st.servers.push(srv.clone());
    Ok(Json(json!({"server": srv})))
}

fn not_found() -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_FOUND, Json(json!({"error": {"code": "not_found", "message": "server not found"}})))
}

async fn get_server(State(s): State<H>, h: HeaderMap, Path(id): Path<String>) -> R {
    authed(&h, &s)?;
    let st = s.lock().unwrap();
    match st.servers.iter().find(|x| x["id"].to_string() == id) {
        Some(x) => Ok(Json(json!({"server": x}))),
        None => Err(not_found()),
    }
}

async fn delete_server(State(s): State<H>, h: HeaderMap, Path(id): Path<String>) -> R {
    authed(&h, &s)?;
    let mut st = s.lock().unwrap();
    let before = st.servers.len();
    st.servers.retain(|x| x["id"].to_string() != id);
    if st.servers.len() == before {
        return Err(not_found());
    }
    st.deleted.push(id);
    Ok(Json(json!({"action": {"id": 1}})))
}

async fn start_hetzner() -> (String, H) {
    let state: H = Arc::new(Mutex::new(HState { next_id: 100, next_ip: 1, ..Default::default() }));
    let app = Router::new()
        .route("/ssh_keys", get(|State(s): State<H>, h: HeaderMap| async move {
            authed(&h, &s)?;
            Ok::<_, (StatusCode, Json<Value>)>(Json(json!({"ssh_keys": s.lock().unwrap().ssh_keys.clone()})))
        }).post(|State(s): State<H>, h: HeaderMap, Json(b): Json<Value>| async move {
            authed(&h, &s)?;
            let mut st = s.lock().unwrap();
            st.next_id += 1;
            let k = json!({"id": st.next_id, "public_key": b["public_key"], "name": b["name"]});
            st.ssh_keys.push(k.clone());
            Ok::<_, (StatusCode, Json<Value>)>(Json(json!({"ssh_key": k})))
        }))
        .route("/servers", get(|State(s): State<H>, h: HeaderMap, Query(q): Query<HashMap<String, String>>| async move {
            authed(&h, &s)?;
            let want = q.get("label_selector").cloned().unwrap_or_default();
            let (k, v) = want.split_once('=').unwrap_or(("", ""));
            let list: Vec<Value> = s.lock().unwrap().servers.iter().filter(|x| want.is_empty() || x["labels"][k] == json!(v)).cloned().collect();
            Ok::<_, (StatusCode, Json<Value>)>(Json(json!({"servers": list})))
        }).post(post_server))
        .route("/servers/:id", get(get_server).delete(delete_server))
        .route("/locations", get(|State(s): State<H>, h: HeaderMap| async move {
            authed(&h, &s)?;
            Ok::<_, (StatusCode, Json<Value>)>(Json(json!({"locations": [
            {"name": "ash", "description": "Ashburn, VA", "city": "Ashburn", "country": "US", "network_zone": "us-east"},
            {"name": "hil", "description": "Hillsboro, OR", "city": "Hillsboro", "country": "US", "network_zone": "us-west"}]})))
        }))
        .route("/server_types", get(|State(s): State<H>, h: HeaderMap| async move {
            authed(&h, &s)?;
            Ok::<_, (StatusCode, Json<Value>)>(Json(json!({"server_types": [
            {"name": "cpx11", "description": "CPX 11", "cores": 2, "memory": 2.0, "disk": 40, "architecture": "x86", "deprecation": null,
             "prices": [{"location": "ash", "price_monthly": {"gross": "5.49"}}]},
            {"name": "old1", "description": "Old", "cores": 1, "memory": 1.0, "disk": 10, "architecture": "x86", "deprecation": {"announced": "2025-01-01"}, "prices": []}]})))
        }))
        .with_state(state.clone());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, state)
}

// ---- mock Cloudflare ------------------------------------------------------------------------------

type C = Arc<Mutex<Vec<Value>>>;

async fn start_cloudflare() -> (String, C) {
    let recs: C = Arc::new(Mutex::new(vec![
        // Not ours: must never be touched.
        json!({"id": "pre1", "type": "A", "name": "app.example.test", "content": "203.0.113.99", "comment": "hand-made", "proxied": false}),
    ]));
    let app = Router::new()
        .route("/zones/:zone/dns_records", get(|State(r): State<C>, Query(q): Query<HashMap<String, String>>| async move {
            let name = q.get("name").cloned().unwrap_or_default();
            let list: Vec<Value> = r.lock().unwrap().iter().filter(|x| x["name"] == json!(name)).cloned().collect();
            Json(json!({"success": true, "result": list}))
        }).post(|State(r): State<C>, Json(mut b): Json<Value>| async move {
            let id = format!("rec{}", r.lock().unwrap().len() + 1000 + rand_suffix());
            b["id"] = json!(id);
            r.lock().unwrap().push(b);
            Json(json!({"success": true, "result": {"id": id}}))
        }))
        .route("/zones/:zone/dns_records/:id", axum::routing::delete(|State(r): State<C>, Path((_z, id)): Path<(String, String)>| async move {
            r.lock().unwrap().retain(|x| x["id"] != json!(id));
            Json(json!({"success": true, "result": {"id": id}}))
        }))
        .with_state(recs.clone());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, recs)
}

fn rand_suffix() -> usize {
    static N: AtomicU32 = AtomicU32::new(0);
    N.fetch_add(1, Ordering::Relaxed) as usize
}

fn managed_ips(c: &C, name: &str) -> Vec<String> {
    let mut v: Vec<String> = c.lock().unwrap().iter().filter(|x| x["name"] == json!(name) && x["comment"] == json!("edge-lb:managed")).map(|x| x["content"].as_str().unwrap().to_string()).collect();
    v.sort();
    v
}

// ---- in-process "machines" ---------------------------------------------------------------------------

#[derive(Default)]
struct Machines {
    edges: tokio::sync::Mutex<HashMap<String, EdgeHandle>>,
    fail_install: Mutex<Option<String>>,
    dir: std::path::PathBuf,
}

#[async_trait]
impl Bootstrapper for Machines {
    async fn probe(&self, _t: &Target) -> anyhow::Result<()> {
        Ok(())
    }
    async fn install(&self, t: &Target, ctx: &InstallCtx) -> anyhow::Result<Installed> {
        if let Some(m) = self.fail_install.lock().unwrap().clone() {
            anyhow::bail!(m);
        }
        let h = start_edge(&self.dir.join(&t.edge_id), SocketAddr::new(t.ip, 0), &ctx.ca_pem).await;
        let out = Installed { cert_pem: h.cert_pem.clone(), mgmt_port: h.addr.port() };
        self.edges.lock().await.insert(t.edge_id.clone(), h);
        Ok(out)
    }
    async fn uninstall(&self, t: &Target) -> anyhow::Result<()> {
        if let Some(h) = self.edges.lock().await.remove(&t.edge_id) {
            h.stop().await;
        }
        Ok(())
    }
    async fn forget(&self, _t: &Target) {}
}

async fn start_edge(dir: &std::path::Path, mgmt: SocketAddr, ca: &str) -> EdgeHandle {
    edge::start(EdgeOptions {
        mgmt,
        controller_ca_pem: ca.to_string(),
        engine: EngineOptions {
            data_dir: dir.to_path_buf(),
            reserved_ports: vec![],
            health_interval: Duration::from_millis(100),
            maintenance_interval: Duration::from_millis(100),
            ..Default::default()
        },
    })
    .await
    .unwrap()
}

impl Machines {
    /// Simulate an outage: the machine stops answering.
    async fn kill(&self, id: &str) -> SocketAddr {
        let h = self.edges.lock().await.remove(id).unwrap();
        let addr = h.addr;
        h.stop().await;
        addr
    }
    /// Bring it back with the same identity (data dir) on the same address.
    async fn revive(&self, id: &str, addr: SocketAddr, ca: &str) {
        let h = start_edge(&self.dir.join(id), addr, ca).await;
        self.edges.lock().await.insert(id.to_string(), h);
    }
}

// ---- harness ---------------------------------------------------------------------------------------------

struct Rig {
    ctl: Arc<Controller>,
    machines: Arc<Machines>,
    hz: H,
    cf: C,
    dir: std::path::PathBuf,
}

fn tmp(tag: &str) -> std::path::PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let d = std::env::temp_dir().join(format!("edge-lbd-fleet-{tag}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn opts(dir: &std::path::Path, machines: Arc<Machines>, hz: &str, cf: &str) -> Options {
    let mut o = Options::new(dir.join("ctl"));
    o.bootstrapper = Some(machines);
    o.hetzner_base = hz.to_string();
    o.cloudflare_base = cf.to_string();
    o.tick = Duration::from_millis(40);
    o.poll_every = Duration::from_millis(100);
    o.retry_backoff = (Duration::from_millis(30), Duration::from_millis(200));
    o
}

async fn rig(tag: &str) -> Rig {
    let dir = tmp(tag);
    let (hz_url, hz) = start_hetzner().await;
    let (cf_url, cf) = start_cloudflare().await;
    let machines = Arc::new(Machines { dir: dir.join("machines"), ..Default::default() });
    let ctl = Controller::start(opts(&dir, machines.clone(), &hz_url, &cf_url)).await.unwrap();
    ctl.update_settings(
        "test",
        serde_json::from_value(json!({
            "hetzner_token": TOKEN, "drain_seconds": 1,
            "dns": {"cloudflare_token": "cf-secret", "zone_id": "zone1", "names": ["app.example.test"], "ttl": 120}
        }))
        .unwrap(),
    )
    .unwrap();
    Rig { ctl, machines, hz, cf, dir }
}

fn hetzner_edge(name: &str, region: &str) -> NewEdge {
    NewEdge { name: name.into(), region: region.into(), provider: ProviderSpec::Hetzner { location: "ash".into(), server_type: "cpx11".into() }, ip: None, ssh_user: None, ssh_port: None, mgmt_port: None }
}

async fn wait_for<F: FnMut() -> bool>(what: &str, mut f: F) {
    for _ in 0..300 {
        if f() {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn status_of(ctl: &Controller, id: &str) -> Option<EdgeStatus> {
    ctl.edges().into_iter().find(|e| e.edge.id == id).map(|e| e.edge.status)
}

async fn echo_backend(tag: &'static str) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let _ = s.write_all(tag.as_bytes()).await;
        }
    });
    port
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
}

fn croute(name: &str, ip: &str, port: u16, target: u16, edges: &[&str]) -> edge_lbd::controller::model::CRoute {
    let route: Route = serde_json::from_value(json!({
        "name": name, "listen": {"ip": ip, "port": port}, "targets": [{"address": "127.0.0.1", "port": target}]
    }))
    .unwrap();
    edge_lbd::controller::model::CRoute { route, edges: edges.iter().map(|s| s.to_string()).collect() }
}

async fn fetch(addr: SocketAddr) -> String {
    let mut c = TcpStream::connect(addr).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), c.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

// ---- tests ---------------------------------------------------------------------------------------------------

#[tokio::test]
async fn full_lifecycle_create_serve_fail_recover_drain_delete() {
    let r = rig("full").await;
    let (east_backend, west_backend) = (echo_backend("EAST").await, echo_backend("WEST").await);
    let (p_east, p_west) = (free_port().await, free_port().await);

    // Routes scoped to edges that don't exist yet are refused...
    assert!(matches!(r.ctl.create_route("t", croute("web-east", "127.0.0.1", p_east, east_backend, &["us-east"])), Err(CtlError::Invalid(_))));

    // ...so create the edge first. The controller asks Hetzner for a server, installs, pins, joins.
    let e = r.ctl.create_edge("t", hetzner_edge("US East", "us-east")).unwrap();
    assert_eq!(e.id, "us-east");
    wait_for("us-east healthy", || status_of(&r.ctl, "us-east") == Some(EdgeStatus::Healthy)).await;

    {
        let st = r.hz.lock().unwrap();
        assert_eq!(st.post_servers.len(), 1, "exactly one server requested");
        let req = &st.post_servers[0];
        assert_eq!(req["location"], "ash");
        assert_eq!(req["server_type"], "cpx11");
        assert_eq!(req["image"], "debian-12");
        assert_eq!(req["labels"]["edge-lb-id"], "us-east", "label lets us find the server again after a crash");
        assert_eq!(st.ssh_keys.len(), 1, "the controller's SSH key was registered with the project");
        assert!(st.ssh_keys[0]["public_key"].as_str().unwrap().starts_with("ssh-ed25519 "));
    }
    wait_for("DNS for the first edge", || managed_ips(&r.cf, "app.example.test") == ["127.0.0.1"]).await;
    // The hand-made record is untouched and not counted as ours.
    assert!(r.cf.lock().unwrap().iter().any(|x| x["id"] == json!("pre1")));
    let rec = r.cf.lock().unwrap().iter().find(|x| x["content"] == json!("127.0.0.1")).cloned().unwrap();
    assert_eq!(rec["proxied"], json!(false), "proxying would break TLS passthrough");

    // A scoped route reaches the edge and carries traffic.
    r.ctl.create_route("t", croute("web-east", "127.0.0.1", p_east, east_backend, &["us-east"])).unwrap();
    wait_for("route live on us-east", || {
        r.ctl.edges()[0].live.as_ref().and_then(|l| l.status.as_ref()).is_some_and(|s| s["routes"].as_array().is_some_and(|a| a.len() == 1))
    })
    .await;
    assert_eq!(fetch(format!("127.0.0.1:{p_east}").parse().unwrap()).await, "EAST");

    // A second edge in another region gets only its own routes.
    r.ctl.create_edge("t", hetzner_edge("US West", "us-west")).unwrap();
    wait_for("us-west healthy", || status_of(&r.ctl, "us-west") == Some(EdgeStatus::Healthy)).await;
    r.ctl.create_route("t", croute("web-west", "127.0.0.2", p_west, west_backend, &["us-west"])).unwrap();
    wait_for("route live on us-west", || {
        r.ctl.edges().iter().find(|e| e.edge.id == "us-west").and_then(|e| e.live.as_ref()).and_then(|l| l.status.as_ref()).is_some_and(|s| s["routes"].as_array().is_some_and(|a| a.len() == 1))
    })
    .await;
    assert_eq!(fetch(format!("127.0.0.2:{p_west}").parse().unwrap()).await, "WEST");
    let east_live = r.ctl.edges()[0].live.clone().unwrap().status.unwrap();
    assert_eq!(east_live["routes"].as_array().unwrap().len(), 1, "east must not receive west's route");
    wait_for("both edges in DNS", || managed_ips(&r.cf, "app.example.test") == ["127.0.0.1", "127.0.0.2"]).await;

    // Outage: east stops answering -> Unreachable, and it leaves DNS while west stays.
    let east_addr = r.machines.kill("us-east").await;
    wait_for("us-east unreachable", || status_of(&r.ctl, "us-east") == Some(EdgeStatus::Unreachable)).await;
    wait_for("DNS drops the dead edge", || managed_ips(&r.cf, "app.example.test") == ["127.0.0.2"]).await;
    // Recovery with the same identity: pinned cert still matches, edge comes back by itself.
    let ca = r.ctl.store.read(|s| s.ca.cert.clone());
    r.machines.revive("us-east", east_addr, &ca).await;
    wait_for("us-east recovers", || status_of(&r.ctl, "us-east") == Some(EdgeStatus::Healthy)).await;
    wait_for("DNS restores it", || managed_ips(&r.cf, "app.example.test") == ["127.0.0.1", "127.0.0.2"]).await;
    // The revived edge was restarted from its own disk: its route is still there.
    wait_for("route survives edge restart", || fetch_ok(format!("127.0.0.1:{p_east}").parse().unwrap())).await;

    // Deleting an edge drains it, destroys the server, and disables routes that only ran there.
    r.ctl.delete_edge("t", "us-east", false).unwrap();
    assert_eq!(status_of(&r.ctl, "us-east"), Some(EdgeStatus::Draining));
    wait_for("us-east gone", || status_of(&r.ctl, "us-east").is_none()).await;
    assert_eq!(r.hz.lock().unwrap().deleted.len(), 1, "the billed server was destroyed");
    assert_eq!(r.hz.lock().unwrap().servers.len(), 1);
    let routes = r.ctl.routes();
    let east_route = routes.iter().find(|x| x.route.id == "web-east").unwrap();
    assert!(!east_route.route.enabled && east_route.edges.is_empty(), "a route must not silently widen to every edge");
    wait_for("DNS only west", || managed_ips(&r.cf, "app.example.test") == ["127.0.0.2"]).await;

    // The last healthy edge is protected from accidental deletion...
    let err = r.ctl.delete_edge("t", "us-west", false).unwrap_err();
    assert!(matches!(err, CtlError::Conflict(ref m) if m.contains("last healthy")), "{err:?}");
    // ...unless forced. DNS then fails static: stale records beat an empty answer.
    r.ctl.delete_edge("t", "us-west", true).unwrap();
    wait_for("us-west gone", || status_of(&r.ctl, "us-west").is_none()).await;
    assert!(r.hz.lock().unwrap().servers.is_empty(), "no orphaned servers left billing");
    sleep(Duration::from_millis(300)).await;
    assert_eq!(managed_ips(&r.cf, "app.example.test"), ["127.0.0.2"], "last records are held, not withdrawn");
    assert!(r.ctl.dns_status().held);

    // The audit trail recorded the story.
    let actions: Vec<String> = r.ctl.audit.tail(100).iter().map(|v| v["action"].as_str().unwrap().to_string()).collect();
    for a in ["edge.create", "edge.healthy", "edge.unreachable", "edge.delete", "edge.removed", "route.create", "dns.sync"] {
        assert!(actions.iter().any(|x| x == a), "missing audit action {a}: {actions:?}");
    }
    let _ = std::fs::remove_dir_all(&r.dir);
}

fn fetch_ok(addr: SocketAddr) -> bool {
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

#[tokio::test]
async fn adopts_an_existing_server_instead_of_creating_a_duplicate() {
    // Simulates a crash after "create server" but before the controller recorded its id.
    let r = rig("adopt").await;
    r.hz.lock().unwrap().servers.push(json!({"id": 7, "name": "edge-lb-orphan", "status": "running", "labels": {"edge-lb-id": "orphan"}, "public_net": {"ipv4": {"ip": "127.0.0.1"}}}));
    r.ctl.create_edge("t", hetzner_edge("orphan", "x")).unwrap();
    wait_for("orphan healthy", || status_of(&r.ctl, "orphan") == Some(EdgeStatus::Healthy)).await;
    assert!(r.hz.lock().unwrap().post_servers.is_empty(), "must not pay for a second server");
    assert_eq!(r.ctl.edges()[0].edge.server_id.as_deref(), Some("7"));
}

#[tokio::test]
async fn failures_are_reported_and_never_leave_a_billed_server_behind() {
    let r = rig("fail").await;
    // Server gets created, but installing onto it keeps failing.
    *r.machines.fail_install.lock().unwrap() = Some("disk full".into());
    r.ctl.create_edge("t", hetzner_edge("broken", "x")).unwrap();
    wait_for("broken failed", || status_of(&r.ctl, "broken") == Some(EdgeStatus::Failed)).await;
    let e = r.ctl.edges()[0].edge.clone();
    assert!(e.error.unwrap().contains("disk full"));
    assert_eq!(r.hz.lock().unwrap().servers.len(), 1, "a server exists and is billing");
    assert!(managed_ips(&r.cf, "app.example.test").is_empty(), "a failed edge never enters DNS");

    // Deleting the failed edge destroys that server.
    r.ctl.delete_edge("t", "broken", false).unwrap();
    wait_for("broken removed", || status_of(&r.ctl, "broken").is_none()).await;
    assert!(r.hz.lock().unwrap().servers.is_empty());

    // Retry after fixing the cause: a new edge with the same name succeeds.
    *r.machines.fail_install.lock().unwrap() = None;
    r.ctl.create_edge("t", hetzner_edge("broken", "x")).unwrap();
    wait_for("second attempt healthy", || status_of(&r.ctl, "broken") == Some(EdgeStatus::Healthy)).await;

    // A bad API token fails fast with a clear message and creates nothing.
    r.hz.lock().unwrap().reject_auth = true;
    r.ctl.create_edge("t", hetzner_edge("nope", "x")).unwrap();
    wait_for("nope failed", || status_of(&r.ctl, "nope") == Some(EdgeStatus::Failed)).await;
    let err = r.ctl.edges().into_iter().find(|e| e.edge.id == "nope").unwrap().edge.error.unwrap();
    assert!(err.contains("token") || err.contains("unable to authenticate"), "{err}");
    assert_eq!(r.hz.lock().unwrap().post_servers.len(), 2, "no further servers requested with a bad token");
}

#[tokio::test]
async fn guards_on_creating_edges() {
    let dir = tmp("guards");
    let (hz_url, _hz) = start_hetzner().await;
    let machines = Arc::new(Machines { dir: dir.join("m"), ..Default::default() });
    let ctl = Controller::start(opts(&dir, machines, &hz_url, "http://127.0.0.1:1")).await.unwrap();

    // No token yet.
    assert!(matches!(ctl.create_edge("t", hetzner_edge("a", "")), Err(CtlError::Invalid(ref m)) if m[0].contains("token")));
    ctl.update_settings("t", SettingsUpdate { hetzner_token: Some(TOKEN.into()), max_edges: Some(2), ..Default::default() }).unwrap();

    // Option-injection through the SSH user is rejected outright.
    let mut bad = hetzner_edge("evil", "");
    bad.ssh_user = Some("-oProxyCommand=curl evil".into());
    assert!(matches!(ctl.create_edge("t", bad), Err(CtlError::Invalid(_))));
    // A manual edge needs an IP.
    let manual = |ip: Option<&str>| NewEdge { name: "m".into(), region: "".into(), provider: ProviderSpec::Manual, ip: ip.map(|s| s.parse().unwrap()), ssh_user: None, ssh_port: None, mgmt_port: Some(7500) };
    assert!(matches!(ctl.create_edge("t", manual(None)), Err(CtlError::Invalid(_))));
    assert!(matches!(ctl.create_edge("t", manual(Some("0.0.0.0"))), Err(CtlError::Invalid(_))));

    // Cost guard.
    ctl.create_edge("t", hetzner_edge("one", "")).unwrap();
    ctl.create_edge("t", hetzner_edge("two", "")).unwrap();
    let err = ctl.create_edge("t", hetzner_edge("three", "")).unwrap_err();
    assert!(matches!(err, CtlError::Invalid(ref m) if m[0].contains("limit")), "{err:?}");
    // Same display name gets a distinct id.
    ctl.update_settings("t", SettingsUpdate { max_edges: Some(5), ..Default::default() }).unwrap();
    assert_eq!(ctl.create_edge("t", hetzner_edge("one", "")).unwrap().id, "one-2");

    // Settings never echo secrets back.
    let view = serde_json::to_string(&ctl.settings_view()).unwrap();
    assert!(!view.contains(TOKEN) && view.contains("\"hetzner_token_set\":true"));
}

#[tokio::test]
async fn route_scoping_is_validated_per_edge() {
    let r = rig("scope").await;
    for n in ["alpha", "beta"] {
        r.ctl.create_edge("t", hetzner_edge(n, n)).unwrap();
    }
    wait_for("both healthy", || ["alpha", "beta"].iter().all(|i| status_of(&r.ctl, i) == Some(EdgeStatus::Healthy))).await;
    let b = echo_backend("X").await;
    let p = free_port().await;
    let with_domain = |name: &str, edges: &[&str]| {
        let mut c = croute(name, "0.0.0.0", p, b, edges);
        c.route.domains = vec!["same.example.test".into()];
        c
    };
    // The same domain+listener on *different* edges is fine (they are different machines)...
    r.ctl.create_route("t", with_domain("on-alpha", &["alpha"])).unwrap();
    r.ctl.create_route("t", with_domain("on-beta", &["beta"])).unwrap();
    // ...but not twice on one edge, nor when one of them applies to every edge.
    assert!(matches!(r.ctl.create_route("t", with_domain("again-alpha", &["alpha"])), Err(CtlError::Invalid(_))));
    let err = r.ctl.create_route("t", with_domain("everywhere", &[])).unwrap_err();
    assert!(matches!(err, CtlError::Invalid(ref m) if m.iter().any(|x| x.contains("same.example.test"))), "{err:?}");
    // The management port and SSH are reserved on every edge.
    assert!(matches!(r.ctl.create_route("t", croute("ssh", "0.0.0.0", 22, b, &[])), Err(CtlError::Invalid(_))));
    assert!(matches!(r.ctl.create_route("t", croute("mgmt", "0.0.0.0", 7443, b, &[])), Err(CtlError::Invalid(_))));
    assert_eq!(r.ctl.routes().len(), 2, "rejected routes leave no trace");
}

#[tokio::test]
async fn controller_restart_resumes_without_disturbing_edges() {
    let dir = tmp("restart");
    let (hz_url, hz) = start_hetzner().await;
    let (cf_url, _cf) = start_cloudflare().await;
    let machines = Arc::new(Machines { dir: dir.join("m"), ..Default::default() });
    let ctl = Controller::start(opts(&dir, machines.clone(), &hz_url, &cf_url)).await.unwrap();
    ctl.update_settings("t", SettingsUpdate { hetzner_token: Some(TOKEN.into()), ..Default::default() }).unwrap();
    ctl.create_edge("t", hetzner_edge("keep", "")).unwrap();
    wait_for("healthy", || status_of(&ctl, "keep") == Some(EdgeStatus::Healthy)).await;
    let backend = echo_backend("OK").await;
    let p = free_port().await;
    ctl.create_route("t", croute("svc", "127.0.0.1", p, backend, &[])).unwrap();
    wait_for("route applied", || fetch_ok(format!("127.0.0.1:{p}").parse().unwrap())).await;
    wait_for("controller recorded the push", || {
        ctl.store.read(|s| s.edges[0].applied_hash.as_deref() == Some(edge_lbd::controller::model::routes_hash(&s.routes_for("keep")).as_str()))
    })
    .await;
    let (fp, applied) = ctl.store.read(|s| (s.edges[0].mgmt_fingerprint.clone(), s.edges[0].applied_hash.clone()));
    ctl.stop();
    drop(ctl);

    // New controller process on the same data dir.
    let ctl2 = Controller::start(opts(&dir, machines, &hz_url, "http://127.0.0.1:1")).await.unwrap();
    assert_eq!(status_of(&ctl2, "keep"), Some(EdgeStatus::Healthy), "state was persisted");
    assert_eq!(ctl2.store.read(|s| s.edges[0].mgmt_fingerprint.clone()), fp, "pin survives restart");
    wait_for("polling resumed", || ctl2.edges()[0].live.as_ref().is_some_and(|l| l.reachable)).await;
    assert_eq!(ctl2.store.read(|s| s.edges[0].applied_hash.clone()), applied, "no needless re-push");
    assert_eq!(hz.lock().unwrap().post_servers.len(), 1, "no second server");
    assert_eq!(fetch(format!("127.0.0.1:{p}").parse().unwrap()).await, "OK");
}

#[tokio::test]
async fn catalog_hides_deprecated_server_types() {
    let (hz_url, _hz) = start_hetzner().await;
    let h = edge_lbd::controller::providers::Hetzner::new(&hz_url, TOKEN).unwrap();
    let cat = h.catalog().await.unwrap();
    assert_eq!(cat.locations.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(), ["ash", "hil"]);
    assert_eq!(cat.locations[0].network_zone, "us-east");
    assert_eq!(cat.server_types.len(), 1, "deprecated types are hidden");
    assert_eq!(cat.server_types[0].prices[0].monthly, 5.49);
    assert!(edge_lbd::controller::providers::Hetzner::new(&hz_url, "wrong").unwrap().catalog().await.unwrap_err().to_string().contains("token"));
}
