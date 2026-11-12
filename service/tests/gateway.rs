//! Managed WireGuard, minus the kernel: a real controller with its TLS gateway listener, a real
//! gateway agent talking to it, and the edge's handling of WireGuard state. Only the final
//! `wg`/`ip`/`nft` calls are replaced by a recorder; the live tunnel is exercised separately in
//! containers (tests/wireguard-e2e.sh).

use async_trait::async_trait;
use edge_lbd::controller::model::{CRoute, Edge, EdgeStatus};
use edge_lbd::controller::sites::{GatewayListen, NewSite, SiteUpdate};
use edge_lbd::controller::{Controller, CtlError, Options, SettingsUpdate};
use edge_lbd::edge::{self, EdgeOptions};
use edge_lbd::edge_client::{ClientError, EdgeClient};
use edge_lbd::gateway::{self, Handshake, HostWg};
use edge_lbd::wg::{self, Desired, Peer};
use edge_lbd::{pki, tls};
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;

const K_EDGE: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const K_GW: &str = "gN8FfqbA3XQ2o6a0lYtB5g2f6Tn9m7yV1m0zq3K4s2A=";

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("edge-lbd-gw-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

async fn wait_for<F: FnMut() -> bool>(what: &str, mut f: F) {
    for _ in 0..200 {
        if f() {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

/// A controller that isn't running its fleet loop (no SSH, no polling): these tests drive the
/// store directly and only care about sites and gateways.
async fn controller(tag: &str) -> (Arc<Controller>, PathBuf) {
    let dir = tmp(tag);
    let mut o = Options::new(dir.join("ctl"));
    o.tick = Duration::from_secs(3600);
    o.edge_binary = dir.join("fake-binary");
    std::fs::write(&o.edge_binary, b"#!fake-binary").unwrap();
    o.gateway = Some(GatewayListen { listen: "127.0.0.1:0".parse().unwrap(), host: "127.0.0.1".into() });
    let ctl = Controller::start(o).await.unwrap();
    // The reconcile loop's first tick is immediate; let it pass while there are no edges, so it
    // never tries to poll the fake ones these tests insert.
    sleep(Duration::from_millis(50)).await;
    (ctl, dir)
}

fn add_edge(ctl: &Controller, id: &str, ip: &str, key: Option<&str>, status: EdgeStatus) {
    let e: Edge = serde_json::from_value(json!({
        "id": id, "name": id, "region": "", "provider": {"kind": "manual"}, "server_id": null, "ip": ip,
        "ssh_user": "root", "ssh_port": 22, "mgmt_port": 7443, "mgmt_fingerprint": null, "status": status,
        "error": null, "created_at": 0, "status_since": 0, "applied_hash": null, "drain_started": null,
        "wg_public_key": key,
    }))
    .unwrap();
    ctl.store.update(|s| s.edges.push(e)).unwrap();
    ctl.store.update(|s| s.assign_addresses()).unwrap();
}

fn site(ctl: &Controller, name: &str, cidrs: &[&str]) -> Result<String, CtlError> {
    ctl.create_site("t", NewSite { name: name.into(), lan_cidrs: cidrs.iter().map(|s| s.to_string()).collect() }).map(|v| v.id)
}

fn croute(name: &str, target: &str, site: Option<&str>) -> CRoute {
    serde_json::from_value(json!({
        "name": name, "listen": {"ip": "127.0.0.1", "port": 8443}, "domains": [name],
        "targets": [{"address": target, "port": 443}], "site": site,
    }))
    .unwrap()
}

/// reqwest client that trusts exactly the controller's gateway certificate.
fn pinned_http(ctl: &Controller) -> (reqwest::Client, String, String) {
    let pem = ctl.store.read(|s| s.gateway_tls.clone().unwrap());
    let fp = pki::fingerprint_pem(&pem.cert).unwrap();
    let http = reqwest::Client::builder().use_preconfigured_tls(tls::pinned_client_config_no_auth(&fp).unwrap()).build().unwrap();
    (http, ctl.gateway_endpoint().unwrap().hostport, fp)
}

fn token_of(command: &str) -> String {
    command.split("/gw/install/").nth(1).unwrap().split('\'').next().unwrap().to_string()
}

// ---- sites and routes ------------------------------------------------------------------------------

#[tokio::test]
async fn sites_validate_ranges_and_routes_must_stay_inside_them() {
    let (ctl, _d) = controller("sites").await;
    let home = site(&ctl, "Home", &["192.168.1.0/24"]).unwrap();
    assert_eq!(home, "home");

    // Bad ranges, each with a reason.
    for (cidrs, why) in [
        (vec!["192.168.1.0/25"], "overlaps"),
        (vec!["10.100.0.0/24"], "tunnel network"),
        (vec!["0.0.0.0/0"], "too broad"),
        (vec!["169.254.169.254/32"], "link-local"),
        (vec!["192.168.9.5/24"], "host bits"),
        (vec![], "at least one"),
    ] {
        let err = site(&ctl, "Other", &cidrs).unwrap_err();
        let CtlError::Invalid(d) = err else { panic!("{err:?}") };
        assert!(d.iter().any(|m| m.contains(why)), "{cidrs:?} should mention '{why}': {d:?}");
    }
    assert_eq!(site(&ctl, "Cabin", &["192.168.2.0/24"]).unwrap(), "cabin");

    // A site gets a tunnel address immediately.
    assert!(ctl.sites()[0].gateway.tunnel_ip.is_some());

    // Routes: inside the site is fine, outside is not, and an un-sited route may not point into one.
    ctl.create_route("t", croute("good.test", "192.168.1.50", Some("home"))).unwrap();
    let outside = ctl.create_route("t", croute("bad.test", "192.168.7.50", Some("home"))).unwrap_err();
    assert!(format!("{outside:?}").contains("outside site"), "{outside:?}");
    let unsited = ctl.create_route("t", croute("sneaky.test", "192.168.1.60", None)).unwrap_err();
    assert!(format!("{unsited:?}").contains("set the route's site"), "{unsited:?}");
    let v6 = ctl.create_route("t", croute("v6.test", "fd00::1", Some("home"))).unwrap_err();
    assert!(format!("{v6:?}").contains("IPv6"), "{v6:?}");
    let ghost = ctl.create_route("t", croute("ghost.test", "192.168.1.5", Some("nope"))).unwrap_err();
    assert!(format!("{ghost:?}").contains("unknown site"), "{ghost:?}");
    ctl.create_route("t", croute("public.test", "203.0.113.9", None)).unwrap();

    // A site in use can't be deleted or shrunk out from under its routes.
    let in_use = ctl.delete_site("t", "home").unwrap_err();
    assert!(matches!(in_use, CtlError::Conflict(_)) && in_use.to_string().contains("good.test"), "{in_use:?}");
    let shrink = ctl.update_site("t", "home", SiteUpdate { lan_cidrs: Some(vec!["192.168.1.128/25".into()]), ..Default::default() }).unwrap_err();
    assert!(format!("{shrink:?}").contains("outside site"), "{shrink:?}");
    assert_eq!(ctl.sites().iter().find(|s| s.id == "home").unwrap().lan_cidrs, ["192.168.1.0/24"], "failed update changed nothing");
    ctl.update_site("t", "home", SiteUpdate { lan_cidrs: Some(vec!["192.168.1.0/24".into(), "192.168.3.0/24".into()]), ..Default::default() }).unwrap();

    ctl.delete_route("t", "good-test").unwrap();
    ctl.delete_site("t", "home").unwrap();
    assert_eq!(ctl.sites().len(), 1);
}

#[tokio::test]
async fn tunnel_network_is_fixed_once_sites_exist() {
    let (ctl, _d) = controller("netset").await;
    let bad = ctl.update_settings("t", SettingsUpdate { wg_network: Some("8.8.8.0/24".into()), ..Default::default() }).unwrap_err();
    assert!(format!("{bad:?}").contains("must be inside"));
    add_edge(&ctl, "e1", "203.0.113.1", Some(K_EDGE), EdgeStatus::Healthy);
    let before = ctl.edges()[0].edge.tunnel_ip.unwrap();
    assert_eq!(before.octets()[..3], [10, 100, 0]);
    let v = ctl.update_settings("t", SettingsUpdate { wg_network: Some("172.30.0.0/24".into()), wg_port: Some(51999), ..Default::default() }).unwrap();
    assert_eq!((v.wg_network.as_str(), v.wg_port), ("172.30.0.0/24", 51999));
    ctl.store.update(|s| s.assign_addresses()).unwrap();
    assert_eq!(ctl.edges()[0].edge.tunnel_ip.unwrap().octets()[..3], [172, 30, 0], "edges move into the new network");

    site(&ctl, "Home", &["192.168.1.0/24"]).unwrap();
    let locked = ctl.update_settings("t", SettingsUpdate { wg_network: Some("10.50.0.0/24".into()), ..Default::default() }).unwrap_err();
    assert!(format!("{locked:?}").contains("sites exist"));
    ctl.update_settings("t", SettingsUpdate { wg_port: Some(51888), ..Default::default() }).unwrap();
}

// ---- enrolment ---------------------------------------------------------------------------------------

#[tokio::test]
async fn enrolment_tokens_are_single_use_expire_and_reveal_nothing() {
    let (ctl, _d) = controller("enrol").await;
    site(&ctl, "Home", &["192.168.1.0/24"]).unwrap();
    let (http, host, fp) = pinned_http(&ctl);

    // The command pins the controller's key and points at the gateway listener, not the admin UI.
    let info = ctl.start_enrolment("t", "home").unwrap();
    assert!(info.command.contains("--pinnedpubkey 'sha256//") && info.command.contains(&format!("https://{host}/gw/install/")), "{}", info.command);
    let token = token_of(&info.command);
    assert_eq!(token.len(), 64);

    // The script is served to the token holder, with the pin and fingerprint baked in; the stored
    // token is only a hash.
    let script = http.get(format!("https://{host}/gw/install/{token}")).send().await.unwrap();
    assert_eq!(script.status(), 200);
    let script = script.text().await.unwrap();
    assert!(script.contains(&format!("--pin {fp}")) && script.contains(&token) && !script.contains('@'));
    assert!(!std::fs::read_to_string(_d.join("ctl/controller.json")).unwrap().contains(&token), "token stored in clear");
    let bin = http.get(format!("https://{host}/gw/binary/{token}")).send().await.unwrap();
    assert_eq!(bin.bytes().await.unwrap().as_ref(), b"#!fake-binary");

    let enrol = |tok: String, key: &'static str| {
        let (http, host) = (http.clone(), host.clone());
        async move { http.post(format!("https://{host}/gw/v1/enroll")).json(&json!({"token": tok, "public_key": key, "version": "t"})).send().await.unwrap() }
    };
    // Garbage and a malformed key are refused without saying why.
    assert_eq!(enrol("00".repeat(32), K_GW).await.status(), 401);
    assert_eq!(enrol("short".into(), K_GW).await.status(), 401);
    assert_eq!(enrol(token.clone(), "not a key").await.status(), 422);
    // A key already used by an edge can't also be a gateway.
    add_edge(&ctl, "e1", "203.0.113.1", Some(K_EDGE), EdgeStatus::Healthy);
    assert_eq!(enrol(token.clone(), K_EDGE).await.status(), 422);
    assert!(ctl.sites()[0].gateway.enrol_pending_until.is_some(), "a failed attempt doesn't burn the token");

    let ok = enrol(token.clone(), K_GW).await;
    assert_eq!(ok.status(), 200);
    let body: Value = ok.json().await.unwrap();
    assert_eq!(body["secret"].as_str().unwrap().len(), 64);
    assert!(!std::fs::read_to_string(_d.join("ctl/controller.json")).unwrap().contains(body["secret"].as_str().unwrap()), "secret stored in clear");
    let g = &ctl.sites()[0].gateway;
    assert!(g.enrolled && g.public_key.as_deref() == Some(K_GW) && g.enrol_pending_until.is_none());

    // Single use: replay, and the installer for a spent token, are both refused.
    assert_eq!(enrol(token.clone(), K_GW).await.status(), 401);
    assert_eq!(http.get(format!("https://{host}/gw/install/{token}")).send().await.unwrap().status(), 401);
    assert_eq!(http.get(format!("https://{host}/gw/binary/{token}")).send().await.unwrap().status(), 401);

    // Expiry.
    let t2 = token_of(&ctl.start_enrolment("t", "home").unwrap().command);
    ctl.store.update(|s| s.sites[0].gateway.enrol.as_mut().unwrap().expires = 1).unwrap();
    assert_eq!(enrol(t2.clone(), "gN8FfqbA3XQ2o6a0lYtB5g2f6Tn9m7yV1m0zq3K4s2A=").await.status(), 401, "expired");
    assert_eq!(http.get(format!("https://{host}/gw/install/{t2}")).send().await.unwrap().status(), 401);
}

#[tokio::test]
async fn sync_needs_the_secret_and_only_the_gateway_listener_serves_it() {
    let (ctl, _d) = controller("auth").await;
    site(&ctl, "Home", &["192.168.1.0/24"]).unwrap();
    let (http, host, _) = pinned_http(&ctl);
    let url = format!("https://{host}/gw/v1/sync");
    let body = json!({"version": "t", "handshakes": []});
    assert_eq!(http.post(&url).json(&body).send().await.unwrap().status(), 401, "no credentials");
    assert_eq!(http.post(&url).bearer_auth("wrong").json(&body).send().await.unwrap().status(), 401);
    assert_eq!(http.post(&url).bearer_auth("00".repeat(32)).json(&body).send().await.unwrap().status(), 401);
    // The admin API and UI aren't on this listener.
    for path in ["/api/status", "/", "/api/sites"] {
        assert_eq!(http.get(format!("https://{host}{path}")).send().await.unwrap().status(), 404, "{path}");
    }
    // A client that doesn't pin the right certificate never gets a connection.
    let wrong = reqwest::Client::builder().use_preconfigured_tls(tls::pinned_client_config_no_auth(&"00".repeat(32)).unwrap()).build().unwrap();
    assert!(wrong.post(&url).json(&body).send().await.is_err());
}

#[tokio::test]
async fn enrolment_is_unavailable_without_a_gateway_listener() {
    let dir = tmp("nolisten");
    let mut o = Options::new(dir.join("ctl"));
    o.tick = Duration::from_secs(3600);
    let ctl = Controller::start(o).await.unwrap();
    ctl.create_site("t", NewSite { name: "Home".into(), lan_cidrs: vec!["192.168.1.0/24".into()] }).unwrap();
    let err = ctl.start_enrolment("t", "home").unwrap_err();
    assert!(format!("{err:?}").contains("--gateway-listen"), "{err:?}");
    assert!(ctl.gateway_endpoint().is_none());
}

// ---- the gateway agent -----------------------------------------------------------------------------------

#[derive(Default)]
struct MockHost {
    applied: Mutex<Vec<Desired>>,
    handshakes: Mutex<Vec<Handshake>>,
    fail_apply: Mutex<Option<String>>,
    probed: Mutex<Vec<std::net::Ipv4Addr>>,
}

#[async_trait]
impl HostWg for MockHost {
    async fn ensure_key(&self, path: &Path) -> anyhow::Result<String> {
        std::fs::write(path, "private-key-stays-here\n")?;
        Ok(K_GW.to_string())
    }
    async fn apply(&self, d: &Desired, _key: &Path) -> anyhow::Result<()> {
        if let Some(e) = self.fail_apply.lock().unwrap().clone() {
            anyhow::bail!(e);
        }
        self.applied.lock().unwrap().push(d.clone());
        Ok(())
    }
    async fn handshakes(&self) -> Vec<Handshake> {
        self.handshakes.lock().unwrap().clone()
    }
    async fn probe(&self, targets: &[std::net::Ipv4Addr]) {
        self.probed.lock().unwrap().extend(targets.iter().copied());
    }
}

fn spawn_gateway(ctl: &Controller, dir: &Path, host: Arc<MockHost>, pin: Option<String>) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let (_, hostport, fp) = pinned_http(ctl);
    tokio::spawn(gateway::run(gateway::Options {
        controller: hostport,
        pin: pin.unwrap_or(fp),
        data_dir: dir.to_path_buf(),
        interval: Duration::from_millis(100),
        host,
    }))
}

#[tokio::test]
async fn gateway_enrols_receives_its_peers_and_tracks_edges_coming_and_going() {
    let (ctl, d) = controller("agent").await;
    site(&ctl, "Home", &["192.168.1.0/24"]).unwrap();
    add_edge(&ctl, "e1", "203.0.113.1", Some(K_EDGE), EdgeStatus::Healthy);
    let token = token_of(&ctl.start_enrolment("t", "home").unwrap().command);

    let gwdir = d.join("gw");
    std::fs::create_dir_all(&gwdir).unwrap();
    std::fs::write(gwdir.join("enrol-token"), format!("{token}\n")).unwrap();
    let host = Arc::new(MockHost::default());
    let task = spawn_gateway(&ctl, &gwdir, host.clone(), None);

    wait_for("enrolled", || ctl.sites()[0].gateway.enrolled).await;
    wait_for("the token file is consumed and the identity saved", || !gwdir.join("enrol-token").exists() && gwdir.join("identity.json").exists()).await;
    assert_eq!(std::fs::metadata(gwdir.join("identity.json")).unwrap().permissions().mode() & 0o777, 0o600);

    wait_for("first tunnel config applied", || !host.applied.lock().unwrap().is_empty()).await;
    let d1 = host.applied.lock().unwrap().last().unwrap().clone();
    wg::validate(&d1).unwrap();
    let edge_ip = ctl.edges()[0].edge.tunnel_ip.unwrap();
    let gw_ip = ctl.sites()[0].gateway.tunnel_ip.unwrap();
    assert_eq!(d1.address, format!("{gw_ip}/24"));
    assert_eq!(d1.peers.len(), 1);
    assert_eq!(d1.peers[0].public_key, K_EDGE);
    assert_eq!(d1.peers[0].endpoint.as_deref(), Some("203.0.113.1:51820"));
    assert_eq!(d1.peers[0].allowed_ips, [format!("{edge_ip}/32")]);
    assert_eq!(d1.forward_to, ["192.168.1.0/24"]);
    assert!(gwdir.join("desired.json").exists(), "saved so a reboot can restore tunnels without the controller");

    // With no handshake yet the gateway probes the edge's tunnel address, which is what makes the
    // kernel re-handshake with a peer that silently lost its session.
    wait_for("the stale peer is probed", || host.probed.lock().unwrap().contains(&edge_ip)).await;

    // The controller sees it online and in sync, and reports each tunnel from the gateway's own view.
    *host.handshakes.lock().unwrap() = vec![Handshake { public_key: K_EDGE.into(), age_secs: Some(7) }];
    sleep(Duration::from_millis(300)).await;
    host.probed.lock().unwrap().clear();
    sleep(Duration::from_millis(400)).await;
    assert!(host.probed.lock().unwrap().is_empty(), "a peer with a fresh handshake isn't probed");
    wait_for("online and in sync", || {
        let g = &ctl.sites()[0].gateway;
        g.online && g.in_sync == Some(true) && g.tunnels.first().is_some_and(|t| t.up == Some(true) && t.handshake_age_secs == Some(7))
    })
    .await;

    // A second edge appears: the gateway is told, and nothing is torn down for the first.
    add_edge(&ctl, "e2", "203.0.113.2", Some("not-a-key"), EdgeStatus::Joining);
    // (that key is malformed on purpose: it must never reach the gateway as a peer)
    sleep(Duration::from_millis(400)).await;
    assert!(host.applied.lock().unwrap().iter().all(|d| d.peers.iter().all(|p| wg::is_key(&p.public_key))));
    ctl.store.update(|s| s.edges[1].wg_public_key = Some("fZ3rYq0pQ9hC6w2m1s8vN4xK7tB5jD0aL2eG9uHcR1I=".into())).unwrap();
    wait_for("two peers", || host.applied.lock().unwrap().last().is_some_and(|d| d.peers.len() == 2)).await;

    // An edge being deleted leaves the gateway's peer list.
    ctl.store.update(|s| s.edges[0].status = EdgeStatus::Deleting).unwrap();
    wait_for("one peer left", || host.applied.lock().unwrap().last().is_some_and(|d| d.peers.len() == 1 && d.peers[0].public_key != K_EDGE)).await;
    task.abort();
}

#[tokio::test]
async fn gateway_reports_a_failed_apply_and_retries_until_it_works() {
    let (ctl, d) = controller("applyfail").await;
    site(&ctl, "Home", &["192.168.1.0/24"]).unwrap();
    add_edge(&ctl, "e1", "203.0.113.1", Some(K_EDGE), EdgeStatus::Healthy);
    let token = token_of(&ctl.start_enrolment("t", "home").unwrap().command);
    let gwdir = d.join("gw");
    std::fs::create_dir_all(&gwdir).unwrap();
    std::fs::write(gwdir.join("enrol-token"), &token).unwrap();
    let host = Arc::new(MockHost::default());
    *host.fail_apply.lock().unwrap() = Some("wireguard module missing".into());
    let task = spawn_gateway(&ctl, &gwdir, host.clone(), None);

    wait_for("error surfaced in the controller", || {
        let g = &ctl.sites()[0].gateway;
        g.online && g.error.as_deref().is_some_and(|e| e.contains("wireguard module missing")) && g.in_sync == Some(false)
    })
    .await;
    *host.fail_apply.lock().unwrap() = None;
    wait_for("recovers and clears the error", || {
        let g = &ctl.sites()[0].gateway;
        g.error.is_none() && g.in_sync == Some(true)
    })
    .await;
    task.abort();
}

#[tokio::test]
async fn gateway_with_the_wrong_pin_never_sends_its_token() {
    let (ctl, d) = controller("wrongpin").await;
    site(&ctl, "Home", &["192.168.1.0/24"]).unwrap();
    let token = token_of(&ctl.start_enrolment("t", "home").unwrap().command);
    let gwdir = d.join("gw");
    std::fs::create_dir_all(&gwdir).unwrap();
    std::fs::write(gwdir.join("enrol-token"), &token).unwrap();
    let host = Arc::new(MockHost::default());
    let task = spawn_gateway(&ctl, &gwdir, host.clone(), Some("00".repeat(32)));
    sleep(Duration::from_millis(1200)).await;
    task.abort();
    assert!(!ctl.sites()[0].gateway.enrolled, "enrolled against an unpinned server");
    assert!(ctl.sites()[0].gateway.enrol_pending_until.is_some(), "the token is still unspent");
    assert!(host.applied.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_expired_or_spent_token_stops_the_gateway_cleanly() {
    let (ctl, d) = controller("badtoken").await;
    site(&ctl, "Home", &["192.168.1.0/24"]).unwrap();
    let gwdir = d.join("gw");
    std::fs::create_dir_all(&gwdir).unwrap();
    std::fs::write(gwdir.join("enrol-token"), "ab".repeat(32)).unwrap();
    let host = Arc::new(MockHost::default());
    let err = spawn_gateway(&ctl, &gwdir, host, None).await.unwrap().unwrap_err();
    assert!(err.to_string().contains("not enrolled"), "{err:#}");
    assert!(!gwdir.join("enrol-token").exists(), "a rejected token isn't retried forever");
}

#[tokio::test]
async fn re_enrolling_replaces_the_old_gateway() {
    let (ctl, d) = controller("reenrol").await;
    site(&ctl, "Home", &["192.168.1.0/24"]).unwrap();
    let (http, host, _) = pinned_http(&ctl);
    let enrol = |tok: String, key: &'static str| {
        let (http, host) = (http.clone(), host.clone());
        async move { http.post(format!("https://{host}/gw/v1/enroll")).json(&json!({"token": tok, "public_key": key})).send().await.unwrap().json::<Value>().await.unwrap() }
    };
    let t1 = token_of(&ctl.start_enrolment("t", "home").unwrap().command);
    let first = enrol(t1, K_GW).await;
    let sync = |secret: String| {
        let (http, host) = (http.clone(), host.clone());
        async move { http.post(format!("https://{host}/gw/v1/sync")).bearer_auth(secret).json(&json!({"version": "t"})).send().await.unwrap().status() }
    };
    assert_eq!(sync(first["secret"].as_str().unwrap().into()).await, 200);

    let t2 = token_of(&ctl.start_enrolment("t", "home").unwrap().command);
    let second = enrol(t2, "fZ3rYq0pQ9hC6w2m1s8vN4xK7tB5jD0aL2eG9uHcR1I=").await;
    assert_eq!(sync(first["secret"].as_str().unwrap().into()).await, 401, "the old gateway's secret stops working");
    assert_eq!(sync(second["secret"].as_str().unwrap().into()).await, 200);
    assert_eq!(ctl.sites()[0].gateway.public_key.as_deref(), Some("fZ3rYq0pQ9hC6w2m1s8vN4xK7tB5jD0aL2eG9uHcR1I="));
    drop(d);
}

// ---- the edge's side -----------------------------------------------------------------------------------------

#[tokio::test]
async fn edge_validates_then_hands_wireguard_state_to_the_root_applier() {
    let ca = pki::new_ca().unwrap();
    let me = pki::issue_client(&ca.key, "controller").unwrap();
    let data = tmp("edge");
    let h = edge::start(EdgeOptions {
        mgmt: "127.0.0.1:0".parse().unwrap(),
        controller_ca_pem: ca.cert.clone(),
        engine: edge_lbd::engine::Options { data_dir: data.clone(), reserved_ports: vec![], ..Default::default() },
    })
    .await
    .unwrap();
    let c = EdgeClient::new(h.addr.ip(), h.addr.port(), &h.fingerprint, &me).unwrap();

    let good = Desired {
        address: "10.100.0.1/24".into(),
        listen_port: Some(51820),
        peers: vec![Peer { public_key: K_GW.into(), allowed_ips: vec!["10.100.0.2/32".into(), "192.168.1.0/24".into()], endpoint: None, keepalive: None }],
        forward_to: vec![],
    };
    c.put_config(1, &[], Some(&good)).await.unwrap();
    let saved: Desired = serde_json::from_slice(&std::fs::read(data.join("wg.json")).unwrap()).unwrap();
    assert_eq!(saved, good);
    assert!(!std::fs::read_to_string(data.join("wg.json")).unwrap().contains("PRIVATE"), "no key material in the state file");

    // Hostile or broken states are refused and leave the previous one alone.
    let mut default_route = good.clone();
    default_route.peers[0].allowed_ips.push("0.0.0.0/0".into());
    let mut metadata = good.clone();
    metadata.peers[0].allowed_ips = vec!["169.254.169.254/32".into()];
    let mut forwards = good.clone();
    forwards.forward_to = vec!["192.168.1.0/24".into()];
    let mut bad_key = good.clone();
    bad_key.peers[0].public_key = "x\nPostUp = rm -rf /".into();
    for (name, bad) in [("default route", default_route), ("metadata", metadata), ("edge forwarding", forwards), ("injected key", bad_key)] {
        let err = c.put_config(2, &[], Some(&bad)).await.unwrap_err();
        assert!(matches!(err, ClientError::Rejected(_)), "{name}: {err:?}");
        let still: Desired = serde_json::from_slice(&std::fs::read(data.join("wg.json")).unwrap()).unwrap();
        assert_eq!(still, good, "{name} must not replace the saved state");
    }

    // A push without WireGuard (an older controller, or an edge with none) leaves it untouched.
    c.put_config(3, &[], None).await.unwrap();
    assert_eq!(serde_json::from_slice::<Desired>(&std::fs::read(data.join("wg.json")).unwrap()).unwrap(), good);

    // No peers means "no tunnel": the applier removes the interface.
    let none = Desired { peers: vec![], ..good };
    c.put_config(4, &[], Some(&none)).await.unwrap();
    assert!(serde_json::from_slice::<Desired>(&std::fs::read(data.join("wg.json")).unwrap()).unwrap().peers.is_empty());
}

#[tokio::test]
async fn edge_state_persists_in_the_controller_json_shape_for_old_controllers() {
    // Controller state written before WireGuard existed must still load.
    let dir = tmp("legacy");
    let ctl_dir = dir.join("ctl");
    {
        let c = Controller::start({
            let mut o = Options::new(ctl_dir.clone());
            o.tick = Duration::from_secs(3600);
            o
        })
        .await
        .unwrap();
        c.stop();
    }
    let mut v: Value = serde_json::from_slice(&std::fs::read(ctl_dir.join("controller.json")).unwrap()).unwrap();
    let obj = v.as_object_mut().unwrap();
    obj.remove("sites");
    obj.remove("gateway_tls");
    v["settings"].as_object_mut().unwrap().remove("wg_network");
    v["settings"].as_object_mut().unwrap().remove("wg_port");
    std::fs::write(ctl_dir.join("controller.json"), serde_json::to_vec(&v).unwrap()).unwrap();
    let c = Controller::start({
        let mut o = Options::new(ctl_dir);
        o.tick = Duration::from_secs(3600);
        o
    })
    .await
    .unwrap();
    assert!(c.sites().is_empty());
    let s = c.settings_view();
    assert_eq!((s.wg_network.as_str(), s.wg_port), ("10.100.0.0/24", 51820));
}
