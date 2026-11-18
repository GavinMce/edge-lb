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
#[cfg(unix)]
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
    let fake = dir.join("fake-binary");
    std::fs::write(&fake, b"#!fake-binary").unwrap();
    o.agents = edge_lbd::controller::agents::Agents::single("x86_64", fake);
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

/// The controller's saved state as JSON text, read the way the controller reads it (so it works
/// where `controller.json` is encrypted at rest, i.e. on Windows).
fn saved_state(dir: &Path) -> Vec<u8> {
    edge_lbd::controller::store::Store::open(dir).unwrap().read(|s| serde_json::to_vec(s).unwrap())
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
    assert!(!String::from_utf8(saved_state(&_d.join("ctl"))).unwrap().contains(&token), "token stored in clear");
    let bin = http.get(format!("https://{host}/gw/binary/{token}/x86_64")).send().await.unwrap();
    assert_eq!(bin.bytes().await.unwrap().as_ref(), b"#!fake-binary");
    // Only architectures the controller really has; the name is looked up, never used as a path.
    for arch in ["aarch64", "riscv64", "..%2F..%2Fetc%2Fpasswd"] {
        assert_eq!(http.get(format!("https://{host}/gw/binary/{token}/{arch}")).send().await.unwrap().status(), 422, "{arch}");
    }

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
    assert!(!String::from_utf8(saved_state(&_d.join("ctl"))).unwrap().contains(body["secret"].as_str().unwrap()), "secret stored in clear");
    let g = &ctl.sites()[0].gateway;
    assert!(g.enrolled && g.public_key.as_deref() == Some(K_GW) && g.enrol_pending_until.is_none());

    // Single use: replay, and the installer for a spent token, are both refused.
    assert_eq!(enrol(token.clone(), K_GW).await.status(), 401);
    assert_eq!(http.get(format!("https://{host}/gw/install/{token}")).send().await.unwrap().status(), 401);
    assert_eq!(http.get(format!("https://{host}/gw/binary/{token}/x86_64")).send().await.unwrap().status(), 401);

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
    spawn_gateway_with(ctl, dir, host, pin, false)
}

/// `self_update`: this gateway was installed with the updater unit.
fn spawn_gateway_with(ctl: &Controller, dir: &Path, host: Arc<MockHost>, pin: Option<String>, self_update: bool) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let (_, hostport, fp) = pinned_http(ctl);
    tokio::spawn(gateway::run(gateway::Options {
        controller: hostport,
        pin: pin.unwrap_or(fp),
        data_dir: dir.to_path_buf(),
        interval: Duration::from_millis(100),
        host,
        self_update,
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
    #[cfg(unix)]
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
    // Rewritten below as plain JSON, which is also how an older version would have left it (on
    // Windows the file is otherwise encrypted, and plain JSON must still be accepted).
    let mut v: Value = serde_json::from_slice(&saved_state(&ctl_dir)).unwrap();
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

// ---- the gateway listener, changed from Settings --------------------------------------------------

use edge_lbd::controller::GatewayUpdate;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn upd(listen: &str, host: &str) -> Option<GatewayUpdate> {
    Some(GatewayUpdate { listen: listen.into(), host: host.into() })
}

fn accepts(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(&format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_millis(500)).is_ok()
}

/// Wait until `port` can be bound again (a stopped controller releases it asynchronously).
async fn wait_free(port: u16) {
    for _ in 0..60 {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("port {port} never became free");
}

async fn plain_controller(dir: &Path) -> Arc<Controller> {
    let mut o = Options::new(dir.to_path_buf());
    o.tick = Duration::from_secs(3600);
    Controller::start(o).await.unwrap()
}

fn invalid(r: Result<(), CtlError>) -> Vec<String> {
    match r {
        Err(CtlError::Invalid(v)) => v,
        other => panic!("expected a validation error, got {other:?}"),
    }
}

#[tokio::test]
async fn the_gateway_listener_can_be_turned_on_changed_and_off_without_a_restart() {
    let dir = tmp("gwset").join("ctl");
    let ctl = plain_controller(&dir).await;
    let v = ctl.settings_view().gateway;
    assert!(v.listen.is_none() && v.active.is_none() && !v.locked, "off by default: {v:?}");
    site(&ctl, "Home", &["192.168.1.0/24"]).unwrap();
    assert!(ctl.start_enrolment("t", "home").is_err(), "no command without a listener");

    let (p1, p2) = (free_port(), free_port());
    ctl.set_gateway("t", upd(&format!("127.0.0.1:{p1}"), "ctl.example.com")).await.unwrap();
    assert!(accepts(p1), "really listening");
    let v = ctl.settings_view().gateway;
    assert_eq!((v.listen.as_deref(), v.host.as_deref()), (Some(format!("127.0.0.1:{p1}").as_str()), Some("ctl.example.com")));
    assert_eq!(v.active, Some(format!("ctl.example.com:{p1}")));
    let cmd = ctl.start_enrolment("t", "home").unwrap().command;
    assert!(cmd.contains(&format!("ctl.example.com:{p1}")), "{cmd}");

    // Change both the port and the address gateways dial.
    ctl.set_gateway("t", upd(&format!("127.0.0.1:{p2}"), "10.0.0.5")).await.unwrap();
    assert!(accepts(p2) && !accepts(p1), "moved: the old port is closed, the new one open");
    assert_eq!(ctl.settings_view().gateway.active, Some(format!("10.0.0.5:{p2}")));

    // Same port, different host: must not trip over its own previous socket.
    ctl.set_gateway("t", upd(&format!("127.0.0.1:{p2}"), "ctl.example.org")).await.unwrap();
    assert!(accepts(p2));
    assert_eq!(ctl.settings_view().gateway.active, Some(format!("ctl.example.org:{p2}")));

    ctl.set_gateway("t", None).await.unwrap();
    assert!(!accepts(p2), "closed");
    let v = ctl.settings_view().gateway;
    assert!(v.listen.is_none() && v.active.is_none());
    assert!(ctl.start_enrolment("t", "home").is_err());
    ctl.stop();
}

#[tokio::test]
async fn a_saved_listener_comes_back_after_a_restart() {
    let dir = tmp("gwsave").join("ctl");
    let ctl = plain_controller(&dir).await;
    let p = free_port();
    ctl.set_gateway("t", upd(&format!("127.0.0.1:{p}"), "ctl.example.com")).await.unwrap();
    ctl.stop();
    drop(ctl);
    wait_free(p).await;

    let again = plain_controller(&dir).await;
    wait_for("the saved listener to come back", || again.gateway_endpoint().is_some()).await;
    assert!(accepts(p));
    assert_eq!(again.settings_view().gateway.active, Some(format!("ctl.example.com:{p}")));
    again.stop();
}

#[tokio::test]
async fn a_saved_listener_that_cannot_start_is_reported_not_fatal() {
    let dir = tmp("gwbroken").join("ctl");
    let ctl = plain_controller(&dir).await;
    let p = free_port();
    ctl.set_gateway("t", upd(&format!("127.0.0.1:{p}"), "ctl.example.com")).await.unwrap();
    ctl.stop();
    drop(ctl);
    wait_free(p).await;

    let squatter = std::net::TcpListener::bind(("127.0.0.1", p)).unwrap();
    let again = plain_controller(&dir).await; // must still start
    let v = again.settings_view().gateway;
    assert!(v.active.is_none(), "not listening");
    assert_eq!(v.listen.as_deref(), Some(format!("127.0.0.1:{p}").as_str()), "the saved setting is still shown so it can be fixed");
    assert!(v.error.as_deref().is_some_and(|e| !e.is_empty()), "says why: {v:?}");

    drop(squatter);
    again.set_gateway("t", upd(&format!("127.0.0.1:{p}"), "ctl.example.com")).await.unwrap();
    let v = again.settings_view().gateway;
    assert!(v.error.is_none() && v.active.is_some(), "fixed: {v:?}");
    again.stop();
}

#[tokio::test]
async fn a_failed_change_leaves_the_working_listener_and_the_saved_setting_alone() {
    let dir = tmp("gwfail").join("ctl");
    let ctl = plain_controller(&dir).await;
    let (p1, p2) = (free_port(), free_port());
    ctl.set_gateway("t", upd(&format!("127.0.0.1:{p1}"), "ctl.example.com")).await.unwrap();

    let squatter = std::net::TcpListener::bind(("127.0.0.1", p2)).unwrap();
    let errs = invalid(ctl.set_gateway("t", upd(&format!("127.0.0.1:{p2}"), "other.example.com")).await);
    assert!(errs.iter().any(|e| e.contains(&p2.to_string())), "names the address: {errs:?}");
    drop(squatter);

    assert!(accepts(p1), "the old listener is still serving");
    let v = ctl.settings_view().gateway;
    assert_eq!(v.listen.as_deref(), Some(format!("127.0.0.1:{p1}").as_str()));
    assert_eq!(v.host.as_deref(), Some("ctl.example.com"));
    assert_eq!(v.active, Some(format!("ctl.example.com:{p1}")));
    ctl.stop();
}

#[tokio::test]
async fn gateway_listener_values_are_validated_and_nothing_is_bound_on_a_bad_one() {
    let dir = tmp("gwbad").join("ctl");
    let ctl = plain_controller(&dir).await;
    let p = free_port();
    let good = format!("127.0.0.1:{p}");
    let cases = [
        ("0.0.0.0", "ctl.example.com"),
        ("7444", "ctl.example.com"),
        ("0.0.0.0:0", "ctl.example.com"),
        ("0.0.0.0:99999", "ctl.example.com"),
        ("localhost:7444", "ctl.example.com"),
        ("", "ctl.example.com"),
        (good.as_str(), ""),
        (good.as_str(), "a b"),
        (good.as_str(), "a;b"),
        (good.as_str(), "x\nExecStartPre=/bin/sh"),
        (good.as_str(), "$(id)"),
        (good.as_str(), "[::1]"),
        (good.as_str(), "-bad.example.com"),
    ];
    for (listen, host) in cases {
        let errs = invalid(ctl.set_gateway("t", upd(listen, host)).await);
        assert!(!errs.is_empty(), "{listen:?} {host:?}");
        assert!(ctl.gateway_endpoint().is_none() && !accepts(p), "{listen:?} {host:?} left a listener behind");
    }
    ctl.stop();
}

#[tokio::test]
async fn startup_options_fix_the_listener_so_settings_cannot_fight_them() {
    let dir = tmp("gwlock").join("ctl");
    let p = free_port();
    let mut o = Options::new(dir);
    o.tick = Duration::from_secs(3600);
    o.gateway = Some(edge_lbd::controller::sites::GatewayListen { listen: format!("127.0.0.1:{p}").parse().unwrap(), host: "ctl.example.com".into() });
    let ctl = Controller::start(o).await.unwrap();

    let v = ctl.settings_view().gateway;
    assert!(v.locked && v.active.is_some(), "{v:?}");
    assert_eq!(v.listen.as_deref(), Some(format!("127.0.0.1:{p}").as_str()));
    for r in [ctl.set_gateway("t", upd("127.0.0.1:9", "x.example.com")).await, ctl.set_gateway("t", None).await] {
        assert!(matches!(r, Err(CtlError::Conflict(_))), "{r:?}");
    }
    assert!(accepts(p), "still serving");
    ctl.stop();
}
// ---- updating gateways ---------------------------------------------------------------------------------

use edge_lbd::controller::update::{UpdateState, AGENT_VERSION};
use edge_lbd::gateway_update;
use sha2::{Digest, Sha256};

/// Enrol a gateway through the real agent, then stop the agent: tests drive its sync by hand from here.
/// Returns its data directory and its secret.
async fn enrolled_gateway(ctl: &Arc<Controller>, d: &Path, site_id: &str) -> (PathBuf, String) {
    let token = token_of(&ctl.start_enrolment("t", site_id).unwrap().command);
    let gwdir = d.join(format!("gw-{site_id}"));
    std::fs::create_dir_all(&gwdir).unwrap();
    std::fs::write(gwdir.join("enrol-token"), format!("{token}\n")).unwrap();
    let task = spawn_gateway_with(ctl, &gwdir, Arc::new(MockHost::default()), None, true);
    wait_for("the gateway to enrol and sync", || ctl.sites().iter().any(|s| s.id == site_id && s.gateway.enrolled && s.gateway.online)).await;
    task.abort();
    let _ = task.await;
    let secret = serde_json::from_slice::<Value>(&std::fs::read(gwdir.join("identity.json")).unwrap()).unwrap()["secret"].as_str().unwrap().to_string();
    (gwdir, secret)
}

async fn raw_sync(ctl: &Controller, secret: &str, body: Value) -> Value {
    let (http, host, _) = pinned_http(ctl);
    let r = http.post(format!("https://{host}/gw/v1/sync")).bearer_auth(secret).json(&body).send().await.unwrap();
    assert_eq!(r.status(), 200);
    r.json().await.unwrap()
}

fn gw_update(ctl: &Controller) -> edge_lbd::controller::update::UpdateView {
    ctl.sites()[0].gateway.update.clone()
}

#[tokio::test]
async fn a_gateway_is_only_offered_an_update_when_asked_and_the_outcome_is_tracked() {
    let (ctl, d) = controller("upd-offer").await;
    site(&ctl, "Home", &["192.168.1.0/24"]).unwrap();
    let (_gw, secret) = enrolled_gateway(&ctl, &d, "home").await;
    assert!(ctl.sites()[0].gateway.self_update, "an install with the updater says so");

    // Nobody asked: a gateway on an old version is told it is behind, but is not told to move.
    let r = raw_sync(&ctl, &secret, json!({"version": "0.0.1", "caps": ["self-update"], "handshakes": []})).await;
    assert!(r.get("update").is_none(), "no update was requested: {r}");
    assert_eq!(gw_update(&ctl).available.as_deref(), Some(AGENT_VERSION));
    assert_eq!(gw_update(&ctl).state, None);

    // Asked: the next sync carries the offer.
    ctl.update_gateway("t", "home").unwrap();
    assert_eq!(gw_update(&ctl).state, Some(UpdateState::Running));
    let r = raw_sync(&ctl, &secret, json!({"version": "0.0.1", "caps": ["self-update"], "handshakes": []})).await;
    assert_eq!(r["update"]["version"], AGENT_VERSION);
    assert!(gw_update(&ctl).message.unwrap().contains("installing"));
    // Asking twice doesn't start two.
    assert!(matches!(ctl.update_gateway("t", "home"), Err(CtlError::Conflict(m)) if m.contains("already")));

    // The updater reports failure: the offer stops, the reason is shown, and it can be tried again.
    let r = raw_sync(&ctl, &secret, json!({"version": "0.0.1", "caps": ["self-update"], "handshakes": [], "update_result": {"version": "9.9.9", "ok": false, "error": "9.9.9 did not complete a sync"}})).await;
    assert!(r.get("update").is_none(), "{r}");
    assert_eq!(gw_update(&ctl).state, Some(UpdateState::Failed));
    assert!(gw_update(&ctl).message.unwrap().contains("did not complete a sync"));

    ctl.update_gateway("t", "home").unwrap();
    let r = raw_sync(&ctl, &secret, json!({"version": AGENT_VERSION, "caps": ["self-update"], "handshakes": []})).await;
    assert!(r.get("update").is_none(), "already there: {r}");
    let v = gw_update(&ctl);
    assert_eq!(v.state, Some(UpdateState::Done));
    assert_eq!(v.message.as_deref(), Some(format!("updated to v{AGENT_VERSION}").as_str()));
    assert_eq!(v.available, None, "up to date now");

    let actions: Vec<String> = ctl.audit.tail(50).iter().map(|v| v["action"].as_str().unwrap().to_string()).collect();
    assert!(actions.iter().any(|a| a == "gateway.update"), "{actions:?}");
}

#[tokio::test]
async fn a_gateway_that_cannot_update_itself_is_told_what_to_do_instead() {
    let (ctl, d) = controller("upd-guards").await;
    site(&ctl, "Home", &["192.168.1.0/24"]).unwrap();
    site(&ctl, "Cabin", &["192.168.2.0/24"]).unwrap();
    let (_gw, secret) = enrolled_gateway(&ctl, &d, "home").await;

    assert!(matches!(ctl.update_gateway("t", "nowhere"), Err(CtlError::NotFound(_))));
    assert!(matches!(ctl.update_gateway("t", "cabin"), Err(CtlError::Conflict(m)) if m.contains("no gateway yet")));

    // Enrolled but never heard from.
    ctl.store.update(|s| s.sites[1].gateway.public_key = Some(K_GW.into())).unwrap();
    assert!(matches!(ctl.update_gateway("t", "cabin"), Err(CtlError::Conflict(m)) if m.contains("offline")));

    // An older gateway (no updater unit) syncs without the capability: it must re-enrol once.
    raw_sync(&ctl, &secret, json!({"version": "0.1.2", "handshakes": []})).await;
    assert!(!ctl.sites()[0].gateway.self_update);
    let err = ctl.update_gateway("t", "home").unwrap_err();
    assert!(matches!(&err, CtlError::Conflict(m) if m.contains("Re-enrol")), "{err:?}");
    assert_eq!(gw_update(&ctl).state, None, "nothing was started");
    // A gateway can't claim a capability with an absurd name.
    raw_sync(&ctl, &secret, json!({"version": "0.1.2", "caps": ["x".repeat(500)], "handshakes": []})).await;
    assert!(!ctl.sites()[0].gateway.self_update);
}

#[tokio::test]
async fn the_agent_reports_what_the_updater_left_and_marks_every_good_sync() {
    let (ctl, d) = controller("upd-agent").await;
    site(&ctl, "Home", &["192.168.1.0/24"]).unwrap();
    let token = token_of(&ctl.start_enrolment("t", "home").unwrap().command);
    let gwdir = d.join("gw");
    std::fs::create_dir_all(&gwdir).unwrap();
    std::fs::write(gwdir.join("enrol-token"), format!("{token}\n")).unwrap();
    // The updater tried and failed before this agent started: the controller should hear about it.
    std::fs::write(gwdir.join("update-result.json"), br#"{"version":"9.9.9","ok":false,"error":"9.9.9 did not complete a sync with the controller"}"#).unwrap();
    let task = spawn_gateway_with(&ctl, &gwdir, Arc::new(MockHost::default()), None, true);
    wait_for("enrolled and online", || ctl.sites()[0].gateway.enrolled && ctl.sites()[0].gateway.online).await;

    // The marker the updater waits for names the version that wrote it.
    wait_for("the sync marker", || std::fs::read_to_string(gwdir.join("synced")).is_ok_and(|s| s.starts_with(&format!("{} ", gateway::VERSION)))).await;
    // The result is handed over once and then removed, so it isn't reported forever.
    wait_for("the result to be consumed", || !gwdir.join("update-result.json").exists()).await;

    // An agent already on the controller's version is never offered anything, so no request is written.
    ctl.update_gateway("t", "home").unwrap();
    wait_for("the request to resolve", || gw_update(&ctl).state == Some(UpdateState::Done)).await;
    assert!(gw_update(&ctl).message.unwrap().contains("already running"));
    assert!(!gwdir.join("update-request").exists());
    task.abort();

    // Without the updater unit, none of this happens.
    let (ctl2, d2) = controller("upd-agent-off").await;
    site(&ctl2, "Home", &["192.168.1.0/24"]).unwrap();
    let token = token_of(&ctl2.start_enrolment("t", "home").unwrap().command);
    let gwdir2 = d2.join("gw");
    std::fs::create_dir_all(&gwdir2).unwrap();
    std::fs::write(gwdir2.join("enrol-token"), format!("{token}\n")).unwrap();
    let task2 = spawn_gateway_with(&ctl2, &gwdir2, Arc::new(MockHost::default()), None, false);
    wait_for("enrolled and online", || ctl2.sites()[0].gateway.enrolled && ctl2.sites()[0].gateway.online).await;
    sleep(Duration::from_millis(300)).await;
    assert!(!ctl2.sites()[0].gateway.self_update);
    assert!(!gwdir2.join("synced").exists(), "no updater, no marker");
    task2.abort();
}

#[tokio::test]
async fn the_update_binary_is_served_only_to_a_gateway_that_proves_who_it_is() {
    let (ctl, d) = controller("upd-bin").await;
    site(&ctl, "Home", &["192.168.1.0/24"]).unwrap();
    let (_gw, secret) = enrolled_gateway(&ctl, &d, "home").await;
    let (http, host, _) = pinned_http(&ctl);
    let url = |arch: &str| format!("https://{host}/gw/v1/update?arch={arch}");

    let ok = http.get(url("x86_64")).bearer_auth(&secret).send().await.unwrap();
    assert_eq!(ok.status(), 200);
    let stated = ok.headers()["x-edge-lb-sha256"].to_str().unwrap().to_string();
    let body = ok.bytes().await.unwrap();
    assert_eq!(&body[..], b"#!fake-binary");
    assert_eq!(stated, Sha256::digest(&body).iter().map(|b| format!("{b:02x}")).collect::<String>(), "the checksum covers exactly what was sent");

    assert_eq!(http.get(url("x86_64")).send().await.unwrap().status(), 401, "no credentials");
    assert_eq!(http.get(url("x86_64")).bearer_auth("wrong").send().await.unwrap().status(), 401);
    assert_eq!(http.get(url("x86_64")).bearer_auth("00".repeat(32)).send().await.unwrap().status(), 401);
    // Enrolment tokens open the installer, not the update download.
    let token = token_of(&ctl.start_enrolment("t", "home").unwrap().command);
    assert_eq!(http.get(url("x86_64")).bearer_auth(&token).send().await.unwrap().status(), 401);
    // The architecture is only a lookup key.
    for arch in ["aarch64", "..%2F..%2Fetc%2Fpasswd", "x86_64%2F..%2Fx86_64", "", "%2e%2e"] {
        assert_eq!(http.get(url(arch)).bearer_auth(&secret).send().await.unwrap().status(), 422, "{arch:?}");
    }
    assert_eq!(http.get(format!("https://{host}/gw/v1/update")).bearer_auth(&secret).send().await.unwrap().status(), 422, "no arch at all");
}

// The updater, with only the restart and the version check faked.

struct FakeHost {
    dir: PathBuf,
    version: Mutex<Result<String, String>>,
    /// What the "new" agent would write to its sync marker after a restart (None: it never syncs).
    syncs_as: Mutex<Option<String>>,
    restarts: Mutex<u32>,
}

impl FakeHost {
    fn new(dir: &Path, version: Result<&str, &str>, syncs_as: Option<&str>) -> Arc<FakeHost> {
        Arc::new(FakeHost { dir: dir.to_path_buf(), version: Mutex::new(version.map(String::from).map_err(String::from)), syncs_as: Mutex::new(syncs_as.map(String::from)), restarts: Mutex::new(0) })
    }
}

#[async_trait]
impl gateway_update::Host for FakeHost {
    async fn restart(&self) -> anyhow::Result<()> {
        *self.restarts.lock().unwrap() += 1;
        if let Some(v) = self.syncs_as.lock().unwrap().clone() {
            std::fs::write(self.dir.join("synced"), format!("{v} 1\n"))?;
        }
        Ok(())
    }
    async fn version_output(&self, _binary: &Path) -> anyhow::Result<String> {
        self.version.lock().unwrap().clone().map_err(|e| anyhow::anyhow!(e))
    }
}

struct UpdaterRig {
    ctl: Arc<Controller>,
    gwdir: PathBuf,
    bin: PathBuf,
}

async fn updater_rig(tag: &str) -> UpdaterRig {
    let (ctl, d) = controller(tag).await;
    site(&ctl, "Home", &["192.168.1.0/24"]).unwrap();
    let (gwdir, _) = enrolled_gateway(&ctl, &d, "home").await;
    let bin = d.join("bin").join("edge-lbd");
    std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
    std::fs::write(&bin, "OLD BINARY").unwrap();
    std::fs::write(gwdir.join("update-request"), "9.9.9\n").unwrap();
    UpdaterRig { ctl, gwdir, bin }
}

impl UpdaterRig {
    async fn run(&self, host: Arc<FakeHost>, wait_secs: u64, pin: Option<String>) {
        let (_, hostport, fp) = pinned_http(&self.ctl);
        gateway_update::run(gateway_update::Options {
            controller: hostport,
            pin: pin.unwrap_or(fp),
            data_dir: self.gwdir.clone(),
            bin: self.bin.clone(),
            arch: "x86_64".into(),
            wait: Duration::from_secs(wait_secs),
            host,
        })
        .await
        .unwrap();
    }

    fn result(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.gwdir.join("update-result.json")).expect("the updater always leaves a result")).unwrap()
    }

    fn old(&self) -> PathBuf {
        PathBuf::from(format!("{}.old", self.bin.display()))
    }

    fn new_file(&self) -> PathBuf {
        PathBuf::from(format!("{}.new", self.bin.display()))
    }
}

#[tokio::test]
async fn the_updater_installs_what_the_controller_serves_once_the_new_version_syncs() {
    let r = updater_rig("upd-run-ok").await;
    let host = FakeHost::new(&r.gwdir, Ok("edge-lbd 9.9.9\n"), Some("9.9.9"));
    r.run(host.clone(), 5, None).await;

    assert_eq!(std::fs::read_to_string(&r.bin).unwrap(), "#!fake-binary", "the controller's binary is in place");
    assert_eq!(std::fs::read_to_string(r.old()).unwrap(), "OLD BINARY", "the previous one is kept");
    assert!(!r.new_file().exists());
    assert_eq!(*host.restarts.lock().unwrap(), 1);
    let res = r.result();
    assert_eq!((res["ok"].as_bool(), res["version"].as_str()), (Some(true), Some("9.9.9")), "{res}");
    assert!(!r.gwdir.join("update-request").exists(), "the request is taken first, so systemd can't loop on it");
    #[cfg(unix)]
    assert_eq!(std::fs::metadata(&r.bin).unwrap().permissions().mode() & 0o777, 0o755);
}

#[tokio::test]
async fn a_new_version_that_never_reaches_the_controller_is_rolled_back() {
    let r = updater_rig("upd-run-rollback").await;
    let host = FakeHost::new(&r.gwdir, Ok("edge-lbd 9.9.9\n"), None);
    r.run(host.clone(), 1, None).await;

    assert_eq!(std::fs::read_to_string(&r.bin).unwrap(), "OLD BINARY", "the previous binary is back");
    assert_eq!(*host.restarts.lock().unwrap(), 2, "restarted onto the new one, then onto the old one again");
    let res = r.result();
    assert_eq!(res["ok"], false);
    let err = res["error"].as_str().unwrap();
    assert!(err.contains("did not complete a sync") && err.contains("went back"), "{err}");
    assert_eq!(res["version"], "9.9.9", "the controller is told which version was tried");

    // Another version's marker doesn't count as the new version being healthy.
    let r = updater_rig("upd-run-wrong-marker").await;
    let host = FakeHost::new(&r.gwdir, Ok("edge-lbd 9.9.9\n"), Some("0.0.1"));
    r.run(host, 1, None).await;
    assert_eq!(std::fs::read_to_string(&r.bin).unwrap(), "OLD BINARY");
    assert_eq!(r.result()["ok"], false);
}

#[tokio::test]
async fn a_binary_that_will_not_run_is_refused_before_anything_is_replaced() {
    let r = updater_rig("upd-run-broken").await;
    let host = FakeHost::new(&r.gwdir, Err("exec format error"), Some("9.9.9"));
    r.run(host.clone(), 2, None).await;

    assert_eq!(std::fs::read_to_string(&r.bin).unwrap(), "OLD BINARY");
    assert!(!r.old().exists(), "nothing was backed up because nothing changed");
    assert!(!r.new_file().exists(), "the rejected download is not left lying around");
    assert_eq!(*host.restarts.lock().unwrap(), 0, "the running service was never touched");
    let res = r.result();
    assert_eq!(res["ok"], false);
    assert!(res["error"].as_str().unwrap().contains("does not run"), "{res}");
}

#[tokio::test]
async fn the_updater_does_nothing_without_a_request_and_nothing_to_do_when_already_current() {
    let r = updater_rig("upd-run-noop").await;
    std::fs::remove_file(r.gwdir.join("update-request")).unwrap();
    let host = FakeHost::new(&r.gwdir, Ok("edge-lbd 9.9.9\n"), Some("9.9.9"));
    r.run(host.clone(), 2, None).await;
    assert_eq!(std::fs::read_to_string(&r.bin).unwrap(), "OLD BINARY");
    assert!(!r.gwdir.join("update-result.json").exists(), "no request, no result");
    assert_eq!(*host.restarts.lock().unwrap(), 0);

    // The served binary turns out to be the version already running: say so, change nothing.
    std::fs::write(r.gwdir.join("update-request"), "x\n").unwrap();
    let host = FakeHost::new(&r.gwdir, Ok(&format!("edge-lbd {}\n", gateway::VERSION)), Some("x"));
    r.run(host.clone(), 2, None).await;
    assert_eq!(std::fs::read_to_string(&r.bin).unwrap(), "OLD BINARY");
    assert_eq!(*host.restarts.lock().unwrap(), 0);
    assert_eq!(r.result()["ok"], true);
}

#[tokio::test]
async fn the_updater_trusts_only_the_controller_it_was_installed_for() {
    // The wrong pin: it never gets a binary.
    let r = updater_rig("upd-run-pin").await;
    let host = FakeHost::new(&r.gwdir, Ok("edge-lbd 9.9.9\n"), Some("9.9.9"));
    r.run(host.clone(), 2, Some("00".repeat(32))).await;
    assert_eq!(std::fs::read_to_string(&r.bin).unwrap(), "OLD BINARY");
    assert!(r.result()["error"].as_str().unwrap().contains("cannot reach the controller"), "{}", r.result());

    // A gateway that was never enrolled has no secret to ask with.
    let r = updater_rig("upd-run-noid").await;
    std::fs::remove_file(r.gwdir.join("identity.json")).unwrap();
    let host = FakeHost::new(&r.gwdir, Ok("edge-lbd 9.9.9\n"), Some("9.9.9"));
    r.run(host, 2, None).await;
    assert!(r.result()["error"].as_str().unwrap().contains("not enrolled"), "{}", r.result());

    // A secret the controller doesn't know (the gateway was re-enrolled elsewhere) is refused.
    let r = updater_rig("upd-run-badsecret").await;
    std::fs::write(r.gwdir.join("identity.json"), r#"{"secret":"deadbeef","site":"home"}"#).unwrap();
    let host = FakeHost::new(&r.gwdir, Ok("edge-lbd 9.9.9\n"), Some("9.9.9"));
    r.run(host.clone(), 2, None).await;
    assert_eq!(std::fs::read_to_string(&r.bin).unwrap(), "OLD BINARY");
    assert!(r.result()["error"].as_str().unwrap().contains("401"), "{}", r.result());
    assert_eq!(*host.restarts.lock().unwrap(), 0);
}

#[test]
fn the_gateway_installer_sets_up_the_updater_and_tells_the_agent_about_it() {
    let sha = "ab".repeat(32);
    let pin = format!("sha256//{}=", "A".repeat(43));
    let script = edge_lbd::controller::sites::render_install_script("h.test:7444", &"cd".repeat(32), &pin, &"ef".repeat(32), &[("x86_64", sha)]).unwrap();
    assert!(script.contains("--data-dir /var/lib/edge-lb-gateway --self-update"), "the agent must be told it has an updater");
    assert!(script.contains("edge-lb-gateway-update.service") && script.contains("edge-lb-gateway-update.path"));
    assert!(script.contains("PathExists=/var/lib/edge-lb-gateway/update-request"));
    assert!(script.contains("gateway-update --controller h.test:7444"), "the updater talks to the same controller");
    assert!(script.contains("systemctl enable --now edge-lb-gateway-update.path"));
    assert!(!script.contains('@'), "unreplaced placeholder");
    // The gateway's own unit stays sandboxed: it is not given write access to its binary.
    let gw_unit = script.split("edge-lb-gateway.service <<'UNIT'").nth(1).unwrap().split("\nUNIT").next().unwrap();
    assert!(gw_unit.contains("ProtectSystem=strict") && gw_unit.contains("ReadWritePaths=/var/lib/edge-lb-gateway\n"), "{gw_unit}");
    assert!(!gw_unit.contains("/usr/local/bin") || gw_unit.contains("ExecStart=/usr/local/bin/edge-lbd gateway"), "{gw_unit}");
}
