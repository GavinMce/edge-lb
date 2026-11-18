//! The controller's HTTP surface: first-run setup, sessions, CSRF, lockout, and the resource API.

use async_trait::async_trait;
use edge_lbd::controller::api::router;
use edge_lbd::controller::bootstrap::{Bootstrapper, InstallCtx, Installed, Target};
use edge_lbd::controller::{Controller, Options};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Machines never come up: these tests are about the API, not provisioning.
struct Offline;
#[async_trait]
impl Bootstrapper for Offline {
    async fn probe(&self, _: &Target) -> anyhow::Result<()> { anyhow::bail!("offline") }
    async fn install(&self, _: &Target, _: &InstallCtx) -> anyhow::Result<Installed> { anyhow::bail!("offline") }
    async fn uninstall(&self, _: &Target) -> anyhow::Result<()> { Ok(()) }
    async fn forget(&self, _: &Target) {}
}

struct Rig {
    addr: SocketAddr,
    ctl: Arc<Controller>,
    dir: std::path::PathBuf,
}

async fn start(tag: &str) -> Rig {
    let dir = std::env::temp_dir().join(format!("edge-lbd-capi-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut o = Options::new(dir.clone());
    o.bootstrapper = Some(Arc::new(Offline));
    let ctl = Controller::start(o).await.unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let app = router(ctl.clone(), false).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    Rig { addr, ctl, dir }
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
    fn cookie(&self) -> Option<String> {
        self.headers.lines().find(|l| l.starts_with("set-cookie:")).map(|l| l["set-cookie:".len()..].trim().split(';').next().unwrap().to_string())
    }
}

#[derive(Default)]
struct Opts<'a> {
    cookie: Option<&'a str>,
    csrf: bool,
    body: Option<Value>,
}

async fn http(addr: SocketAddr, method: &str, path: &str, o: Opts<'_>) -> Resp {
    let mut c = TcpStream::connect(addr).await.unwrap();
    let body = o.body.map(|b| b.to_string());
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n");
    if let Some(ck) = o.cookie {
        req += &format!("Cookie: {ck}\r\n");
    }
    if o.csrf {
        req += "X-EdgeLB: 1\r\n";
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
    timeout(Duration::from_secs(10), c.read_to_end(&mut raw)).await.unwrap().unwrap();
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    Resp { status: head.split_whitespace().nth(1).unwrap().parse().unwrap(), headers: head.to_ascii_lowercase(), body: body.to_string() }
}

const PW: &str = "correct horse battery staple";

/// Complete first-run setup and return the session cookie.
async fn signed_in(r: &Rig) -> String {
    let code = r.ctl.setup_code.lock().unwrap().clone().unwrap();
    let resp = http(r.addr, "POST", "/api/setup", Opts { csrf: true, body: Some(json!({"setup_code": code, "username": "admin", "password": PW})), ..Default::default() }).await;
    assert_eq!(resp.status, 200, "{}", resp.body);
    resp.cookie().unwrap()
}

async fn api(r: &Rig, ck: &str, method: &str, path: &str, body: Option<Value>) -> Resp {
    http(r.addr, method, path, Opts { cookie: Some(ck), csrf: true, body }).await
}

#[tokio::test]
async fn nothing_works_before_setup_and_setup_needs_the_console_code() {
    let r = start("setup").await;
    let s = http(r.addr, "GET", "/api/session", Opts::default()).await.json();
    assert_eq!(s["setup_needed"], true);
    assert_eq!(s["authenticated"], false);
    assert_eq!(http(r.addr, "GET", "/api/status", Opts::default()).await.status, 401);

    // The setup code was written next to the state, for whoever has shell access.
    let code = r.ctl.setup_code.lock().unwrap().clone().unwrap();
    assert_eq!(std::fs::read_to_string(r.dir.join("setup-code")).unwrap().trim(), code);

    let body = |c: &str, p: &str| Opts { csrf: true, body: Some(json!({"setup_code": c, "username": "admin", "password": p})), ..Default::default() };
    // Without the code a passer-by can't claim the controller.
    assert_eq!(http(r.addr, "POST", "/api/setup", body("WRONGCODE123", PW)).await.status, 403);
    // Weak passwords are refused (and the code stays valid).
    assert_eq!(http(r.addr, "POST", "/api/setup", body(&code, "short")).await.status, 422);
    // Cross-site form posts (no custom header) are refused.
    let no_csrf = http(r.addr, "POST", "/api/setup", Opts { body: Some(json!({"setup_code": code, "username": "admin", "password": PW})), ..Default::default() }).await;
    assert_eq!(no_csrf.status, 403);

    let ok = http(r.addr, "POST", "/api/setup", body(&code.to_lowercase(), PW)).await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    let set_cookie = ok.headers.lines().find(|l| l.starts_with("set-cookie:")).unwrap().to_string();
    assert!(set_cookie.contains("httponly") && set_cookie.contains("samesite=strict"), "{set_cookie}");

    // One-shot: the code is gone and a second setup is refused.
    assert!(!r.dir.join("setup-code").exists());
    assert_eq!(http(r.addr, "POST", "/api/setup", body(&code, PW)).await.status, 409);
    // The password is stored hashed.
    let raw = std::fs::read(r.dir.join("controller.json")).unwrap();
    assert!(!raw.windows(PW.len()).any(|w| w == PW.as_bytes()), "password stored in clear");
    // On Windows the file is DPAPI-encrypted, so read it back through the store (which decrypts it).
    #[cfg(windows)]
    assert!(raw.starts_with(b"EDGELB-DPAPI-1\n"), "controller.json should be DPAPI-encrypted");
    #[cfg(not(windows))]
    assert!(String::from_utf8(raw).unwrap().contains("$argon2"));
    let reopened = edge_lbd::controller::store::Store::open(&r.dir).unwrap();
    let hash = reopened.read(|s| s.admin.as_ref().map(|a| a.password_hash.clone())).unwrap();
    assert!(hash.starts_with("$argon2") && !hash.contains(PW));
}

#[tokio::test]
async fn sessions_csrf_logout_and_password_change() {
    let r = start("session").await;
    let ck = signed_in(&r).await;

    assert_eq!(http(r.addr, "GET", "/api/status", Opts { cookie: Some(&ck), ..Default::default() }).await.status, 200);
    // State-changing calls need the custom header even with a valid cookie.
    let no_header = http(r.addr, "POST", "/api/routes", Opts { cookie: Some(&ck), body: Some(json!({})), ..Default::default() }).await;
    assert_eq!(no_header.status, 403);
    assert_eq!(http(r.addr, "GET", "/api/status", Opts { cookie: Some("edgelb_session=forged"), ..Default::default() }).await.status, 401);

    // Login works from a fresh client; a wrong password does not.
    let bad = http(r.addr, "POST", "/api/login", Opts { csrf: true, body: Some(json!({"username": "admin", "password": "wrong wrong wrong"})), ..Default::default() }).await;
    assert_eq!(bad.status, 401);
    assert!(bad.cookie().is_none());
    let good = http(r.addr, "POST", "/api/login", Opts { csrf: true, body: Some(json!({"username": "admin", "password": PW})), ..Default::default() }).await;
    assert_eq!(good.status, 200);
    let second = good.cookie().unwrap();

    // Changing the password revokes every other session.
    let wrong = api(&r, &ck, "POST", "/api/password", Some(json!({"current": "nope nope nope nope", "new": "another long passphrase"}))).await;
    assert_eq!(wrong.status, 403);
    let changed = api(&r, &ck, "POST", "/api/password", Some(json!({"current": PW, "new": "another long passphrase"}))).await;
    assert_eq!(changed.status, 204);
    assert_eq!(api(&r, &second, "GET", "/api/status", None).await.status, 401, "other sessions are revoked");
    assert_eq!(api(&r, &ck, "GET", "/api/status", None).await.status, 401, "so is the old cookie");
    let fresh = changed.cookie().unwrap();
    assert_eq!(api(&r, &fresh, "GET", "/api/status", None).await.status, 200);

    // Logout kills the session server-side, not just in the browser.
    assert_eq!(api(&r, &fresh, "POST", "/api/logout", None).await.status, 204);
    assert_eq!(api(&r, &fresh, "GET", "/api/status", None).await.status, 401);
}

#[tokio::test]
async fn repeated_bad_logins_are_locked_out() {
    let r = start("lockout").await;
    let _ = signed_in(&r).await;
    let attempt = |pw: &'static str| http(r.addr, "POST", "/api/login", Opts { csrf: true, body: Some(json!({"username": "admin", "password": pw})), ..Default::default() });
    for _ in 0..5 {
        assert_eq!(attempt("guess guess guess").await.status, 401);
    }
    // Even the right password is refused while locked out.
    assert_eq!(attempt(PW).await.status, 429);
}

#[tokio::test]
async fn settings_never_reveal_secrets_and_are_validated() {
    let r = start("settings").await;
    let ck = signed_in(&r).await;

    let put = api(&r, &ck, "PUT", "/api/settings", Some(json!({
        "hetzner_token": "super-secret-token", "max_edges": 3,
        "dns": {"cloudflare_token": "cf-secret", "zone_id": "abc123", "names": ["App.Example.com"], "ttl": 300}
    }))).await;
    assert_eq!(put.status, 200, "{}", put.body);
    for body in [put.body.clone(), api(&r, &ck, "GET", "/api/settings", None).await.body, api(&r, &ck, "GET", "/api/status", None).await.body] {
        assert!(!body.contains("super-secret-token") && !body.contains("cf-secret"), "secret leaked: {body}");
    }
    let v = api(&r, &ck, "GET", "/api/settings", None).await.json();
    assert_eq!(v["hetzner_token_set"], true);
    assert_eq!(v["max_edges"], 3);
    assert_eq!(v["dns"]["names"], json!(["app.example.com"]), "names are normalized");
    assert_eq!(v["dns"]["token_set"], true);

    // Updating DNS without resending the token keeps the old one.
    api(&r, &ck, "PUT", "/api/settings", Some(json!({"dns": {"zone_id": "abc123", "names": ["x.example.com"], "ttl": 60}}))).await;
    assert_eq!(r.ctl.store.read(|s| s.settings.dns.as_ref().unwrap().cloudflare_token.clone()), "cf-secret");

    let bad = api(&r, &ck, "PUT", "/api/settings", Some(json!({"max_edges": 0, "drain_seconds": 99999, "dns": {"cloudflare_token": "t", "zone_id": "z", "names": ["*.wild.com", "bad name"], "ttl": 5}}))).await;
    assert_eq!(bad.status, 422);
    assert!(bad.json()["details"].as_array().unwrap().len() >= 4, "{}", bad.body);
    // Nothing from the rejected update was applied.
    assert_eq!(api(&r, &ck, "GET", "/api/settings", None).await.json()["max_edges"], 3);

    // Clearing the token.
    api(&r, &ck, "PUT", "/api/settings", Some(json!({"hetzner_token": ""}))).await;
    assert_eq!(api(&r, &ck, "GET", "/api/settings", None).await.json()["hetzner_token_set"], false);
}

#[tokio::test]
async fn edges_routes_and_ssh_key_over_http() {
    let r = start("resources").await;
    let ck = signed_in(&r).await;

    // The controller shows the public key to authorize on machines you adopt.
    let key = api(&r, &ck, "GET", "/api/ssh-key", None).await.json();
    assert!(key["public_key"].as_str().unwrap().starts_with("ssh-ed25519 "), "{key}");
    assert!(!key.to_string().contains("PRIVATE"));

    // Hetzner edges need a token first.
    let hz = json!({"name": "East", "region": "us-east", "provider": {"kind": "hetzner", "location": "ash", "server_type": "cpx11"}});
    let r1 = api(&r, &ck, "POST", "/api/edges", Some(hz.clone())).await;
    assert_eq!(r1.status, 422);
    assert!(r1.body.contains("token"));

    // Manual edge.
    let manual = api(&r, &ck, "POST", "/api/edges", Some(json!({"name": "Lab Box", "provider": {"kind": "manual"}, "ip": "192.0.2.10"}))).await;
    assert_eq!(manual.status, 201, "{}", manual.body);
    assert_eq!(manual.json()["id"], "lab-box");
    assert_eq!(manual.json()["status"], "creating");
    assert_eq!(api(&r, &ck, "POST", "/api/edges", Some(json!({"name": "Lab Box", "provider": {"kind": "manual"}, "ip": "192.0.2.10"}))).await.status, 409, "same ip:port twice");
    let hostile = api(&r, &ck, "POST", "/api/edges", Some(json!({"name": "x", "provider": {"kind": "manual"}, "ip": "192.0.2.11", "ssh_user": "-oProxyCommand=evil"}))).await;
    assert_eq!(hostile.status, 422);

    // Routes, including scope validation.
    let route = json!({"name": "Web", "listen": {"port": 8443}, "domains": ["Site.Example.com"], "targets": [{"address": "10.0.0.5", "port": 443}], "edges": ["lab-box"]});
    let created = api(&r, &ck, "POST", "/api/routes", Some(route.clone())).await;
    assert_eq!(created.status, 201, "{}", created.body);
    assert_eq!(created.json()["id"], "web");
    assert_eq!(created.json()["domains"], json!(["site.example.com"]));
    let bad_scope = api(&r, &ck, "POST", "/api/routes", Some(json!({"name": "W2", "listen": {"port": 9000}, "targets": [{"address": "10.0.0.5", "port": 1}], "edges": ["ghost"]}))).await;
    assert_eq!(bad_scope.status, 422);
    assert!(bad_scope.body.contains("unknown edge"));
    let upd = api(&r, &ck, "PUT", "/api/routes/web", Some(json!({"name": "Web", "enabled": false, "listen": {"port": 8443}, "targets": [{"address": "10.0.0.5", "port": 443}]}))).await;
    assert_eq!(upd.status, 200);
    assert_eq!(upd.json()["enabled"], false);
    assert_eq!(api(&r, &ck, "PUT", "/api/routes/nope", Some(route)).await.status, 404);

    // Status ties it together.
    let st = api(&r, &ck, "GET", "/api/status", None).await.json();
    assert_eq!(st["edges"].as_array().unwrap().len(), 1);
    assert_eq!(st["routes"].as_array().unwrap().len(), 1);

    // Delete a not-yet-serving edge: removed straight away; the route that only ran there is disabled, not widened.
    assert_eq!(api(&r, &ck, "DELETE", "/api/edges/lab-box", None).await.status, 202);
    for _ in 0..100 {
        if api(&r, &ck, "GET", "/api/edges", None).await.json().as_array().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(api(&r, &ck, "GET", "/api/edges", None).await.json().as_array().unwrap().is_empty());
    assert_eq!(api(&r, &ck, "DELETE", "/api/edges/lab-box", None).await.status, 404);
    assert_eq!(api(&r, &ck, "DELETE", "/api/routes/web", None).await.status, 204);

    // Catalog without a token is a clear error, not a crash.
    assert_eq!(api(&r, &ck, "GET", "/api/catalog", None).await.status, 422);

    // Everything above is in the audit trail.
    let actions: Vec<String> = api(&r, &ck, "GET", "/api/audit", None).await.json().as_array().unwrap().iter().map(|v| v["action"].as_str().unwrap().to_string()).collect();
    for a in ["admin.setup", "edge.create", "route.create", "route.update", "edge.delete"] {
        assert!(actions.iter().any(|x| x == a), "{a} missing from {actions:?}");
    }
}

#[tokio::test]
async fn ui_assets_use_a_strict_csp_without_inline_code() {
    let r = start("ui").await;
    for (path, ct) in [("/", "text/html"), ("/app.js", "text/javascript"), ("/app.css", "text/css")] {
        let resp = http(r.addr, "GET", path, Opts::default()).await;
        assert_eq!(resp.status, 200, "{path}");
        assert!(resp.headers.contains(ct), "{path}");
        assert!(resp.headers.contains("content-security-policy: default-src 'none'"), "{path}");
        assert!(resp.headers.contains("cache-control: no-store"));
    }
    let html = http(r.addr, "GET", "/", Opts::default()).await.body;
    assert!(!html.contains("<script>") && !html.contains(" style="), "inline script/style would be blocked by the CSP");
    assert_eq!(http(r.addr, "GET", "/healthz", Opts::default()).await.body, "ok");
}
