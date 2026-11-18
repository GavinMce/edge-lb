//! The controller's HTTP API and embedded web UI.
//!
//! Auth model: admin password -> session cookie (HttpOnly, SameSite=Strict). Every state-changing
//! request must also carry `X-EdgeLB: 1`, which a cross-site page cannot send without a CORS
//! preflight we never grant. First-run setup needs a one-time code printed on the controller's
//! console, so a freshly deployed controller can't be claimed by whoever finds it first.

use super::model::now;
use super::sites::{NewSite, SiteUpdate};
use super::{auth, Controller, CtlError, NewEdge, SettingsUpdate};
use crate::controller::model::CRoute;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;

const INDEX: &str = include_str!("../../ui-controller/index.html");
const APP_JS: &str = include_str!("../../ui-controller/app.js");
const APP_CSS: &str = include_str!("../../ui-controller/app.css");
const COOKIE: &str = "edgelb_session";
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

#[derive(Clone)]
pub struct AppState {
    ctl: Arc<Controller>,
    secure_cookies: bool,
}

#[derive(Clone)]
struct Actor(String);

struct ApiErr(Box<Response>);

impl From<CtlError> for ApiErr {
    fn from(e: CtlError) -> Self {
        let (status, body) = match &e {
            CtlError::NotFound(_) => (StatusCode::NOT_FOUND, json!({ "error": e.to_string() })),
            CtlError::Conflict(_) => (StatusCode::CONFLICT, json!({ "error": e.to_string() })),
            CtlError::Invalid(d) => (StatusCode::UNPROCESSABLE_ENTITY, json!({ "error": "invalid request", "details": d })),
            CtlError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": e.to_string() })),
        };
        ApiErr(Box::new((status, Json(body)).into_response()))
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        *self.0
    }
}

fn plain(status: StatusCode, msg: &str) -> ApiErr {
    ApiErr(Box::new((status, Json(json!({ "error": msg }))).into_response()))
}

type Res<T> = Result<T, ApiErr>;

fn csrf_ok(h: &HeaderMap, m: &Method) -> bool {
    matches!(*m, Method::GET | Method::HEAD | Method::OPTIONS) || h.get("x-edgelb").is_some_and(|v| v == "1")
}

fn session_token(h: &HeaderMap) -> Option<String> {
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_string())
}

fn cookie_header(token: &str, secure: bool, max_age: u64) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!("{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}")).unwrap()
}

fn with_cookie(mut r: Response, v: HeaderValue) -> Response {
    r.headers_mut().insert(header::SET_COOKIE, v);
    r
}

async fn require_auth(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    if !csrf_ok(req.headers(), req.method()) {
        return plain(StatusCode::FORBIDDEN, "missing X-EdgeLB header").into_response();
    }
    let user = session_token(req.headers()).and_then(|t| st.ctl.sessions.lookup(&t));
    match user {
        Some(u) => {
            req.extensions_mut().insert(Actor(u));
            let mut resp = next.run(req).await;
            resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        None => plain(StatusCode::UNAUTHORIZED, "not signed in").into_response(),
    }
}

// ---- session / setup ---------------------------------------------------------------------------

async fn session(State(st): State<AppState>, headers: HeaderMap) -> Json<Value> {
    let user = session_token(&headers).and_then(|t| st.ctl.sessions.lookup(&t));
    Json(json!({
        "setup_needed": st.ctl.store.read(|s| s.admin.is_none()),
        "authenticated": user.is_some(),
        "username": user,
    }))
}

#[derive(Deserialize)]
struct SetupReq {
    setup_code: String,
    username: String,
    password: String,
}

async fn setup(State(st): State<AppState>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(b): Json<SetupReq>) -> Res<Response> {
    if !csrf_ok(&headers, &Method::POST) {
        return Err(plain(StatusCode::FORBIDDEN, "missing X-EdgeLB header"));
    }
    if let Some(left) = st.ctl.sessions.locked_for(peer.ip()) {
        return Err(plain(StatusCode::TOO_MANY_REQUESTS, &format!("too many attempts; try again in {}s", left.as_secs() + 1)));
    }
    if st.ctl.store.read(|s| s.admin.is_some()) {
        return Err(plain(StatusCode::CONFLICT, "this controller is already set up"));
    }
    let expected = st.ctl.setup_code.lock().unwrap().clone().unwrap_or_default();
    if expected.is_empty() || !bool::from(b.setup_code.trim().to_ascii_uppercase().as_bytes().ct_eq(expected.as_bytes())) {
        st.ctl.sessions.record_failure(peer.ip());
        tokio::time::sleep(Duration::from_millis(300)).await;
        return Err(plain(StatusCode::FORBIDDEN, "wrong setup code (it is printed in the controller's log and stored in <data-dir>/setup-code)"));
    }
    let username = b.username.trim().to_string();
    if username.is_empty() || username.len() > 40 || !username.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
        return Err(CtlError::Invalid(vec!["username must be 1-40 letters, digits, '.', '_' or '-'".into()]).into());
    }
    let hash = auth::hash_password(&b.password).map_err(|e| CtlError::Invalid(vec![e.to_string()]))?;
    st.ctl
        .store
        .update(|s| s.admin = Some(super::model::Admin { username: username.clone(), password_hash: hash }))
        .map_err(|e| CtlError::Internal(e.to_string()))?;
    *st.ctl.setup_code.lock().unwrap() = None;
    let _ = std::fs::remove_file(st.ctl.opts.data_dir.join("setup-code"));
    st.ctl.audit.record(&username, "admin.setup", "admin account created");
    let token = st.ctl.sessions.create(&username);
    Ok(with_cookie(Json(json!({ "username": username })).into_response(), cookie_header(&token, st.secure_cookies, 43200)))
}

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

async fn login(State(st): State<AppState>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(b): Json<LoginReq>) -> Res<Response> {
    if !csrf_ok(&headers, &Method::POST) {
        return Err(plain(StatusCode::FORBIDDEN, "missing X-EdgeLB header"));
    }
    if let Some(left) = st.ctl.sessions.locked_for(peer.ip()) {
        return Err(plain(StatusCode::TOO_MANY_REQUESTS, &format!("too many failed attempts; try again in {}s", left.as_secs() + 1)));
    }
    let admin = st.ctl.store.read(|s| s.admin.clone());
    // Always run the hash, so response time doesn't reveal whether the username exists.
    let (hash, name) = admin.map(|a| (a.password_hash, a.username)).unwrap_or_else(|| ("$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(), String::new()));
    let pw_ok = tokio::task::spawn_blocking({
        let pw = b.password.clone();
        move || auth::verify_password(&pw, &hash)
    })
    .await
    .unwrap_or(false);
    if !(pw_ok && !name.is_empty() && b.username == name) {
        st.ctl.sessions.record_failure(peer.ip());
        st.ctl.audit.record("anonymous", "login.failed", &format!("from {}", peer.ip()));
        tokio::time::sleep(Duration::from_millis(300)).await;
        return Err(plain(StatusCode::UNAUTHORIZED, "wrong username or password"));
    }
    st.ctl.sessions.record_success(peer.ip());
    st.ctl.audit.record(&name, "login", &format!("from {}", peer.ip()));
    let token = st.ctl.sessions.create(&name);
    Ok(with_cookie(Json(json!({ "username": name })).into_response(), cookie_header(&token, st.secure_cookies, 43200)))
}

async fn logout(State(st): State<AppState>, headers: HeaderMap) -> Res<Response> {
    if !csrf_ok(&headers, &Method::POST) {
        return Err(plain(StatusCode::FORBIDDEN, "missing X-EdgeLB header"));
    }
    if let Some(t) = session_token(&headers) {
        st.ctl.sessions.destroy(&t);
    }
    Ok(with_cookie(StatusCode::NO_CONTENT.into_response(), cookie_header("", st.secure_cookies, 0)))
}

#[derive(Deserialize)]
struct PasswordReq {
    current: String,
    new: String,
}

async fn change_password(State(st): State<AppState>, Extension(Actor(user)): Extension<Actor>, Json(b): Json<PasswordReq>) -> Res<Response> {
    let hash = st.ctl.store.read(|s| s.admin.as_ref().map(|a| a.password_hash.clone())).unwrap_or_default();
    if !auth::verify_password(&b.current, &hash) {
        return Err(plain(StatusCode::FORBIDDEN, "current password is wrong"));
    }
    let new = auth::hash_password(&b.new).map_err(|e| CtlError::Invalid(vec![e.to_string()]))?;
    st.ctl.store.update(|s| {
        if let Some(a) = s.admin.as_mut() {
            a.password_hash = new;
        }
    }).map_err(|e| CtlError::Internal(e.to_string()))?;
    st.ctl.sessions.destroy_all(); // every other session is now invalid
    st.ctl.audit.record(&user, "admin.password", "password changed");
    let token = st.ctl.sessions.create(&user);
    Ok(with_cookie(StatusCode::NO_CONTENT.into_response(), cookie_header(&token, st.secure_cookies, 43200)))
}

// ---- resources -----------------------------------------------------------------------------------

async fn status(State(st): State<AppState>) -> Json<Value> {
    let c = &st.ctl;
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "now": now(),
        "edges": c.edges(),
        "routes": c.routes(),
        "sites": c.sites(),
        "gateway_listener": c.gateway_endpoint().map(|g| g.hostport),
        "deployment": c.deployment(),
        "dns": c.dns_status(),
        "dns_names": c.store.read(|s| s.settings.dns.as_ref().map(|d| d.names.clone())),
    }))
}

async fn list_sites(State(st): State<AppState>) -> Json<Value> {
    Json(json!(st.ctl.sites()))
}

async fn create_site(State(st): State<AppState>, Extension(Actor(u)): Extension<Actor>, Json(n): Json<NewSite>) -> Res<Response> {
    Ok((StatusCode::CREATED, Json(st.ctl.create_site(&u, n)?)).into_response())
}

async fn update_site(State(st): State<AppState>, Extension(Actor(u)): Extension<Actor>, Path(id): Path<String>, Json(b): Json<SiteUpdate>) -> Res<Response> {
    Ok(Json(st.ctl.update_site(&u, &id, b)?).into_response())
}

async fn delete_site(State(st): State<AppState>, Extension(Actor(u)): Extension<Actor>, Path(id): Path<String>) -> Res<StatusCode> {
    st.ctl.delete_site(&u, &id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn enrol_site(State(st): State<AppState>, Extension(Actor(u)): Extension<Actor>, Path(id): Path<String>) -> Res<Response> {
    Ok(Json(st.ctl.start_enrolment(&u, &id)?).into_response())
}

async fn list_edges(State(st): State<AppState>) -> Json<Value> {
    Json(json!(st.ctl.edges()))
}

async fn create_edge(State(st): State<AppState>, Extension(Actor(u)): Extension<Actor>, Json(n): Json<NewEdge>) -> Res<Response> {
    let e = st.ctl.create_edge(&u, n)?;
    Ok((StatusCode::CREATED, Json(e)).into_response())
}

async fn delete_edge(State(st): State<AppState>, Extension(Actor(u)): Extension<Actor>, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> Res<StatusCode> {
    st.ctl.delete_edge(&u, &id, q.get("force").is_some_and(|v| v == "true"))?;
    Ok(StatusCode::ACCEPTED)
}

async fn retry_edge(State(st): State<AppState>, Extension(Actor(u)): Extension<Actor>, Path(id): Path<String>) -> Res<StatusCode> {
    st.ctl.retry_edge(&u, &id)?;
    Ok(StatusCode::ACCEPTED)
}

async fn forget_edge(State(st): State<AppState>, Extension(Actor(u)): Extension<Actor>, Path(id): Path<String>) -> Res<StatusCode> {
    st.ctl.forget_edge(&u, &id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn catalog(State(st): State<AppState>) -> Res<Json<Value>> {
    Ok(Json(st.ctl.catalog().await?))
}

async fn list_routes(State(st): State<AppState>) -> Json<Value> {
    Json(json!(st.ctl.routes()))
}

async fn create_route(State(st): State<AppState>, Extension(Actor(u)): Extension<Actor>, Json(r): Json<CRoute>) -> Res<Response> {
    Ok((StatusCode::CREATED, Json(st.ctl.create_route(&u, r)?)).into_response())
}

async fn update_route(State(st): State<AppState>, Extension(Actor(u)): Extension<Actor>, Path(id): Path<String>, Json(r): Json<CRoute>) -> Res<Json<CRoute>> {
    Ok(Json(st.ctl.update_route(&u, &id, r)?))
}

async fn delete_route(State(st): State<AppState>, Extension(Actor(u)): Extension<Actor>, Path(id): Path<String>) -> Res<StatusCode> {
    st.ctl.delete_route(&u, &id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_settings(State(st): State<AppState>) -> Json<Value> {
    Json(json!(st.ctl.settings_view()))
}

async fn put_settings(State(st): State<AppState>, Extension(Actor(u)): Extension<Actor>, Json(b): Json<SettingsUpdate>) -> Res<Json<Value>> {
    if b.gateway.is_some() && b.clear_gateway {
        return Err(CtlError::Invalid(vec!["send either gateway or clear_gateway, not both".into()]).into());
    }
    // The gateway listener is applied immediately (it binds a port), on its own; every other setting
    // goes through the usual validated update.
    if b.gateway.is_some() || b.clear_gateway {
        st.ctl.set_gateway(&u, b.gateway.clone()).await?;
        if b.only_gateway() {
            return Ok(Json(json!(st.ctl.settings_view())));
        }
    }
    Ok(Json(json!(st.ctl.update_settings(&u, b)?)))
}

async fn ssh_key(State(st): State<AppState>) -> Res<Json<Value>> {
    let k = st.ctl.ssh_key().await.map_err(|e| CtlError::Internal(format!("{e:#}")))?;
    Ok(Json(json!({ "public_key": k.public })))
}

async fn audit(State(st): State<AppState>) -> Json<Value> {
    Json(json!(st.ctl.audit.tail(200)))
}

/// Recent connections from the edges (see `controller::logs`). Filters are query parameters.
async fn logs(State(st): State<AppState>, Query(q): Query<super::logs::LogQuery>) -> Res<Json<super::logs::LogsView>> {
    Ok(Json(st.ctl.access_logs(q).await?))
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    let mut r = body.into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    r
}

pub fn router(ctl: Arc<Controller>, secure_cookies: bool) -> Router {
    let st = AppState { ctl, secure_cookies };
    let protected = Router::new()
        .route("/status", get(status))
        .route("/edges", get(list_edges).post(create_edge))
        .route("/edges/:id", axum::routing::delete(delete_edge))
        .route("/edges/:id/retry", post(retry_edge))
        .route("/edges/:id/forget", post(forget_edge))
        .route("/catalog", get(catalog))
        .route("/sites", get(list_sites).post(create_site))
        .route("/sites/:id", axum::routing::put(update_site).delete(delete_site))
        .route("/sites/:id/enrol", post(enrol_site))
        .route("/routes", get(list_routes).post(create_route))
        .route("/routes/:id", axum::routing::put(update_route).delete(delete_route))
        .route("/settings", get(get_settings).put(put_settings))
        .route("/ssh-key", get(ssh_key))
        .route("/audit", get(audit))
        .route("/logs", get(logs))
        .route("/password", post(change_password))
        .layer(middleware::from_fn_with_state(st.clone(), require_auth));
    let open = Router::new().route("/session", get(session)).route("/setup", post(setup)).route("/login", post(login)).route("/logout", post(logout));

    Router::new()
        .route("/", get(|| async { asset("text/html; charset=utf-8", INDEX) }))
        .route("/app.js", get(|| async { asset("text/javascript; charset=utf-8", APP_JS) }))
        .route("/app.css", get(|| async { asset("text/css; charset=utf-8", APP_CSS) }))
        .route("/healthz", get(|| async { "ok" }))
        .nest("/api", protected.merge(open))
        .with_state(st)
}

/// Serve the UI and API on `listener` until `shutdown` resolves, then stop the controller's
/// background work. The CLI and the desktop app both run the controller through this.
pub async fn serve(
    ctl: Arc<Controller>,
    listener: tokio::net::TcpListener,
    secure_cookies: bool,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let app = router(ctl.clone(), secure_cookies).into_make_service_with_connect_info::<SocketAddr>();
    let res = axum::serve(listener, app).with_graceful_shutdown(shutdown).await;
    ctl.stop();
    res
}
