//! The edge-lb controller as a Windows desktop app.
//!
//! At start the app shows a small **launcher** with two choices: run the controller on this PC
//! (the same library `edge-lbd controller` uses, serving its web UI on 127.0.0.1) or connect to a
//! controller running somewhere else. Either way the controller's own web page is shown in a
//! WebView2 window, so the UI, its strict Content-Security-Policy and its cookie/CSRF handling are
//! exactly what a browser would get.
//!
//! Only the launcher page can call into this program (Tauri capability `launcher`). The window
//! that shows a controller is a plain external page: no IPC, and it can't navigate off its origin.
//!
//! Closing a window hides it to the tray; "Quit" stops the local controller. Edges never depend on
//! this process: they keep serving while it is closed.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod setup;

use anyhow::{anyhow, bail, Context, Result};
use config::{AppConfig, Remote};
use edge_lbd::controller::{agents::Agents, sites::GatewayListen, Controller, Options};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, RunEvent, State, Url, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
use tokio::sync::oneshot;

const LAUNCHER: &str = "launcher";

struct AppState {
    config_dir: PathBuf,
    cfg: AppConfig,
    /// A problem to show in the launcher: a broken config file, or the last failed attempt.
    notice: Mutex<Option<String>>,
    local: tokio::sync::Mutex<Option<LocalServer>>,
    /// Label of the window currently showing a controller, if any.
    current: Mutex<Option<String>>,
    seq: AtomicU32,
}

/// The local controller, once started. It keeps running until the app quits, so switching to a
/// remote controller and back doesn't restart it.
struct LocalServer {
    url: Url,
    ctl: Arc<Controller>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tauri::async_runtime::JoinHandle<()>>,
}

fn main() {
    let app = tauri::Builder::default()
        // A second launch just brings the existing window forward.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_window(app)))
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![get_state, start_local, connect_remote, forget_remote, plan_setup])
        .setup(|app| {
            if let Err(e) = setup(app.handle()) {
                tracing::error!("startup failed: {e:#}");
                let handle = app.handle().clone();
                app.dialog()
                    .message(format!("edge-lb could not start.\n\n{e:#}"))
                    .title("edge-lb")
                    .kind(MessageDialogKind::Error)
                    .show(move |_| handle.exit(1));
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building the edge-lb app");

    app.run(|app, event| match event {
        // Closing a window only hides it, so this means "no windows left": stay in the tray.
        RunEvent::ExitRequested { api, code: None, .. } => api.prevent_exit(),
        RunEvent::Exit => stop_local(app),
        _ => {}
    });
}

fn setup(app: &AppHandle) -> Result<()> {
    let config_dir = config_dir()?;
    std::fs::create_dir_all(&config_dir).with_context(|| format!("creating {}", config_dir.display()))?;
    init_logging(&config_dir);
    let (cfg, notice) = AppConfig::load(&config_dir);
    let startup = cfg.startup.clone().unwrap_or_else(|| "ask".into());
    app.manage(AppState {
        config_dir,
        cfg,
        notice: Mutex::new(notice.clone()),
        local: tokio::sync::Mutex::new(None),
        current: Mutex::new(None),
        seq: AtomicU32::new(0),
    });
    make_tray(app)?;

    // A broken config file always shows the launcher, so the message is seen.
    if notice.is_some() || startup.eq_ignore_ascii_case("ask") {
        return show_launcher(app, false);
    }
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let st = handle.state::<AppState>();
        let result = if startup.eq_ignore_ascii_case("local") {
            connect_local(&handle, &st).await
        } else {
            connect_saved(&handle, &st, &startup).await
        };
        if let Err(e) = result {
            tracing::error!("startup connection failed: {e:#}");
            *st.notice.lock().unwrap() = Some(format!("Could not start with \"{startup}\": {e:#}"));
            if let Err(e) = show_launcher(&handle, false) {
                tracing::error!("could not open the launcher: {e:#}");
            }
        }
    });
    Ok(())
}

// ---- what the launcher page can ask for -------------------------------------------------------------

#[derive(Serialize)]
struct StateView {
    notice: Option<String>,
    config_dir: String,
    local: LocalView,
    remotes: Vec<Remote>,
}

#[derive(Serialize)]
struct LocalView {
    data_dir: String,
    has_data: bool,
    running: bool,
    port: u16,
    agents: Vec<&'static str>,
    gateway: Option<String>,
}

#[tauri::command]
async fn get_state(app: AppHandle, st: State<'_, AppState>) -> std::result::Result<StateView, String> {
    let data_dir = local_data_dir(&st);
    let mut notice = st.notice.lock().unwrap().clone();
    let remotes = match config::load_remotes(&st.config_dir) {
        Ok(r) => r,
        Err(e) => {
            notice.get_or_insert_with(|| format!("{e:#}"));
            Vec::new()
        }
    };
    let gateway = st.cfg.local.gateway_listen.zip(st.cfg.local.gateway_host.as_ref()).map(|(l, h)| format!("{l}, gateways connect to {h}"));
    Ok(StateView {
        notice,
        config_dir: st.config_dir.display().to_string(),
        local: LocalView {
            // The setup code file exists until the administrator account has been created.
            has_data: data_dir.join("controller.json").is_file() && !data_dir.join("setup-code").is_file(),
            data_dir: data_dir.display().to_string(),
            running: st.local.lock().await.is_some(),
            port: st.cfg.local.port,
            agents: local_agents(&app).archs(),
            gateway,
        },
        remotes,
    })
}

#[tauri::command]
async fn start_local(app: AppHandle, st: State<'_, AppState>) -> std::result::Result<(), String> {
    connect_local(&app, &st).await.map_err(|e| {
        tracing::error!("starting the local controller failed: {e:#}");
        format!("{e:#}")
    })
}

#[tauri::command]
async fn connect_remote(app: AppHandle, st: State<'_, AppState>, url: String, name: Option<String>) -> std::result::Result<(), String> {
    let url = config::normalize_remote(&url)?;
    let name = name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
    if name.as_ref().is_some_and(|n| n.chars().count() > 60 || n.chars().any(char::is_control)) {
        return Err("Use a shorter name, without control characters.".into());
    }
    connect_to(&app, &st, &url, name.as_deref()).await.map_err(|e| {
        tracing::warn!("connecting to {url} failed: {e:#}");
        format!("{e:#}")
    })
}

#[tauri::command]
async fn forget_remote(st: State<'_, AppState>, url: String) -> std::result::Result<(), String> {
    let mut list = config::load_remotes(&st.config_dir).map_err(|e| format!("{e:#}"))?;
    list.retain(|r| r.url != url);
    config::save_remotes(&st.config_dir, &list).map_err(|e| format!("{e:#}"))
}

/// The commands for installing a controller on a server. Pure text: nothing runs and nothing is sent.
#[tauri::command]
fn plan_setup(request: setup::SetupRequest) -> std::result::Result<setup::SetupPlan, String> {
    setup::plan(&request, env!("CARGO_PKG_REPOSITORY"))
}

// ---- connecting -------------------------------------------------------------------------------------

async fn connect_local(app: &AppHandle, st: &AppState) -> Result<()> {
    let (url, setup_code) = ensure_local(app, st).await?;
    open_controller(app, st, &url, "edge-lb", setup_code.as_deref())
}

async fn connect_saved(app: &AppHandle, st: &AppState, name: &str) -> Result<()> {
    let remotes = config::load_remotes(&st.config_dir)?;
    let r = remotes.iter().find(|r| r.name.eq_ignore_ascii_case(name)).ok_or_else(|| anyhow!("no saved controller is called \"{name}\" (see remotes.toml)"))?;
    let url = config::normalize_remote(&r.url).map_err(|e| anyhow!(e))?;
    connect_to(app, st, &url, None).await
}

/// Check that `url` really is an edge-lb controller, remember it, and show it.
async fn connect_to(app: &AppHandle, st: &AppState, url: &Url, name: Option<&str>) -> Result<()> {
    probe(url).await?;
    let origin = config::origin_string(url);
    match config::load_remotes(&st.config_dir) {
        Ok(mut list) => {
            config::remember(&mut list, &origin, name, now());
            let title = list.iter().find(|r| r.url == origin).map(|r| r.name.clone()).unwrap_or_default();
            if let Err(e) = config::save_remotes(&st.config_dir, &list) {
                tracing::warn!("could not save remotes.toml: {e:#}");
            }
            open_controller(app, st, url, &format!("edge-lb \u{2014} {title}"), None)
        }
        Err(e) => {
            // Don't overwrite a file we couldn't read; connecting still works.
            tracing::warn!("not saving this controller: {e:#}");
            open_controller(app, st, url, &format!("edge-lb \u{2014} {}", url.host_str().unwrap_or("remote")), None)
        }
    }
}

/// `GET /api/session` on a real controller answers JSON with two booleans, and nothing else we
/// might be pointed at does. Nothing about this machine or the user is sent.
async fn probe(url: &Url) -> Result<()> {
    edge_lbd::tls::init();
    let client = reqwest::Client::builder().timeout(Duration::from_secs(6)).redirect(reqwest::redirect::Policy::none()).build()?;
    let hint = if url.scheme() == "https" && config::host_is_private(&url.host().unwrap_or(url::Host::Domain(""))) {
        " If this controller doesn't use TLS, enter it as http://host:port."
    } else {
        ""
    };
    let resp = client.get(url.join("api/session")?).send().await.map_err(|e| anyhow!("Could not reach {}: {}.{hint}", url.authority(), root_cause(&e)))?;
    if !resp.status().is_success() {
        bail!("{} answered HTTP {}, so it doesn't look like an edge-lb controller.", url.authority(), resp.status().as_u16());
    }
    let v: serde_json::Value = resp.json().await.map_err(|_| anyhow!("{} answered, but not like an edge-lb controller.", url.authority()))?;
    if !(v["setup_needed"].is_boolean() && v["authenticated"].is_boolean()) {
        bail!("{} answered, but not like an edge-lb controller.", url.authority());
    }
    Ok(())
}

/// The innermost reason in an error chain: "connection refused", "certificate not trusted", ...
fn root_cause(e: &(dyn std::error::Error + 'static)) -> String {
    let mut cur = e;
    while let Some(next) = cur.source() {
        cur = next;
    }
    cur.to_string().trim_end_matches('.').to_string()
}

// ---- the local controller ---------------------------------------------------------------------------

fn local_data_dir(st: &AppState) -> PathBuf {
    // A relative path means "inside the app's folder", not "wherever the shortcut started us".
    st.cfg.local.data_dir.as_ref().map(|d| st.config_dir.join(d)).unwrap_or_else(|| st.config_dir.clone())
}

fn local_agents(app: &AppHandle) -> Agents {
    let mut agents = Agents::for_this_controller();
    // The Linux builds the controller pushes to machines ship beside the app.
    if let Ok(res) = app.path().resource_dir() {
        agents.discover(&res.join("agents"));
    }
    agents
}

fn gateway_setting(st: &AppState) -> Result<Option<GatewayListen>> {
    let l = &st.cfg.local;
    if let (Some(listen), Some(host)) = (l.gateway_listen, l.gateway_host.clone()) {
        return Ok(Some(GatewayListen { listen, host }));
    }
    // Environment switches, as for `edge-lbd controller`.
    if let (Ok(listen), Ok(host)) = (std::env::var("EDGE_LB_GATEWAY_LISTEN"), std::env::var("EDGE_LB_GATEWAY_HOST")) {
        let listen: SocketAddr = listen.parse().context("EDGE_LB_GATEWAY_LISTEN must be ip:port")?;
        return Ok(Some(GatewayListen { listen, host }));
    }
    Ok(None)
}

/// Start the local controller if it isn't running. Returns where to find it and the first-run
/// setup code, if one is still pending.
async fn ensure_local(app: &AppHandle, st: &AppState) -> Result<(Url, Option<String>)> {
    let mut guard = st.local.lock().await;
    if guard.is_none() {
        *guard = Some(start_local_controller(app, st).await?);
    }
    let local = guard.as_ref().expect("just started");
    let code = local.ctl.setup_code.lock().unwrap().clone();
    Ok((local.url.clone(), code))
}

async fn start_local_controller(app: &AppHandle, st: &AppState) -> Result<LocalServer> {
    let data_dir = local_data_dir(st);
    let mut opts = Options::new(data_dir);
    opts.agents = local_agents(app);
    if opts.agents.is_empty() {
        tracing::warn!("no Linux edge binaries found: edges and gateways can't be installed");
    } else {
        tracing::info!("can install edges and gateways for: {}", opts.agents.archs().join(", "));
    }
    opts.gateway = gateway_setting(st)?;

    let ctl = Controller::start(opts).await?;
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", st.cfg.local.port)).await {
        Ok(l) => Ok(l),
        Err(_) => tokio::net::TcpListener::bind(("127.0.0.1", 0)).await,
    };
    let listener = match listener {
        Ok(l) => l,
        Err(e) => {
            ctl.stop();
            return Err(anyhow!(e).context("could not open a local port for the controller"));
        }
    };
    let url: Url = format!("http://{}/", listener.local_addr()?).parse()?;
    tracing::info!("controller UI on {url}");

    let (stop, stopped) = oneshot::channel::<()>();
    let serving = ctl.clone();
    let task = tauri::async_runtime::spawn(async move {
        let shutdown = async {
            let _ = stopped.await;
        };
        if let Err(e) = edge_lbd::controller::api::serve(serving, listener, false, shutdown).await {
            tracing::error!("controller server stopped: {e}");
        }
    });
    Ok(LocalServer { url, ctl, stop: Some(stop), task: Some(task) })
}

/// Stop serving and let the controller's background work wind down (bounded, so Quit never hangs).
fn stop_local(app: &AppHandle) {
    let Some(st) = app.try_state::<AppState>() else { return };
    let local = tauri::async_runtime::block_on(async { st.local.lock().await.take() });
    let Some(mut local) = local else { return };
    if let Some(stop) = local.stop.take() {
        let _ = stop.send(());
    }
    if let Some(task) = local.task.take() {
        let _ = tauri::async_runtime::block_on(tokio::time::timeout(Duration::from_secs(5), task));
    }
}

// ---- windows ----------------------------------------------------------------------------------------

/// Show `url` in a fresh window (replacing the one showing the previous controller).
fn open_controller(app: &AppHandle, st: &AppState, url: &Url, title: &str, setup_code: Option<&str>) -> Result<()> {
    let previous = st.current.lock().unwrap().take();
    if let Some(w) = previous.and_then(|l| app.get_webview_window(&l)) {
        let _ = w.destroy();
    }
    let label = format!("ctl{}", st.seq.fetch_add(1, Ordering::Relaxed));
    let origin = url.origin();
    let mut builder = WebviewWindowBuilder::new(app, &label, WebviewUrl::External(url.clone()))
        .title(title)
        .inner_size(1200.0, 800.0)
        .min_inner_size(900.0, 600.0)
        // The window only ever shows the controller it was opened for.
        .on_navigation(move |to| to.origin() == origin);
    if let Some(code) = setup_code {
        let script = fill_setup_code_script(url, code);
        if !script.is_empty() {
            builder = builder.initialization_script(script);
        }
    }
    let window = builder.build()?;
    let w = window.clone();
    window.on_window_event(move |event| {
        if let WindowEvent::CloseRequested { api, .. } = event {
            api.prevent_close();
            let _ = w.hide();
        }
    });
    *st.current.lock().unwrap() = Some(label);
    if let Some(l) = app.get_webview_window(LAUNCHER) {
        let _ = l.hide();
    }
    Ok(())
}

/// First run has no console to print the setup code to, so type it into the form for the person
/// at the keyboard. The controller still requires it: this only moves it from the file in the
/// data folder to the window. Runs only on the local controller's own origin.
fn fill_setup_code_script(url: &Url, code: &str) -> String {
    // The code is alphanumeric; refuse anything else rather than build a script around it.
    if code.is_empty() || !code.chars().all(|c| c.is_ascii_alphanumeric()) {
        return String::new();
    }
    let origin = url.origin().ascii_serialization();
    format!(
        r#"(function () {{
  if (location.origin !== "{origin}") return;
  var code = "{code}";
  function fill() {{
    var wrap = document.getElementById("f-code-wrap"), el = document.getElementById("f-code");
    if (wrap && el && !wrap.hidden && !el.value) {{ el.value = code; }}
  }}
  new MutationObserver(fill).observe(document, {{ subtree: true, childList: true, attributes: true, attributeFilter: ["hidden"] }});
  document.addEventListener("DOMContentLoaded", fill);
}})();"#
    )
}

fn controller_window(app: &AppHandle) -> Option<tauri::WebviewWindow> {
    let st = app.try_state::<AppState>()?;
    let label = st.current.lock().unwrap().clone()?;
    app.get_webview_window(&label)
}

/// The launcher. `hide_controller` is for "Switch controller": get the current one out of the way.
fn show_launcher(app: &AppHandle, hide_controller: bool) -> Result<()> {
    if hide_controller {
        if let Some(w) = controller_window(app) {
            let _ = w.hide();
        }
    }
    if let Some(w) = app.get_webview_window(LAUNCHER) {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
        return Ok(());
    }
    let window = WebviewWindowBuilder::new(app, LAUNCHER, WebviewUrl::App("index.html".into()))
        .title("edge-lb")
        .inner_size(900.0, 700.0)
        .min_inner_size(640.0, 480.0)
        .build()?;
    let (w, handle) = (window.clone(), app.clone());
    window.on_window_event(move |event| {
        if let WindowEvent::CloseRequested { api, .. } = event {
            api.prevent_close();
            let _ = w.hide();
            // Closing the launcher means "never mind": back to the controller we were showing, or, if
            // there was none (nothing chosen yet), leave.
            match controller_window(&handle) {
                Some(c) => {
                    let _ = c.show();
                    let _ = c.set_focus();
                }
                None => handle.exit(0),
            }
        }
    });
    Ok(())
}

fn show_window(app: &AppHandle) {
    match controller_window(app) {
        Some(w) => {
            let _ = w.show();
            let _ = w.unminimize();
            let _ = w.set_focus();
        }
        None => {
            if let Err(e) = show_launcher(app, false) {
                tracing::error!("could not open the launcher: {e:#}");
            }
        }
    }
}

fn make_tray(app: &AppHandle) -> Result<()> {
    let open = MenuItem::with_id(app, "open", "Open edge-lb", true, None::<&str>)?;
    let switch = MenuItem::with_id(app, "switch", "Switch controller\u{2026}", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit edge-lb", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &switch, &quit])?;
    let mut tray = TrayIconBuilder::new()
        .tooltip("edge-lb")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_window(app),
            "switch" => {
                if let Err(e) = show_launcher(app, true) {
                    tracing::error!("could not open the launcher: {e:#}");
                }
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

// ---- small things -----------------------------------------------------------------------------------

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `%APPDATA%\edge-lb`, the same folder `edge-lbd controller` uses, unless overridden.
fn config_dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("EDGE_LB_CONTROLLER_DIR") {
        return Ok(PathBuf::from(d));
    }
    let appdata = std::env::var_os("APPDATA").context("%APPDATA% is not set")?;
    Ok(PathBuf::from(appdata).join("edge-lb"))
}

/// There is no console in the desktop app, so log to a file in the app's folder.
fn init_logging(dir: &std::path::Path) {
    let path = dir.join("edge-lb.log");
    if std::fs::metadata(&path).map(|m| m.len() > 5 * 1024 * 1024).unwrap_or(false) {
        let _ = std::fs::remove_file(&path);
    }
    if let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = tracing_subscriber::fmt().with_writer(Mutex::new(file)).with_ansi(false).try_init();
    }
}
