//! The real bootstrap path with the real edge binary: upload, run the installer script, read the
//! identity back, pin it, join, serve traffic, uninstall.
//!
//! Only the transport is faked: a stub `ssh` runs the remote command locally, and the installer
//! runs in its "staged" mode (no root, no systemd) under a scratch directory. The systemd unit
//! itself is covered by a syntax check in the unit tests, not executed here.

use edge_lbd::controller::bootstrap::{Bootstrapper, SshBootstrapper, SshKey, Target};
use edge_lbd::controller::model::{EdgeStatus, ProviderSpec};
use edge_lbd::controller::{Controller, NewEdge, Options};
use edge_lbd::pki;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

const FAKE_SSH: &str = "#!/bin/sh\n# Runs the \"remote\" command (the last argument) locally, passing stdin through.\nfor a; do last=\"$a\"; done\nexec sh -c \"$last\"\n";

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("edge-lbd-ssh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_exec(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn bootstrapper(dir: &Path, ssh_bin: &Path, stage: Option<PathBuf>) -> SshBootstrapper {
    let mut b = SshBootstrapper::new(SshKey { private: dir.join("id_test"), public: "ssh-ed25519 AAAATEST edge-lb-controller".into() }, dir);
    b.ssh_bin = ssh_bin.display().to_string();
    b.keygen_bin = "true".into();
    b.stage = stage;
    b
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
}

/// Kills the staged edge process if a test fails halfway.
struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Ok(pid) = std::fs::read_to_string(self.0.join("edge.pid")) {
            let _ = std::process::Command::new("kill").arg(pid.trim()).status();
        }
    }
}

#[tokio::test]
async fn bootstraps_a_machine_over_ssh_and_manages_it() {
    let dir = scratch("e2e");
    let stage = dir.join("machine");
    let _guard = Cleanup(stage.clone());
    let fake = dir.join("fake-ssh");
    write_exec(&fake, FAKE_SSH);
    let mgmt = free_port().await;

    let mut o = Options::new(dir.join("ctl"));
    o.edge_binary = PathBuf::from(env!("CARGO_BIN_EXE_edge-lbd"));
    o.bootstrapper = Some(Arc::new(bootstrapper(&dir, &fake, Some(stage.clone()))));
    o.tick = Duration::from_millis(50);
    o.poll_every = Duration::from_millis(150);
    o.retry_backoff = (Duration::from_millis(50), Duration::from_millis(200));
    let ctl = Controller::start(o).await.unwrap();
    ctl.update_settings("t", serde_json::from_value(json!({"drain_seconds": 1})).unwrap()).unwrap();

    // A backend and a route that every edge should serve.
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = backend.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = backend.accept().await else { return };
            let _ = s.write_all(b"through the real edge").await;
        }
    });
    let route_port = free_port().await;
    ctl.create_route(
        "t",
        serde_json::from_value(json!({"name": "svc", "listen": {"ip": "127.0.0.1", "port": route_port}, "targets": [{"address": "127.0.0.1", "port": bport}]})).unwrap(),
    )
    .unwrap();

    // Adopt an "existing machine".
    ctl.create_edge("t", NewEdge { name: "adopted".into(), region: "lab".into(), provider: ProviderSpec::Manual, ip: Some("127.0.0.1".parse().unwrap()), ssh_user: Some("root".into()), ssh_port: None, mgmt_port: Some(mgmt) }).unwrap();

    let status = || ctl.edges()[0].edge.status;
    for _ in 0..300 {
        if status() == EdgeStatus::Healthy || status() == EdgeStatus::Failed {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let e = ctl.edges()[0].edge.clone();
    assert_eq!(e.status, EdgeStatus::Healthy, "edge ended {:?}: {:?}\nlog: {:#?}", e.status, e.error, e.log);

    // The pinned identity is exactly the certificate the edge generated for itself on "disk".
    let on_disk = std::fs::read_to_string(stage.join("var/lib/edge-lb/mgmt-cert.pem")).unwrap();
    assert_eq!(e.mgmt_fingerprint.as_deref(), Some(pki::fingerprint_pem(&on_disk).unwrap().as_str()));
    let key_mode = std::fs::metadata(stage.join("var/lib/edge-lb/mgmt-key.pem")).unwrap().permissions().mode() & 0o777;
    assert_eq!(key_mode, 0o600, "edge private key must not be group/world readable");
    assert!(stage.join("usr/local/bin/edge-lbd").exists());
    assert!(std::fs::read_to_string(stage.join("etc/edge-lb/controller-ca.pem")).unwrap().contains("BEGIN CERTIFICATE"));

    // A real separate process is now carrying traffic for the controller's route.
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", route_port)).await.is_ok() {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let mut c = TcpStream::connect(("127.0.0.1", route_port)).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), c.read_to_end(&mut out)).await;
    assert_eq!(out, b"through the real edge");

    // Deleting it drains, removes our software from the machine, and stops the process.
    ctl.delete_edge("t", "adopted", true).unwrap();
    for _ in 0..200 {
        if ctl.edges().is_empty() {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(ctl.edges().is_empty(), "edge should be gone: {:?}", ctl.edges().first().map(|e| (e.edge.status, e.edge.error.clone())));
    assert!(!stage.join("usr").exists(), "uninstall removed the files");
    sleep(Duration::from_millis(300)).await;
    assert!(TcpStream::connect(("127.0.0.1", mgmt)).await.is_err(), "the edge process was stopped");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn ssh_failures_surface_clearly_and_nothing_is_run_on_bad_input() {
    let dir = scratch("fail");
    let t = |user: &str| Target { edge_id: "x".into(), ip: "127.0.0.1".parse().unwrap(), ssh_user: user.into(), ssh_port: 22, mgmt_port: 7443 };

    // Login refused: the stderr tail reaches the caller.
    let denied = dir.join("denied-ssh");
    write_exec(&denied, "#!/bin/sh\necho 'root@127.0.0.1: Permission denied (publickey).' >&2\nexit 255\n");
    let err = bootstrapper(&dir, &denied, None).probe(&t("root")).await.unwrap_err().to_string();
    assert!(err.contains("Permission denied"), "{err}");

    // A hostile SSH user name never reaches the command line.
    let marker = dir.join("ran");
    let spy = dir.join("spy-ssh");
    write_exec(&spy, &format!("#!/bin/sh\ntouch {}\n", marker.display()));
    let err = bootstrapper(&dir, &spy, None).probe(&t("-oProxyCommand=touch /tmp/pwned")).await.unwrap_err().to_string();
    assert!(err.contains("invalid SSH user"), "{err}");
    assert!(!marker.exists(), "ssh must not be invoked at all");

    // A malicious host that answers `mktemp` with a crafted path is refused before any root script is built.
    let evil = dir.join("evil-ssh");
    write_exec(&evil, "#!/bin/sh\necho '/tmp/edge-lb.x; rm -rf /'\n");
    let ctx = edge_lbd::controller::bootstrap::InstallCtx { ca_pem: "x".into(), binary: PathBuf::from(env!("CARGO_BIN_EXE_edge-lbd")) };
    let err = bootstrapper(&dir, &evil, None).install(&t("root"), &ctx).await.unwrap_err().to_string();
    assert!(err.contains("unexpected temp directory"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
