//! The edge updater script, run for real. Only `systemctl` and `journalctl` are faked: the script
//! itself (backups, unit rewrite, wait for the service, rollback) runs exactly as it would on an edge,
//! against a scratch directory standing in for `/`.
//!
//! What matters most about an updater is what it does when the new version is bad, so most of this is
//! about failure: a binary that won't run, one that won't start, and going back afterwards.

#![cfg(unix)]

use edge_lbd::controller::bootstrap::{extract_identity, rollback_script, update_script};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const OLD_BIN: &str = "#!/bin/sh\n# OLDBIN\n[ \"$1\" = --version ] && echo 'edge-lbd 0.1.2'\nexit 0\n";
const GOOD_BIN: &str = "#!/bin/sh\n# NEWBIN\n[ \"$1\" = --version ] && echo 'edge-lbd 0.1.3'\nexit 0\n";
/// Runs, but the (fake) service refuses to stay up with it.
const BAD_BIN: &str = "#!/bin/sh\n# BADBIN\n[ \"$1\" = --version ] && echo 'edge-lbd 0.1.3'\nexit 0\n";
/// Doesn't even run.
const BROKEN_BIN: &str = "#!/bin/sh\nexit 1\n";

struct Box_ {
    root: PathBuf,
    upload: PathBuf,
    cert: String,
}

fn write(path: &Path, text: &str, mode: u32) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

impl Box_ {
    /// An installed edge (old binary and units, identity on disk), a fake systemd, and an upload
    /// directory holding `new_bin`. `wg`: the machine also has the WireGuard helper unit.
    fn new(new_bin: &str, wg: bool) -> Box_ {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("edge-lb-update-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        write(&root.join("usr/local/bin/edge-lbd"), OLD_BIN, 0o755);
        write(&root.join("etc/systemd/system/edge-lbd.service"), "OLD UNIT\n", 0o644);
        if wg {
            write(&root.join("etc/systemd/system/edge-lb-wg.service"), "OLD WG UNIT\n", 0o644);
        }
        let cert = edge_lbd::pki::self_signed_server().unwrap().cert;
        write(&root.join("var/lib/edge-lb/mgmt-cert.pem"), &cert, 0o644);
        std::fs::create_dir_all(root.join("state")).unwrap();
        std::fs::write(root.join("state/active"), "").unwrap(); // the old version is running

        // The script insists on this exact kind of directory name.
        let upload = PathBuf::from(format!("/tmp/edge-lb.upd{}x{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&upload);
        write(&upload.join("edge-lbd"), new_bin, 0o755);
        write(&upload.join("ca.pem"), "CA\n", 0o644);

        // A systemd that is active whenever the installed binary isn't marked BADBIN.
        let r = root.display();
        write(
            &root.join("fakebin/systemctl"),
            &format!(
                "#!/bin/sh\nSTATE='{r}/state'; BIN='{r}/usr/local/bin/edge-lbd'\necho \"$*\" >> \"$STATE/calls\"\ncase \"$1\" in\n  restart) if grep -q BADBIN \"$BIN\"; then rm -f \"$STATE/active\"; else touch \"$STATE/active\"; fi; exit 0 ;;\n  is-active) [ -e \"$STATE/active\" ] ;;\n  *) exit 0 ;;\nesac\n"
            ),
            0o755,
        );
        write(&root.join("fakebin/journalctl"), "#!/bin/sh\nexit 0\n", 0o755);
        Box_ { root, upload, cert }
    }

    fn bin(&self) -> String {
        read(&self.root.join("usr/local/bin/edge-lbd"))
    }
    fn unit(&self) -> String {
        read(&self.root.join("etc/systemd/system/edge-lbd.service"))
    }
    fn exists(&self, rel: &str) -> bool {
        self.root.join(rel).exists()
    }
    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.root.join("state/calls")).unwrap_or_default().lines().map(String::from).collect()
    }
    fn active(&self) -> bool {
        self.exists("state/active")
    }

    fn run(&self, script: &str) -> (bool, String, String) {
        let path = format!("{}:{}", self.root.join("fakebin").display(), std::env::var("PATH").unwrap_or_default());
        let mut child = Command::new("sh").arg("-s").env("PATH", path).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(script.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
    }

    fn update(&self, wait: u32) -> (bool, String, String) {
        self.run(&update_script(self.upload.to_str().unwrap(), 7443, Some(&self.root), wait).unwrap())
    }
    fn rollback(&self) -> (bool, String, String) {
        self.run(&rollback_script(Some(&self.root)).unwrap())
    }
}

impl Drop for Box_ {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
        let _ = std::fs::remove_dir_all(&self.upload);
    }
}

#[test]
fn a_good_update_swaps_the_binary_and_units_keeps_the_old_ones_and_reports_the_same_identity() {
    let b = Box_::new(GOOD_BIN, true);
    let (ok, out, err) = b.update(5);
    assert!(ok, "{err}");

    assert!(b.bin().contains("NEWBIN"), "the new binary is in place");
    assert!(read(&b.root.join("usr/local/bin/edge-lbd.old")).contains("OLDBIN"), "the old one is kept for a rollback");
    assert!(b.unit().contains("edge --mgmt 0.0.0.0:7443") && b.unit().contains("DynamicUser=yes"), "the unit is rewritten from the current template:\n{}", b.unit());
    assert!(read(&b.root.join("etc/systemd/system/edge-lb-wg.service")).contains("wg-apply"), "so is the WireGuard helper's");
    assert_eq!(read(&b.root.join("etc/systemd/system/edge-lbd.service.old")), "OLD UNIT\n");
    assert_eq!(read(&b.root.join("etc/systemd/system/edge-lb-wg.service.old")), "OLD WG UNIT\n");
    assert!(b.active());
    let calls = b.calls();
    assert!(calls.iter().any(|c| c == "restart edge-lbd") && calls.iter().any(|c| c == "restart edge-lb-wg"), "{calls:?}");
    assert!(!b.upload.exists(), "the uploaded files are cleaned up");

    // The controller compares this with the identity it pinned: an update must not change it.
    assert_eq!(extract_identity(&out).unwrap().trim(), b.cert.trim());
    assert!(!b.exists("usr/local/bin/edge-lbd.new"), "no half-installed leftovers");
}

#[test]
fn a_machine_without_the_wireguard_helper_is_updated_without_one() {
    let b = Box_::new(GOOD_BIN, false);
    let (ok, _, err) = b.update(5);
    assert!(ok, "{err}");
    assert!(b.bin().contains("NEWBIN"));
    assert!(!b.exists("etc/systemd/system/edge-lb-wg.service"), "the updater must not invent a WireGuard helper");
    assert!(!b.calls().iter().any(|c| c.contains("edge-lb-wg")), "{:?}", b.calls());
}

#[test]
fn a_new_version_that_will_not_start_is_undone_automatically() {
    let b = Box_::new(BAD_BIN, true);
    let (ok, _, err) = b.update(2);
    assert!(!ok, "the update must report failure");
    assert!(err.contains("did not start") && err.contains("putting the previous version back"), "{err}");

    // Everything is as it was, and the old version is running again.
    assert!(b.bin().contains("OLDBIN"), "the previous binary is back:\n{}", b.bin());
    assert_eq!(b.unit(), "OLD UNIT\n", "and the previous unit");
    assert_eq!(read(&b.root.join("etc/systemd/system/edge-lb-wg.service")), "OLD WG UNIT\n");
    assert!(b.active(), "the service is running the old version, not left stopped");
    assert!(!b.exists("usr/local/bin/edge-lbd.old"), "the backup was moved back, not left behind");
    assert!(!b.upload.exists());
    assert_eq!(read(&b.root.join("var/lib/edge-lb/mgmt-cert.pem")).trim(), b.cert.trim(), "the identity was never touched");
}

#[test]
fn a_binary_that_does_not_run_here_is_refused_before_anything_changes() {
    let b = Box_::new(BROKEN_BIN, true);
    let (ok, _, err) = b.update(2);
    assert!(!ok);
    assert!(err.contains("does not run on this machine"), "{err}");
    assert!(b.bin().contains("OLDBIN"));
    assert_eq!(b.unit(), "OLD UNIT\n");
    assert!(!b.exists("usr/local/bin/edge-lbd.old"), "nothing was backed up because nothing was changed");
    assert!(b.calls().is_empty(), "the running service was never touched: {:?}", b.calls());
    assert!(b.active());
    assert!(!b.upload.exists());
}

#[test]
fn nothing_is_installed_if_edge_lb_is_not_there() {
    let b = Box_::new(GOOD_BIN, false);
    std::fs::remove_file(b.root.join("etc/systemd/system/edge-lbd.service")).unwrap();
    let (ok, _, err) = b.update(2);
    assert!(!ok);
    assert!(err.contains("not installed"), "{err}");
    assert!(b.bin().contains("OLDBIN"));
}

#[test]
fn a_rollback_puts_the_previous_version_back_after_a_good_update() {
    let b = Box_::new(GOOD_BIN, true);
    assert!(b.update(5).0);
    assert!(b.bin().contains("NEWBIN"));

    let (ok, _, err) = b.rollback();
    assert!(ok, "{err}");
    assert!(b.bin().contains("OLDBIN"));
    assert_eq!(b.unit(), "OLD UNIT\n");
    assert_eq!(read(&b.root.join("etc/systemd/system/edge-lb-wg.service")), "OLD WG UNIT\n");
    assert!(b.active());
}

#[test]
fn a_rollback_with_nothing_to_go_back_to_says_so_and_changes_nothing() {
    let b = Box_::new(GOOD_BIN, false);
    let (ok, _, err) = b.rollback();
    assert!(!ok);
    assert!(err.contains("no previous version"), "{err}");
    assert!(b.bin().contains("OLDBIN"));
    assert!(b.calls().is_empty(), "{:?}", b.calls());
}

#[test]
fn the_production_scripts_demand_root_and_refuse_odd_upload_directories() {
    for script in [update_script("/tmp/edge-lb.AbC123xyz9", 7443, None, 30).unwrap(), rollback_script(None).unwrap()] {
        assert!(script.contains(r#"[ "$(id -u)" -eq 0 ]"#), "must check for root");
        assert!(script.contains("ROOT=''"), "production acts on the real /");
        assert!(!script.contains('@'), "unreplaced placeholder in:\n{script}");
    }
    for bad in ["", "/etc", "/tmp/edge-lb.", "/tmp/edge-lb.a;rm -rf /", "/tmp/edge-lb.$(id)", "/tmp/edge-lb/../x"] {
        assert!(update_script(bad, 7443, None, 30).is_err(), "{bad:?}");
    }
    // The scratch root used by tests can't smuggle in shell syntax either.
    assert!(update_script("/tmp/edge-lb.AbC123xyz9", 7443, Some(Path::new("/tmp/x; rm -rf /")), 30).is_err());
}
