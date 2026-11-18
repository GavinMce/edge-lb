//! `deploy/install-controller.sh`, the script the desktop app's "set up on a server" command runs.
//!
//! The real script runs in its `--stage` mode (no root, no systemd) against a fake release on
//! `file://`: the download, checksum, layout, unit and refusal paths are all exercised. Starting the
//! service itself needs root and systemd and is not covered here.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/deploy/install-controller.sh");
const TAG: &str = "v0.0.0-test";

struct Rig {
    root: PathBuf,
    release: PathBuf,
    stage: PathBuf,
}

fn this_arch() -> &'static str {
    std::env::consts::ARCH
}

fn rig(tag: &str) -> Rig {
    let root = std::env::temp_dir().join(format!("edge-lbd-installer-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (release, stage) = (root.join("release"), root.join("stage"));
    std::fs::create_dir_all(&release).unwrap();
    std::fs::create_dir_all(&stage).unwrap();
    for arch in ["x86_64", "aarch64"] {
        let name = format!("edge-lbd-{TAG}-linux-{arch}");
        let dir = root.join("pack").join(&name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("edge-lbd"), format!("fake-{arch}\n")).unwrap();
        run(Command::new("tar").arg("czf").arg(release.join(format!("{name}.tar.gz"))).arg("-C").arg(root.join("pack")).arg(&name));
        let sum = run(Command::new("sha256sum").arg(format!("{name}.tar.gz")).current_dir(&release));
        std::fs::write(release.join(format!("{name}.tar.gz.sha256")), sum).unwrap();
    }
    Rig { root, release, stage }
}

fn run(cmd: &mut Command) -> Vec<u8> {
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{cmd:?}: {}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

impl Rig {
    fn base(&self) -> String {
        format!("file://{}", self.release.display())
    }
    fn install(&self, extra: &[&str]) -> Output {
        Command::new("sh")
            .arg(SCRIPT)
            .args(["--stage"])
            .arg(&self.stage)
            .args(["--version", TAG, "--release-base"])
            .arg(self.base())
            .args(extra)
            .output()
            .unwrap()
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.stage.join(rel)
    }
    fn unit(&self) -> String {
        std::fs::read_to_string(self.p("etc/systemd/system/edge-lb-controller.service")).unwrap()
    }
    fn nothing_installed(&self) -> bool {
        std::fs::read_dir(&self.stage).unwrap().next().is_none()
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn ok(out: &Output) {
    assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

fn err(out: &Output) -> String {
    assert!(!out.status.success(), "should have been refused: {}", String::from_utf8_lossy(&out.stdout));
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn installs_the_program_both_cpu_builds_and_a_sandboxed_unit() {
    use std::os::unix::fs::PermissionsExt;
    let r = rig("basic");
    ok(&r.install(&[]));

    let bin = r.p("usr/local/bin/edge-lb-controller");
    assert_eq!(std::fs::read_to_string(&bin).unwrap(), format!("fake-{}\n", this_arch()), "the build for this machine's CPU");
    assert_eq!(std::fs::metadata(&bin).unwrap().permissions().mode() & 0o777, 0o755);
    for arch in ["x86_64", "aarch64"] {
        let a = r.p(&format!("usr/local/lib/edge-lb/agents/edge-lbd-{arch}"));
        assert_eq!(std::fs::read_to_string(a).unwrap(), format!("fake-{arch}\n"), "both CPUs, so edges of either kind can be installed");
    }

    let unit = r.unit();
    assert!(
        unit.contains("ExecStart=/usr/local/bin/edge-lb-controller controller --listen 127.0.0.1:8080 --data-dir /var/lib/edge-lb-controller --agents-dir /usr/local/lib/edge-lb/agents\n"),
        "{unit}"
    );
    for must in ["User=edge-lb", "StateDirectory=edge-lb-controller", "StateDirectoryMode=0700", "NoNewPrivileges=yes", "ProtectSystem=strict", "CapabilityBoundingSet=\n"] {
        assert!(unit.contains(must), "missing {must}");
    }
    assert!(!unit.contains("--gateway") && !unit.contains("--secure-cookies") && !unit.contains("--allow-public"));
    // No leftovers from the atomic replace.
    assert!(!r.p("usr/local/bin/edge-lb-controller.new").exists() && !r.p("etc/systemd/system/edge-lb-controller.service.new").exists());
}

#[test]
fn gateway_and_tls_proxy_options_reach_the_unit_and_a_rerun_updates_it() {
    let r = rig("opts");
    ok(&r.install(&["--listen", "10.0.0.5:9000", "--gateway-listen", "0.0.0.0:7444", "--gateway-host", "ctl.example.com", "--tls-proxy"]));
    let unit = r.unit();
    assert!(unit.contains("--listen 10.0.0.5:9000 "), "{unit}");
    assert!(unit.contains("--gateway-listen 0.0.0.0:7444 --gateway-host ctl.example.com"), "{unit}");
    assert!(unit.trim_end().lines().any(|l| l.starts_with("ExecStart=") && l.ends_with("--secure-cookies")), "{unit}");

    ok(&r.install(&[]));
    let unit = r.unit();
    assert!(unit.contains("--listen 127.0.0.1:8080") && !unit.contains("--gateway") && !unit.contains("--secure-cookies"), "a rerun replaces the options: {unit}");
}

#[test]
fn this_arch_only_skips_the_other_cpu() {
    let r = rig("one");
    ok(&r.install(&["--this-arch-only"]));
    let other = if this_arch() == "x86_64" { "aarch64" } else { "x86_64" };
    assert!(r.p(&format!("usr/local/lib/edge-lb/agents/edge-lbd-{}", this_arch())).exists());
    assert!(!r.p(&format!("usr/local/lib/edge-lb/agents/edge-lbd-{other}")).exists());
}

#[test]
fn local_builds_can_be_used_instead_of_downloading() {
    let r = rig("from");
    let dir = r.root.join("mine");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("edge-lbd-{}", this_arch())), "mine\n").unwrap();
    let out = Command::new("sh").arg(SCRIPT).arg("--stage").arg(&r.stage).arg("--from").arg(&dir).output().unwrap();
    ok(&out);
    assert_eq!(std::fs::read_to_string(r.p("usr/local/bin/edge-lb-controller")).unwrap(), "mine\n");
}

#[test]
fn a_bad_checksum_installs_nothing() {
    let r = rig("sum");
    let name = format!("edge-lbd-{TAG}-linux-{}.tar.gz", this_arch());
    let mut bytes = std::fs::read(r.release.join(&name)).unwrap();
    let last = bytes.len() / 2;
    bytes[last] ^= 0xff;
    std::fs::write(r.release.join(&name), bytes).unwrap();
    let e = err(&r.install(&[]));
    assert!(e.contains("checksum mismatch"), "{e}");
    assert!(r.nothing_installed(), "nothing may be written when verification fails");
}

#[test]
fn a_missing_release_is_a_clear_error() {
    let r = rig("gone");
    std::fs::remove_file(r.release.join(format!("edge-lbd-{TAG}-linux-{}.tar.gz", this_arch()))).unwrap();
    let e = err(&r.install(&[]));
    assert!(e.contains("no build for this machine's CPU"), "{e}");
    assert!(r.nothing_installed());
}

#[test]
fn unsafe_or_malformed_values_are_refused_before_anything_is_written() {
    let r = rig("bad");
    let cases: &[&[&str]] = &[
        &["--listen", "127.0.0.1:8080;touch /tmp/pwned"],
        &["--listen", "localhost:8080"],
        &["--listen", "127.0.0.1:99999"],
        &["--listen", "127.0.0.1"],
        &["--gateway-listen", "0.0.0.0:7444"],
        &["--gateway-host", "ctl.example.com"],
        &["--gateway-listen", "0.0.0.0:7444", "--gateway-host", "a b"],
        &["--gateway-listen", "0.0.0.0:7444", "--gateway-host", "$(id)"],
        &["--gateway-listen", "0.0.0.0:7444", "--gateway-host", "x\nExecStartPre=/bin/sh"],
        &["--version", "../etc"],
        &["--version", "v1;id"],
        &["--release-base", "http://example.com/x"],
        &["--release-base", "https://example.com/x y"],
        &["--bogus"],
        &["--listen"],
    ];
    for args in cases {
        let e = err(&r.install(args));
        assert!(!e.is_empty(), "{args:?}: silent refusal");
        assert!(r.nothing_installed(), "{args:?} left files behind");
    }
    assert!(!Path::new("/tmp/pwned").exists());
}

#[test]
fn a_copy_that_did_not_come_from_a_release_says_what_to_pass() {
    let out = Command::new("sh").arg(SCRIPT).arg("--stage").arg(std::env::temp_dir()).output().unwrap();
    let e = err(&out);
    assert!(e.contains("--version") && e.contains("--from"), "{e}");
}

#[test]
fn uninstall_keeps_the_data_unless_asked() {
    let r = rig("rm");
    ok(&r.install(&[]));
    let data = r.p("var/lib/edge-lb-controller");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("controller.json"), "{}").unwrap();

    ok(&r.install(&["--uninstall"]));
    assert!(!r.p("usr/local/bin/edge-lb-controller").exists());
    assert!(!r.p("etc/systemd/system/edge-lb-controller.service").exists());
    assert!(!r.p("usr/local/lib/edge-lb").exists());
    assert!(data.join("controller.json").exists(), "data survives a plain uninstall");

    ok(&r.install(&["--uninstall", "--purge"]));
    assert!(!data.exists());
}

#[test]
fn help_works_when_the_script_is_piped_into_sh() {
    // `curl ... | sh -s -- --help`: there is no script file to read the text from.
    let script = std::fs::read(SCRIPT).unwrap();
    let mut child = Command::new("sh").args(["-s", "--", "--help"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), &script).unwrap();
    let out = child.wait_with_output().unwrap();
    ok(&out);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("--gateway-listen") && text.contains("--uninstall"), "{text}");
}

#[test]
fn the_script_parses_as_plain_posix_sh() {
    let out = Command::new("sh").arg("-n").arg(SCRIPT).output().unwrap();
    ok(&out);
}
