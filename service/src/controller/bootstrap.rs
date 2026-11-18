//! Turning a bare machine into an edge: push the binary, install a hardened systemd unit,
//! and read back the identity the edge generated for itself.
//!
//! Everything goes over the system `ssh` (key auth, host key pinned on first use). Values that
//! come *back* from the remote machine are untrusted — a hostile or compromised host must not
//! be able to inject anything into a script that runs as root.

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct Target {
    pub edge_id: String,
    pub ip: IpAddr,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub mgmt_port: u16,
}

pub struct InstallCtx {
    pub ca_pem: String,
    /// The Linux binaries available to install; the one matching the machine's CPU is used.
    pub agents: super::agents::Agents,
}

#[derive(Debug, Clone)]
pub struct Installed {
    pub cert_pem: String,
    pub mgmt_port: u16,
    /// The edge's WireGuard public key, if WireGuard could be set up on the machine.
    pub wg_public_key: Option<String>,
}

#[async_trait]
pub trait Bootstrapper: Send + Sync {
    /// Can we log in (key accepted, SSH up)?
    async fn probe(&self, t: &Target) -> Result<()>;
    async fn install(&self, t: &Target, ctx: &InstallCtx) -> Result<Installed>;
    /// Best-effort removal from a machine we don't destroy.
    async fn uninstall(&self, t: &Target) -> Result<()>;
    /// Forget any recorded SSH host key for this machine (IPs get recycled).
    async fn forget(&self, t: &Target);
}

// ---- the SSH key the controller logs in with ----------------------------------------------

#[derive(Debug, Clone)]
pub struct SshKey {
    pub private: PathBuf,
    pub public: String,
}

impl SshKey {
    /// Load the controller's SSH key from `<dir>/ssh/`, generating an ed25519 pair on first use.
    pub async fn ensure(dir: &Path, keygen: &str) -> Result<SshKey> {
        let ssh_dir = dir.join("ssh");
        std::fs::create_dir_all(&ssh_dir)?;
        let private = ssh_dir.join("id_ed25519");
        let pub_path = ssh_dir.join("id_ed25519.pub");
        if !private.exists() {
            let mut cmd = Command::new(keygen);
            cmd.args(["-q", "-t", "ed25519", "-N", "", "-C", "edge-lb-controller", "-f"]).arg(&private);
            let out = quiet(&mut cmd)
                .output()
                .await
                .with_context(|| format!("running {keygen} (is openssh-client installed?)"))?;
            if !out.status.success() {
                bail!("ssh-keygen failed: {}", String::from_utf8_lossy(&out.stderr).trim());
            }
        }
        let public = std::fs::read_to_string(&pub_path).with_context(|| format!("reading {}", pub_path.display()))?.trim().to_string();
        Ok(SshKey { private, public })
    }
}

/// Don't flash a console window for every `ssh` when the controller runs as a Windows GUI app.
fn quiet(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// `-o UserKnownHostsFile=...`. OpenSSH splits option values on spaces, and Windows profile paths
/// often have one, so there the path is quoted and uses forward slashes.
fn known_hosts_option(path: &Path) -> String {
    #[cfg(windows)]
    {
        format!("UserKnownHostsFile=\"{}\"", path.display().to_string().replace('\\', "/"))
    }
    #[cfg(not(windows))]
    {
        format!("UserKnownHostsFile={}", path.display())
    }
}

// ---- scripts ---------------------------------------------------------------------------------

const MARK_BEGIN: &str = "-----BEGIN EDGE-LB IDENTITY-----";
const MARK_END: &str = "-----END EDGE-LB IDENTITY-----";
const WG_BEGIN: &str = "-----BEGIN EDGE-LB WIREGUARD-----";
const WG_END: &str = "-----END EDGE-LB WIREGUARD-----";

const INSTALL_SH: &str = r#"#!/bin/sh
# edge-lb installer. Pushed by the controller over SSH. Idempotent.
set -eu
UP='@UP@'
BIN=/usr/local/bin/edge-lbd
log() { printf 'edge-lb: %s\n' "$*" >&2; }
[ "$(id -u)" -eq 0 ] || { log "must run as root"; exit 1; }
command -v systemctl >/dev/null 2>&1 || { log "systemd is required"; exit 1; }

install -d -m 0755 /etc/edge-lb
install -m 0755 "$UP/edge-lbd" "$BIN.new"
mv -f "$BIN.new" "$BIN"
install -m 0644 "$UP/ca.pem" /etc/edge-lb/controller-ca.pem

cat > /etc/systemd/system/edge-lbd.service <<'UNIT'
[Unit]
Description=edge-lb edge node
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/edge-lbd edge --mgmt 0.0.0.0:@PORT@ --data-dir /var/lib/edge-lb --controller-ca /etc/edge-lb/controller-ca.pem
Restart=on-failure
RestartSec=2
DynamicUser=yes
StateDirectory=edge-lb
StateDirectoryMode=0700
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable edge-lbd >/dev/null 2>&1
systemctl restart edge-lbd

CERT=/var/lib/edge-lb/mgmt-cert.pem
i=0
while [ "$i" -lt 30 ]; do
  if systemctl is-active --quiet edge-lbd && [ -s "$CERT" ]; then break; fi
  sleep 1; i=$((i+1))
done
if ! systemctl is-active --quiet edge-lbd || [ ! -s "$CERT" ]; then
  journalctl -u edge-lbd -n 20 --no-pager >&2 || true
  log "edge service did not start"
  exit 1
fi
rm -rf "$UP"

# --- WireGuard (only used once a gateway site exists). Best effort: a machine without it still
# serves direct routes. The private key is generated here and never leaves the machine.
WGPUB=''
setup_wg() {
  if ! command -v wg >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools >/dev/null 2>&1 || return 1
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y -q wireguard-tools >/dev/null 2>&1 || return 1
    else
      return 1
    fi
  fi
  command -v ip >/dev/null 2>&1 || return 1
  modprobe wireguard >/dev/null 2>&1 || true
  ip link add edgelb-probe type wireguard >/dev/null 2>&1 || return 1
  ip link del edgelb-probe >/dev/null 2>&1 || true
  ( umask 077; [ -s /etc/edge-lb/wg.key ] || wg genkey > /etc/edge-lb/wg.key )
  chmod 600 /etc/edge-lb/wg.key
  WGPUB=$(wg pubkey < /etc/edge-lb/wg.key) || return 1
  cat > /etc/systemd/system/edge-lb-wg.service <<'UNIT'
[Unit]
Description=edge-lb WireGuard applier
After=network-online.target edge-lbd.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/edge-lbd wg-apply --state /var/lib/edge-lb/wg.json --key /etc/edge-lb/wg.key
Restart=always
RestartSec=2
CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable edge-lb-wg >/dev/null 2>&1
  systemctl restart edge-lb-wg
}
if ! setup_wg; then
  WGPUB=''
  log "WireGuard is not available here: this edge can serve direct routes but not gateway sites"
fi

echo '@BEGIN@'
cat "$CERT"
echo '@END@'
if [ -n "$WGPUB" ]; then
  echo '@WGBEGIN@'
  echo "$WGPUB"
  echo '@WGEND@'
fi
"#;

/// Same flow without root or systemd: installs under a scratch directory and runs the edge as
/// a background process. Lets tests exercise the real upload/identity/pinning path locally.
const INSTALL_STAGED_SH: &str = r#"#!/bin/sh
set -eu
UP='@UP@'
ROOT='@STAGE@'
BIN="$ROOT/usr/local/bin/edge-lbd"
install -d -m 0755 "$ROOT/usr/local/bin" "$ROOT/etc/edge-lb"
install -d -m 0700 "$ROOT/var/lib/edge-lb"
if [ -f "$ROOT/edge.pid" ]; then kill "$(cat "$ROOT/edge.pid")" 2>/dev/null || true; sleep 0.3; fi
install -m 0755 "$UP/edge-lbd" "$BIN"
install -m 0644 "$UP/ca.pem" "$ROOT/etc/edge-lb/controller-ca.pem"
nohup "$BIN" edge --mgmt 127.0.0.1:@PORT@ --data-dir "$ROOT/var/lib/edge-lb" --controller-ca "$ROOT/etc/edge-lb/controller-ca.pem" >"$ROOT/edge.log" 2>&1 &
echo $! > "$ROOT/edge.pid"
CERT="$ROOT/var/lib/edge-lb/mgmt-cert.pem"
i=0; while [ ! -s "$CERT" ] && [ "$i" -lt 50 ]; do sleep 0.2; i=$((i+1)); done
[ -s "$CERT" ] || { cat "$ROOT/edge.log" >&2; echo "edge did not start" >&2; exit 1; }
rm -rf "$UP"
echo '@BEGIN@'
cat "$CERT"
echo '@END@'
"#;

const UNINSTALL_SH: &str = r#"#!/bin/sh
set -u
systemctl disable --now edge-lb-wg >/dev/null 2>&1 || true
ip link del wg-edge >/dev/null 2>&1 || true
systemctl disable --now edge-lbd >/dev/null 2>&1 || true
rm -f /etc/systemd/system/edge-lb-wg.service /etc/systemd/system/edge-lbd.service /usr/local/bin/edge-lbd
rm -rf /etc/edge-lb /var/lib/edge-lb /var/lib/private/edge-lb
systemctl daemon-reload >/dev/null 2>&1 || true
"#;

const UNINSTALL_STAGED_SH: &str = r#"#!/bin/sh
set -u
ROOT='@STAGE@'
if [ -f "$ROOT/edge.pid" ]; then kill "$(cat "$ROOT/edge.pid")" 2>/dev/null || true; fi
rm -rf "$ROOT/usr" "$ROOT/etc" "$ROOT/var" "$ROOT/edge.pid"
"#;

/// Render the installer. `stage` is for tests only.
pub fn install_script(upload_dir: &str, mgmt_port: u16, stage: Option<&Path>) -> Result<String> {
    if !valid_remote_dir(upload_dir) {
        bail!("refusing to use unexpected remote directory {upload_dir:?}");
    }
    let base = if stage.is_some() { INSTALL_STAGED_SH } else { INSTALL_SH };
    let mut s = base
        .replace("@UP@", upload_dir)
        .replace("@PORT@", &mgmt_port.to_string())
        .replace("@BEGIN@", MARK_BEGIN)
        .replace("@END@", MARK_END)
        .replace("@WGBEGIN@", WG_BEGIN)
        .replace("@WGEND@", WG_END);
    if let Some(st) = stage {
        s = s.replace("@STAGE@", &shell_safe(st)?);
    }
    Ok(s)
}

fn uninstall_script(stage: Option<&Path>) -> Result<String> {
    Ok(match stage {
        Some(st) => UNINSTALL_STAGED_SH.replace("@STAGE@", &shell_safe(st)?),
        None => UNINSTALL_SH.to_string(),
    })
}

fn shell_safe(p: &Path) -> Result<String> {
    let s = p.to_str().ok_or_else(|| anyhow!("non-UTF-8 path"))?;
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c)) {
        Ok(s.to_string())
    } else {
        bail!("unsupported characters in path {s:?}")
    }
}

/// `mktemp -d /tmp/edge-lb.XXXXXXXXXX` output — and nothing else — may be interpolated.
pub fn valid_remote_dir(d: &str) -> bool {
    d.strip_prefix("/tmp/edge-lb.").is_some_and(|r| !r.is_empty() && r.len() <= 32 && r.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// SSH user names: conservative POSIX set; can never start with '-' (option injection).
pub fn valid_ssh_user(u: &str) -> bool {
    let b = u.as_bytes();
    !b.is_empty() && b.len() <= 32 && (b[0].is_ascii_lowercase() || b[0] == b'_') && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Pull the certificate out of the installer's output and make sure it is exactly one cert.
pub fn extract_identity(stdout: &str) -> Result<String> {
    let start = stdout.find(MARK_BEGIN).ok_or_else(|| anyhow!("installer did not report an identity"))? + MARK_BEGIN.len();
    let end = stdout[start..].find(MARK_END).ok_or_else(|| anyhow!("installer output was cut off"))? + start;
    let pem = stdout[start..end].trim().to_string();
    let certs = crate::pki::certs_from_pem(&pem)?;
    if certs.len() != 1 {
        bail!("expected exactly one certificate from the edge, got {}", certs.len());
    }
    Ok(pem + "\n")
}

/// The edge's WireGuard public key, if the installer reported one. It comes from the remote
/// machine, so it is accepted only if it is exactly a well-formed key.
pub fn extract_wg_key(stdout: &str) -> Option<String> {
    let start = stdout.find(WG_BEGIN)? + WG_BEGIN.len();
    let end = stdout[start..].find(WG_END)? + start;
    let key = stdout[start..end].trim();
    crate::wg::is_key(key).then(|| key.to_string())
}

// ---- the real thing ----------------------------------------------------------------------------

enum Input {
    None,
    File(PathBuf),
    Bytes(Vec<u8>),
}

pub struct SshBootstrapper {
    pub ssh_bin: String,
    pub keygen_bin: String,
    pub key: SshKey,
    pub known_hosts: PathBuf,
    /// Tests only: install under this directory instead of the real system.
    pub stage: Option<PathBuf>,
}

impl SshBootstrapper {
    pub fn new(key: SshKey, data_dir: &Path) -> Self {
        Self { ssh_bin: "ssh".into(), keygen_bin: "ssh-keygen".into(), key, known_hosts: data_dir.join("ssh").join("known_hosts"), stage: None }
    }

    async fn ssh(&self, t: &Target, remote: &str, input: Input, limit: Duration) -> Result<String> {
        if !valid_ssh_user(&t.ssh_user) {
            bail!("invalid SSH user {:?}", t.ssh_user);
        }
        let mut cmd = Command::new(&self.ssh_bin);
        cmd.arg("-i").arg(&self.key.private)
            .args(["-p", &t.ssh_port.to_string()])
            .args(["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR"])
            .arg("-o").arg(known_hosts_option(&self.known_hosts))
            .args(["-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3"])
            .arg(format!("{}@{}", t.ssh_user, t.ip))
            .arg(remote)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        match &input {
            Input::None => cmd.stdin(Stdio::null()),
            Input::File(p) => cmd.stdin(Stdio::from(std::fs::File::open(p).with_context(|| format!("opening {}", p.display()))?)),
            Input::Bytes(_) => cmd.stdin(Stdio::piped()),
        };
        let mut child = quiet(&mut cmd).spawn().with_context(|| format!("running {} (is the OpenSSH client installed?)", self.ssh_bin))?;
        if let Input::Bytes(b) = input {
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(&b).await.ok();
            drop(stdin);
        }
        let out = tokio::time::timeout(limit, child.wait_with_output())
            .await
            .map_err(|_| anyhow!("ssh timed out after {}s", limit.as_secs()))??;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let tail: String = err.trim().chars().rev().take(500).collect::<Vec<_>>().into_iter().rev().collect();
            bail!("ssh failed ({}): {}", out.status.code().map(|c| c.to_string()).unwrap_or("signal".into()), tail);
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn sudo(t: &Target) -> &'static str {
        if t.ssh_user == "root" { "" } else { "sudo -n " }
    }
}

#[async_trait]
impl Bootstrapper for SshBootstrapper {
    async fn probe(&self, t: &Target) -> Result<()> {
        self.ssh(t, "true", Input::None, Duration::from_secs(20)).await.map(|_| ())
    }

    async fn install(&self, t: &Target, ctx: &InstallCtx) -> Result<Installed> {
        let dir = self.ssh(t, "umask 077; mktemp -d /tmp/edge-lb.XXXXXXXXXX", Input::None, Duration::from_secs(20)).await?;
        let dir = dir.trim().to_string();
        if !valid_remote_dir(&dir) {
            bail!("remote host returned an unexpected temp directory: {dir:?}");
        }
        // What the machine reports is only ever compared against our own table, never interpolated.
        let raw_arch = self.ssh(t, "uname -m", Input::None, Duration::from_secs(20)).await?;
        let binary = ctx.agents.get(raw_arch.trim()).ok_or_else(|| {
            let have = ctx.agents.archs().join(", ");
            let have = if have.is_empty() { "none".to_string() } else { have };
            anyhow!(
                "this machine's CPU ({}) has no matching edge binary; this controller can install: {have}",
                raw_arch.trim().chars().take(20).filter(|c| c.is_ascii_graphic()).collect::<String>()
            )
        })?;
        self.ssh(t, &format!("cat > {dir}/edge-lbd"), Input::File(binary.to_path_buf()), Duration::from_secs(300)).await.context("uploading the edge binary")?;
        self.ssh(t, &format!("cat > {dir}/ca.pem"), Input::Bytes(ctx.ca_pem.clone().into_bytes()), Duration::from_secs(30)).await?;
        let script = install_script(&dir, t.mgmt_port, self.stage.as_deref())?;
        let out = self.ssh(t, &format!("{}sh -s", Self::sudo(t)), Input::Bytes(script.into_bytes()), Duration::from_secs(180)).await.context("running the installer")?;
        Ok(Installed { cert_pem: extract_identity(&out)?, mgmt_port: t.mgmt_port, wg_public_key: extract_wg_key(&out) })
    }

    async fn uninstall(&self, t: &Target) -> Result<()> {
        let script = uninstall_script(self.stage.as_deref())?;
        self.ssh(t, &format!("{}sh -s", Self::sudo(t)), Input::Bytes(script.into_bytes()), Duration::from_secs(60)).await.map(|_| ())
    }

    async fn forget(&self, t: &Target) {
        for host in [t.ip.to_string(), format!("[{}]:{}", t.ip, t.ssh_port)] {
            let mut cmd = Command::new(&self.keygen_bin);
            cmd.arg("-R").arg(host).arg("-f").arg(&self.known_hosts).stdout(Stdio::null()).stderr(Stdio::null());
            let _ = quiet(&mut cmd).status().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn sh_syntax_ok(script: &str) -> bool {
        let mut child = Command::new("sh").arg("-n").stdin(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(script.as_bytes()).await.unwrap();
        child.wait_with_output().await.unwrap().status.success()
    }

    #[tokio::test]
    async fn scripts_have_valid_shell_syntax_and_no_leftover_placeholders() {
        let prod = install_script("/tmp/edge-lb.AbC123xyz9", 7443, None).unwrap();
        let staged = install_script("/tmp/edge-lb.AbC123xyz9", 17443, Some(Path::new("/tmp/stage-x"))).unwrap();
        for s in [&prod, &staged, &uninstall_script(None).unwrap(), &uninstall_script(Some(Path::new("/tmp/s"))).unwrap()] {
            assert!(!s.contains('@'), "unreplaced placeholder in:\n{s}");
            assert!(sh_syntax_ok(s).await, "shell syntax error in:\n{s}");
        }
        assert!(prod.contains("edge --mgmt 0.0.0.0:7443"));
        assert!(prod.contains("DynamicUser=yes") && prod.contains("NoNewPrivileges=yes"));
        assert!(prod.contains("/tmp/edge-lb.AbC123xyz9"));
        // WireGuard: the root applier is its own unit with a narrow capability set, and the
        // edge's own unit stays unprivileged.
        assert!(prod.contains("edge-lbd wg-apply --state /var/lib/edge-lb/wg.json --key /etc/edge-lb/wg.key"));
        assert!(prod.contains("CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH"));
        assert!(prod.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
        assert!(!staged.contains("wg-apply"), "the test installer needs no root or WireGuard");
    }

    #[test]
    fn wireguard_key_extraction_trusts_nothing() {
        let key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        assert_eq!(extract_wg_key(&format!("x\n{WG_BEGIN}\n{key}\n{WG_END}\n")).as_deref(), Some(key));
        assert_eq!(extract_wg_key("no block"), None);
        assert_eq!(extract_wg_key(&format!("{WG_BEGIN}\n{key}")), None, "truncated");
        for bad in ["", "short", "abc\nPostUp = rm -rf /", &format!("{key}\n{key}")] {
            assert_eq!(extract_wg_key(&format!("{WG_BEGIN}\n{bad}\n{WG_END}")), None, "{bad:?}");
        }
    }

    #[test]
    fn untrusted_remote_values_are_rejected() {
        assert!(valid_remote_dir("/tmp/edge-lb.Ab12Cd34Ef"));
        for bad in ["", "/tmp/edge-lb.", "/tmp/edge-lb.a;rm -rf /", "/tmp/edge-lb.a b", "/etc/passwd", "/tmp/edge-lb.$(id)", "/tmp/edge-lb.a\nb", "/tmp/edge-lb/../x"] {
            assert!(!valid_remote_dir(bad), "{bad:?}");
            assert!(install_script(bad, 7443, None).is_err(), "{bad:?}");
        }
        assert!(valid_ssh_user("root") && valid_ssh_user("deploy-1") && valid_ssh_user("_svc"));
        for bad in ["", "-oProxyCommand=evil", "Root", "a b", "a;b", "a@b", &"x".repeat(40)] {
            assert!(!valid_ssh_user(bad), "{bad:?}");
        }
    }

    #[test]
    fn identity_extraction_requires_exactly_one_certificate() {
        let cert = crate::pki::self_signed_server().unwrap().cert;
        let out = format!("noise\n{MARK_BEGIN}\n{cert}{MARK_END}\n");
        assert_eq!(extract_identity(&out).unwrap().trim(), cert.trim());
        assert!(extract_identity("nothing here").is_err());
        assert!(extract_identity(&format!("{MARK_BEGIN}\n{cert}")).is_err(), "truncated output");
        assert!(extract_identity(&format!("{MARK_BEGIN}\n{cert}{cert}{MARK_END}")).is_err(), "two certs");
        assert!(extract_identity(&format!("{MARK_BEGIN}\ngarbage\n{MARK_END}")).is_err());
    }
}
