//! The gateway's updater: a small root-owned step that swaps the gateway binary.
//!
//! The gateway service runs with a read-only filesystem, so it cannot replace its own binary, and
//! we don't want to loosen that. Instead it drops a request file (see `gateway::request_update`),
//! systemd's path unit starts `edge-lbd gateway-update`, and this module does the rest as root:
//!
//! 1. fetch the binary *from the controller*, over the same pinned TLS the gateway uses and
//!    authenticated with the gateway's own secret, and check it against the SHA-256 the controller
//!    states (so a compromised gateway process can ask for an update, never choose what is installed);
//! 2. make sure it runs here (`--version`);
//! 3. keep the old binary beside it, put the new one in place and restart the service;
//! 4. wait for the new version to complete a sync with the controller. If it doesn't, put the old
//!    binary back and restart again.
//!
//! The outcome is left in `update-result.json` for the gateway to report to the controller.

use crate::gateway::{client, UpdateResult, SYNCED, UPDATE_REQUEST, UPDATE_RESULT, VERSION};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

/// No gateway binary is anywhere near this; it only stops a broken server filling the disk.
const MAX_BINARY: usize = 64 * 1024 * 1024;

/// How the updater touches the machine (replaceable in tests).
#[async_trait]
pub trait Host: Send + Sync {
    async fn restart(&self) -> Result<()>;
    /// What `<binary> --version` prints.
    async fn version_output(&self, binary: &Path) -> Result<String>;
}

pub struct RealHost {
    pub service: String,
}

#[async_trait]
impl Host for RealHost {
    async fn restart(&self) -> Result<()> {
        let out = tokio::process::Command::new("systemctl").args(["restart", &self.service]).output().await.context("running systemctl")?;
        if !out.status.success() {
            bail!("systemctl restart {} failed: {}", self.service, String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }

    async fn version_output(&self, binary: &Path) -> Result<String> {
        let out = tokio::process::Command::new(binary).arg("--version").output().await.with_context(|| format!("running {}", binary.display()))?;
        if !out.status.success() {
            bail!("{} --version failed", binary.display());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

pub struct Options {
    /// `host:port` of the controller's gateway listener.
    pub controller: String,
    /// SHA-256 (hex) of the controller's certificate.
    pub pin: String,
    pub data_dir: PathBuf,
    /// The installed binary, e.g. `/usr/local/bin/edge-lbd`.
    pub bin: PathBuf,
    /// How the controller names the build for this CPU: `x86_64` or `aarch64`.
    pub arch: String,
    /// How long the new version gets to complete a sync before it is rolled back.
    pub wait: Duration,
    pub host: Arc<dyn Host>,
}

#[derive(Deserialize)]
struct Identity {
    secret: String,
}

/// The version out of `edge-lbd 0.1.4`. Anything that doesn't look like that is refused.
pub fn parse_version_output(s: &str) -> Option<String> {
    let v = s.split_whitespace().nth(1)?;
    (!v.is_empty() && v.len() <= 32 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))).then(|| v.to_string())
}

fn sibling(bin: &Path, suffix: &str) -> PathBuf {
    let mut s = bin.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn synced_version(dir: &Path) -> Option<String> {
    std::fs::read_to_string(dir.join(SYNCED)).ok()?.split_whitespace().next().map(String::from)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Does `body` hash to `stated` (hex, either case)? The controller sends the checksum in a header, so
/// this catches a truncated or corrupted download; the TLS pin is what says it came from the controller.
fn matches_checksum(body: &[u8], stated: &str) -> bool {
    hex(&Sha256::digest(body)) == stated.trim().to_ascii_lowercase()
}

fn write_executable(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o755);
    }
    let mut f = opts.open(path).with_context(|| format!("writing {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// Do the update the request file asks for, if there is one. Never returns an error for a failed
/// update: that is reported through the result file, which is what the controller shows.
pub async fn run(o: Options) -> Result<()> {
    let request = o.data_dir.join(UPDATE_REQUEST);
    if !request.exists() {
        return Ok(());
    }
    // Take the request first, so that whatever goes wrong can never make systemd loop on it.
    let _ = std::fs::remove_file(&request);

    let mut tried = String::new();
    let result = match attempt(&o, &mut tried).await {
        Ok(msg) => {
            info!("{msg}");
            UpdateResult { version: tried, ok: true, error: None }
        }
        Err(e) => {
            error!("the update failed: {e:#}");
            UpdateResult { version: tried, ok: false, error: Some(format!("{e:#}")) }
        }
    };
    let path = o.data_dir.join(UPDATE_RESULT);
    std::fs::write(&path, serde_json::to_vec(&result)?).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

async fn attempt(o: &Options, tried: &mut String) -> Result<String> {
    if !o.arch.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        bail!("unexpected architecture name");
    }
    let id: Identity = serde_json::from_slice(&std::fs::read(o.data_dir.join("identity.json")).context("this gateway is not enrolled")?).context("reading identity.json")?;

    let resp = client(&o.pin)?
        .get(format!("https://{}/gw/v1/update?arch={}", o.controller, o.arch))
        .bearer_auth(&id.secret)
        .send()
        .await
        .map_err(|e| anyhow!("cannot reach the controller: {e}"))?;
    if !resp.status().is_success() {
        bail!("the controller answered HTTP {} when asked for the new version", resp.status());
    }
    let stated = resp
        .headers()
        .get("x-edge-lb-sha256")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow!("the controller did not state a checksum for the binary"))?;
    let body = resp.bytes().await.map_err(|e| anyhow!("downloading the new version: {e}"))?;
    if body.is_empty() || body.len() > MAX_BINARY {
        bail!("the downloaded binary has an unexpected size ({} bytes)", body.len());
    }
    if !matches_checksum(&body, &stated) {
        bail!("the downloaded binary does not match the checksum the controller stated");
    }

    let new = sibling(&o.bin, ".new");
    write_executable(&new, &body)?;
    let drop_new = |e: anyhow::Error| {
        let _ = std::fs::remove_file(&new);
        e
    };
    let out = o.host.version_output(&new).await.map_err(drop_new).context("the new binary does not run on this machine")?;
    let version = parse_version_output(&out).ok_or_else(|| drop_new(anyhow!("the new binary did not identify its version")))?;
    *tried = version.clone();
    if version == VERSION {
        let _ = std::fs::remove_file(&new);
        return Ok(format!("already running {version}; nothing to do"));
    }

    let old = sibling(&o.bin, ".old");
    std::fs::copy(&o.bin, &old).context("keeping a copy of the current version")?;
    std::fs::rename(&new, &o.bin).context("putting the new version in place")?;
    match switch(o, &version).await {
        Ok(()) => Ok(format!("updated from {VERSION} to {version}")),
        Err(e) => {
            warn!("rolling back: {e:#}");
            let back = std::fs::rename(&old, &o.bin).context("restoring the previous binary");
            let again = o.host.restart().await.context("restarting the previous version");
            match (back, again) {
                (Ok(()), Ok(())) => Err(e.context(format!("went back to {VERSION}"))),
                (b, a) => Err(anyhow!("{e:#}; and then going back failed: {}", [b.err(), a.err()].into_iter().flatten().map(|x| format!("{x:#}")).collect::<Vec<_>>().join("; "))),
            }
        }
    }
}

/// Restart onto the new binary and wait until *that version* has talked to the controller.
async fn switch(o: &Options, version: &str) -> Result<()> {
    // A leftover marker must not be mistaken for the new version's.
    let _ = std::fs::remove_file(o.data_dir.join(SYNCED));
    o.host.restart().await?;
    let deadline = Instant::now() + o.wait;
    loop {
        if synced_version(&o.data_dir).as_deref() == Some(version) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("version {version} did not complete a sync with the controller within {} seconds", o.wait.as_secs());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_read_from_clap_output_and_nothing_else_is_trusted() {
        assert_eq!(parse_version_output("edge-lbd 0.1.4\n").as_deref(), Some("0.1.4"));
        assert_eq!(parse_version_output("edge-lbd 1.2.3-rc.1+build5").as_deref(), Some("1.2.3-rc.1+build5"));
        for bad in ["", "edge-lbd", "edge-lbd \n", "edge-lbd 1.0; rm -rf /", "edge-lbd $(id)", &format!("edge-lbd {}", "9".repeat(40))] {
            assert_eq!(parse_version_output(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_download_must_hash_to_exactly_what_the_controller_stated() {
        let body = b"#!fake-binary";
        let good = hex(&Sha256::digest(body));
        assert!(matches_checksum(body, &good));
        assert!(matches_checksum(body, &good.to_ascii_uppercase()), "case does not matter");
        assert!(!matches_checksum(b"#!fake-binarY", &good), "one changed byte");
        assert!(!matches_checksum(&body[..5], &good), "truncated");
        assert!(!matches_checksum(body, ""));
        assert!(!matches_checksum(body, &"0".repeat(64)));
    }

    #[test]
    fn backup_and_staging_files_sit_beside_the_binary() {
        assert_eq!(sibling(Path::new("/usr/local/bin/edge-lbd"), ".old"), PathBuf::from("/usr/local/bin/edge-lbd.old"));
    }

    #[test]
    fn the_sync_marker_names_the_version_that_wrote_it() {
        let dir = std::env::temp_dir().join(format!("edge-lb-synced-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(synced_version(&dir), None);
        std::fs::write(dir.join(SYNCED), "0.1.4 1700000000\n").unwrap();
        assert_eq!(synced_version(&dir).as_deref(), Some("0.1.4"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
