//! Small cross-platform file helpers.
//!
//! The Linux services rely on `mode 0600` for secrets. Windows has no such mode: files created
//! under the user's profile inherit an ACL that already limits them to the user, SYSTEM and
//! Administrators, and [`restrict_dir`] tightens a data directory further on a best-effort basis.

use std::fs::OpenOptions;
use std::path::Path;

/// `OpenOptions` for a file that holds a secret: owner-only (0600) on Unix.
pub fn private_options() -> OpenOptions {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut o = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o
}

/// Make `dir` accessible to the current user only. Best effort: returns a message on failure
/// rather than an error, because a data directory in the user's profile is already private.
/// A no-op everywhere but Windows (the Linux services rely on file modes instead).
pub fn restrict_dir(dir: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let user = std::env::var("USERNAME").map_err(|_| "USERNAME is not set".to_string())?;
        if user.is_empty() || user.contains(['"', ':', '(', ')', ',']) {
            return Err(format!("unusual user name {user:?}"));
        }
        let domain = std::env::var("USERDOMAIN").unwrap_or_default();
        let who = if domain.is_empty() || domain.contains(['"', ':', '(', ')', ',']) { user } else { format!("{domain}\\{user}") };
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let out = std::process::Command::new("icacls")
            .arg(dir)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!("{who}:(OI)(CI)F"))
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("running icacls: {e}"))?;
        if !out.status.success() {
            return Err(format!("icacls failed: {}", String::from_utf8_lossy(&out.stdout).trim()));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = dir;
        Ok(())
    }
}
