//! Persistent controller state: one file, replaced atomically.
//!
//! It holds secrets (the CA key, provider tokens). On Linux it is plain JSON with mode 0600, so
//! protect the data directory like a key store and use full-disk encryption. On Windows it is
//! encrypted with the signed-in user's DPAPI key, so a copy of the file is useless on another
//! machine or account. A plain-JSON file from an older version is read as is and encrypted on
//! its next save.

use super::model::State;
use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct Store {
    path: PathBuf,
    state: Mutex<State>,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Store> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        if let Err(e) = crate::fsutil::restrict_dir(dir) {
            tracing::warn!("could not restrict {} to your account: {e}", dir.display());
        }
        let path = dir.join("controller.json");
        let state = match std::fs::read(&path) {
            Ok(bytes) => {
                let json = unseal(&bytes).with_context(|| format!("reading {}", path.display()))?;
                serde_json::from_slice(&json).with_context(|| format!("parsing {}", path.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let s = State::fresh()?;
                write_atomic(&path, &s)?;
                s
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Store { path, state: Mutex::new(state) })
    }

    pub fn read<R>(&self, f: impl FnOnce(&State) -> R) -> R {
        f(&self.state.lock().unwrap())
    }

    /// Mutate and persist. If the closure returns `Err`, nothing is written and the in-memory
    /// state is rolled back to what it was.
    pub fn try_update<R, E>(&self, f: impl FnOnce(&mut State) -> std::result::Result<R, E>) -> std::result::Result<R, E>
    where
        E: From<anyhow::Error>,
    {
        let mut guard = self.state.lock().unwrap();
        let snapshot = serde_json::to_vec(&*guard).map_err(anyhow::Error::from)?;
        match f(&mut guard) {
            Ok(r) => {
                if let Err(e) = write_atomic(&self.path, &guard) {
                    *guard = serde_json::from_slice(&snapshot).map_err(anyhow::Error::from)?;
                    return Err(e.into());
                }
                Ok(r)
            }
            Err(e) => {
                *guard = serde_json::from_slice(&snapshot).map_err(anyhow::Error::from)?;
                Err(e)
            }
        }
    }

    pub fn update<R>(&self, f: impl FnOnce(&mut State) -> R) -> Result<R> {
        self.try_update(|s| Ok::<R, anyhow::Error>(f(s)))
    }
}

fn write_atomic(path: &Path, state: &State) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = crate::fsutil::private_options().write(true).create(true).truncate(true).open(&tmp)?;
        f.write_all(&seal(&serde_json::to_vec_pretty(state)?)?)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Marks a file whose contents are DPAPI-protected. Plain JSON never starts with it.
const SEALED_MAGIC: &[u8] = b"EDGELB-DPAPI-1\n";

/// What goes on disk for `plain`: unchanged on Linux, DPAPI-protected on Windows.
fn seal(plain: &[u8]) -> Result<Vec<u8>> {
    #[cfg(windows)]
    {
        let mut out = SEALED_MAGIC.to_vec();
        out.extend(dpapi::protect(plain)?);
        Ok(out)
    }
    #[cfg(not(windows))]
    Ok(plain.to_vec())
}

/// The inverse of [`seal`]; also accepts the plain JSON an older version wrote.
fn unseal(stored: &[u8]) -> Result<Vec<u8>> {
    let Some(cipher) = stored.strip_prefix(SEALED_MAGIC) else { return Ok(stored.to_vec()) };
    #[cfg(windows)]
    {
        dpapi::unprotect(cipher).context("could not decrypt it: it was encrypted by a different Windows user or machine")
    }
    #[cfg(not(windows))]
    {
        let _ = cipher;
        anyhow::bail!("this file is encrypted for a Windows user account and can only be opened on that Windows account")
    }
}

#[cfg(windows)]
mod dpapi {
    use anyhow::{bail, Result};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB};

    pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
        run(data, true)
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>> {
        run(data, false)
    }

    fn run(data: &[u8], protect: bool) -> Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };
        // SAFETY: `input` points at `data`, which outlives the call; the result buffer is copied
        // and then released with LocalFree as the API requires.
        let ok = unsafe {
            if protect {
                CryptProtectData(&input, null(), null(), null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            } else {
                CryptUnprotectData(&input, null_mut(), null(), null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            }
        };
        if ok == 0 {
            bail!("DPAPI failed: {}", std::io::Error::last_os_error());
        }
        let bytes = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
        unsafe { LocalFree(out.pbData as _) };
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_json_from_an_older_version_is_read_as_is() {
        let json = br#"{"a":1}"#;
        assert_eq!(unseal(json).unwrap(), json);
    }

    #[test]
    fn round_trips_through_seal() {
        let json = br#"{"secret":"hunter2"}"#;
        assert_eq!(unseal(&seal(json).unwrap()).unwrap(), json);
    }

    #[cfg(not(windows))]
    #[test]
    fn a_windows_encrypted_file_is_refused_with_a_clear_message_elsewhere() {
        let mut f = SEALED_MAGIC.to_vec();
        f.extend_from_slice(b"\x01\x02");
        let err = unseal(&f).unwrap_err().to_string();
        assert!(err.contains("Windows"), "{err}");
    }
}
