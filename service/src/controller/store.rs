//! Persistent controller state: one JSON file, mode 0600, replaced atomically.
//!
//! It holds secrets (the CA key, provider tokens), so protect the data directory like a key
//! store and use full-disk encryption on the machine that runs the controller.

use super::model::State;
use anyhow::{Context, Result};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct Store {
    path: PathBuf,
    state: Mutex<State>,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Store> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join("controller.json");
        let state = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?,
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
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(state)?)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
