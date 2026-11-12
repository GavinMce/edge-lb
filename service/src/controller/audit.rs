//! Append-only audit trail of who changed what (JSON lines).

use super::model::now;
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

pub struct Audit {
    path: PathBuf,
    lock: Mutex<()>,
}

impl Audit {
    pub fn new(dir: &std::path::Path) -> Self {
        Self { path: dir.join("audit.log"), lock: Mutex::new(()) }
    }

    pub fn record(&self, actor: &str, action: &str, detail: &str) {
        tracing::info!(%actor, %action, %detail, "audit");
        let _g = self.lock.lock().unwrap();
        let line = json!({ "ts": now(), "actor": actor, "action": action, "detail": detail }).to_string();
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = writeln!(f, "{line}");
        }
    }

    /// Newest first.
    pub fn tail(&self, n: usize) -> Vec<Value> {
        let _g = self.lock.lock().unwrap();
        let text = std::fs::read_to_string(&self.path).unwrap_or_default();
        text.lines().rev().take(n).filter_map(|l| serde_json::from_str(l).ok()).collect()
    }
}
