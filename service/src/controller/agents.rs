//! The edge/gateway binaries a controller can install on other machines, by CPU architecture.
//!
//! A Linux controller can simply push a copy of itself. A controller that doesn't run on Linux
//! (the Windows desktop app) can't, so it ships static Linux builds in an `agents` directory next
//! to it, named `edge-lbd-<arch>`. Architectures use the names `uname -m` prints.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const X86_64: &str = "x86_64";
pub const AARCH64: &str = "aarch64";

/// Map any spelling of a CPU architecture (`uname -m`, Rust's `ARCH`, Debian's `dpkg`, Hetzner's
/// `x86`/`arm`) to the canonical name we key binaries by. `None` for architectures we don't ship.
pub fn normalize_arch(raw: &str) -> Option<&'static str> {
    match raw.trim() {
        "x86_64" | "amd64" | "x86" => Some(X86_64),
        "aarch64" | "arm64" | "arm" => Some(AARCH64),
        _ => None,
    }
}

#[derive(Debug, Clone, Default)]
pub struct Agents {
    by_arch: BTreeMap<&'static str, PathBuf>,
}

impl Agents {
    pub fn empty() -> Self {
        Self::default()
    }

    /// One binary for one architecture.
    pub fn single(arch: &str, path: impl Into<PathBuf>) -> Self {
        let mut a = Self::empty();
        a.insert(arch, path);
        a
    }

    /// What this controller can install by default: a copy of itself when it runs on Linux, plus
    /// whatever is in an `agents` directory beside the executable.
    pub fn for_this_controller() -> Self {
        let mut a = Self::empty();
        let exe = std::env::current_exe().ok();
        if cfg!(target_os = "linux") {
            if let Some(exe) = &exe {
                a.insert(std::env::consts::ARCH, exe);
            }
        }
        if let Some(dir) = exe.as_deref().and_then(Path::parent).map(|d| d.join("agents")) {
            a.discover(&dir);
        }
        a
    }

    /// Add (or replace) the binary for `arch`. Ignored for architectures we don't know.
    pub fn insert(&mut self, arch: &str, path: impl Into<PathBuf>) {
        if let Some(arch) = normalize_arch(arch) {
            self.by_arch.insert(arch, path.into());
        }
    }

    /// Look for `edge-lbd-<arch>` files in `dir`. Architectures already present are kept.
    pub fn discover(&mut self, dir: &Path) {
        for arch in [X86_64, AARCH64] {
            let p = dir.join(format!("edge-lbd-{arch}"));
            if p.is_file() {
                self.by_arch.entry(arch).or_insert(p);
            }
        }
    }

    /// The binary for a machine whose CPU is `arch` (any spelling).
    pub fn get(&self, arch: &str) -> Option<&Path> {
        self.by_arch.get(normalize_arch(arch)?).map(PathBuf::as_path)
    }

    pub fn archs(&self) -> Vec<&'static str> {
        self.by_arch.keys().copied().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.by_arch.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_map_to_one_name() {
        for a in ["x86_64", "amd64", "x86", " x86_64\n"] {
            assert_eq!(normalize_arch(a), Some(X86_64), "{a:?}");
        }
        for a in ["aarch64", "arm64", "arm"] {
            assert_eq!(normalize_arch(a), Some(AARCH64), "{a:?}");
        }
        for a in ["", "riscv64", "i686", "x86_64; id", "../../etc"] {
            assert_eq!(normalize_arch(a), None, "{a:?}");
        }
    }

    #[test]
    fn lookup_is_by_architecture_and_unknown_ones_are_refused() {
        let mut a = Agents::single("amd64", "/bin/one");
        assert_eq!(a.get("x86_64"), Some(Path::new("/bin/one")));
        assert_eq!(a.get("aarch64"), None);
        assert_eq!(a.get("riscv64"), None);
        a.insert("riscv64", "/bin/nope");
        assert_eq!(a.archs(), vec![X86_64]);
        a.insert("arm64", "/bin/two");
        assert_eq!(a.archs(), vec![AARCH64, X86_64]);
    }

    #[test]
    fn discovers_files_by_name_without_overriding() {
        let d = std::env::temp_dir().join(format!("edge-lbd-agents-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("edge-lbd-x86_64"), b"x").unwrap();
        std::fs::write(d.join("edge-lbd-aarch64"), b"a").unwrap();
        std::fs::write(d.join("edge-lbd-riscv64"), b"r").unwrap();
        let mut a = Agents::single("x86_64", "/mine");
        a.discover(&d);
        assert_eq!(a.get("x86_64"), Some(Path::new("/mine")), "an explicit binary wins");
        assert_eq!(a.get("aarch64"), Some(d.join("edge-lbd-aarch64").as_path()));
        assert_eq!(a.archs().len(), 2);
        let _ = std::fs::remove_dir_all(&d);
    }
}
