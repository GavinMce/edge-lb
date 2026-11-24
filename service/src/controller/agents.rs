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

    /// What this controller can install by default. A static binary runs on any Linux, so those
    /// win: an `agents` directory beside the executable, then a musl build next to a cargo
    /// `target/<profile>` directory. A copy of this executable on Linux is the last resort, and
    /// only a static one is trusted to run everywhere (a dynamic one is warned about at startup).
    pub fn for_this_controller() -> Self {
        let mut a = Self::empty();
        let exe = std::env::current_exe().ok();
        let dir = exe.as_deref().and_then(Path::parent);
        if let Some(d) = dir {
            a.discover(&d.join("agents"));
            a.discover_cargo_musl(d);
        }
        if cfg!(target_os = "linux") {
            if let Some(exe) = &exe {
                let arch = normalize_arch(std::env::consts::ARCH);
                let have_static = arch.and_then(|r| a.by_arch.get(r)).is_some_and(|p| !is_dynamic_elf(p));
                if !have_static {
                    a.by_arch.entry(arch.unwrap_or(X86_64)).or_insert_with(|| exe.clone());
                }
            }
        }
        a
    }

    /// When running from `target/<profile>`, pick up `target/<arch>-unknown-linux-musl/<profile>/edge-lbd`.
    fn discover_cargo_musl(&mut self, exe_dir: &Path) {
        let (Some(profile), Some(target)) = (exe_dir.file_name(), exe_dir.parent()) else { return };
        if target.file_name().is_none_or(|n| n != "target") {
            return;
        }
        for (arch, triple) in [(X86_64, "x86_64-unknown-linux-musl"), (AARCH64, "aarch64-unknown-linux-musl")] {
            let p = target.join(triple).join(profile).join("edge-lbd");
            if p.is_file() && !is_dynamic_elf(&p) {
                self.by_arch.entry(arch).or_insert(p);
            }
        }
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

    /// Binaries that need the target's own libc. They only run on machines with an equal or newer
    /// glibc, so the install can fail on older distros; a static (musl) build runs anywhere.
    pub fn dynamically_linked(&self) -> Vec<(&'static str, &Path)> {
        self.by_arch.iter().filter(|(_, p)| is_dynamic_elf(p)).map(|(a, p)| (*a, p.as_path())).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.by_arch.is_empty()
    }
}

/// True if `path` is an ELF executable with a dynamic loader (`PT_INTERP`), i.e. not static.
pub fn is_dynamic_elf(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else { return false };
    let mut h = vec![0u8; 64];
    if f.read_exact(&mut h).is_err() || &h[..4] != b"\x7fELF" || h[4] != 2 || h[5] != 1 {
        return false; // only 64-bit little-endian ELF is shipped
    }
    let u16at = |o: usize| u16::from_le_bytes([h[o], h[o + 1]]) as u64;
    let u64at = |o: usize| u64::from_le_bytes(h[o..o + 8].try_into().unwrap());
    let (phoff, phentsize, phnum) = (u64at(32), u16at(54), u16at(56));
    if phentsize < 4 || phnum > 256 {
        return false;
    }
    let mut table = vec![0u8; (phentsize * phnum) as usize];
    use std::io::Seek;
    if f.seek(std::io::SeekFrom::Start(phoff)).is_err() || f.read_exact(&mut table).is_err() {
        return false;
    }
    table.chunks(phentsize as usize).any(|e| u32::from_le_bytes([e[0], e[1], e[2], e[3]]) == 3)
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

    #[test]
    fn detects_dynamic_binaries() {
        // /bin/sh is dynamic on practically every distro this suite runs on; a text file is not ELF.
        let sh = std::fs::canonicalize("/bin/sh").unwrap();
        if std::fs::read(&sh).map(|b| b.starts_with(b"\x7fELF")).unwrap_or(false) {
            assert!(is_dynamic_elf(&sh), "{sh:?} should be dynamic");
        }
        let release = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/x86_64-unknown-linux-musl/release/edge-lbd");
        if release.is_file() {
            assert!(!is_dynamic_elf(&release), "the musl build must read as static");
        }
        assert!(!is_dynamic_elf(Path::new("/definitely/not/here")));
        let t = std::env::temp_dir().join(format!("edge-lbd-notelf-{}", std::process::id()));
        std::fs::write(&t, b"#!/bin/sh\n").unwrap();
        assert!(!is_dynamic_elf(&t));
        let _ = std::fs::remove_file(&t);
    }
}
