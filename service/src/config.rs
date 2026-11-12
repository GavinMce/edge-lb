//! Route model, validation, and the on-disk store.
//!
//! A route says: "traffic arriving on `listen` (ip, port), optionally for one of `domains`,
//! is forwarded to one of `targets` (ip, port)".

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

fn yes() -> bool {
    true
}
fn any_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// Stable identifier (slug). Generated from `name` when empty.
    #[serde(default)]
    pub id: String,
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub listen: Listen,
    /// Hostnames to match (TLS SNI, HTTP Host, or Minecraft handshake address).
    /// `*.example.com` matches any subdomain. Empty = match everything on this listener
    /// (plain L4 forward, and the fallback when other routes on the listener don't match).
    #[serde(default)]
    pub domains: Vec<String>,
    pub targets: Vec<Target>,
    /// Send PROXY protocol v2 to the target so it sees the real client address.
    #[serde(default)]
    pub proxy_protocol: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listen {
    #[serde(default = "any_ip")]
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub address: IpAddr,
    pub port: u16,
}

pub const MAX_TARGETS: usize = 32;

pub fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut dash = true;
    for c in s.chars().flat_map(|c| c.to_lowercase()) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            dash = false;
        } else if !dash {
            out.push('-');
            dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out.truncate(48);
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "route".into()
    } else {
        out
    }
}

pub fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'_')
}

/// Lowercase, strip a trailing dot, and check that this is a plausible hostname or `*.suffix`.
pub fn normalize_domain(d: &str) -> Result<String, String> {
    let d = d.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return Err("empty".into());
    }
    if d.len() > 253 {
        return Err("too long".into());
    }
    let body = d.strip_prefix("*.").unwrap_or(&d);
    for label in body.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("bad label length".into());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("label may not start or end with '-'".into());
        }
        if !label
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
        {
            return Err("only letters, digits, '-' and '_' are allowed (wildcard only as a leading '*.')".into());
        }
    }
    Ok(d)
}

/// Does `pattern` (exact or `*.suffix`) match `host` (already normalized)?
pub fn domain_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(suffix) && host.as_bytes()[host.len() - suffix.len() - 1] == b'.',
        None => pattern == host,
    }
}

impl Route {
    /// Clean up fields in place and report every problem found.
    pub fn normalize(&mut self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        self.name = self.name.trim().to_string();
        if self.name.is_empty() {
            errs.push("name is required".into());
        } else if self.name.chars().count() > 80 {
            errs.push("name is longer than 80 characters".into());
        }
        if !self.id.is_empty() && !valid_id(&self.id) {
            errs.push(format!("id '{}' is invalid (use a-z, 0-9, '-', '_')", self.id));
        }
        if self.listen.port == 0 {
            errs.push("listen port must be 1-65535".into());
        }
        let mut seen = HashSet::new();
        let mut domains = Vec::new();
        for d in &self.domains {
            if d.trim().is_empty() {
                continue;
            }
            match normalize_domain(d) {
                Ok(n) => {
                    if seen.insert(n.clone()) {
                        domains.push(n);
                    }
                }
                Err(e) => errs.push(format!("domain '{}': {}", d.trim(), e)),
            }
        }
        self.domains = domains;
        if self.targets.is_empty() {
            errs.push("at least one target is required".into());
        }
        if self.targets.len() > MAX_TARGETS {
            errs.push(format!("at most {MAX_TARGETS} targets per route"));
        }
        for t in &self.targets {
            if t.port == 0 {
                errs.push(format!("target {}: port must be 1-65535", t.address));
            }
            if t.address.is_unspecified() {
                errs.push("target address may not be 0.0.0.0 or ::".into());
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }
}

/// Validate the whole route set. Only enabled routes can conflict with each other.
pub fn validate_set(routes: &[Route], reserved_ports: &[u16]) -> Result<(), Vec<String>> {
    let mut errs = Vec::new();
    let mut ids = HashSet::new();
    for r in routes {
        if !ids.insert(r.id.as_str()) {
            errs.push(format!("duplicate route id '{}'", r.id));
        }
    }

    let enabled: Vec<&Route> = routes.iter().filter(|r| r.enabled).collect();

    for r in &enabled {
        if reserved_ports.contains(&r.listen.port) {
            errs.push(format!(
                "route '{}': port {} is reserved (management or SSH)",
                r.name, r.listen.port
            ));
        }
    }

    // A wildcard bind (0.0.0.0 / ::) overlaps every other address on the same port.
    let mut by_port: BTreeMap<u16, Vec<&Route>> = BTreeMap::new();
    for r in &enabled {
        by_port.entry(r.listen.port).or_default().push(r);
    }
    for (port, rs) in &by_port {
        let ips: HashSet<IpAddr> = rs.iter().map(|r| r.listen.ip).collect();
        if ips.len() > 1 && ips.iter().any(|ip| ip.is_unspecified()) {
            errs.push(format!(
                "port {port}: a wildcard listen address (0.0.0.0 or ::) overlaps the other addresses used on this port; use one or the other"
            ));
        }
    }

    // Per listener: no duplicate domains, at most one catch-all.
    let mut by_listener: BTreeMap<(IpAddr, u16), Vec<&Route>> = BTreeMap::new();
    for r in &enabled {
        by_listener.entry((r.listen.ip, r.listen.port)).or_default().push(r);
    }
    for ((ip, port), rs) in &by_listener {
        let mut domains: BTreeMap<&str, &str> = BTreeMap::new();
        let mut catch_all: Option<&str> = None;
        for r in rs {
            if r.domains.is_empty() {
                if let Some(first) = catch_all {
                    errs.push(format!(
                        "{ip}:{port}: routes '{first}' and '{}' both match everything; give one of them domains",
                        r.name
                    ));
                }
                catch_all.get_or_insert(&r.name);
            }
            for d in &r.domains {
                if let Some(other) = domains.insert(d.as_str(), r.name.as_str()) {
                    errs.push(format!(
                        "{ip}:{port}: domain '{d}' is used by both '{other}' and '{}'",
                        r.name
                    ));
                }
            }
        }
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// Pick an id not already in `routes`.
pub fn unique_id(routes: &[Route], base: &str) -> String {
    let taken: HashSet<&str> = routes.iter().map(|r| r.id.as_str()).collect();
    if !taken.contains(base) {
        return base.to_string();
    }
    (2..)
        .map(|n| format!("{base}-{n}"))
        .find(|c| !taken.contains(c.as_str()))
        .unwrap()
}

#[derive(Serialize, Deserialize)]
struct File {
    version: u32,
    routes: Vec<Route>,
}

/// JSON file store with atomic replace.
#[derive(Debug, Clone)]
pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn load(&self) -> anyhow::Result<Vec<Route>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let f: File = serde_json::from_slice(&bytes)
                    .map_err(|e| anyhow::anyhow!("{}: {e}", self.path.display()))?;
                Ok(f.routes)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(anyhow::anyhow!("{}: {e}", self.path.display())),
        }
    }

    pub fn save(&self, routes: &[Route]) -> anyhow::Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(&File { version: 1, routes: routes.to_vec() })?;
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(name: &str, ip: &str, port: u16, domains: &[&str]) -> Route {
        let mut r = Route {
            id: slugify(name),
            name: name.into(),
            enabled: true,
            listen: Listen { ip: ip.parse().unwrap(), port },
            domains: domains.iter().map(|s| s.to_string()).collect(),
            targets: vec![Target { address: "10.0.0.5".parse().unwrap(), port: 8080 }],
            proxy_protocol: false,
        };
        r.normalize().unwrap();
        r
    }

    #[test]
    fn domain_normalization() {
        assert_eq!(normalize_domain(" Example.COM. ").unwrap(), "example.com");
        assert_eq!(normalize_domain("*.Foo.io").unwrap(), "*.foo.io");
        assert!(normalize_domain("a*.com").is_err());
        assert!(normalize_domain("foo.*.com").is_err());
        assert!(normalize_domain("-bad.com").is_err());
        assert!(normalize_domain("has space.com").is_err());
        assert!(normalize_domain("").is_err());
    }

    #[test]
    fn wildcard_matching() {
        assert!(domain_matches("*.example.com", "a.example.com"));
        assert!(domain_matches("*.example.com", "a.b.example.com"));
        assert!(!domain_matches("*.example.com", "example.com"));
        assert!(!domain_matches("*.example.com", "badexample.com"));
        assert!(domain_matches("example.com", "example.com"));
        assert!(!domain_matches("example.com", "www.example.com"));
    }

    #[test]
    fn slugs() {
        assert_eq!(slugify("My Blog (prod)!"), "my-blog-prod");
        assert_eq!(slugify("!!!"), "route");
    }

    #[test]
    fn duplicate_domain_on_one_listener_is_rejected() {
        let a = route("a", "0.0.0.0", 443, &["x.com"]);
        let b = route("b", "0.0.0.0", 443, &["x.com", "y.com"]);
        let errs = validate_set(&[a, b], &[]).unwrap_err();
        assert!(errs[0].contains("x.com"), "{errs:?}");
    }

    #[test]
    fn same_domain_on_different_ports_is_fine() {
        let a = route("a", "0.0.0.0", 443, &["x.com"]);
        let b = route("b", "0.0.0.0", 8443, &["x.com"]);
        validate_set(&[a, b], &[]).unwrap();
    }

    #[test]
    fn two_catch_alls_conflict_but_one_plus_domains_is_fine() {
        let a = route("a", "0.0.0.0", 25565, &[]);
        let b = route("b", "0.0.0.0", 25565, &[]);
        assert!(validate_set(&[a.clone(), b], &[]).is_err());
        let c = route("c", "0.0.0.0", 25565, &["mc.example.com"]);
        validate_set(&[a, c], &[]).unwrap();
    }

    #[test]
    fn wildcard_bind_overlaps_specific_ip() {
        let a = route("a", "0.0.0.0", 9000, &[]);
        let b = route("b", "192.0.2.1", 9000, &[]);
        assert!(validate_set(&[a, b], &[]).is_err());
        let c = route("c", "192.0.2.1", 9000, &[]);
        let d = route("d", "192.0.2.2", 9000, &[]);
        validate_set(&[c, d], &[]).unwrap();
    }

    #[test]
    fn disabled_routes_do_not_conflict_and_reserved_ports_block() {
        let a = route("a", "0.0.0.0", 443, &["x.com"]);
        let mut b = route("b", "0.0.0.0", 443, &["x.com"]);
        b.enabled = false;
        validate_set(&[a, b], &[]).unwrap();
        let r = route("r", "0.0.0.0", 22, &[]);
        assert!(validate_set(&[r], &[22]).is_err());
    }

    #[test]
    fn route_field_errors_are_all_reported() {
        let mut r = Route {
            id: String::new(),
            name: " ".into(),
            enabled: true,
            listen: Listen { ip: any_ip(), port: 0 },
            domains: vec!["bad domain".into()],
            targets: vec![],
            proxy_protocol: false,
        };
        let errs = r.normalize().unwrap_err();
        assert!(errs.len() >= 4, "{errs:?}");
    }

    #[test]
    fn json_defaults() {
        let r: Route = serde_json::from_str(
            r#"{"name":"x","listen":{"port":80},"targets":[{"address":"10.0.0.1","port":80}]}"#,
        )
        .unwrap();
        assert!(r.enabled);
        assert!(r.listen.ip.is_unspecified());
        assert!(r.domains.is_empty());
        assert!(!r.proxy_protocol);
    }

    #[test]
    fn store_roundtrip_and_missing_file() {
        let dir = std::env::temp_dir().join(format!("edge-lbd-store-{}", std::process::id()));
        let s = Store::new(dir.join("routes.json"));
        assert!(s.load().unwrap().is_empty());
        let r = route("a", "0.0.0.0", 443, &["x.com"]);
        s.save(std::slice::from_ref(&r)).unwrap();
        assert_eq!(s.load().unwrap(), vec![r]);
        let _ = std::fs::remove_dir_all(dir);
    }
}
