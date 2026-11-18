//! The app's two small config files, both in the app's folder (`%APPDATA%\edge-lb`):
//!
//! * `app.toml` is edited by hand and never written by the app, so your comments survive.
//! * `remotes.toml` is the list of controllers you have connected to. The app keeps it up to date
//!   (and it is plain TOML, so it can be edited too).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use tauri::Url;

pub const DEFAULT_PORT: u16 = 17480;
const APP_FILE: &str = "app.toml";
const REMOTES_FILE: &str = "remotes.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    /// `"ask"` (the default) shows the launcher; `"local"` starts the local controller straight
    /// away; any other value is the name of a saved remote controller to connect to.
    pub startup: Option<String>,
    pub local: LocalConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocalConfig {
    /// Loopback port for the local controller's UI. If it is taken, a free one is used.
    pub port: u16,
    /// Where the local controller keeps its state. Default: the app's folder.
    pub data_dir: Option<PathBuf>,
    /// Let WireGuard gateways on your LAN reach this PC: `gateway_listen = "0.0.0.0:7444"` and
    /// `gateway_host = "192.168.1.20"` (this PC's address as the gateways see it). Both or neither.
    pub gateway_listen: Option<SocketAddr>,
    pub gateway_host: Option<String>,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self { port: DEFAULT_PORT, data_dir: None, gateway_listen: None, gateway_host: None }
    }
}

impl AppConfig {
    /// Read `app.toml`. A missing file is the defaults. A broken one is also the defaults, plus a
    /// message for the launcher to show: a typo must not stop the app from opening.
    pub fn load(dir: &Path) -> (AppConfig, Option<String>) {
        let path = dir.join(APP_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (AppConfig::default(), None),
            Err(e) => return (AppConfig::default(), Some(format!("Could not read {}: {e}", path.display()))),
        };
        match toml::from_str::<AppConfig>(&text) {
            Ok(cfg) => match cfg.check() {
                Ok(()) => (cfg, None),
                Err(msg) => (AppConfig::default(), Some(format!("{}: {msg}. Using the defaults.", path.display()))),
            },
            Err(e) => {
                let line = e.span().map(|s| format!(" line {}", text[..s.start.min(text.len())].matches('\n').count() + 1)).unwrap_or_default();
                (AppConfig::default(), Some(format!("{}{line}: {}. Using the defaults.", path.display(), e.message())))
            }
        }
    }

    fn check(&self) -> std::result::Result<(), String> {
        if self.local.gateway_listen.is_some() != self.local.gateway_host.is_some() {
            return Err("set both gateway_listen and gateway_host, or neither".into());
        }
        if self.local.port == 0 {
            return Err("port must be 1-65535".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Remote {
    pub name: String,
    pub url: String,
    /// Unix seconds of the last successful connection.
    #[serde(default)]
    pub last_used: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct RemotesFile {
    #[serde(default, rename = "remote")]
    remotes: Vec<Remote>,
}

pub fn load_remotes(dir: &Path) -> Result<Vec<Remote>> {
    let path = dir.join(REMOTES_FILE);
    match std::fs::read_to_string(&path) {
        Ok(t) => Ok(toml::from_str::<RemotesFile>(&t).with_context(|| format!("reading {}", path.display()))?.remotes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

pub fn save_remotes(dir: &Path, remotes: &[Remote]) -> Result<()> {
    let path = dir.join(REMOTES_FILE);
    let tmp = dir.join("remotes.toml.tmp");
    let body = toml::to_string_pretty(&RemotesFile { remotes: remotes.to_vec() })?;
    std::fs::write(&tmp, format!("# Controllers this app has connected to. Safe to edit.\n\n{body}"))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Add `url` to the list, or update its name and time. Most recently used first.
pub fn remember(list: &mut Vec<Remote>, url: &str, name: Option<&str>, now: u64) {
    match list.iter_mut().find(|r| r.url == url) {
        Some(r) => {
            r.last_used = now;
            if let Some(n) = name {
                r.name = n.to_string();
            }
        }
        None => list.push(Remote { name: name.map(str::to_string).unwrap_or_else(|| default_name(url)), url: url.to_string(), last_used: now }),
    }
    list.sort_by(|a, b| b.last_used.cmp(&a.last_used).then_with(|| a.name.cmp(&b.name)));
}

fn default_name(url: &str) -> String {
    Url::parse(url).ok().and_then(|u| u.host_str().map(|h| match u.port() { Some(p) => format!("{h}:{p}"), None => h.to_string() })).unwrap_or_else(|| url.to_string())
}

/// Turn what someone typed into the controller's origin (`https://host[:port]`), or say why not.
///
/// The controller's sign-in cookie must not cross an untrusted network in the clear, so plain
/// `http://` is accepted only for loopback and private-network hosts (a LAN box, a Tailscale
/// address, an SSH tunnel to `127.0.0.1`). Everything else needs `https://`.
pub fn normalize_remote(input: &str) -> std::result::Result<Url, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("Enter the controller's address.".into());
    }
    let with_scheme = if input.contains("://") { input.to_string() } else { format!("https://{input}") };
    let mut url = Url::parse(&with_scheme).map_err(|_| "That doesn't look like a web address.".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("Use an http:// or https:// address.".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Leave the user name and password out of the address; you sign in in the controller's own page.".into());
    }
    let Some(host) = url.host() else { return Err("The address has no host name.".into()) };
    if url.scheme() == "http" && !host_is_private(&host) {
        return Err("Plain http:// is only allowed for addresses on a private network, because the sign-in cookie would travel unencrypted. Use https://.".into());
    }
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

/// The origin without a trailing slash: how a remote is stored and compared.
pub fn origin_string(url: &Url) -> String {
    url.origin().ascii_serialization()
}

pub fn host_is_private(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Ipv4(ip) => ipv4_private(*ip),
        url::Host::Ipv6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80,
        url::Host::Domain(d) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            !d.contains('.') || [".local", ".lan", ".internal", ".home.arpa", ".localdomain"].iter().any(|s| d.ends_with(s))
        }
    }
}

fn ipv4_private(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback() || ip.is_private() || ip.is_link_local() || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10: Tailscale and friends
}

/// Same rule for a literal IP.
pub fn ip_is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => ipv4_private(v),
        IpAddr::V6(v) => host_is_private(&url::Host::Ipv6(v)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> String {
        origin_string(&normalize_remote(s).unwrap_or_else(|e| panic!("{s}: {e}")))
    }
    fn err(s: &str) -> String {
        normalize_remote(s).expect_err(s)
    }

    #[test]
    fn a_bare_host_means_https_and_only_the_origin_is_kept() {
        assert_eq!(ok("edge.example.com"), "https://edge.example.com");
        assert_eq!(ok("  https://Edge.Example.com:8443/some/path?x=1#frag "), "https://edge.example.com:8443");
        assert_eq!(ok("https://edge.example.com:443"), "https://edge.example.com");
    }

    #[test]
    fn plain_http_is_only_for_private_hosts() {
        for good in ["http://127.0.0.1:8081", "http://localhost:8080", "http://192.168.1.5:8080", "http://10.0.0.2", "http://172.16.4.1", "http://100.101.102.103", "http://[::1]:8080", "http://[fd00::1]", "http://pi", "http://pi.local", "http://nas.lan:8080", "http://169.254.1.1"] {
            ok(good);
        }
        for bad in ["http://example.com", "http://8.8.8.8", "http://172.32.0.1", "http://100.128.0.1", "http://[2001:db8::1]", "http://edge.example.com:8080"] {
            assert!(err(bad).contains("https://"), "{bad}");
        }
    }

    #[test]
    fn junk_credentials_and_other_schemes_are_refused() {
        for bad in ["", "   ", "ftp://host", "file:///c:/x", "javascript:alert(1)", "https://user:pw@host", "https://user@host", "https://"] {
            err(bad);
        }
    }

    #[test]
    fn remembering_updates_in_place_and_orders_by_recent_use() {
        let mut l = Vec::new();
        remember(&mut l, "https://a.example", None, 10);
        remember(&mut l, "https://b.example:8443", Some("Backup"), 20);
        assert_eq!(l.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["Backup", "a.example"]);
        remember(&mut l, "https://a.example", Some("Home"), 30);
        assert_eq!(l.len(), 2);
        assert_eq!((l[0].name.as_str(), l[0].last_used), ("Home", 30));
        remember(&mut l, "https://b.example:8443", None, 40);
        assert_eq!(l[0].name, "Backup", "a connect without a name keeps the saved name");
    }

    #[test]
    fn config_files_round_trip_and_bad_ones_fall_back() {
        let dir = std::env::temp_dir().join(format!("edge-lb-desktop-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        assert!(load_remotes(&dir).unwrap().is_empty());
        let mut l = Vec::new();
        remember(&mut l, "https://a.example", Some("A \"quoted\" name"), 5);
        save_remotes(&dir, &l).unwrap();
        assert_eq!(load_remotes(&dir).unwrap(), l);
        std::fs::write(dir.join("remotes.toml"), "this is = not [valid").unwrap();
        assert!(load_remotes(&dir).is_err());

        let (c, w) = AppConfig::load(&dir);
        assert!(w.is_none() && c.local.port == DEFAULT_PORT && c.startup.is_none());
        std::fs::write(dir.join("app.toml"), "startup = \"local\"\n[local]\nport = 9000\ngateway_listen = \"0.0.0.0:7444\"\ngateway_host = \"192.168.1.20\"\n").unwrap();
        let (c, w) = AppConfig::load(&dir);
        assert!(w.is_none(), "{w:?}");
        assert_eq!((c.startup.as_deref(), c.local.port), (Some("local"), 9000));
        for (body, needle) in [("[local]\ngateway_listen = \"0.0.0.0:7444\"\n", "both"), ("[local]\nprot = 1\n", "prot"), ("startup = 3\n", "line 1: invalid type"), ("[local]\nport = 0\n", "port")] {
            std::fs::write(dir.join("app.toml"), body).unwrap();
            let (c, w) = AppConfig::load(&dir);
            assert!(w.as_deref().is_some_and(|m| m.contains(needle)), "{body}: {w:?}");
            assert_eq!(c.local.port, DEFAULT_PORT, "falls back to the defaults");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

