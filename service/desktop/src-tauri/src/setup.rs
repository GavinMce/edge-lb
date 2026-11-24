//! "Set up a controller on a server": turn a few answers into the commands to paste.
//!
//! What is typed here ends up in a command someone pastes into a (root) shell, so every value is
//! checked against a strict, small grammar first, and anything else is refused rather than quoted
//! into shape. Nothing is sent anywhere: this only builds text.

use crate::config;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

/// The controller's web UI port on the server, and the local port the SSH tunnel uses.
pub const UI_PORT: u16 = 8080;
const TUNNEL_PORT: u16 = 8081;
const GATEWAY_PORT: u16 = 7444;
/// Where the installer keeps the controller's data (and the pending first-run setup code).
pub const DATA_DIR: &str = "/var/lib/edge-lb-controller";

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// Listen on the server's loopback; reach it through `ssh -L`. Nothing is exposed.
    Tunnel,
    /// Listen on a private (LAN / Tailscale) address.
    Private,
    /// Loopback behind a TLS reverse proxy the person runs.
    Proxy,
}

#[derive(Debug, Deserialize)]
pub struct SetupRequest {
    pub access: Access,
    /// `user@host`, for the tunnel command.
    pub login: Option<String>,
    pub private_ip: Option<String>,
    pub domain: Option<String>,
    pub gateways: bool,
    pub gateway_host: Option<String>,
    /// Logged in as root on the server, so there is no `sudo`.
    pub root: bool,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Step {
    pub title: String,
    pub note: String,
    pub command: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SetupPlan {
    pub steps: Vec<Step>,
    /// What to type into the launcher's address field afterwards.
    pub connect_url: Option<String>,
    /// The install command on its own, for running it over SSH instead of showing it.
    #[serde(skip)]
    pub installer: Installer,
}

/// The one-line installer, before it is told how to get root.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Installer {
    url: String,
    args: String,
}

impl Installer {
    /// `sudo` is the prefix that gets root: `""` when already root, `"sudo "` to show a person, or
    /// `"sudo -n "` when nobody is there to type a password (it fails rather than waiting).
    pub fn command(&self, sudo: &str) -> String {
        format!("curl -fsSL {} | {sudo}sh -s --{}", self.url, self.args)
    }
}

/// `repo` is the `owner/name` of the GitHub repository the releases live in.
pub fn plan(req: &SetupRequest, repo: &str) -> Result<SetupPlan, String> {
    let repo = github_slug(repo)?;
    let login = req.login.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let login = login.map(valid_login).transpose()?;
    let domain = req.domain.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let private_ip = req.private_ip.as_deref().map(str::trim).filter(|s| !s.is_empty());

    let mut flags: Vec<String> = Vec::new();
    let (access_step, connect_url) = match req.access {
        Access::Tunnel => {
            let login = login.ok_or("Enter how you log in to the server, like root@203.0.113.10 (it's used for the tunnel command).")?;
            (
                Step {
                    title: "Open an SSH tunnel from this PC".into(),
                    note: "Run this in a separate PowerShell window and leave it open while you use the controller. The controller listens only on the server itself, so nothing is exposed to the internet.".into(),
                    command: Some(format!("ssh -N -L {TUNNEL_PORT}:127.0.0.1:{UI_PORT} {login}")),
                },
                Some(format!("http://127.0.0.1:{TUNNEL_PORT}")),
            )
        }
        Access::Private => {
            let ip: IpAddr = private_ip.ok_or("Enter the server's private IP address.")?.parse().map_err(|_| "That isn't an IP address.".to_string())?;
            if !config::ip_is_private(ip) {
                return Err("That address isn't on a private network (LAN, Tailscale). The controller refuses public addresses: use the tunnel, or an HTTPS reverse proxy.".into());
            }
            let addr = match ip {
                IpAddr::V4(v) => format!("{v}:{UI_PORT}"),
                IpAddr::V6(v) => format!("[{v}]:{UI_PORT}"),
            };
            flags.push(format!("--listen {}", quote(&addr)));
            (
                Step {
                    title: "Allow the port on your private network".into(),
                    note: format!("Allow inbound TCP {UI_PORT} on the server from your private network only, never from the internet. The page is plain http, so anyone on that network could read your sign-in."),
                    command: None,
                },
                Some(format!("http://{}", addr)),
            )
        }
        Access::Proxy => {
            let domain = valid_domain(domain.ok_or("Enter the domain name the controller will be served on.")?)?;
            flags.push("--tls-proxy".into());
            (
                Step {
                    title: "Put TLS in front".into(),
                    note: format!("Point DNS for {domain} at the server, open ports 80 and 443, and run a reverse proxy there that terminates TLS (for example Caddy, which also gets the certificate for you). This is the whole Caddy configuration:"),
                    command: Some(format!("{domain} {{\n    reverse_proxy 127.0.0.1:{UI_PORT}\n}}")),
                },
                Some(format!("https://{domain}")),
            )
        }
    };

    let mut gateway_step = None;
    if req.gateways {
        let host = match req.gateway_host.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(h) => valid_gateway_host(h)?,
            // The address you log in to is usually the one gateways should dial, if it's a name or IPv4.
            None => login
                .and_then(|l| l.rsplit_once('@').map(|(_, h)| h))
                .or(domain)
                .and_then(|h| valid_gateway_host(h).ok())
                .ok_or("Enter the address your gateways will use to reach the server (a name or IPv4 address).")?,
        };
        flags.push(format!("--gateway-listen {} --gateway-host {}", quote(&format!("0.0.0.0:{GATEWAY_PORT}")), quote(host)));
        gateway_step = Some(Step {
            title: "Let gateways connect".into(),
            note: format!("Allow inbound TCP {GATEWAY_PORT} to the server (its firewall and your cloud provider's). Gateways dial {host}:{GATEWAY_PORT}; you create them later from the controller's Sites page. Each edge also needs UDP 51820 open."),
            command: None,
        });
    }

    let sudo = if req.root { "" } else { "sudo " };
    let args = if flags.is_empty() { String::new() } else { format!(" {}", flags.join(" ")) };
    let installer = Installer { url: format!("https://github.com/{repo}/releases/latest/download/install-controller.sh"), args };
    let install = installer.command(sudo);

    let mut steps = vec![Step {
        title: "Install it on the server".into(),
        note: "Run this on the server (Linux with systemd: Debian, Ubuntu, Fedora…). It downloads the release, checks its checksum, installs the controller under its own unprivileged user, starts it, and prints a one-time setup code. Run it again to upgrade; add --uninstall to remove it.".into(),
        command: Some(install),
    }];
    steps.push(access_step);
    steps.extend(gateway_step);
    steps.push(Step {
        title: "Connect and create the administrator account".into(),
        note: "Use the address below in \"Connect to a new one\". The setup code is printed at the end of the install; to see it again:".into(),
        command: Some(format!("{sudo}cat {DATA_DIR}/setup-code")),
    });
    Ok(SetupPlan { steps, connect_url, installer })
}

// ---- the grammar every typed value must fit -----------------------------------------------------

fn github_slug(repo: &str) -> Result<String, String> {
    let slug = repo.trim().trim_end_matches('/').trim_end_matches(".git").strip_prefix("https://github.com/").unwrap_or(repo.trim());
    let ok = slug.split_once('/').is_some_and(|(o, n)| [o, n].iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))));
    if ok && slug.matches('/').count() == 1 {
        Ok(slug.to_string())
    } else {
        Err("This build doesn't know where its releases are published.".into())
    }
}

pub fn is_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

fn valid_login(s: &str) -> Result<&str, String> {
    let bad = || "Use the form user@host, like root@203.0.113.10 or admin@server.example.com.".to_string();
    let (user, host) = s.split_once('@').ok_or_else(bad)?;
    let user_ok = !user.is_empty() && user.len() <= 32 && !user.starts_with(['-', '.']) && user.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    let host_ok = is_hostname(host) || host.parse::<IpAddr>().is_ok();
    // A host that parses as an IPv4 address but isn't digits-and-dots is handled by is_hostname.
    if user_ok && host_ok && !host.starts_with('-') {
        Ok(s)
    } else {
        Err(bad())
    }
}

fn valid_domain(s: &str) -> Result<&str, String> {
    if is_hostname(s) && s.contains('.') && s.parse::<Ipv4Addr>().is_err() {
        Ok(s)
    } else {
        Err("Enter a domain name like ctl.example.com (not an IP address).".into())
    }
}

fn valid_gateway_host(s: &str) -> Result<&str, String> {
    let ipv6 = s.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6());
    if is_hostname(s) && !ipv6 {
        Ok(s)
    } else {
        Err("Gateways need a host name or an IPv4 address to dial.".into())
    }
}

/// Single-quote a value for the shell unless it is plainly safe. Values are already validated,
/// so no value can contain a quote; the quotes only stop `[` and `]` being read as a glob.
fn quote(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_')) {
        s.to_string()
    } else {
        debug_assert!(!s.contains('\''));
        format!("'{s}'")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPO: &str = "https://github.com/Someone/edge-lb";

    fn req(access: Access) -> SetupRequest {
        SetupRequest { access, login: None, private_ip: None, domain: None, gateways: false, gateway_host: None, root: false }
    }
    fn cmd(p: &SetupPlan, i: usize) -> String {
        p.steps[i].command.clone().unwrap()
    }

    #[test]
    fn tunnel_is_the_plain_default() {
        let mut r = req(Access::Tunnel);
        r.login = Some("root@203.0.113.10".into());
        let p = plan(&r, REPO).unwrap();
        assert_eq!(cmd(&p, 0), "curl -fsSL https://github.com/Someone/edge-lb/releases/latest/download/install-controller.sh | sudo sh -s --");
        assert_eq!(cmd(&p, 1), "ssh -N -L 8081:127.0.0.1:8080 root@203.0.113.10");
        assert_eq!(p.connect_url.as_deref(), Some("http://127.0.0.1:8081"));
        assert_eq!(cmd(&p, 2), "sudo cat /var/lib/edge-lb-controller/setup-code");
        let mut root = req(Access::Tunnel);
        root.login = Some("root@h.example.com".into());
        root.root = true;
        assert!(!cmd(&plan(&root, REPO).unwrap(), 0).contains("sudo"), "logged in as root: no sudo");
    }

    #[test]
    fn the_installer_is_the_same_command_with_a_different_way_to_get_root() {
        let mut r = req(Access::Tunnel);
        r.login = Some("admin@vps.example.com".into());
        r.gateways = true;
        let p = plan(&r, REPO).unwrap();
        assert_eq!(p.installer.command("sudo "), cmd(&p, 0), "the shown command is the installer's");
        let auto = p.installer.command("sudo -n ");
        assert!(auto.starts_with("curl -fsSL https://github.com/Someone/edge-lb/releases/latest/download/install-controller.sh | sudo -n sh -s -- --gateway-listen"), "{auto}");
        assert!(!p.installer.command("").contains("sudo"));
    }

    #[test]
    fn private_address_must_be_private() {
        let mut r = req(Access::Private);
        r.private_ip = Some("192.168.1.20".into());
        let p = plan(&r, REPO).unwrap();
        assert!(cmd(&p, 0).ends_with("sh -s -- --listen 192.168.1.20:8080"), "{}", cmd(&p, 0));
        assert_eq!(p.connect_url.as_deref(), Some("http://192.168.1.20:8080"));

        r.private_ip = Some("fd00::5".into());
        assert!(cmd(&plan(&r, REPO).unwrap(), 0).ends_with("--listen '[fd00::5]:8080'"), "brackets are quoted so the shell can't glob them");
        r.private_ip = Some("100.101.102.103".into());
        plan(&r, REPO).unwrap();
        for bad in ["8.8.8.8", "203.0.113.10", "example.com", "", "192.168.1.20; id", "2001:db8::1"] {
            r.private_ip = Some(bad.into());
            assert!(plan(&r, REPO).is_err(), "{bad}");
        }
    }

    #[test]
    fn proxy_mode_marks_cookies_secure_and_gives_the_caddy_config() {
        let mut r = req(Access::Proxy);
        r.domain = Some("ctl.example.com".into());
        let p = plan(&r, REPO).unwrap();
        assert!(cmd(&p, 0).ends_with("sh -s -- --tls-proxy"));
        assert_eq!(cmd(&p, 1), "ctl.example.com {\n    reverse_proxy 127.0.0.1:8080\n}");
        assert_eq!(p.connect_url.as_deref(), Some("https://ctl.example.com"));
        for bad in ["", "localhost", "1.2.3.4", "a b.example.com", "x.example.com/path", "-x.example.com", "x..example.com"] {
            r.domain = Some(bad.into());
            assert!(plan(&r, REPO).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn gateways_add_the_listener_and_default_the_host() {
        let mut r = req(Access::Tunnel);
        r.login = Some("admin@vps.example.com".into());
        r.gateways = true;
        let p = plan(&r, REPO).unwrap();
        assert!(cmd(&p, 0).ends_with("--gateway-listen 0.0.0.0:7444 --gateway-host vps.example.com"), "{}", cmd(&p, 0));
        assert!(p.steps.iter().any(|s| s.title.contains("gateways") && s.note.contains("7444")));

        r.gateway_host = Some("198.51.100.7".into());
        assert!(cmd(&plan(&r, REPO).unwrap(), 0).ends_with("--gateway-host 198.51.100.7"));

        r.gateway_host = None;
        r.login = Some("admin@2001:db8::1".into());
        assert!(plan(&r, REPO).is_err(), "an IPv6 login can't be the gateway address: ask for one");
        r.gateway_host = Some("2001:db8::1".into());
        assert!(plan(&r, REPO).is_err());
    }

    #[test]
    fn hostile_input_never_reaches_a_command() {
        let evil = ["a;rm -rf /", "a b", "a\nb", "a'b", "a\"b", "$(id)", "`id`", "a&b", "a|b", "a>b", "a<b", "a\\b", "../x", "-oProxyCommand=x", "a$IFS", "a#b", "a*b", "a?b", "é.example.com", "a\0b"];
        for e in evil {
            let tries: Vec<SetupRequest> = vec![
                SetupRequest { login: Some(format!("root@{e}")), ..req(Access::Tunnel) },
                SetupRequest { login: Some(format!("{e}@host.example.com")), ..req(Access::Tunnel) },
                SetupRequest { domain: Some(e.into()), ..req(Access::Proxy) },
                SetupRequest { private_ip: Some(e.into()), ..req(Access::Private) },
                SetupRequest { login: Some("root@h.example.com".into()), gateways: true, gateway_host: Some(e.into()), ..req(Access::Tunnel) },
            ];
            for t in &tries {
                if let Ok(p) = plan(t, REPO) {
                    let all: String = p.steps.iter().filter_map(|s| s.command.clone()).collect::<Vec<_>>().join("\n");
                    assert!(!all.contains(e), "{e:?} reached a command: {all}");
                }
            }
        }
        // The release location is validated too, since it is part of the URL.
        for bad in ["", "https://example.com/x/y", "Someone/edge lb", "a/b/c", "Someone", "https://github.com/a;b/c"] {
            let mut r = req(Access::Tunnel);
            r.login = Some("root@h.example.com".into());
            assert!(plan(&r, bad).is_err(), "{bad:?}");
        }
        assert!(plan(&SetupRequest { login: Some("root@h.example.com".into()), ..req(Access::Tunnel) }, "Someone/edge-lb").is_ok(), "a bare owner/name works too");
    }

    #[test]
    fn missing_answers_say_what_to_enter() {
        assert!(plan(&req(Access::Tunnel), REPO).unwrap_err().contains("log in"));
        assert!(plan(&req(Access::Private), REPO).unwrap_err().contains("private IP"));
        assert!(plan(&req(Access::Proxy), REPO).unwrap_err().contains("domain"));
    }
}
