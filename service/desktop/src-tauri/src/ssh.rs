//! Setting up and reaching a controller on a server, over the OpenSSH client that ships with Windows.
//!
//! This is the "Install it for me" button: it does what the commands in the launcher's setup panel
//! would have had you paste by hand. Nothing here asks for, sees or stores a password or a private
//! key: `ssh` logs in with the keys you already use (your `~/.ssh` and ssh-agent), in batch mode, so
//! it fails with a clear message instead of waiting for a prompt nobody can see.
//!
//! The server's host key is shown to you once, by fingerprint, to confirm. After that every
//! connection insists on exactly that key, from this app's own `ssh\known_hosts`.
//!
//! Everything typed ends up in a command line, so it is validated against a small grammar first
//! ([`Login::parse`]) and everything a server sends back is validated before it is used.

use crate::setup;
use anyhow::{anyhow, bail, Result};
use edge_lbd::controller::bootstrap::{known_hosts_option, quiet, valid_ssh_user};
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};
use tokio::sync::{oneshot, watch};

/// `user@host`, checked.
#[derive(Debug, Clone, PartialEq)]
pub struct Login {
    user: String,
    host: String,
}

impl Login {
    pub fn parse(input: &str) -> std::result::Result<Login, String> {
        let bad = || "Use the form user@host, like root@203.0.113.10 or deploy@server.example.com (the user name in lower case).".to_string();
        let (user, host) = input.trim().split_once('@').ok_or_else(bad)?;
        // `ssh` lower-cases the host it looks up, so the trusted key has to be stored under that name.
        let host = host.to_ascii_lowercase();
        let host_ok = setup::is_hostname(&host) || host.parse::<IpAddr>().is_ok();
        if valid_ssh_user(user) && host_ok {
            Ok(Login { user: user.to_string(), host })
        } else {
            Err(bad())
        }
    }

    pub fn target(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// How a command gets root. Never `sudo` without `-n`: there is nobody to type a password.
    pub fn sudo(&self) -> &'static str {
        if self.user == "root" {
            ""
        } else {
            "sudo -n "
        }
    }
}

/// What the launcher needs to ask "do you trust this server?".
#[derive(Debug, Serialize, PartialEq)]
pub struct HostKeyView {
    pub host: String,
    /// Already trusted: nothing to ask.
    pub known: bool,
    pub algorithm: Option<String>,
    /// `SHA256:...`, the same form `ssh-keygen -lf` and most provider consoles show.
    pub fingerprint: Option<String>,
}

#[derive(Clone)]
pub struct Ssh {
    dir: PathBuf,
}

impl Ssh {
    /// Keeps its files in `<config_dir>\ssh`.
    pub fn new(config_dir: &Path) -> Self {
        let s = Self { dir: config_dir.join("ssh") };
        // A tunnel that keeps failing must not fill the disk.
        if std::fs::metadata(s.log_path()).map(|m| m.len() > 1024 * 1024).unwrap_or(false) {
            let _ = std::fs::remove_file(s.log_path());
        }
        s
    }

    pub fn known_hosts(&self) -> PathBuf {
        self.dir.join("known_hosts")
    }

    fn log_path(&self) -> PathBuf {
        self.dir.join("tunnel.log")
    }

    /// `ssh` with the options every use shares, ready for the remote command (or `-N`) to follow.
    fn command(&self, login: &Login, extra: &[String]) -> Command {
        let mut cmd = Command::new("ssh");
        // No `LogLevel=ERROR`: some failures ("banner exchange", a refused tunnel) are only said at the default level.
        cmd.args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"])
            .args(["-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3"])
            .arg("-o")
            .arg(known_hosts_option(&self.known_hosts()))
            .args(extra)
            .arg(login.target())
            .kill_on_drop(true);
        quiet(&mut cmd);
        cmd
    }

    // ---- trusting the server ----------------------------------------------------------------------

    /// Is this server already trusted? If not, what key does it show?
    pub async fn check_host(&self, login: &Login) -> Result<HostKeyView> {
        if self.is_known(login.host()).await {
            return Ok(HostKeyView { host: login.host.clone(), known: true, algorithm: None, fingerprint: None });
        }
        let k = self.scan(login.host()).await?;
        Ok(HostKeyView { host: login.host.clone(), known: false, algorithm: Some(k.algorithm), fingerprint: Some(k.fingerprint) })
    }

    /// Trust the server's key, but only if it is still the one with `fingerprint`, the one the person
    /// was shown. The key is fetched again here: nothing the launcher page sends is written down.
    pub async fn trust_host(&self, login: &Login, fingerprint: &str) -> Result<()> {
        if self.is_known(login.host()).await {
            return Ok(());
        }
        let k = self.scan(login.host()).await?;
        if k.fingerprint != fingerprint {
            bail!("The server's host key changed while you were looking at it (it now shows {}). Nothing was trusted; start again.", k.fingerprint);
        }
        std::fs::create_dir_all(&self.dir)?;
        let mut text = std::fs::read_to_string(self.known_hosts()).unwrap_or_default();
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&k.line);
        text.push('\n');
        std::fs::write(self.known_hosts(), text)?;
        Ok(())
    }

    async fn is_known(&self, host: &str) -> bool {
        let mut c = tool("ssh-keygen");
        c.arg("-F").arg(host).arg("-f").arg(self.known_hosts());
        run(c, Duration::from_secs(10)).await.map(|o| o.ok()).unwrap_or(false)
    }

    /// Read the key the server shows, without logging in. This is `ssh` itself, told to write what it
    /// sees to a scratch `known_hosts` and to try no authentication at all (so none of your keys is
    /// offered, and the login "fails" by design). `ssh-keyscan` is not used: the one that ships with
    /// Windows cannot talk to servers that offer the `sntrup761x25519` key exchange, which is now
    /// the default on current OpenSSH, so it fails against most up-to-date servers.
    async fn scan(&self, host: &str) -> Result<Scanned> {
        std::fs::create_dir_all(&self.dir)?;
        let scratch = self.dir.join(format!("probe-{}.tmp", std::process::id()));
        let _ = std::fs::remove_file(&scratch);
        let mut c = Command::new("ssh");
        c.args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "HashKnownHosts=no", "-o", "ConnectTimeout=8"])
            .args(["-o", "PubkeyAuthentication=no", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "GSSAPIAuthentication=no"])
            .arg("-o")
            .arg(known_hosts_option(&scratch))
            .arg(format!("nobody@{host}"))
            .arg("true")
            .kill_on_drop(true);
        quiet(&mut c);
        let out = run(c, Duration::from_secs(25)).await;
        let seen = std::fs::read_to_string(&scratch).unwrap_or_default();
        let _ = std::fs::remove_file(&scratch);
        let out = out?;
        let (algorithm, blob) = parse_scan(&seen).ok_or_else(|| {
            let why = explain(&out.stderr, &Login { user: "nobody".into(), host: host.to_string() }, &self.known_hosts());
            anyhow!("{}", why.unwrap_or_else(|| format!("Couldn't get an SSH host key from {host}. Check that the name or address is right and that SSH is running there on port 22.\n\n{}", tail(&out.stderr, 400))))
        })?;
        let line = format!("{host} {algorithm} {blob}");
        let fingerprint = self.fingerprint(&line).await?;
        Ok(Scanned { line, algorithm: algorithm_name(&algorithm), fingerprint })
    }

    /// Ask `ssh-keygen` for the fingerprint: it is the tool the person would use to cross-check it.
    async fn fingerprint(&self, known_hosts_line: &str) -> Result<String> {
        std::fs::create_dir_all(&self.dir)?;
        let tmp = self.dir.join(format!("scan-{}.tmp", std::process::id()));
        std::fs::write(&tmp, format!("{known_hosts_line}\n"))?;
        let mut c = tool("ssh-keygen");
        c.arg("-l").arg("-f").arg(&tmp);
        let out = run(c, Duration::from_secs(10)).await;
        let _ = std::fs::remove_file(&tmp);
        parse_fingerprint(&out?.stdout).ok_or_else(|| anyhow!("ssh-keygen could not read the server's host key."))
    }

    // ---- installing --------------------------------------------------------------------------------

    /// Run the installer command on the server. It is idempotent (running it again upgrades), so
    /// this doubles as "connect to an existing server and bring it up to date".
    pub async fn install(&self, login: &Login, command: &str) -> Result<()> {
        let mut c = self.command(login, &[]);
        c.arg(command);
        let out = run(c, Duration::from_secs(420)).await?;
        if out.ok() {
            return Ok(());
        }
        bail!("{}", failure("The install didn't finish.", &out, login, &self.known_hosts()))
    }

    /// The one-time code for creating the administrator account, if one is pending. `None` once the
    /// account exists (the file is gone), or if it can't be read: the person can still read it
    /// from the installer's output.
    pub async fn setup_code(&self, login: &Login) -> Option<String> {
        let mut c = self.command(login, &[]);
        c.arg(format!("{}cat {}/setup-code", login.sudo(), setup::DATA_DIR));
        let out = run(c, Duration::from_secs(30)).await.ok().filter(Out::ok)?;
        let code = out.stdout.trim();
        (!code.is_empty() && code.len() <= 64 && code.chars().all(|c| c.is_ascii_alphanumeric())).then(|| code.to_string())
    }

    // ---- tunnels -----------------------------------------------------------------------------------

    fn spawn_tunnel(&self, login: &Login, remote_port: u16, local_port: u16) -> Result<Child> {
        std::fs::create_dir_all(&self.dir)?;
        let log = std::fs::OpenOptions::new().create(true).append(true).open(self.log_path())?;
        let forward = format!("127.0.0.1:{local_port}:127.0.0.1:{remote_port}");
        let mut c = self.command(login, &["-N".into(), "-o".into(), "ExitOnForwardFailure=yes".into(), "-L".into(), forward]);
        c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::from(log));
        c.spawn().map_err(spawn_error)
    }

    fn log_len(&self) -> u64 {
        std::fs::metadata(self.log_path()).map(|m| m.len()).unwrap_or(0)
    }

    /// What `ssh` wrote to the log since `from`.
    fn log_since(&self, from: u64) -> String {
        let bytes = std::fs::read(self.log_path()).unwrap_or_default();
        let new = bytes.get(from as usize..).unwrap_or_default();
        tail(&String::from_utf8_lossy(new), 600)
    }
}

struct Scanned {
    /// `host algorithm key`, a `known_hosts` line, rebuilt from validated parts.
    line: String,
    algorithm: String,
    fingerprint: String,
}

fn tool(name: &str) -> Command {
    let mut c = Command::new(name);
    c.kill_on_drop(true);
    quiet(&mut c);
    c
}

// ---- running things --------------------------------------------------------------------------------

struct Out {
    status: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Out {
    fn ok(&self) -> bool {
        self.status == Some(0)
    }
}

async fn run(mut cmd: Command, limit: Duration) -> Result<Out> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = cmd.spawn().map_err(spawn_error)?;
    let out = tokio::time::timeout(limit, child.wait_with_output()).await.map_err(|_| anyhow!("It took longer than {} seconds, so it was stopped.", limit.as_secs()))??;
    Ok(Out {
        status: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).replace('\r', ""),
        stderr: String::from_utf8_lossy(&out.stderr).replace('\r', ""),
    })
}

fn spawn_error(e: std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        anyhow!("The OpenSSH client isn't installed. In Windows, open Settings → System → Optional features → Add a feature, and add \"OpenSSH Client\".")
    } else {
        anyhow!("Could not run ssh: {e}")
    }
}

/// The last `max` characters, trimmed.
fn tail(s: &str, max: usize) -> String {
    let s = s.trim();
    let n = s.chars().count();
    if n <= max {
        s.to_string()
    } else {
        format!("…{}", s.chars().skip(n - max).collect::<String>().trim_start())
    }
}

/// A failed `ssh`: say what to do about it when the cause is a common one, then show what the
/// server said.
fn failure(headline: &str, out: &Out, login: &Login, known_hosts: &Path) -> String {
    let said = tail(&format!("{}\n{}", out.stdout.trim(), out.stderr.trim()), 1200);
    let lead = explain(&out.stderr, login, known_hosts).unwrap_or_else(|| headline.to_string());
    format!("{lead}\n\n{said}").trim_end().to_string()
}

/// Plain words for the failures people actually meet.
pub fn explain(stderr: &str, login: &Login, known_hosts: &Path) -> Option<String> {
    let s = stderr.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| s.contains(n));
    let (target, host) = (login.target(), login.host());
    Some(if has(&["identification has changed", "host key verification failed"]) {
        format!("The SSH host key of {host} isn't the one you trusted. If you rebuilt that server, delete its line from {} and try again; otherwise someone may be intercepting the connection.", known_hosts.display())
    } else if has(&["a password is required", "a terminal is required", "no tty present"]) {
        format!("{} has to type a password for sudo, and nobody is there to do it. Log in as root instead, or let that user run sudo without a password.", login.user)
    } else if has(&["permission denied"]) {
        format!("The server didn't accept your SSH key, and this app can't type a password for you. Make `ssh {target}` log in without asking for one (put your public key in ~/.ssh/authorized_keys on the server, and load a passphrase-protected key into ssh-agent), or use \"Show the commands\" and run the install yourself.")
    } else if has(&["could not resolve hostname", "name or service not known", "no such host is known"]) {
        format!("Couldn't find a machine called {host}. Check the name or address.")
    } else if has(&["banner exchange", "connection closed by", "connection reset", "kex_exchange_identification"]) {
        format!("Something at {host} answered on port 22 and then hung up before SSH could start. Check that SSH is running there, and that a firewall or a tool like fail2ban isn't turning this PC away.")
    } else if has(&["timed out", "connection refused", "no route to host", "network is unreachable"]) {
        format!("Couldn't reach {host} on SSH (port 22). Check the address, that SSH is running there, and that no firewall is blocking it.")
    } else {
        return None;
    })
}

// ---- reading what a server sends -------------------------------------------------------------------

/// Host key algorithms in the order to prefer them.
const KEY_KINDS: [&str; 5] = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"];

/// The best key in a `known_hosts` file the server's answer was written to, as `(algorithm, base64 key)`.
/// This is network input: only
/// a known algorithm and plain base64 get through, so a hostile answer can't put anything else
/// into the `known_hosts` file.
fn parse_scan(stdout: &str) -> Option<(String, String)> {
    stdout
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (_host, kind, blob, rest) = (f.next()?, f.next()?, f.next()?, f.next());
            let blob_ok = (20..=2048).contains(&blob.len()) && blob.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='));
            (rest.is_none() && blob_ok).then_some(())?;
            let rank = KEY_KINDS.iter().position(|k| *k == kind)?;
            Some((rank, kind.to_string(), blob.to_string()))
        })
        .min_by_key(|(rank, ..)| *rank)
        .map(|(_, kind, blob)| (kind, blob))
}

fn algorithm_name(kind: &str) -> String {
    match kind {
        "ssh-ed25519" => "ED25519",
        "ssh-rsa" => "RSA",
        "ecdsa-sha2-nistp256" => "ECDSA (P-256)",
        "ecdsa-sha2-nistp384" => "ECDSA (P-384)",
        "ecdsa-sha2-nistp521" => "ECDSA (P-521)",
        other => other,
    }
    .to_string()
}

/// `256 SHA256:abc... host (ED25519)` → `SHA256:abc...`.
fn parse_fingerprint(keygen_output: &str) -> Option<String> {
    let f = keygen_output.split_whitespace().nth(1)?;
    let b64 = f.strip_prefix("SHA256:")?;
    (!b64.is_empty() && b64.len() <= 64 && b64.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/'))).then(|| f.to_string())
}

// ---- tunnels ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum State {
    Starting,
    Up,
    Down(String),
}

struct Tunnel {
    local_port: u16,
    state: watch::Receiver<State>,
    stop: Option<oneshot::Sender<()>>,
    task: tauri::async_runtime::JoinHandle<()>,
}

/// The SSH tunnels this app keeps open, one per server. A tunnel stays up (and reconnects when the
/// network drops) until the controller is forgotten or the app quits.
#[derive(Default)]
pub struct Tunnels {
    map: tokio::sync::Mutex<HashMap<(String, u16), Tunnel>>,
}

impl Tunnels {
    /// Make sure the tunnel to `login`'s controller is up and return its local port. `prefer` is the
    /// port it used last time, so the controller keeps the same address (and sign-in) when it is free.
    pub async fn ensure(&self, ssh: &Ssh, login: &Login, remote_port: u16, prefer: Option<u16>) -> Result<u16> {
        let key = (login.target(), remote_port);
        let (mut state, port, fresh) = {
            let mut map = self.map.lock().await;
            match map.get(&key) {
                Some(t) => (t.state.clone(), t.local_port, false),
                None => {
                    let port = pick_port(prefer)?;
                    let (tx, rx) = watch::channel(State::Starting);
                    let (stop, stopped) = oneshot::channel();
                    let task = tauri::async_runtime::spawn(supervise(ssh.clone(), login.clone(), remote_port, port, tx, stopped));
                    map.insert(key.clone(), Tunnel { local_port: port, state: rx.clone(), stop: Some(stop), task });
                    (rx, port, true)
                }
            }
        };
        match wait_until_up(&mut state, Duration::from_secs(30), fresh).await {
            Ok(()) => Ok(port),
            Err(why) => {
                // A tunnel that never worked (wrong key, wrong address) is not worth retrying behind the person's back.
                if fresh {
                    self.stop(&key).await;
                }
                bail!("{why}")
            }
        }
    }

    pub async fn stop_login(&self, login: &str) {
        let keys: Vec<_> = self.map.lock().await.keys().filter(|(l, _)| l == login).cloned().collect();
        for k in keys {
            self.stop(&k).await;
        }
    }

    pub async fn stop_all(&self) {
        let keys: Vec<_> = self.map.lock().await.keys().cloned().collect();
        for k in keys {
            self.stop(&k).await;
        }
    }

    async fn stop(&self, key: &(String, u16)) {
        let tunnel = self.map.lock().await.remove(key);
        if let Some(mut t) = tunnel {
            if let Some(stop) = t.stop.take() {
                let _ = stop.send(());
            }
            let _ = tokio::time::timeout(Duration::from_secs(3), t.task).await;
        }
    }
}

/// A free loopback port: `prefer` if it is free, else any.
fn pick_port(prefer: Option<u16>) -> Result<u16> {
    if let Some(p) = prefer.filter(|p| *p != 0) {
        if std::net::TcpListener::bind(("127.0.0.1", p)).is_ok() {
            return Ok(p);
        }
    }
    let l = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| anyhow!("could not find a free local port for the SSH tunnel: {e}"))?;
    Ok(l.local_addr()?.port())
}

/// Wait for `Up`. A first attempt that goes `Down` has failed; a tunnel that was working and is
/// reconnecting gets the whole time, since it is already trying again.
async fn wait_until_up(state: &mut watch::Receiver<State>, limit: Duration, first_attempt: bool) -> std::result::Result<(), String> {
    let mut last_down = None;
    let wait = async {
        loop {
            match state.borrow_and_update().clone() {
                State::Up => return Ok(()),
                State::Down(why) if first_attempt => return Err(why),
                State::Down(why) => last_down = Some(why),
                State::Starting => {}
            }
            if state.changed().await.is_err() {
                return Err("The SSH tunnel stopped.".to_string());
            }
        }
    };
    let finished = tokio::time::timeout(limit, wait).await;
    match finished {
        Ok(r) => r,
        Err(_) => Err(last_down.unwrap_or_else(|| "The SSH tunnel did not come up in time.".into())),
    }
}

enum Ready {
    Yes,
    Exited,
    TimedOut,
}

/// The tunnel is up once `ssh` has authenticated and is listening on the local port.
async fn wait_ready(child: &mut Child, port: u16) -> Ready {
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
            return Ready::Exited;
        }
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ready::Yes;
        }
        if Instant::now() >= deadline {
            return Ready::TimedOut;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// Keep one tunnel up until told to stop: start `ssh`, report when it is listening, and when it
/// exits start it again after a pause that grows while it keeps failing.
async fn supervise(ssh: Ssh, login: Login, remote_port: u16, local_port: u16, state: watch::Sender<State>, mut stopped: oneshot::Receiver<()>) {
    let mut delay = Duration::from_secs(2);
    loop {
        let _ = state.send(State::Starting);
        let from = ssh.log_len();
        let mut up_at = None;
        let why = match ssh.spawn_tunnel(&login, remote_port, local_port) {
            Err(e) => e.to_string(),
            Ok(mut child) => {
                let ready = tokio::select! {
                    _ = &mut stopped => {
                        let _ = child.kill().await;
                        return;
                    }
                    r = wait_ready(&mut child, local_port) => r,
                };
                match ready {
                    Ready::Yes => {
                        up_at = Some(Instant::now());
                        let _ = state.send(State::Up);
                        tokio::select! {
                            _ = &mut stopped => {
                                let _ = child.kill().await;
                                return;
                            }
                            _ = child.wait() => {}
                        }
                    }
                    Ready::Exited => {}
                    Ready::TimedOut => {
                        let _ = child.kill().await;
                    }
                }
                let said = ssh.log_since(from);
                if said.is_empty() {
                    "ssh stopped without saying why.".to_string()
                } else {
                    explain(&said, &login, &ssh.known_hosts()).unwrap_or(said)
                }
            }
        };
        tracing::warn!("SSH tunnel to {} is down: {why}", login.target());
        let _ = state.send(State::Down(why));
        delay = if up_at.is_some_and(|t| t.elapsed() > Duration::from_secs(30)) { Duration::from_secs(2) } else { (delay * 2).min(Duration::from_secs(30)) };
        tokio::select! {
            _ = &mut stopped => return,
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // GitHub's published ED25519 host key and the fingerprint they publish for it.
    const GITHUB_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    const GITHUB_FP: &str = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU";

    fn login(s: &str) -> Login {
        Login::parse(s).unwrap()
    }

    #[test]
    fn logins_are_checked_and_never_reach_ssh_as_an_option() {
        assert_eq!(login("root@203.0.113.10").target(), "root@203.0.113.10");
        assert_eq!(login(" deploy@Server.Example.com ").target(), "deploy@server.example.com", "the host is lower-cased as ssh does");
        assert_eq!(login("root@2001:db8::1").host(), "2001:db8::1");
        assert_eq!((login("root@h.example.com").sudo(), login("deploy@h.example.com").sudo()), ("", "sudo -n "));
        for bad in [
            "", "root", "@host", "root@", "root@-oProxyCommand=x", "-oProxyCommand=x@host", "Root@host.example.com", "a b@host", "root@host name", "root@host;id", "root@$(id)",
            "root@a.example.com -p 1", "root@h.example.com\nid", "root@h'.example.com", "root@é.example.com", "root@@h.example.com", "root@h..example.com",
        ] {
            assert!(Login::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn every_ssh_is_batch_mode_and_insists_on_the_trusted_key() {
        let ssh = Ssh::new(Path::new(r"C:\Users\Some One\AppData\Roaming\edge-lb"));
        let cmd = ssh.command(&login("root@h.example.com"), &["-N".into()]);
        let args: Vec<String> = cmd.as_std().get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        for want in ["BatchMode=yes", "StrictHostKeyChecking=yes"] {
            assert!(args.iter().any(|a| a == want), "{want} in {args:?}");
        }
        assert!(args.iter().any(|a| a.starts_with("UserKnownHostsFile=") && a.contains("known_hosts") && a.contains("Some One")), "{args:?}");
        assert_eq!(args.last().map(String::as_str), Some("root@h.example.com"), "the target is the last argument");
        assert!(args.iter().position(|a| a == "-N") < args.iter().position(|a| a == "root@h.example.com"));
    }

    #[test]
    fn the_best_key_wins_and_hostile_output_is_ignored() {
        let out = format!("# h:22 SSH-2.0-OpenSSH\nh ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7aaaaaaaaaaaaaaaa\nh {GITHUB_KEY}\nh ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY=\n");
        let (kind, blob) = parse_scan(&out).unwrap();
        assert_eq!((kind.as_str(), blob.as_str()), ("ssh-ed25519", &GITHUB_KEY["ssh-ed25519 ".len()..]));
        assert_eq!(parse_scan("h ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7aaaaaaaaaaaaaaaa\n").unwrap().0, "ssh-rsa");
        for bad in [
            "",
            "# only a comment\n",
            "h ssh-dss AAAAB3NzaC1kc3MAAACBAPaaaaaaaaaaaaaaaaaaaa\n",
            "h ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI;rm -rf\n",
            "h ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMq extra\n",
            "h ssh-ed25519 short\n",
            "h ssh-ed25519\n",
        ] {
            assert_eq!(parse_scan(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn fingerprints_are_read_strictly() {
        assert_eq!(parse_fingerprint(&format!("256 {GITHUB_FP} github.com (ED25519)\n")).as_deref(), Some(GITHUB_FP));
        for bad in ["", "256", "256 MD5:aa:bb host (ED25519)", "256 SHA256: host", "256 SHA256:a;b host", &format!("256 SHA256:{} host", "A".repeat(80))] {
            assert_eq!(parse_fingerprint(bad), None, "{bad:?}");
        }
    }

    /// Needs the OpenSSH client (`ssh-keygen`), like the controller's own Windows tests.
    #[tokio::test]
    async fn the_fingerprint_matches_the_one_the_provider_publishes() {
        let dir = std::env::temp_dir().join(format!("edge-lb-ssh-fp-{}", std::process::id()));
        let ssh = Ssh::new(&dir);
        let fp = ssh.fingerprint(&format!("github.com {GITHUB_KEY}")).await.unwrap();
        assert_eq!(fp, GITHUB_FP);
        assert!(!std::fs::read_dir(dir.join("ssh")).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with("scan-")), "the scratch file is removed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_host_is_known_once_its_line_is_in_the_file() {
        let dir = std::env::temp_dir().join(format!("edge-lb-ssh-trust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ssh = Ssh::new(&dir);
        assert!(!ssh.is_known("github.com").await, "no file yet");
        std::fs::create_dir_all(dir.join("ssh")).unwrap();
        std::fs::write(ssh.known_hosts(), format!("other.example.com {GITHUB_KEY}\ngithub.com {GITHUB_KEY}\n")).unwrap();
        assert!(ssh.is_known("github.com").await);
        assert!(!ssh.is_known("gitlab.com").await);
        // Already trusted: trusting again changes nothing, and needs no network.
        ssh.trust_host(&login("git@github.com"), "SHA256:whatever").await.unwrap();
        assert_eq!(std::fs::read_to_string(ssh.known_hosts()).unwrap().lines().count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn common_failures_get_plain_words() {
        let l = login("deploy@vps.example.com");
        let kh = Path::new("C:/x/known_hosts");
        let say = |s: &str| explain(s, &l, kh).unwrap_or_default();
        assert!(say("deploy@vps.example.com: Permission denied (publickey).").contains("authorized_keys"));
        assert!(say("sudo: a password is required").contains("sudo without a password"));
        assert!(say("sudo: a terminal is required to read the password").contains("sudo"));
        assert!(say("ssh: Could not resolve hostname vps.example.com: No such host is known.").contains("Couldn't find a machine called vps.example.com"));
        assert!(say("ssh: connect to host vps.example.com port 22: Connection timed out").contains("port 22"));
        assert!(say("ssh: connect to host vps.example.com port 22: Connection refused").contains("port 22"));
        assert!(say("banner exchange: Connection to UNKNOWN port -1: Connection refused").contains("hung up"), "refused after connecting is not the same as unreachable");
        assert!(say("kex_exchange_identification: read: Connection reset by peer").contains("hung up"));
        assert!(say("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!").contains("C:/x/known_hosts"));
        assert!(say("No ED25519 host key is known for h and you have requested strict checking.\nHost key verification failed.").contains("trusted"));
        assert_eq!(explain("edge-lb: checksum mismatch", &l, kh), None, "anything else is shown as the server said it");
    }

    #[test]
    fn a_failure_shows_the_servers_words_after_the_advice() {
        let out = Out { status: Some(255), stdout: "==> Getting the programs\n".into(), stderr: "edge-lb: checksum mismatch\n".into() };
        let m = failure("The install didn't finish.", &out, &login("root@h.example.com"), Path::new("kh"));
        assert!(m.starts_with("The install didn't finish.\n\n"), "{m}");
        assert!(m.contains("Getting the programs") && m.ends_with("edge-lb: checksum mismatch"), "{m}");
        let long = Out { status: Some(1), stdout: "x".repeat(5000), stderr: String::new() };
        assert!(failure("h", &long, &login("root@h.example.com"), Path::new("kh")).chars().count() < 1400, "a huge log is cut to its tail");
    }

    #[test]
    fn the_local_port_is_the_preferred_one_only_when_it_is_free() {
        let taken = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let busy = taken.local_addr().unwrap().port();
        let got = pick_port(Some(busy)).unwrap();
        assert_ne!(got, busy);
        drop(taken);
        assert_eq!(pick_port(Some(busy)).unwrap(), busy, "free again");
        assert_ne!(pick_port(None).unwrap(), 0);
        assert_ne!(pick_port(Some(0)).unwrap(), 0);
    }

    #[tokio::test]
    async fn waiting_for_a_tunnel_tells_a_first_failure_from_a_reconnect() {
        let (tx, mut rx) = watch::channel(State::Starting);
        let t = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            t.send(State::Down("Permission denied".into())).unwrap();
        });
        assert_eq!(wait_until_up(&mut rx, Duration::from_secs(5), true).await, Err("Permission denied".into()));

        // A tunnel that is reconnecting is waited for.
        let (tx, mut rx) = watch::channel(State::Down("dropped".into()));
        let t = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            t.send(State::Starting).unwrap();
            t.send(State::Up).unwrap();
        });
        assert_eq!(wait_until_up(&mut rx, Duration::from_secs(5), false).await, Ok(()));

        // ...but not forever, and the last reason is what is reported.
        let (_tx, mut rx) = watch::channel(State::Down("still down".into()));
        assert_eq!(wait_until_up(&mut rx, Duration::from_millis(80), false).await, Err("still down".into()));
        let (_tx, mut rx) = watch::channel(State::Starting);
        assert!(wait_until_up(&mut rx, Duration::from_millis(80), true).await.unwrap_err().contains("in time"));
    }
}
