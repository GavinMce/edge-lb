# edge-lb service

One binary, three modes:

| Mode | What it is |
|---|---|
| `controller` | Web UI + API. Creates and destroys edge machines, installs the edge on them, pushes routes, publishes DNS. Runs anywhere (Docker, a Pi, a VPS, your laptop) — no cluster required. |
| `edge` | The data plane, installed on each public machine **by the controller**. Proxies TCP, routes by domain. Keeps serving from its last config if the controller goes away. |
| `standalone` | Single machine: proxy and a simple route UI together. No controller. |
| `gateway` | A small machine on a home/private network. Dials out to every edge over WireGuard so edges can reach that network (works behind CGNAT). Installed by one command from the controller. |
| `wg-apply` | Root helper on an edge that applies the WireGuard config the (unprivileged) edge process writes. Installed by the controller; you never run it. |

A **route** is `(domain, listen ip:port) → targets (ip:port)`. The domain is read from the first bytes of
the connection — **TLS SNI**, **HTTP `Host`**, or the **Minecraft handshake address** — and nothing is
terminated or decrypted. One port can serve many names, and non-HTTP protocols work too. Routes run on
**all edges** or on **selected edges**. A route can also say which **site** its targets live in (see
[Reaching a private network](#reaching-a-private-network-managed-wireguard)).

## Quick start (controller)

```sh
# Build a static binary: runs on any Linux (a normal glibc build only runs on equal-or-newer glibc).
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=gcc cargo build --release --target x86_64-unknown-linux-musl
BIN=target/x86_64-unknown-linux-musl/release/edge-lbd      # ~7 MiB, statically linked

$BIN controller --data-dir ./ctl --listen 127.0.0.1:8080
# "FIRST RUN: ... setup code ABCD..." is printed (and written to ./ctl/setup-code).
```

Open <http://127.0.0.1:8080/>, create the admin account with the setup code, then:

1. **Settings → Hetzner Cloud**: paste an API token (read & write). Optionally set up **DNS (Cloudflare)**.
2. **Edges → Add edge**: pick a location and server type (live prices shown), or adopt an existing machine.
3. **Routes → Add route**: choose which edges it runs on.

The controller needs `ssh` and `ssh-keygen` (openssh-client). Machines need systemd and either root or
passwordless `sudo`, and TCP **7443** (management) plus your route ports reachable. To adopt an existing
machine, add the public key shown in *Settings* to its `authorized_keys`.

## Running the controller on a server

On a Linux server with systemd (Debian, Ubuntu, Fedora…), one command installs the controller from a release,
checks its checksum, runs it as its own unprivileged user (`edge-lb`) in a sandboxed service, and prints the
one-time setup code:

```sh
curl -fsSL https://github.com/<owner>/<repo>/releases/latest/download/install-controller.sh | sudo sh -s -- [options]
```

The desktop app's launcher has **Set up a controller on a server**, which fills in the options for you and
writes the exact commands (including how to reach the controller afterwards). Options:

| Option | Meaning |
|---|---|
| *(none)* | UI on `127.0.0.1:8080` of the server. Reach it from your PC through an SSH tunnel: `ssh -N -L 8081:127.0.0.1:8080 user@server`, then connect to `http://127.0.0.1:8081`. Nothing is exposed. |
| `--listen 192.168.1.20:8080` | UI on a private address (LAN, Tailscale). The controller refuses public addresses. The page is plain `http`. |
| `--tls-proxy` | You run a TLS reverse proxy on the server in front of `127.0.0.1:8080` (the installer prints a Caddy example); cookies are marked `Secure`. |
| `--gateway-listen 0.0.0.0:7444 --gateway-host <name-or-ip>` | Accept WireGuard gateways. Open inbound TCP 7444. |
| `--this-arch-only` | Don't also fetch the other CPU's build. By default both are installed so the controller can set up x86_64 and aarch64 edges. |
| `--version TAG`, `--release-base URL`, `--from DIR` | Pin a release, use a mirror, or install local builds. |
| `--uninstall` / `--purge` | Remove it (your data stays unless `--purge`). |

Layout: program `/usr/local/bin/edge-lb-controller`, Linux builds for edges in `/usr/local/lib/edge-lb/agents`,
data in `/var/lib/edge-lb-controller` (mode 0700), unit `edge-lb-controller.service`. Run the command again to
upgrade or change options. The checksum comes from the same release as the download, so it catches corruption
but trusts GitHub and your TLS connection; for anything stricter, build from source and use `--from`.

`deploy/install-controller.sh` is tested by `tests/controller_installer.rs` (the real script in its `--stage`
mode, with a fake release on `file://`), plus a check that OpenSSH works inside the unit's sandbox. Starting
the service as root under real systemd is not covered by an automated test.

## Running the controller on Windows

The controller (and only the controller) builds and runs on Windows. Edges and gateways are Linux machines
the controller installs for you, so the Windows build carries static Linux builds to push:

```
edge-lbd.exe
agents\edge-lbd-x86_64      static Linux builds (musl), one per CPU you want to install on
agents\edge-lbd-aarch64
```

`edge-lbd.exe controller` finds `agents` beside itself (or pass `--agents-dir`). The controller reads each
machine's CPU over SSH and uploads the matching build; a gateway's install command does the same with
`uname -m`. A Linux controller still defaults to pushing a copy of itself (any other CPU needs `agents`).

- **Needs** the Windows OpenSSH client (`ssh`, `ssh-keygen`; included in Windows 10/11, *Optional features*).
- **Data** lives in `%APPDATA%\edge-lb`, restricted to your account. `controller.json` (CA key, provider
  tokens) is encrypted with your Windows login (DPAPI), so a copy is useless on another account or machine.
  The controller's SSH private key is a normal file in `ssh\`; Windows `ssh-keygen` gives it the ACL OpenSSH
  requires (your account, Administrators and SYSTEM).
- **Gateways on your LAN** must reach the controller: turn the listener on in **Settings → Gateways** (the form
  is pre-filled with this PC's LAN address), and allow the Windows Firewall prompt.
- **Tested on Windows 11:** the build, the full test suite, DPAPI, the data-folder ACL, SSH key creation and the
  `ssh` option quoting. **Not yet tested:** adopting or creating a real machine end to end from Windows.

### Desktop app (MSI)

`desktop\` wraps the controller in a [Tauri](https://tauri.app) app (WebView2). It opens a small **launcher**
with two choices:

- **This PC** runs the controller inside the app (the same code as `edge-lbd controller`), serving the normal
  UI on `127.0.0.1:17480` (any free port if that is taken). On the very first run the setup code is filled into
  the form for you (the server still requires it).
- **Another machine** connects to a controller running elsewhere. Saved controllers are listed; a form adds a
  new one. An address is checked (`GET /api/session` must answer like an edge-lb controller) before it is
  saved or shown. `https://` is required, except for private-network addresses (LAN, Tailscale, `127.0.0.1`
  through an SSH tunnel), because the sign-in cookie must not travel unencrypted.

The controller's page then opens in its own window. That window can only show the controller it was opened
for, and it has no access to the app: only the launcher page may call into it. Closing a window hides it to the
tray. The tray menu has **Switch controller…** (back to the launcher) and **Quit**, which stops the local
controller; a local controller keeps running while you look at a remote one. A second launch brings the
existing window forward. Logs go to `%APPDATA%\edge-lb\edge-lb.log`.

Two small files live in `%APPDATA%\edge-lb`:

```toml
# app.toml — edit by hand; the app never writes it. Every key is optional.
startup = "ask"            # "ask" shows the launcher; "local"; or the name of a saved remote
[local]
port = 17480
data_dir = ""              # default: this folder
# Optional: pin the gateway listener here (both keys, or neither). It is then fixed and shows read-only in
# the controller's Settings. Leave them out and turn it on from Settings → Gateways instead.
# gateway_listen = "0.0.0.0:7444"
# gateway_host   = "192.168.1.20"
```

`remotes.toml` is the saved list; the app maintains it (and you may edit it). A mistake in `app.toml` never
stops the app: it falls back to the defaults and says what is wrong, with the line, in the launcher.

```
cd service\desktop
mkdir src-tauri\agents        # then copy edge-lbd-x86_64 / edge-lbd-aarch64 (static Linux builds) into it
npm ci
npx tauri build               # MSI: target\release\bundle\msi\
npx tauri dev                 # run it without bundling
```

The release workflow builds the MSI (`edge-lb-<tag>-windows-x64.msi`) from the musl builds it makes first. It is
unsigned, so Windows SmartScreen will warn on first run.

## Reaching a private network (managed WireGuard)

Edges are public machines; your services often are not (a home server behind CGNAT, a LAN with no open
ports). A **site** is such a network, and its **gateway** is a small machine inside it that makes the
connection *outward*:

```
                       public internet                         |  home network (no ports open)
 client ─► DNS ─► EDGE (reads the domain, never decrypts) ═════ WireGuard ═════ GATEWAY ─► 192.168.1.50:443
                       dials nobody                  tunnel opened BY the gateway   forwards only into
                                                                                    the site's LAN ranges
```

You manage everything from the controller:

1. **Sites & gateways → Add site**: a name and the LAN range(s), e.g. `192.168.1.0/24`. Saving goes straight on
   to step 2.
2. **Connect a gateway**: the UI shows one command. Run it on the gateway machine. It pins the controller's
   certificate, downloads the binary (checksum-verified), installs `wireguard-tools`/`nftables` and a hardened
   systemd unit, generates the gateway's own key, and enrols with a one-time token. The dialog follows the
   gateway live (waiting, enrolled, connected, with how many tunnels are up) and, once connected, offers
   **Add a route through this site**. If the controller isn't listening for gateways yet, the same dialog says
   how to turn that on for how it is run (the desktop app, a server installed with `install-controller.sh`, or a
   plain command line).
3. **Routes → Add route**: pick the **site**, and give targets inside its ranges (`192.168.1.50:443`).

The controller allocates every node a tunnel address (default `10.100.0.0/24`, change it in Settings before
creating sites), exchanges **public** keys, and keeps every edge's and gateway's tunnel config in step as edges
come and go. **Private keys are generated on the machine that uses them and never travel.**

The gateway listener is off by default, so a plain controller exposes nothing extra. Turn it on in
**Settings → Gateways** (the Sites page and the gateway dialog link there, and the dialog carries straight on to the
command): the address to listen on (default `0.0.0.0:7444`) and the host name or IPv4 address gateways dial
(pre-filled with this machine's address on its network). It starts listening at once, with no restart, is saved in
`controller.json`, and comes back after a restart. If the new address can't be bound the old listener keeps running
and the error is shown. Changing the address gateways dial doesn't reach gateways already installed (their command
has the old one): re-enrol them.

Or fix it at startup, which makes it read-only in Settings (and is what the desktop app's `app.toml` keys and the
installer's `--gateway-listen` do):

```sh
edge-lbd controller --listen 127.0.0.1:8080 \
    --gateway-listen 0.0.0.0:7444 --gateway-host ctl.example.com     # host or IPv4 gateways will dial
```

The controller learns how it is run from `EDGE_LB_DEPLOYMENT` (`desktop` or `server`, set by the desktop app and
the installer) and words the firewall reminder accordingly.

Nothing stops the controller running on an edge's VPS (the ports differ: 7443 edge management, 7444 gateways, the UI
on loopback), but that combination hasn't been tested. Open **TCP 7444** (controller, for gateways) and **UDP 51820**
(each edge, for the tunnel) in your provider firewall; the gateway needs only outbound access.

**Requirements.** Gateway: systemd, `curl`, the same CPU architecture as the controller binary, and *kernel*
WireGuard, which means a VM or bare metal. An unprivileged LXC container usually can't create WireGuard
interfaces (the installer checks and says so). Edges: the installer adds `wireguard-tools` itself.

**What the pieces do**

| | |
|---|---|
| Edge | `wg-edge` interface listening on UDP 51820, one peer per site gateway. A tiny root service (`edge-lb-wg`, capabilities `CAP_NET_ADMIN` + `CAP_DAC_READ_SEARCH` only) applies what the edge process writes to `wg.json`, after strict validation. The edge process itself stays unprivileged. |
| Gateway | Peers with every live edge, with `PersistentKeepalive`, so the NAT mapping stays open. Forwards tunnel traffic into the LAN and masquerades it (LAN hosts reply to the gateway, not via your router). |
| Controller | Owns sites, addressing and key exchange; serves enrolment and sync to gateways on the separate TLS listener. |

**Failure behaviour.** The data path never depends on the controller: edges and gateways keep their tunnels if
it goes away, and both restore them after a reboot from saved state. A gateway re-handshakes quickly with an
edge that rebooted (it probes peers with a stale handshake: WireGuard keepalives alone would leave a dead session
for up to 3 minutes). Verified end to end, see below.

**Limits worth knowing**
- IPv4 only. One gateway per site (several sites are fine; two sites can't share addresses).
- Edges installed before WireGuard support have no key and can't reach sites; the UI flags them. Create them anew.
- Gateway host firewall: forwarding is controlled by the gateway's own nftables table (`edge_lb_gw`). A host that
  already drops forwarded traffic elsewhere (e.g. Docker's default policy) needs its own allow rule.
- If a site is deleted while its gateway is running, the gateway keeps its (now one-sided, inert) tunnel until you stop
  its `edge-lb-gateway` service.

## How an edge's life works

```
Creating → WaitingForSsh → Bootstrapping → Joining → Healthy ⇄ Unreachable
                                                       Healthy → Draining → Deleting → (gone)
```

- **Creating:** asks Hetzner for a server, labelled `edge-lb-id=<id>`. If the controller crashes between
  "create" and "remember the id", the label lets it find the server again instead of paying for a second.
- **Bootstrapping:** over SSH it uploads the binary, installs a hardened systemd unit (dynamic user,
  `NoNewPrivileges`, `ProtectSystem=strict`, only `CAP_NET_BIND_SERVICE`), and reads back the edge's
  self-generated identity.
- **Joining/Healthy:** the controller pushes the edge's routes and polls it. Changes apply live;
  existing connections are never dropped.
- **Unreachable:** removed from DNS; comes back by itself when reachable again.
- **Delete:** removed from DNS → drained (default 60 s, or until idle) → server destroyed (Hetzner) or
  edge-lb uninstalled (adopted machine, which is otherwise left alone). Deleting the **last healthy edge**
  needs an explicit acknowledgement. Routes that only ran on a deleted edge are *disabled*, never silently
  widened to every edge.
- **Failed:** shown with the reason. *Retry* resumes; *Delete* destroys any server that was created
  (nothing is left billing); *Forget* drops only the record.
- All progress is persisted, so a controller restart resumes every edge where it was.

## DNS

Names listed in Settings point at **every healthy edge** (Cloudflare, DNS-only — proxying would break TLS
passthrough). Only records edge-lb created (tagged `edge-lb:managed`) are ever changed. With **no**
healthy edge it holds the existing records rather than emptying the answer. Set the drain time ≥ your TTL.

## Security model

- **Controller ⇄ edge** is mutual TLS with a private PKI: the controller owns a CA and signs its own client
  cert; each edge generates its own key and self-signed cert; the controller **pins** that exact certificate.
  An edge only answers the controller; the controller only talks to the edge it enrolled.
  Verified: no client cert, a cert from another CA, a wrong pin, and plain HTTP are all rejected.
- **Admin login:** argon2id password, session cookie (`HttpOnly`, `SameSite=Strict`), a custom
  `X-EdgeLB` header required on every state-changing request (CSRF), lockout after repeated failures,
  and an audit log of who did what. First-run setup needs a **one-time code** from the controller's console,
  so a fresh controller can't be claimed by whoever finds it first.
- **Secrets** (CA key, provider tokens) live in `controller.json` (mode 0600) and are never returned by the
  API. Protect the data dir like a key store and use full-disk encryption.
- **SSH:** host key pinned on first use. Values returned *by* a remote machine are never interpolated into
  the root installer script, and the SSH user is validated (no option injection).
- The UI is three static files under a strict CSP (no inline script/style) and renders data with
  `textContent`. The controller **refuses a non-private bind** unless `--allow-public` (it is plain HTTP:
  put a TLS-terminating proxy in front and pass `--secure-cookies`).
- **Gateways** reach the controller on a separate TLS listener that serves only enrolment and sync (never the
  admin UI or API). It uses a self-signed certificate that gateways **pin**; `curl` pins the key with
  `--pinnedpubkey`, the agent pins the certificate. Enrolment tokens are 256-bit, single-use, expire after an hour, and
  are stored only as hashes; a gateway's long-lived secret is stored as a hash too.
- **Blast radius of a compromised edge**: it can reach only the site's declared LAN ranges. The gateway drops every
  other forwarded packet from the tunnel, and drops everything addressed to the gateway itself except ping.
  A compromised **gateway** can attack its own LAN and see the plaintext of unencrypted traffic to it, which is
  inherent to a gateway; TLS passthrough still protects TLS end to end.
- All WireGuard input that reaches a root process (keys, addresses, ranges) is parsed and re-rendered, never
  interpolated; default routes, loopback, link-local (cloud metadata) and multicast ranges are refused everywhere.
- Each edge exposes its mTLS management port publicly. To narrow it further, restrict that port to the
  controller's IP in your provider's firewall.

## HTTP API

Sign in (`POST /api/login`), then send the cookie plus `X-EdgeLB: 1`.

| | |
|---|---|
| `GET /api/status` | edges (with live status), routes, DNS state |
| `GET/POST /api/edges` · `DELETE /api/edges/{id}[?force=true]` · `POST …/{id}/retry` · `POST …/{id}/forget` | |
| `GET /api/catalog` | Hetzner locations and server types (+ prices) |
| `GET/POST /api/sites` · `PUT/DELETE /api/sites/{id}` · `POST …/{id}/enrol` | sites, and the one-time gateway enrolment command |
| `GET/POST /api/routes` · `PUT/DELETE /api/routes/{id}` | route + `"edges": [...]` scope (empty = all) + `"site"` (targets inside that site) |
| `GET/PUT /api/settings` · `GET /api/ssh-key` · `GET /api/audit` · `POST /api/password` | |

Errors: `401`, `403` (missing header), `404`, `409`, `422` with `{"details": [...]}`, `429` (lockout).

## Standalone mode

```sh
edge-lbd standalone --api 127.0.0.1:9090 --data-dir ./data --token-file ./token
```

A single machine with a token-protected UI/API (refuses a public bind). `deploy/edge-lbd.service` is a
hardened unit for it. Route rules are identical: no duplicate domain per listener, one catch-all per
listener, a wildcard bind can't coexist with a specific address, reserved ports (22, the API port) refused.
A listener with domain routes waits `--peek-timeout-ms` (3 s) for the first bytes; clients that speak first
(SSH, SMTP) are sent to the catch-all after that, so give server-first protocols their own port.

## Tests and what was actually exercised

`cargo test` — **107 tests**: unit, protocol sniffing, the proxy over real sockets, the mTLS channel, the
HTTP APIs, and the fleet lifecycle (mock Hetzner + Cloudflare, real controller, real edges, real traffic:
create, serve, outage, recovery, drain, delete, DNS fail-static, crash-safe adoption, restart resume).
The SSH bootstrap runs the **real binary** through the real script with a stub `ssh`.
`tests/gateway.rs` runs a real controller with its pinned-TLS gateway listener and a real gateway agent (only the
final `wg`/`ip`/`nft` calls are recorded): enrolment single-use/expiry, wrong pin, re-enrolment, sites and route
validation, peer lists following edges as they come and go, and the edge's handling of hostile WireGuard state.

**`tests/e2e/wireguard.sh`** (needs Docker; not part of `cargo test`) exercises the real thing with the kernel's
WireGuard, real systemd and real packets: a controller adopts an edge over SSH, the gateway is installed with the
exact command the UI shows, and a client reaches a LAN-only web server *through the tunnel* (42 checks). It also
checks: the LAN is unreachable any other way; the gateway drops a "compromised" edge's traffic to anything but the
LAN and closes its own services to the tunnel; traffic keeps flowing with the controller down; the tunnel
recovers after the **edge** reboots and after the **gateway** reboots; deleting the site tears the tunnel down.

```sh
CC_x86_64_unknown_linux_musl=gcc cargo build --target x86_64-unknown-linux-musl
tests/e2e/wireguard.sh            # KEEP=1 leaves the containers up for poking around
```

Also verified by hand, outside `cargo test`:
- **Real Debian 12** container with **systemd, real `sshd`, a non-root user with `sudo`**: the controller
  adopted it, installed the static binary, pinned its identity, served a route on port 80 through the
  unprivileged service, survived service and controller restarts, and uninstalled cleanly.
- Real TLS clients (curl/OpenSSL) through SNI routing; the UI in headless Chromium (setup, Hetzner flow,
  routes, delete safeguards, markup-injection attempt, phone layout, light/dark).
- A glibc build prints `GLIBC_2.39 not found` on Debian 12; the static build runs cleanly.

**Not exercised:** the Hetzner and Cloudflare clients against the *live* APIs (they're tested against mocks
that follow the documented API), other distros (Ubuntu, Fedora, RHEL/SELinux), IPv6 management, a gateway behind a
*real* NAT/CGNAT (the e2e test uses separate networks, not translated ones), and the gateway installer on anything but Debian 12.

## Not done yet

- Several gateways per site (failover). Needs an active/standby choice, because two peers can't both own the same
  `AllowedIPs`. IPv6 sites.
- Upgrading edges installed before WireGuard support in place (today: create them anew).
- Host firewall management on edges (use the provider firewall or `ufw`); a Hetzner Cloud Firewall option.
- TOTP/2FA; controller high availability (edges keep serving without it); encrypting `controller.json` on Linux (on Windows it is already encrypted with DPAPI).
- A container image, rolling edge upgrades, more providers (DigitalOcean, Vultr, …), UDP routes, per-region target overrides,
  weighted / least-connections balancing.
