# edge-lb service

One binary, three modes:

| Mode | What it is |
|---|---|
| `controller` | Web UI + API. Creates and destroys edge machines, installs the edge on them, pushes routes, publishes DNS. Runs anywhere (Docker, a Pi, a VPS, your laptop) — no cluster required. |
| `edge` | The data plane, installed on each public machine **by the controller**. Proxies TCP, routes by domain. Keeps serving from its last config if the controller goes away. |
| `standalone` | Single machine: proxy and a simple route UI together. No controller. |

A **route** is `(domain, listen ip:port) → targets (ip:port)`. The domain is read from the first bytes of
the connection — **TLS SNI**, **HTTP `Host`**, or the **Minecraft handshake address** — and nothing is
terminated or decrypted. One port can serve many names, and non-HTTP protocols work too. Routes run on
**all edges** or on **selected edges**.

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
- Each edge exposes its mTLS management port publicly. To narrow it further, restrict that port to the
  controller's IP in your provider's firewall.

## HTTP API

Sign in (`POST /api/login`), then send the cookie plus `X-EdgeLB: 1`.

| | |
|---|---|
| `GET /api/status` | edges (with live status), routes, DNS state |
| `GET/POST /api/edges` · `DELETE /api/edges/{id}[?force=true]` · `POST …/{id}/retry` · `POST …/{id}/forget` | |
| `GET /api/catalog` | Hetzner locations and server types (+ prices) |
| `GET/POST /api/routes` · `PUT/DELETE /api/routes/{id}` | route + `"edges": [...]` scope (empty = all) |
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

`cargo test` — **71 tests**: unit, protocol sniffing, the proxy over real sockets, the mTLS channel, the
HTTP APIs, and the fleet lifecycle (mock Hetzner + Cloudflare, real controller, real edges, real traffic:
create, serve, outage, recovery, drain, delete, DNS fail-static, crash-safe adoption, restart resume).
The SSH bootstrap runs the **real binary** through the real script with a stub `ssh`.

Also verified by hand, outside `cargo test`:
- **Real Debian 12** container with **systemd, real `sshd`, a non-root user with `sudo`**: the controller
  adopted it, installed the static binary, pinned its identity, served a route on port 80 through the
  unprivileged service, survived service and controller restarts, and uninstalled cleanly.
- Real TLS clients (curl/OpenSSL) through SNI routing; the UI in headless Chromium (setup, Hetzner flow,
  routes, delete safeguards, markup-injection attempt, phone layout, light/dark).
- A glibc build prints `GLIBC_2.39 not found` on Debian 12; the static build runs cleanly.

**Not exercised:** the Hetzner and Cloudflare clients against the *live* APIs (they're tested against mocks
that follow the documented API), other distros (Ubuntu, Fedora, RHEL/SELinux), and IPv6 management.

## Not done yet

- **Managed WireGuard gateway** for origins behind CGNAT. For now an edge reaches targets directly, so they
  must be reachable *from the edge* (public IPs, or a network you already run such as Tailscale or a VPC).
- Host firewall management on edges (use the provider firewall or `ufw`); a Hetzner Cloud Firewall option.
- TOTP/2FA; controller high availability (edges keep serving without it); encrypting `controller.json`.
- A GitHub Actions release pipeline and container image (the static build command above is the recipe),
  rolling edge upgrades, more providers (DigitalOcean, Vultr, …), UDP routes, per-region target overrides,
  weighted / least-connections balancing.
