# edge-lb

> **New:** [`service/`](service/README.md) is a Rust controller + web UI that creates, runs and
> destroys a fleet of edges (Hetzner or any machine you can SSH into) and manages routes across
> them. The Terraform modules below are the original single-edge setup and remain usable.

A tiny self-hosted edge load balancer: a public Linux machine that forwards TLS and TCP
traffic over WireGuard to a home network or Kubernetes cluster. Your home IP is never
exposed, no router ports are opened, and CGNAT doesn't matter.

```
Internet ─► DNS ─► edge machine (HAProxy, nftables) ══ WireGuard ══► home gateway ─► ingress ─► cluster
                   :80 :443 :udp/51820                               (dials OUT)
```

## Works on any Linux machine

The whole setup is one idempotent, provider-independent `install.sh`, rendered by
`modules/core`. It needs only a **systemd** Linux with **apt or dnf** and WireGuard in
the kernel (any mainstream distro since ~2020). Delivering it to a machine is a separate,
swappable concern:

| How | Use when |
|---|---|
| `modules/hetzner` | You want Terraform to create the VPS too (cloud-init runs the script at first boot) |
| `modules/ssh-host` | You have a machine already — bare metal, a VM anywhere, a Pi |
| `terraform output -raw install_script \| ssh root@host sh` | No provider module at all |

Adding another provider is ~40 lines: create a server, pass `module.core.install_script`
as its user-data, and open `module.core.required_ports`.

Tested by running the installer in systemd containers on **Debian 12** and **Fedora 44**
(fresh install, re-run for idempotency, switching firewall modes). Not tested: Ubuntu,
RHEL/Alma/Rocky with SELinux enforcing, real cloud boots, and the Terraform providers
(`hcloud`, `cloudflare`) against live APIs.

## Design

- **L4 passthrough.** `:443` is routed by TLS SNI and TLS is never terminated at the edge,
  so a compromised edge can't read traffic or steal certificates. Certs live in the
  cluster (cert-manager). Non-HTTP TCP (e.g. Minecraft) can share the same edge.
- **PROXY protocol v2** carries the real client IP to the backend.
- **Home dials out** (`PersistentKeepalive`), so the edge is the WireGuard hub.
- **Keys never touch Terraform state.** The edge generates its own key; the home gateway
  generates its own. Terraform only sees public keys.
- **Safe on machines you care about.** Its WireGuard interface is `wg-edge` (not `wg0`),
  its firewall lives in its own nftables table (never `flush ruleset`), and configs are
  validated (`haproxy -c`, `nft -c`) *before* anything is changed.
- **Idempotent.** Re-running only touches what changed: HAProxy is reloaded, not
  restarted, and the WireGuard key is preserved.

## Layout

```
modules/core        Provider-free: renders install.sh + configs. All the logic.
modules/hetzner     Hetzner server + cloud firewall + stable IPs
modules/ssh-host    Run the installer on an existing machine over SSH
modules/dns         Cloudflare A/AAAA records (DNS-only: orange-cloud would break passthrough)
examples/hetzner    core + hetzner + dns
examples/existing-host   core + ssh-host
modules/core/tests  Offline `terraform test` suite (no mocks needed)
```

## Quickstart

```sh
# 1. On the home gateway (small LXC/VM on the LAN): generate its key.
wg genkey | tee /etc/wireguard/private.key | wg pubkey     # -> home_public_key

# 2a. New Hetzner VPS:
export HCLOUD_TOKEN=... CLOUDFLARE_API_TOKEN=...
cd examples/hetzner
# 2b. ...or an existing machine:
cd examples/existing-host

cp terraform.tfvars.example terraform.tfvars   # (hetzner example) edit it
terraform init && terraform apply

# 3. Fetch the edge's public key (generated on the machine).
$(terraform output -raw fetch_server_pubkey_command)

# 4. Print the gateway config, fill <HOME_PRIVATE_KEY>, <SERVER_PUBLIC_KEY>,
#    <LAN_INTERFACE>, install as /etc/wireguard/wg0.conf, enable wg-quick@wg0.
terraform output -raw home_wg_conf

# 5. Verify.
ssh root@<edge-ip> wg show wg-edge   # latest handshake should be recent
curl -v https://example.com
```

## Firewall modes

| `firewall_mode` | Behaviour |
|---|---|
| `strict` (default) | Default-drop inbound in table `inet edge_lb`; allows 80/443, WireGuard, your `tcp_services`, and SSH from the tunnel + `admin_ssh_cidrs`. For a **dedicated** edge machine. |
| `none` | Touches no firewall. Open `module.core.required_ports` yourself. Use this on a machine that does other things. |

With `strict` and empty `admin_ssh_cidrs`, SSH on the public IP is closed (a plan-time
`check` warns you). That is intended for fresh cloud VMs — after the first boot you reach
the machine over the tunnel at `10.100.0.1`.

## Cluster side (ingress-nginx)

The edge sends PROXY protocol, so the ingress must expect it:

```yaml
controller:
  config:
    use-proxy-protocol: "true"
```

Anything that connects to the ingress without PROXY protocol (including in-cluster
clients that hit the LB IP) will fail. Give those a separate path. For certificates use
cert-manager; DNS-01 works regardless, and HTTP-01 works because port 80 is routed too.

## Gotchas

- **MTU.** WireGuard defaults to 1420; behind PPPoE or IPv6 underlays that can stall large
  responses while small ones work. This module defaults to 1380.
- **Masquerade on the gateway.** The edge connects from its tunnel address, so LAN hosts
  would reply via your router. The generated home config masquerades tunnel traffic.
- **`AllowedIPs` is the routing table.** Every backend address must be covered by the home
  peer's `AllowedIPs`; the module derives this from your backends. Keep `wg_network` and
  your backend addresses from overlapping networks the edge host itself is attached to.
- **Replacing the server regenerates its WireGuard key.** Re-run steps 3–4 afterwards.
- **SELinux (RHEL family).** The installer sets `haproxy_connect_any`. Custom
  `tcp_services` ports may additionally need `semanage port -a -t http_port_t -p tcp <port>`.
- **dnf5 (Fedora 41+) automatic updates** need manual config; the installer warns.
- **Containers/LXC** often lack WireGuard; the installer detects this and stops early.
- **Single edge = single point of failure.** Mitigate with a second edge and two A records.
- **user-data limits.** Cloud providers cap user-data (Hetzner 32 KiB, AWS 16 KB); the
  script embeds your configs, so huge backend lists need the `ssh-host` or pipe method.

## Testing

```sh
cd modules/core && terraform init -backend=false && terraform test
```

The tests render the HAProxy/WireGuard/nftables configs and the installer, and assert on
routing, `AllowedIPs`, the scoped firewall, interface naming and input validation.
Separately, the rendered installer was executed end-to-end in systemd containers (see above).
