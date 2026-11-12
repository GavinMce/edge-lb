locals {
  server_wg_ip = cidrhost(var.wg_network, 1)
  wg_prefix    = split("/", var.wg_network)[1]

  # Everything the edge may route into the tunnel toward the home peer:
  # the peer itself, any LAN behind it, and each backend address.
  home_allowed_ips = distinct(concat(
    ["${var.home_peer.wg_ip}/32"],
    var.home_peer.lan_cidrs,
    [for b in values(var.http_backends) : "${b.address}/32"],
    [for s in values(var.tcp_services) : "${s.address}/32"],
  ))

  hostnames = sort(flatten([for b in values(var.http_backends) : b.hosts]))

  bind_addr = var.enable_ipv6 ? "[::]" : "0.0.0.0"
  bind_opts = var.enable_ipv6 ? " v4v6" : ""

  wg_conf = templatefile("${path.module}/templates/wg0.conf.tftpl", {
    server_wg_ip = local.server_wg_ip
    wg_prefix    = local.wg_prefix
    wg_port      = var.wg_port
    mtu          = var.wg_mtu
    home         = var.home_peer
    home_allowed = local.home_allowed_ips
    extra_peers  = var.extra_peers
  })

  haproxy_cfg = templatefile("${path.module}/templates/haproxy.cfg.tftpl", {
    http_backends = var.http_backends
    tcp_services  = var.tcp_services
    bind_addr     = local.bind_addr
    bind_opts     = local.bind_opts
  })

  nftables_conf = var.firewall_mode == "strict" ? templatefile("${path.module}/templates/nftables.nft.tftpl", {
    wg_interface = var.wg_interface
    wg_port      = var.wg_port
    ssh_port     = var.ssh_port
    tcp_services = var.tcp_services
    ssh_cidrs4   = [for c in var.admin_ssh_cidrs : c if !strcontains(c, ":")]
    ssh_cidrs6   = [for c in var.admin_ssh_cidrs : c if strcontains(c, ":")]
  }) : ""

  install_script = templatefile("${path.module}/templates/install.sh.tftpl", {
    wg_interface  = var.wg_interface
    firewall_mode = var.firewall_mode
    harden_ssh    = var.harden_ssh
    auto_updates  = var.auto_updates
    wg_conf_b64   = base64encode(local.wg_conf)
    haproxy_b64   = base64encode(local.haproxy_cfg)
    nftables_b64  = base64encode(local.nftables_conf)
  })

  required_ports = concat(
    [
      { name = "http", protocol = "tcp", port = 80 },
      { name = "https", protocol = "tcp", port = 443 },
      { name = "wireguard", protocol = "udp", port = var.wg_port },
    ],
    [for name, s in var.tcp_services : { name = name, protocol = "tcp", port = s.listen_port }],
  )
}

check "ssh_reachability" {
  assert {
    condition     = var.firewall_mode != "strict" || length(var.admin_ssh_cidrs) > 0
    error_message = "firewall_mode=strict with no admin_ssh_cidrs closes SSH on the public IP; the machine will only be reachable over the tunnel (and not at all until it is up). Fine for fresh cloud VMs; risky for a machine you are logged into."
  }
}
