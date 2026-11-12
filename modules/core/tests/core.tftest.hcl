# Offline tests: the core module has no providers, so these run with no mocks.

variables {
  public_ip = "203.0.113.10"
  home_peer = {
    public_key = "HOMEPUBKEY="
    wg_ip      = "10.100.0.2"
  }
  http_backends = {
    cluster = {
      hosts   = ["example.com", "www.example.com"]
      address = "192.168.1.50"
    }
  }
  tcp_services = {
    minecraft = { listen_port = 25565, address = "192.168.1.60", port = 25565 }
  }
  admin_ssh_cidrs = ["198.51.100.1/32"]
}

run "renders_sni_routing" {
  command = plan

  assert {
    condition     = strcontains(output.haproxy_cfg, "use_backend https_cluster if { req_ssl_sni -i example.com }")
    error_message = "SNI routing rule missing"
  }
  assert {
    condition     = strcontains(output.haproxy_cfg, "server home 192.168.1.50:443 send-proxy-v2 check-send-proxy")
    error_message = "PROXY protocol v2 not enabled on https backend"
  }
  assert {
    condition     = strcontains(output.haproxy_cfg, "bind 0.0.0.0:25565")
    error_message = "TCP service listener missing (IPv4-only by default)"
  }
}

run "ipv6_is_opt_in" {
  command = plan
  variables {
    enable_ipv6 = true
  }

  assert {
    condition     = strcontains(output.haproxy_cfg, "bind [::]:443 v4v6")
    error_message = "enable_ipv6 should bind dual-stack"
  }
}

run "wireguard_routes_backends" {
  command = plan

  assert {
    condition     = strcontains(output.wg_conf, "AllowedIPs = 10.100.0.2/32, 192.168.1.50/32, 192.168.1.60/32")
    error_message = "Backends must be in the home peer's AllowedIPs or traffic won't enter the tunnel"
  }
  assert {
    condition     = strcontains(output.wg_conf, "__PRIVATE_KEY__")
    error_message = "Private key must be a placeholder, never rendered by Terraform"
  }
}

run "strict_firewall_is_scoped" {
  command = plan

  assert {
    condition     = strcontains(output.nftables_conf, "policy drop") && strcontains(output.nftables_conf, "table inet edge_lb")
    error_message = "Default-drop policy in the edge_lb table missing"
  }
  assert {
    condition     = !strcontains(output.nftables_conf, "flush ruleset")
    error_message = "Must never flush the host's whole ruleset"
  }
  assert {
    condition     = strcontains(output.nftables_conf, "ip saddr { 198.51.100.1/32 } tcp dport 22 accept")
    error_message = "Admin SSH CIDR rule missing"
  }
  assert {
    condition     = strcontains(output.nftables_conf, "iifname \"wg-edge\"")
    error_message = "Tunnel SSH rule should use the configured interface"
  }
}

run "firewall_none_installs_no_rules" {
  command = plan
  variables {
    firewall_mode = "none"
  }

  assert {
    condition     = output.nftables_conf == ""
    error_message = "firewall_mode=none must render no ruleset"
  }
  assert {
    condition     = strcontains(output.install_script, "FIREWALL='none'")
    error_message = "installer should know the firewall mode"
  }
}

run "custom_interface" {
  command = plan
  variables {
    wg_interface = "tun-edge"
  }

  assert {
    condition     = strcontains(output.install_script, "IFACE='tun-edge'") && strcontains(output.install_script, "After=wg-quick@tun-edge.service")
    error_message = "interface name must flow into the installer"
  }
}

run "required_ports_cover_services" {
  command = plan

  assert {
    condition     = length(output.required_ports) == 4 && anytrue([for p in output.required_ports : p.port == 25565])
    error_message = "required_ports should list 80, 443, wg, and each tcp service"
  }
}

run "rejects_duplicate_hosts" {
  command = plan
  variables {
    http_backends = {
      a = { hosts = ["dup.example.com"], address = "192.168.1.50" }
      b = { hosts = ["dup.example.com"], address = "192.168.1.51" }
    }
  }
  expect_failures = [var.http_backends]
}

run "rejects_reserved_tcp_port" {
  command = plan
  variables {
    tcp_services = {
      bad = { listen_port = 443, address = "192.168.1.60", port = 25565 }
    }
  }
  expect_failures = [var.tcp_services]
}
