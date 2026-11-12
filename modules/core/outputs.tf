output "install_script" {
  description = "Idempotent POSIX sh installer. Run as root on any systemd Linux (apt or dnf). Contains no secrets."
  value       = local.install_script
}

output "required_ports" {
  description = "Public ports the edge listens on. Open these in any cloud/provider firewall."
  value       = local.required_ports
}

output "hostnames" {
  description = "All SNI hostnames routed by the edge (feed these to the dns module)."
  value       = local.hostnames
}

output "wg_server_ip" {
  value = local.server_wg_ip
}

output "wg_endpoint" {
  value = "${var.public_ip}:${var.wg_port}"
}

output "fetch_server_pubkey_command" {
  description = "The server key is generated on the machine and never enters Terraform state."
  value       = "ssh root@${var.public_ip} cat /etc/wireguard/${var.wg_interface}.pub"
}

output "home_wg_conf" {
  description = "Install on the home gateway as /etc/wireguard/wg0.conf after filling the placeholders."
  value = templatefile("${path.module}/templates/home-wg0.conf.tftpl", {
    home_wg_ip = var.home_peer.wg_ip
    wg_prefix  = local.wg_prefix
    wg_network = var.wg_network
    mtu        = var.wg_mtu
    endpoint   = "${var.public_ip}:${var.wg_port}"
  })
}

# Rendered configs (no secrets) — for review and `terraform test`.
output "haproxy_cfg" {
  value = local.haproxy_cfg
}

output "wg_conf" {
  value = local.wg_conf
}

output "nftables_conf" {
  value = local.nftables_conf
}
