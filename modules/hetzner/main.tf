terraform {
  required_version = ">= 1.7"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.49"
    }
  }
}

variable "name" {
  type    = string
  default = "edge"
}

variable "location" {
  description = "Hetzner location (fsn1, nbg1, hel1, ash, hil, sin)."
  type        = string
  default     = "fsn1"
}

variable "server_type" {
  description = "Hetzner server type. cax11 (ARM) is the cheapest; the stack is arch-agnostic."
  type        = string
  default     = "cax11"
}

variable "image" {
  description = "Any apt- or dnf-based image works."
  type        = string
  default     = "ubuntu-24.04"
}

variable "ssh_public_key" {
  type = string
}

variable "install_script" {
  description = "module.core.install_script. Run once at first boot via cloud-init; changing it replaces the server (the IPs are kept)."
  type        = string
}

variable "ports" {
  description = "module.core.required_ports."
  type = list(object({
    name     = string
    protocol = string
    port     = number
  }))
}

variable "ssh_port" {
  type    = number
  default = 22
}

variable "admin_ssh_cidrs" {
  description = "CIDRs allowed to SSH to the public IP (cloud firewall layer)."
  type        = list(string)
  default     = []
}

# Stable addresses: replacing the server keeps the IPs, so DNS never changes.
resource "hcloud_primary_ip" "v4" {
  name        = "${var.name}-v4"
  type        = "ipv4"
  location    = var.location
  auto_delete = false
}

resource "hcloud_primary_ip" "v6" {
  name        = "${var.name}-v6"
  type        = "ipv6"
  location    = var.location
  auto_delete = false
}

resource "hcloud_ssh_key" "admin" {
  name       = "${var.name}-admin"
  public_key = var.ssh_public_key
}

resource "hcloud_firewall" "edge" {
  name = var.name

  # Cloud-level firewall is a second layer; the host's own policy is in install.sh.
  dynamic "rule" {
    for_each = var.ports
    content {
      description = rule.value.name
      direction   = "in"
      protocol    = rule.value.protocol
      port        = tostring(rule.value.port)
      source_ips  = ["0.0.0.0/0", "::/0"]
    }
  }

  dynamic "rule" {
    for_each = length(var.admin_ssh_cidrs) > 0 ? [1] : []
    content {
      description = "ssh (admin)"
      direction   = "in"
      protocol    = "tcp"
      port        = tostring(var.ssh_port)
      source_ips  = var.admin_ssh_cidrs
    }
  }

  rule {
    description = "icmp"
    direction   = "in"
    protocol    = "icmp"
    source_ips  = ["0.0.0.0/0", "::/0"]
  }
}

resource "hcloud_server" "edge" {
  name         = var.name
  image        = var.image
  server_type  = var.server_type
  location     = var.location
  ssh_keys     = [hcloud_ssh_key.admin.id]
  firewall_ids = [hcloud_firewall.edge.id]
  user_data    = var.install_script # a "#!/bin/sh" script: cloud-init runs it as root

  public_net {
    ipv4_enabled = true
    ipv4         = hcloud_primary_ip.v4.id
    ipv6_enabled = true
    ipv6         = hcloud_primary_ip.v6.id
  }

  labels = {
    role = "edge-lb"
  }
}

output "ipv4" {
  value = hcloud_primary_ip.v4.ip_address
}

output "ipv6" {
  description = "First address of the server's /64."
  value       = hcloud_server.edge.ipv6_address
}
