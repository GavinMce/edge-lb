variable "public_ip" {
  description = "Address the home gateway dials (the edge machine's public IP or DNS name). Only used to render the home-side config."
  type        = string
}

# --- Host behaviour ----------------------------------------------------------

variable "firewall_mode" {
  description = <<-EOT
    strict: install a default-drop inbound policy in its own nftables table (edge_lb). Use on a dedicated edge machine.
    none:   touch no firewall; you must open the ports listed in output.required_ports yourself.
  EOT
  type        = string
  default     = "strict"

  validation {
    condition     = contains(["strict", "none"], var.firewall_mode)
    error_message = "firewall_mode must be \"strict\" or \"none\"."
  }
}

variable "ssh_port" {
  type    = number
  default = 22
}

variable "admin_ssh_cidrs" {
  description = "CIDRs allowed to SSH to the public IP in strict mode. SSH is always allowed over the tunnel."
  type        = list(string)
  default     = []
}

variable "enable_ipv6" {
  description = "Listen on IPv6 as well as IPv4. Disable on hosts without IPv6."
  type        = bool
  default     = false
}

variable "harden_ssh" {
  description = "Disable SSH password login (drop-in file). Opt-in: make sure key login works first."
  type        = bool
  default     = false
}

variable "auto_updates" {
  description = "Enable unattended security updates (apt: unattended-upgrades, dnf: dnf-automatic)."
  type        = bool
  default     = true
}

# --- WireGuard -----------------------------------------------------------------

variable "wg_interface" {
  description = "Interface name on the edge. Deliberately not wg0, so it won't collide with an existing tunnel."
  type        = string
  default     = "wg-edge"
}

variable "wg_port" {
  type    = number
  default = 51820
}

variable "wg_network" {
  description = "Tunnel network. The edge takes .1; peers choose their own addresses within it. Must not overlap networks the edge host is already attached to."
  type        = string
  default     = "10.100.0.0/24"
}

variable "wg_mtu" {
  description = "Tunnel MTU. 1380 is safe over PPPoE/IPv6 underlays; raise to 1420 once verified."
  type        = number
  default     = 1380
}

variable "home_peer" {
  description = "The home gateway. public_key is generated on the gateway (never in Terraform). lan_cidrs are extra networks routed behind it."
  type = object({
    public_key = string
    wg_ip      = string
    lan_cidrs  = optional(list(string), [])
  })
}

variable "extra_peers" {
  description = "Other tunnel clients (laptop, phone) that may reach the edge."
  type = map(object({
    public_key = string
    wg_ip      = string
  }))
  default = {}
}

# --- Traffic ---------------------------------------------------------------------

variable "http_backends" {
  description = <<-EOT
    Public web backends reached through the tunnel, routed by TLS SNI (443) and Host header (80).
    TLS is NOT terminated at the edge: the backend (e.g. ingress-nginx + cert-manager) holds the certs.
    proxy_protocol sends PROXY protocol v2 so the backend sees real client IPs; the backend must expect it.
  EOT
  type = map(object({
    hosts          = list(string)
    address        = string
    https_port     = optional(number, 443)
    http_port      = optional(number, 80)
    proxy_protocol = optional(bool, true)
  }))
  default = {}

  validation {
    condition     = length(distinct(flatten([for b in values(var.http_backends) : b.hosts]))) == length(flatten([for b in values(var.http_backends) : b.hosts]))
    error_message = "A hostname may only appear in one http_backend."
  }
}

variable "tcp_services" {
  description = "Raw TCP services forwarded on their own public port (e.g. Minecraft 25565). No inspection."
  type = map(object({
    listen_port    = number
    address        = string
    port           = number
    proxy_protocol = optional(bool, false)
  }))
  default = {}

  validation {
    condition     = !anytrue([for s in values(var.tcp_services) : contains([22, 80, 443, 51820], s.listen_port)])
    error_message = "tcp_services must not use reserved ports 22, 80, 443 or 51820."
  }
}
