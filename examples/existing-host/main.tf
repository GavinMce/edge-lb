# Any Linux machine you can SSH into — no cloud provider. DNS is left to you
# (or add modules/dns, or any other DNS module, using module.edge.hostnames).

terraform {
  required_version = ">= 1.7"
}

variable "host" {
  description = "Public IP (or DNS name) of the machine."
  type        = string
}
variable "ssh_user" {
  type    = string
  default = "root"
}
variable "home_public_key" { type = string }
variable "ingress_ip" { type = string }
variable "blog_hosts" {
  type    = list(string)
  default = ["example.com", "www.example.com"]
}
variable "admin_ssh_cidrs" {
  description = "Where you SSH from. Required with firewall_mode=strict, or you will lock yourself out."
  type        = list(string)
  default     = []
}

module "edge" {
  source = "../../modules/core"

  public_ip = var.host

  # This is a machine you already use, so be careful with the firewall:
  #   "strict" = default-drop inbound (own nftables table). Needs admin_ssh_cidrs.
  #   "none"   = touch nothing; open module.edge.required_ports yourself.
  firewall_mode   = "none"
  admin_ssh_cidrs = var.admin_ssh_cidrs

  home_peer = {
    public_key = var.home_public_key
    wg_ip      = "10.100.0.2"
  }

  http_backends = {
    cluster = {
      hosts   = var.blog_hosts
      address = var.ingress_ip
    }
  }
}

module "host" {
  source = "../../modules/ssh-host"

  host           = var.host
  ssh_user       = var.ssh_user
  install_script = module.edge.install_script
}

output "required_ports" { value = module.edge.required_ports }
output "fetch_server_pubkey_command" { value = module.edge.fetch_server_pubkey_command }
output "home_wg_conf" { value = module.edge.home_wg_conf }
output "install_script" { value = module.edge.install_script }
