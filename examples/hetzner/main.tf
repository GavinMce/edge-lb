terraform {
  required_version = ">= 1.7"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.49"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

# Credentials come from the environment, never from files:
#   export HCLOUD_TOKEN=...
#   export CLOUDFLARE_API_TOKEN=...
provider "hcloud" {}
provider "cloudflare" {}

variable "ssh_public_key" { type = string }
variable "cloudflare_zone_id" { type = string }
variable "home_public_key" { type = string }
variable "ingress_ip" {
  description = "Home-network IP of your ingress controller (e.g. a MetalLB address)."
  type        = string
}
variable "blog_hosts" {
  type    = list(string)
  default = ["example.com", "www.example.com"]
}
variable "admin_ssh_cidrs" {
  type    = list(string)
  default = []
}

# What the edge does — identical on every provider.
module "edge" {
  source = "../../modules/core"

  public_ip       = module.host.ipv4
  enable_ipv6     = true
  harden_ssh      = true
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

  # tcp_services = {
  #   minecraft = { listen_port = 25565, address = "192.168.1.60", port = 25565 }
  # }
}

# Where it runs — swap this module to change provider.
module "host" {
  source = "../../modules/hetzner"

  ssh_public_key  = var.ssh_public_key
  install_script  = module.edge.install_script
  ports           = module.edge.required_ports
  admin_ssh_cidrs = var.admin_ssh_cidrs
}

module "dns" {
  source = "../../modules/dns"

  zone_id   = var.cloudflare_zone_id
  hostnames = module.edge.hostnames
  ipv4      = module.host.ipv4
  ipv6      = module.host.ipv6
}

output "ipv4" { value = module.host.ipv4 }
output "fetch_server_pubkey_command" { value = module.edge.fetch_server_pubkey_command }
output "home_wg_conf" { value = module.edge.home_wg_conf }
