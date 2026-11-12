terraform {
  required_version = ">= 1.7"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

variable "zone_id" {
  type = string
}

variable "hostnames" {
  description = "Fully-qualified names to point at the edge."
  type        = list(string)
}

variable "ipv4" {
  type = string
}

variable "ipv6" {
  type    = string
  default = null
}

variable "ttl" {
  type    = number
  default = 300
}

# proxied = false is essential: orange-cloud would terminate TLS at Cloudflare
# and defeat L4 passthrough.
resource "cloudflare_dns_record" "a" {
  for_each = toset(var.hostnames)

  zone_id = var.zone_id
  name    = each.value
  type    = "A"
  content = var.ipv4
  ttl     = var.ttl
  proxied = false
}

resource "cloudflare_dns_record" "aaaa" {
  for_each = var.ipv6 == null ? toset([]) : toset(var.hostnames)

  zone_id = var.zone_id
  name    = each.value
  type    = "AAAA"
  content = var.ipv6
  ttl     = var.ttl
  proxied = false
}
