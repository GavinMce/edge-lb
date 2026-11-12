# Installs edge-lb on ANY existing Linux machine you can SSH into — a bare-metal box,
# a VM at any provider, a Raspberry Pi. No cloud provider involved.
#
# Re-running with a changed config re-runs the idempotent installer; the WireGuard key
# is preserved. Prefer no Terraform at all? `terraform output -raw install_script | ssh host sudo sh`.

terraform {
  required_version = ">= 1.7"
}

variable "host" {
  description = "Hostname or IP to SSH to."
  type        = string
}

variable "ssh_user" {
  description = "A root login, or a user with passwordless sudo."
  type        = string
  default     = "root"
}

variable "ssh_port" {
  type    = number
  default = 22
}

variable "ssh_private_key" {
  description = "PEM contents of a private key. Leave null to use your ssh-agent (recommended; keeps the key out of state/plan)."
  type        = string
  default     = null
  sensitive   = true
}

variable "install_script" {
  description = "module.core.install_script."
  type        = string
}

resource "terraform_data" "install" {
  triggers_replace = [sha256(var.install_script)]

  connection {
    type        = "ssh"
    host        = var.host
    user        = var.ssh_user
    port        = var.ssh_port
    private_key = var.ssh_private_key
    agent       = var.ssh_private_key == null
  }

  provisioner "file" {
    content     = var.install_script
    destination = "/tmp/edge-lb-install.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "if [ \"$(id -u)\" -eq 0 ]; then sh /tmp/edge-lb-install.sh; else sudo sh /tmp/edge-lb-install.sh; fi",
      "rm -f /tmp/edge-lb-install.sh",
    ]
  }
}

output "installed" {
  value = terraform_data.install.id
}
