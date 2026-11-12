terraform {
  required_version = ">= 1.7"
  # No providers: this module only renders text. Provider modules (hetzner, ssh-host)
  # or your own tooling deliver the resulting install_script to a machine.
}
