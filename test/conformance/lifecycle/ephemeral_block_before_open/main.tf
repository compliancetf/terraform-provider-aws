terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

variable "secret_name" {
  type    = string
  default = "bobthecorp-blocked"
}

# fake_secret_name_allowed denies this name, so OpenEphemeralResource is
# blocked before the proxy forwards it: the secret is never opened.
ephemeral "fake_secret" "s" {
  name = var.secret_name
}
