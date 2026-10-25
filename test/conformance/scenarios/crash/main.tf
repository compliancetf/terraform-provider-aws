terraform {
  required_providers {
    fake = {
      source = "registry.compliance.tf/compliancetf/aws"
    }
  }
}

variable "crash" {
  type    = bool
  default = false
}

# crash = true makes the fake upstream panic inside ApplyResourceChange.
resource "fake_thing" "a" {
  name  = "bobthecorp-a"
  crash = var.crash
}
