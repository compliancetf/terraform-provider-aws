terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

variable "size" {
  type    = number
  default = 1
}

# size 11 fails fake_thing_size_max: a warning under the profile's soft_fail
# floor proves the profile and the bundle both loaded.
resource "fake_thing" "a" {
  name = "bobthecorp-a"
  size = var.size
}
