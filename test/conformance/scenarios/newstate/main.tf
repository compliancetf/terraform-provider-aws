terraform {
  required_providers {
    fake = {
      source = "registry.compliance.tf/compliancetf/aws"
    }
  }
}

variable "size" {
  type    = number
  default = 1
}

variable "replace_name" {
  type    = string
  default = "bobthecorp-r1"
}

# The fake upstream answers every apply with non-canonical msgpack; the tap
# proves the proxy returned those bytes unchanged.
resource "fake_thing" "a" {
  name = "bobthecorp-a"
  size = var.size
}

# A name change on fake_replace requires replacement: delete plus create.
resource "fake_replace" "r" {
  name = var.replace_name
}
