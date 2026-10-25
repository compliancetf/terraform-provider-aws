terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

variable "size" {
  type    = number
  default = 5
}

# Names starting with drift- make the fake upstream apply size + 1.
resource "fake_thing" "c" {
  name = "drift-create"
  size = 10
}

resource "fake_thing" "u" {
  name = "drift-update"
  size = var.size
}
