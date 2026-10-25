terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

# The signed profile sets data_sources deny; a local advisory cannot lower
# it and the read is blocked.
provider "fake" {
  compliance {
    data_sources = "advisory"
  }
}

# lookup_name_bobthecorp (deny, configured) fails on this query name.
data "fake_lookup" "other" {
  name = "other-db"
}
