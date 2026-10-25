terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

# data_sources = "deny" in HCL raises data source enforcement: the deny
# control keeps action deny and the hard_fail profile floor blocks the read.
provider "fake" {
  compliance {
    data_sources = "deny"
  }
}

# lookup_name_bobthecorp (deny, configured) fails on this query name.
data "fake_lookup" "other" {
  name = "other-db"
}
