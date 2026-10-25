terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

# No data_sources anywhere: data source enforcement is advisory, so the
# failing deny control only warns even under the hard_fail profile floor.

# lookup_name_bobthecorp (deny, configured) fails on this query name.
data "fake_lookup" "other" {
  name = "other-db"
}
