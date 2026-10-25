terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

# name holds the policy document iam_policy_no_star_star reads.
# wildcard_principal and catalog_miss are not_evaluable, which takes the fail
# row: an error before apply when the profile floors the control to
# hard_fail, a warning (never pending) under the soft_fail run mode alone.

# A partial-wildcard principal: the normalizer rejects it as AWS does, so
# iam.parse is type_error.
resource "fake_thing" "wildcard_principal" {
  name = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::222222222222:role/*" }, Action = "iam:PassRole", Resource = "*" }]
  })
}

# An action missing from the bundle's iam-actions.json: iam.grants is
# unresolved.
resource "fake_thing" "catalog_miss" {
  name = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::222222222222:role/bobthecorp-app" }, Action = "iam:BobthecorpNoSuchAction", Resource = "*" }]
  })
}
