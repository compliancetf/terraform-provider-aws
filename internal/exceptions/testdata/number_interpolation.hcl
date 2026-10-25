exception "loop" {
  controls      = ["rds_db_instance_encryption_at_rest_enabled"]
  match         = "type == 'aws_db_instance' && resource.identifier == 'db1'"
  workspace = "bobthecorp-reporting-prod"
  reason    = "${1e100000000}"
  expires   = "2027-01-01"
}
