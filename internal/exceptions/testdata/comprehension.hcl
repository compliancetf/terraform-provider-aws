exception "loop" {
  controls      = [for a in ["x", "y"] : "rds_db_instance_encryption_at_rest_enabled"]
  match         = "type == 'aws_db_instance' && resource.identifier == 'db1'"
  workspace = "bobthecorp-reporting-prod"
  reason    = "loop"
  expires   = "2027-01-01"
}
