exception "at" {
  controls      = ["rds_db_instance_encryption_at_rest_enabled"]
  match         = "type == 'aws_db_instance' && resource.identifier == 'db1'"
  workspace = "other@workspace"
  reason    = "at"
  expires   = "2027-01-01"
}
