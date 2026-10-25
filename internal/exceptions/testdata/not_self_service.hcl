exception "kms" {
  controls      = ["rds_instance_kms_key_configured"]
  match         = "type == 'aws_db_instance' && resource.identifier == 'db1'"
  workspace = "bobthecorp-reporting-prod"
  reason    = "No CMK yet"
  expires   = "2027-01-01"
}
