exception "alias" {
  controls      = ["CKV_AWS_16", "CKV_AWS_999"]
  match         = "type == 'aws_db_instance' && resource.storage_encrypted == false"
  workspace = "bobthecorp-reporting-prod"
  reason    = "Encrypted copy in progress"
  expires   = "2027-01-01"
}
