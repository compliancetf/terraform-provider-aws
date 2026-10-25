exception "multi-env" {
  controls     = ["CKV_AWS_18", "s3_bucket_logging_enabled", "s3_bucket_versioning_enabled"]
  match        = "type == 'aws_s3_bucket' && resource.bucket.startsWith('bobthecorp-logs-')"
  workspace    = "bobthecorp-reporting-prod"
  environments = ["dev", "prod", "staging"]
  reason       = "A different reason and ticket leave the digest unchanged"
  ticket       = "OPS-1"
  expires      = "2027-06-30"
}
