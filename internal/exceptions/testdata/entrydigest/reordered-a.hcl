exception "multi-env" {
  expires      = "2027-06-30"
  environments = ["staging", "prod", "dev"]
  workspace    = "bobthecorp-reporting-prod"
  reason       = "Attributes and lists in another order"
  match        = "type == 'aws_s3_bucket' && resource.bucket.startsWith('bobthecorp-logs-')"
  controls     = ["s3_bucket_versioning_enabled", "s3_bucket_logging_enabled", "CKV_AWS_18"]
}
