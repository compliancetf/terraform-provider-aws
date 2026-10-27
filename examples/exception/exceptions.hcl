# compliance.tf self-service exceptions (exceptions_file)
#
# Each exception block waives one or more controls for the resources its
# match selects. The file is not signed: an entry counts only when the
# signed org profile (profile.json) allows self-service exceptions for each
# of its controls, its workspace is the workspace the profile trusts, and it
# expires within the profile's max_lifetime_days. README.md lists every
# attribute and the CEL variables match can use.
#
# Values are literal strings or lists of strings: no references, functions
# or interpolation.

# 1. One control, selected by an attribute value, limited to one environment.
exception "dev-db-unencrypted" {
  controls     = ["rds_db_instance_encryption_at_rest_enabled"]
  match        = "type == 'aws_db_instance' && resource.identifier.matches('^dev-')"
  workspace    = "bobthecorp-dev"
  environments = ["dev"]
  reason       = "Throwaway dev database with synthetic data"
  ticket       = "PLAT-101"
  expires      = "2026-12-31"
}

# 2. Several controls in one entry. config is the configuration as written;
#    use it to select on arguments you set (resource also holds computed
#    values, known or unknown at plan).
exception "reporting-replica-restore" {
  controls = [
    "rds_db_instance_encryption_at_rest_enabled",
    "rds_db_instance_backup_retention_period_less_than_7",
  ]
  match     = "type == 'aws_db_instance' && config.identifier == 'dev-reporting-restore'"
  workspace = "bobthecorp-dev"
  reason    = "Restored from an unencrypted snapshot for a one-off data check; deleted after the check"
  ticket    = "PLAT-117"
  expires   = "2026-11-15"
}

# 3. Select by tag. Guard optional maps with != null: a missing value is
#    an error, and an error waives nothing.
exception "scratch-volumes" {
  controls  = ["ebs_attached_volume_encryption_enabled"]
  match     = "type == 'aws_ebs_volume' && config.tags != null && 'purpose' in config.tags && config.tags['purpose'] == 'scratch'"
  workspace = "bobthecorp-dev"
  reason    = "Scratch volumes for load tests hold generated data only"
  ticket    = "PLAT-122"
  expires   = "2026-12-31"
}

# 4. Select by provider settings: provider.region, provider.partition and
#    provider.account_id (known only when the provider block sets exactly
#    one allowed_account_ids entry).
exception "public-docs-site" {
  controls  = ["s3_bucket_restrict_public_read_access"]
  match     = "type == 'aws_s3_bucket' && config.bucket.startsWith('bobthecorp-docs-') && provider.region == 'us-east-1'"
  workspace = "bobthecorp-dev"
  reason    = "Public documentation site served straight from S3"
  ticket    = "WEB-12"
  expires   = "2027-01-20"
}

# 5. Select by operation. op is the operation being checked: create, update,
#    delete or replace. Apply checks each half of a replace under 'replace'
#    and again under its own 'create' or 'delete', so a match that reads op
#    names all three; op == 'replace' alone waives at plan and blocks at
#    apply. This entry waives backup retention for new and replaced
#    instances but not for updates of existing ones.
exception "migration-target-backups" {
  controls  = ["rds_db_instance_backup_retention_period_less_than_7"]
  match     = "type == 'aws_db_instance' && config.identifier == 'dev-migration-target' && op in ['create', 'replace', 'delete']"
  workspace = "bobthecorp-dev"
  reason    = "Backups are enabled after the initial data load"
  ticket    = "PLAT-130"
  expires   = "2026-11-30"
}

# 6. Not applied: environments does not include the current environment
#    (dev, from the profile scope). The entry waives nothing here, without a
#    warning; the same file can serve several environments.
exception "staging-only" {
  controls     = ["ebs_attached_volume_encryption_enabled"]
  match        = "type == 'aws_ebs_volume'"
  workspace    = "bobthecorp-dev"
  environments = ["staging"]
  reason       = "Applies to staging only"
  expires      = "2026-12-31"
}

# 7. Not applied: expired. An expired entry waives nothing and the plan shows
#    a warning that names it. Remove expired entries or renew them.
exception "old-load-test" {
  controls  = ["ebs_attached_volume_encryption_enabled"]
  match     = "type == 'aws_ebs_volume'"
  workspace = "bobthecorp-dev"
  reason    = "Load test in September"
  ticket    = "PLAT-88"
  expires   = "2026-10-01"
}
