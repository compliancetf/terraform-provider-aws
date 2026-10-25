# compliance.tf self-service exceptions (exceptions_file)
#
# An unsigned file. An entry counts only when the signed org profile lists
# its controls under exceptions.self_service (and as coverable for
# self_service), its workspace is the trusted workspace from the profile
# scope, and its expiry is a date within exceptions.max_lifetime_days.
#
#   controls       control ids to waive
#   match          CEL selector; the entry applies where it is true. Variables:
#                  type (resource type), resource, config, prior, op, env,
#                  provider. Unknown at plan: not applied, retried at apply.
#                  A match reading op must hold under every op apply checks:
#                  each replace half also runs as create or delete, so name
#                  them (op in ['replace', 'create', 'delete']) or read no op.
#                  op == 'replace' alone waives at plan (with a warning) and
#                  blocks at apply.
#   workspace      trusted workspace the entry applies to
#   environments   environments the entry applies to (optional)
#   reason         justification
#   ticket         issue tracker reference (optional)
#   expires        YYYY-MM-DD, in the future
#
# A waived violation is still recorded in the evidence chain, with the
# entry label, its workspace and expiry, and the sha256 of this file. The
# reason and ticket stay in this file: keep it with the audit trail.

exception "dev-db-unencrypted" {
  controls     = ["rds_db_instance_encryption_at_rest_enabled"]
  match        = "type == 'aws_db_instance' && resource.identifier.matches('^dev-')"
  workspace    = "bobthecorp-dev"
  environments = ["dev"]
  reason       = "Throwaway dev database with synthetic data"
  ticket       = "PLAT-101"
  expires      = "2026-12-31"
}
