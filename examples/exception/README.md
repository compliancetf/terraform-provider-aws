# exception

Self-service exceptions: resources that break CIS `deny` controls, waived by entries in `exceptions.hcl`, so `terraform plan` succeeds in `hard_fail` mode. The example also includes two entries that do not apply, one for another environment and one that has expired, to show what happens to those.

An exceptions file counts only together with a **signed org profile** that allows self-service exceptions for the controls. compliance.tf issues that profile for your organization. This example signs `profile.json` with the test key, so it runs with a development build.

## Files

| File | What it is |
|---|---|
| `main.tf` | Five resources, each with a waived violation |
| `exceptions.hcl` | Seven exception entries, numbered and commented |
| `profile.json` | The org profile payload; sign it to get `profile.dsse.json` (ignored by git) |

## Run it

From the repository root:

1. Build the provider with `make build-dev`; this build trusts the test signing key.
2. Write a CLI config whose `dev_overrides` maps `registry.compliance.tf/compliancetf/aws` to the repository root (see [DEVELOPING.md](../../DEVELOPING.md#manual-testing-with-terraform)), and `export TF_CLI_CONFIG_FILE=<that file>`.
3. Point the provider at a `hashicorp/aws` 6.x binary: `export CTFTEST_UPSTREAM_PATH=<path to terraform-provider-aws_v6.x.y_x5>`.
4. Update the dates:
   - In `profile.json`, set `issued_at` to today and `expires_at` at most 30 days later.
   - In `exceptions.hcl`, every `expires` must be in the future and at most `max_lifetime_days` (90) from today. Entry 7 stays in the past on purpose.
5. Sign the profile:

   ```bash
   go run -tags ctftest ./cmd/ctfbundle sign -type profile \
     -in examples/exception/profile.json -key test:profile \
     -out examples/exception/profile.dsse.json
   ```

6. Plan, without `terraform init` (Terraform skips it under `dev_overrides`):

   ```bash
   cd examples/exception
   terraform plan
   ```

## What to expect

`terraform plan` exits 0 and plans 5 resources with no compliance error. Each waiver:

| Resource | Control | Waived by |
|---|---|---|
| `aws_db_instance.dev_db` | `rds_db_instance_encryption_at_rest_enabled` | `dev-db-unencrypted` |
| `aws_db_instance.restore` | `rds_db_instance_encryption_at_rest_enabled` | `dev-db-unencrypted` (also matched by `reporting-replica-restore`) |
| `aws_db_instance.restore` | `rds_db_instance_backup_retention_period_less_than_7` | `reporting-replica-restore` |
| `aws_db_instance.migration_target` | `rds_db_instance_backup_retention_period_less_than_7` | `migration-target-backups` (create only) |
| `aws_ebs_volume.scratch` | `ebs_volume_encryption_at_rest_enabled` | `scratch-volumes` |
| `aws_s3_bucket.docs` | `s3_bucket_restrict_public_read_access` | `public-docs-site` |

Warnings:
- `exception old-load-test: expired at 2026-10-01T00:00:00Z; ebs_volume_encryption_at_rest_enabled enforced` (entry 7).
- The `hashicorp/aws` deprecation warning for `acl`.
- With a development build, `upstream hashicorp/aws 0.0.0-ctftest is outside the upstream version range of bundle cis-aws v1`. This is expected with `CTFTEST_UPSTREAM_PATH`.

Every waived violation is still recorded in `.terraform/compliancetf/evidence/`, with `"state": "fail"`, `"decision": "excepted"` and the entry: its label, source, workspace, expiry, status and a digest of the entry. The reason and ticket stay in `exceptions.hcl`, so keep the file with your audit trail.

**Without a valid signed profile**, for example on a release build with the test-signed profile, the plan warns:
- `Org profile for bobthecorp unavailable: hard_fail floor applied (... key not in keyring)`;
- `exceptions file ignored: no org profile enables self-service exceptions`.

It then fails with every violation as an error.

## Exception entries

```hcl
exception "<label>" {
  controls     = ["<control id>", ...]
  match        = "<CEL expression>"
  workspace    = "<trusted workspace>"
  environments = ["<environment>", ...] # optional
  reason       = "<why>"
  ticket       = "<tracker reference>"  # optional
  expires      = "YYYY-MM-DD"
}
```

| Attribute | Required | Rules |
|---|---|---|
| label | yes | Unique in the file; letters, digits, `_`, `.`, `-`, up to 128 characters, starting with a letter or digit. It names the entry in warnings and evidence. |
| `controls` | yes | 1 to 64 control ids. Each must be in the profile's `exceptions.self_service` list and coverable for `self_service`; any other id is ignored with a warning. |
| `match` | yes | A CEL expression; the entry applies where it is `true`. Variables below. |
| `workspace` | yes | The workspace the entry is for. It applies only where this equals the workspace the signed profile trusts (`scope.workspace`); elsewhere it waives nothing, without a warning. |
| `environments` | no | Up to 64 names. When set, the entry applies only in those environments and waives nothing, without a warning, elsewhere. A control listed in the profile's `exceptions.forbid_environment_scoped` cannot be waived by an entry with `environments`; that entry is rejected with a warning. |
| `reason` | yes | 1 to 1024 characters. |
| `ticket` | no | Up to 256 characters. |
| `expires` | yes | `YYYY-MM-DD`; the entry stops applying at 00:00 UTC that day. It must be within `max_lifetime_days` of the run date, or the entry is rejected. An expired entry waives nothing and warns. |

The file holds `exception` blocks only, at most 256 of them, and at most 1 MiB. Values are literal strings or lists of strings: references, functions, interpolation, numbers and booleans fail the load. An attribute or block named after a baseline, quarantine, floor or run key fails the load with `self_service_scope`, because self-service covers exceptions only.

### Variables in `match`

| Variable | Value |
|---|---|
| `type` | The resource type, for example `aws_db_instance`. |
| `config` | The configuration as written. Arguments you did not set are `null`. |
| `resource` | The planned resource, including computed attributes; unknown values are unknown at plan. |
| `prior` | The resource in state before the change; `null` on create. |
| `op` | The operation checked: `create`, `update`, `delete` or `replace`. |
| `env` | The environment (`dev` here, from the profile scope). |
| `provider` | `provider.region`, `provider.partition` and `provider.account_id`. `account_id` is known only when the provider block sets exactly one `allowed_account_ids` entry. |

Behaviour of `match`:
- If it reads a value that is unknown at plan, it waives nothing at plan and is evaluated again before apply.
- If it errors (for example indexing a missing map key), it waives nothing. Guard optional values with `!= null` and `in`, as entry 3 does.
- If it reads `op`, it must hold under every operation apply checks. Apply checks each half of a replace under `replace` and again under its own `create` or `delete`, so name all three: `op in ['create', 'replace', 'delete']`. A match on `op == 'replace'` alone waives at plan, with a warning, and blocks at apply.

### What the seven entries show

| # | Label | Shows |
|---|---|---|
| 1 | `dev-db-unencrypted` | One control, selected by an attribute pattern, limited to one environment |
| 2 | `reporting-replica-restore` | Several controls in one entry, selected on a configured argument |
| 3 | `scratch-volumes` | Selection by tag, guarding an optional map |
| 4 | `public-docs-site` | Selection by name prefix and `provider.region` |
| 5 | `migration-target-backups` | Selection by operation: create and replace, but not update |
| 6 | `staging-only` | Not applied: another environment, silently |
| 7 | `old-load-test` | Not applied: expired, with a warning |

## The org profile

The `exceptions` section of `profile.json` controls what the file may waive:

| Field | Meaning |
|---|---|
| `scope.workspace`, `scope.environment` | The trusted workspace and environment. Entries must name this workspace. |
| `exceptions.self_service` | Controls that may be waived from the exceptions file. |
| `exceptions.coverable` | Per control, which exception kinds may cover it (`self_service`, or `grant` for signed exception grants in `exception_grants_dir`). A self-service control must list `self_service` here too. |
| `exceptions.max_lifetime_days` | The latest allowed `expires`, counted from the run date. |
| `exceptions.forbid_environment_scoped` | Controls that entries with `environments` may not waive (optional). |
| `issued_at`, `expires_at` | The profile's validity; an expired profile is not used. |
| `mode_floor` | The minimum enforcement mode for the org; the provider uses the stricter of this and `enforcement_mode`. |

Settings and environment variables for `profile_path`, `exceptions_file` and the rest are in [docs/reference.md](../../docs/reference.md#configuration).
