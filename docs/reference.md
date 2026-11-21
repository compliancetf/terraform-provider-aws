# Reference

The exact settings, environment variables, diagnostics fields, built-in controls and limits of this release of the compliance.tf provider for AWS. This file changes in the same pull request as the code and is frozen with each release tag: open it at the tag of the provider version your lock file records.

How to use these settings, with examples and troubleshooting, is on the docs site: [Reference](https://compliance.tf/docs/provider/reference/), [Roll out and run in CI](https://compliance.tf/docs/provider/roll-out/). Where the two differ on a name or a value, this file at your release tag is right for that release.

## Versions

compliancetf/aws X.Y.Z runs hashicorp/aws X.Y.Z. Fixes to the compliance.tf layer alone ship as prereleases `X.Y.Z-compliancetf.N`, and betas as `X.Y.Z-beta.N`. To use a prerelease, pin its exact version; Terraform never selects one from a range constraint:

```hcl
aws = {
  source  = "registry.compliance.tf/compliancetf/aws"
  version = "6.67.0-compliancetf.1"
}
```

## Configuration

The `compliance {}` block is nested inside `provider "aws" {}`. Every attribute is an optional string. Every other argument of the provider block is passed to `hashicorp/aws` unchanged. Where a variable "wins", a non-empty value overrides the attribute.

| Attribute | Default | Variable | Values |
|---|---|---|---|
| `enforcement_mode` | `"soft_fail"` | `COMPLIANCETF_ENFORCEMENT_MODE`, the stricter one wins | `soft_fail`, `hard_fail`. `advisory` is accepted and ignored; `grandfather` needs organization mode ([Enforcement modes](#enforcement-modes)) |
| `control_profile` | `"cis"` | | `cis` only, the embedded bundle |
| `control_bundle_path` | `""` | `COMPLIANCETF_BUNDLE_PATH` wins | Path of a signed bundle archive, for air-gapped runs |
| `evidence_dir` | `".terraform/compliancetf/evidence"` | `COMPLIANCETF_EVIDENCE_DIR` wins | Directory of the evidence chains |
| `data_sources` | `"advisory"` | `COMPLIANCETF_DATA_SOURCES`, the stricter one wins | `advisory`: every data source control warns. `deny`: a `deny` data source control follows the enforcement mode |
| `environment` | `""` | `COMPLIANCETF_ENVIRONMENT` | Deployment environment name |
| `org_id` | `""` | `COMPLIANCETF_ORG_ID` | Not available ([Organization mode](#organization-mode-is-not-available)) |
| `profile_path` | `""` | `COMPLIANCETF_PROFILE_PATH` | Signed organization profile. Not available |
| `exceptions_file` | `""` | `COMPLIANCETF_EXCEPTIONS_FILE` wins | Self-service exceptions. Not available: ignored with a warning |
| `exception_grants_dir` | `""` | `COMPLIANCETF_EXCEPTION_GRANTS` wins | Signed exception grants. Not available |
| `baseline_file` | `""` | `COMPLIANCETF_BASELINE_FILE` wins | Signed grandfather baseline. Not available; a baseline that does not verify fails configuration |

When `org_id` and `COMPLIANCETF_ORG_ID` are both set and differ, configuration fails.

## Enforcement modes

| Mode | Violated `deny` control | Violated `warn` control |
|---|---|---|
| `soft_fail` (default) | Warning | Warning |
| `hard_fail` | Error: the plan fails and the apply is not forwarded | Warning |

- The table is the outcome at plan and before apply. After apply, and on refresh and import, a violation is a warning, except a blocking violation after an update, which is an error.
- A value unknown until apply gives a `pending` warning at plan and is checked again before apply. For a blocking control on a replacement, an unknown value fails the plan.
- A control that cannot be evaluated counts as a failure.
- An existing resource with no planned change (planned and prior state equal and fully known) only warns at plan, with the note "No change planned: this violation warns until the resource changes; any change to it is blocked."
- `advisory` warns `enforcement_mode advisory is below the default soft_fail and has no effect`; the mode is at least `soft_fail`.
- `grandfather` without signed organization baselines blocks at apply like `hard_fail`; plan reports each violation a baseline could cover (the control's signed coverage allows `baseline` and it reads no sensitive attribute) as `pending exemption: baseline <control id>`, and the provider warns once that every violation is treated as new.

## Environment variables

`COMPLIANCETF_*` variables are not passed to `hashicorp/aws`. Variables read only by test builds are in [DEVELOPING.md](../DEVELOPING.md#environment-variables).

| Name | Meaning |
|---|---|
| `COMPLIANCETF_ENFORCEMENT_MODE` | `soft_fail` or `hard_fail`; the stricter of it and `enforcement_mode` wins |
| `COMPLIANCETF_BUNDLE_PATH` | Signed bundle archive; wins over `control_bundle_path` |
| `COMPLIANCETF_EVIDENCE_DIR` | Evidence directory; wins over `evidence_dir` |
| `COMPLIANCETF_DATA_SOURCES` | `advisory` or `deny`; the stricter of it and `data_sources` wins |
| `COMPLIANCETF_ENVIRONMENT` | Deployment environment name; see `environment` |
| `COMPLIANCETF_DIAGNOSTICS` | Lines printed after each finding: `default`, `minimal`, `full` or a comma list of fields ([Diagnostics](#diagnostics)) |
| `COMPLIANCETF_UPSTREAM_PATH` | Path of the `hashicorp/aws` binary, for air-gapped installs. It must match the pinned checksum; any other binary is fatal |
| `COMPLIANCETF_RUN_ID` | Run id of the evidence records and of their subdirectory. Without it the id comes from `GITHUB_RUN_ID` (with `GITHUB_RUN_ATTEMPT`), `TFC_RUN_ID`, `SPACELIFT_RUN_ID` or `CI_PIPELINE_ID`, else a random id. A value outside `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` is skipped |
| `COMPLIANCETF_RUN_CLASS` | Label recorded in the evidence records as `class_claimed`; not verified. Same characters as `COMPLIANCETF_RUN_ID` |
| `COMPLIANCETF_WORKSPACE` | Workspace name recorded in the evidence records; not trusted. It is ignored with a warning when it differs from the workspace of a signed organization profile |
| `COMPLIANCETF_STATE_DIR` | Directory of `trust-state.json`, the anti-rollback state: the highest accepted bundle and profile versions and the revocations. Default: `compliancetf` in the user configuration directory |
| `COMPLIANCETF_MIN_BUNDLE_VERSION` | Raises the lowest bundle version accepted in this run above the stored minimum and the other floors; it never lowers it. A value that is not a non-negative integer is an error |
| `COMPLIANCETF_MIN_PROFILE_VERSION` | The same for the organization profile version |
| `COMPLIANCETF_BREAK_GLASS` | Set to any value, even empty, it fails configuration: this version cannot verify break-glass overrides |
| `COMPLIANCETF_ORG_ID` | Not available; see `org_id` |
| `COMPLIANCETF_PROFILE_PATH` | Not available; see `profile_path` |
| `COMPLIANCETF_EXCEPTIONS_FILE` | Not available; see `exceptions_file` |
| `COMPLIANCETF_EXCEPTION_GRANTS` | Not available; see `exception_grants_dir` |
| `COMPLIANCETF_BASELINE_FILE` | Not available; see `baseline_file` |
| `COMPLIANCETF_BASELINE_KEY_FILE` | Not available. The organization's baseline key: a file owned by the current user that group and others cannot read, holding 64 lowercase hex characters. While a usable key is set, plan results of existing resources carry `read_digest`, a keyed digest of the attributes the control reads in the prior state. Results of a create, of a control that reads a sensitive attribute and of an unknown read carry none; a file that is not a usable key warns |
| `COMPLIANCETF_TOKEN` | Not available. Bearer token for the compliance.tf service, sent only with `org_id` set and `COMPLIANCETF_OFFLINE` not `true`. The request is refused and configuration fails |
| `COMPLIANCETF_OFFLINE` | Not available. `true` turns off every request to the compliance.tf service; profile and bundles then come from cached copies. Other values are ignored |
| `COMPLIANCETF_CACHE_DIR` | Not available. Directory of cached organization bundles and profiles. Default: `compliancetf` in the user cache directory. It does not move the `hashicorp/aws` copy or its schema |
| `COMPLIANCETF_FLOOR_PATH` | Not available. Floor statement file for `floor_mode: airgap` when the signed profile names none |
| `COMPLIANCETF_GOVERNED` | Not available. `true` marks the run as governed by an organization and then needs an `org_id`; `false` or unset does not. Any other value fails configuration |
| `COMPLIANCETF_VERDICT` | Not available. Path of a signed verdict file (`compliancetf.verdict/v1`), loaded at the first apply. The value must be a path, never the verdict itself |
| `COMPLIANCETF_VERDICT_KEY_FILE` | Not available. The run key of the verdict's plan artifact set |

The ownership and permission rules for the cache directories are in [architecture.md](architecture.md#caches).

## Diagnostics

A violation prints `[<control id>] <message>`, the source snippet Terraform shows, then these lines in this order:

| Field | Line | Default |
|---|---|---|
| `fix` | `Fix: <how to fix it>`, when the control has one | yes |
| `docs` | `Docs: https://compliance.tf/docs/controls/aws/<control id>/` | yes |
| `waive` | `To waive: add an exception for <control id> in <exceptions_file>`, only when an `exceptions_file` entry can waive the control: the signed org profile lists it under self-service with `max_lifetime_days`, a trusted workspace is set, and the exceptions clock is known. Org profiles are not available, so it does not print today | yes |
| `severity` | `Severity: <severity>` | no |
| `mode` | `Mode: <enforcement mode>` | no |
| `stage` | `Stage: <stage>`, and `Type: <data source type>` for data sources | no |
| `frameworks` | `Frameworks: <framework references>` | no |

`COMPLIANCETF_DIAGNOSTICS`: `default` (unset or empty), `minimal` (`fix` only), `full` (all), or a comma list of field names. Unknown names are ignored with one warning; a list with no known name prints the `default` lines. Lines that explain the situation (unknown until apply, not evaluable, applied but violating, pending exemption) always print. The setting changes only what is printed: verdicts, evidence and exit codes stay the same.

## CIS controls

The embedded CIS bundle (`cis-aws`). Each control declares `exemption_coverable` `[baseline, break_glass, grant, self_service]`; every kind needs organization mode, so no CIS violation can be waived today.

| Control | Resource types | Action | Severity |
|---|---|---|---|
| `rds_db_instance_encryption_at_rest_enabled` | `aws_db_instance` | deny | critical |
| `rds_db_instance_prohibit_public_access` | `aws_db_instance` | deny | critical |
| `rds_db_instance_backup_retention_period_less_than_7` | `aws_db_instance`, `aws_rds_cluster` | deny | high |
| `rds_db_instance_deletion_protection_enabled` | `aws_db_instance` | warn | medium |
| `rds_db_cluster_encryption_at_rest_enabled` | `aws_rds_cluster` | deny | critical |
| `rds_db_cluster_deletion_protection_enabled` | `aws_rds_cluster` | warn | medium |
| `ebs_attached_volume_encryption_enabled` | `aws_ebs_volume` | deny | critical |
| `efs_file_system_encrypt_data_at_rest` | `aws_efs_file_system` | deny | critical |
| `efs_file_system_encrypted_with_cmk` | `aws_efs_file_system` | warn | medium |
| `elasticache_replication_group_encryption_at_rest_enabled` | `aws_elasticache_replication_group` | deny | critical |
| `elasticache_replication_group_encryption_in_transit_enabled` | `aws_elasticache_replication_group` | deny | critical |
| `redshift_cluster_kms_enabled` | `aws_redshift_cluster` | deny | critical |
| `redshift_cluster_prohibit_public_access` | `aws_redshift_cluster` | deny | critical |
| `elb_application_network_listener_uses_secure_protocol` | `aws_lb_listener` | deny | critical |
| `s3_bucket_restrict_public_read_access` | `aws_s3_bucket` | deny | critical |
| `s3_bucket_restrict_public_write_access` | `aws_s3_bucket` | deny | critical |
| `vpc_security_group_remote_administration_ipv4` | `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule` | deny | critical |
| `vpc_security_group_remote_administration_ipv6` | `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule` | deny | critical |

## Organization mode is not available

compliance.tf does not issue organization profiles, so organization bundles, mode floors, self-service exceptions, exception grants, grandfather baselines and verified verdicts are not available. Leave `org_id`, `COMPLIANCETF_ORG_ID` and `COMPLIANCETF_TOKEN` unset.

| Setting | Outcome |
|---|---|
| `org_id` without `COMPLIANCETF_TOKEN` | No request is sent. When no signed profile is found, the provider warns `Org profile for <org> unavailable: hard_fail floor applied (no profile found).` Every `deny` control then runs at least in `hard_fail`; `warn` controls still warn. An `exceptions_file` is ignored with a warning |
| `org_id` with `COMPLIANCETF_TOKEN` | The provider requests the profile from the compliance.tf service. The request is refused (for example `bundle service answered HTTP 403 for /v1/orgs/<org>/profile`) and configuration fails, so every plan stops |

How bundles, grants and self-service exceptions would be checked is in [architecture.md](architecture.md#bundles-and-exceptions).

## CIS bundle release asset

Each release ships the embedded CIS bundle as `terraform-provider-aws_X.Y.Z_cis-aws.tar.gz`, listed in the release's signed `SHA256SUMS`. The verdict tool refuses a `--bundle-dir` without it, because the provider always loads this bundle. Use the asset of the provider version your lock file pins. The archive holds `manifest.dsse.json` and `controls.json` at its root, so extract it into a directory named after the bundle id:

```bash
V=X.Y.Z
gpg --verify terraform-provider-aws_${V}_SHA256SUMS.sig terraform-provider-aws_${V}_SHA256SUMS
sha256sum --ignore-missing -c terraform-provider-aws_${V}_SHA256SUMS   # macOS: shasum -a 256 --ignore-missing -c
mkdir -p bundles/cis-aws
tar xzf terraform-provider-aws_${V}_cis-aws.tar.gz -C bundles/cis-aws
```

Then pass `--bundle-dir bundles` to the verdict tool, next to one directory per other bundle.

## Limitations

- **Upstream binary required.** The real `hashicorp/aws` binary is found locally or downloaded on first use. Only the exact pinned version is used, and its sha256 must match the pin. For air-gapped installs set `COMPLIANCETF_UPSTREAM_PATH`.
- **Protocol 5 only.** The provider serves plugin protocol 5, the protocol `hashicorp/aws` speaks.
- **No remediation.** The provider warns or denies; it never changes a value.
- **Replacing a resource with an identity needs Terraform 1.16.6 or later.** Terraform 1.12 to 1.16.5 and OpenTofu (checked with 1.13) do not send the prior resource identity when they destroy the old object of a replace (`-replace` or a forced replacement), so the provider cannot confirm which object is destroyed and blocks that apply. Use Terraform 1.16.6 or later, or taint the object first and apply again (`terraform taint <address>` or `tofu taint <address>`): a tainted replace destroys the object by resource id and is not blocked. Plain destroys, and replaces of resource types without an identity, are not affected.
- **On Terraform 1.12 to 1.16.5 and OpenTofu 1.13 an edited saved plan can make the destroy half of a replace match by resource id.** These versions send no identity for the object a replace destroys, so the provider cannot tell from the apply request whether the compliance data in a saved plan was edited to match that destroy by resource id instead of by identity. Such a destroy is matched to its plan decision by `{"id": id}`, which another object of the same type with the same id could share. Terraform 1.16.6 and later send the identity, and the provider checks it. Terraform before 1.12 sends no usable identity, so its plans match these destroys by id and this check does not apply. Use Terraform 1.16.6 or later.
- **`control_predicate` at configure.** A bundle built for 0.1.x writes a control as a `predicate`. Rewrite each check as a CEL `expr`, then rebuild and re-sign the bundle.
