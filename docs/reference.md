# Reference

Configuration, enforcement modes, the built-in CIS controls, exceptions and known limitations of the compliance.tf provider for AWS. Start with the [README](../README.md).

## Versions

compliancetf/aws X.Y.Z runs hashicorp/aws X.Y.Z, so an existing configuration keeps its `version` constraint and lock file workflow. Resources already in state still name `hashicorp/aws`; rebind them once with `terraform state replace-provider registry.terraform.io/hashicorp/aws registry.compliance.tf/compliancetf/aws`.

Fixes to the compliance.tf layer alone ship as prereleases `X.Y.Z-compliancetf.N`, and betas as `X.Y.Z-beta.N`. Terraform never selects a prerelease from a range constraint, so to use one, pin it exactly:

```hcl
aws = {
  source  = "registry.compliance.tf/compliancetf/aws"
  version = "6.67.0-compliancetf.1"
}
```

## Configuration

The `compliance {}` block is nested inside the `provider "aws" {}` block:

```hcl
provider "aws" {
  region = "us-east-1"

  compliance {
    enforcement_mode = "hard_fail"
    control_profile  = "cis"
  }
}
```

| Attribute | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enforcement_mode` | `string` | No | `"soft_fail"` | `advisory`, `soft_fail`, `grandfather` or `hard_fail`; `COMPLIANCETF_ENFORCEMENT_MODE` (the stricter one wins) |
| `org_id` | `string` | No | `""` | Organization ID; `COMPLIANCETF_ORG_ID` |
| `control_profile` | `string` | No | `"cis"` | Only `cis` (the embedded bundle) |
| `control_bundle_path` | `string` | No | `""` | Signed bundle archive for air-gapped runs; `COMPLIANCETF_BUNDLE_PATH` wins |
| `profile_path` | `string` | No | `""` | Signed org profile; `COMPLIANCETF_PROFILE_PATH` |
| `exceptions_file` | `string` | No | `""` | Self-service exception file; `COMPLIANCETF_EXCEPTIONS_FILE` wins |
| `exception_grants_dir` | `string` | No | `""` | Directory of signed exception grants; `COMPLIANCETF_EXCEPTION_GRANTS` wins |
| `environment` | `string` | No | `""` | Deployment environment; `COMPLIANCETF_ENVIRONMENT` |
| `evidence_dir` | `string` | No | `".terraform/compliancetf/evidence"` | Evidence chain directory; `COMPLIANCETF_EVIDENCE_DIR` wins |
| `data_sources` | `string` | No | `"advisory"` | `advisory` or `deny`; `COMPLIANCETF_DATA_SOURCES` and the org profile `data_sources` (the stricter one wins). Under `advisory` every data source control only warns; under `deny` a `deny` data source control follows the enforcement mode |
| `baseline_file` | `string` | No | `""` | Signed grandfather baseline (`compliancetf.baseline/v1`); `COMPLIANCETF_BASELINE_FILE` wins. Needs `COMPLIANCETF_BASELINE_KEY_FILE`; a baseline that does not verify fails configuration |

## Enforcement modes

`enforcement_mode`, `COMPLIANCETF_ENFORCEMENT_MODE` and a signed org profile floor combine to the strictest of them, in the order `advisory < soft_fail < grandfather < hard_fail`. A control blocks when its action is `deny` and its mode is `hard_fail` (or `grandfather`, which acts as `hard_fail` until baselines ship).

| Mode | Blocking `deny` violation | `warn` violation |
|------|---------------------------|------------------|
| `hard_fail` | Error: the plan fails and the apply is not forwarded | Warning |
| `grandfather` | Same as `hard_fail` in this version | Warning |
| `soft_fail` (default) | Warning | Warning |
| `advisory` | No diagnostic, evidence record only | No diagnostic, evidence record only |

The table is the plan and before-apply outcome. After apply and on refresh or import a violation is a warning, except an error after an update; Terraform has already changed the resource at that point. A value that is unknown until apply gives a `pending` warning at plan and is checked again before apply. A control that cannot be evaluated counts as a failure.

## CIS controls

The embedded CIS bundle (`cis-aws`) holds these controls. Control ids follow the compliance.tf control catalog.

| Control | Resource types | Action | Severity |
|---------|----------------|--------|----------|
| `rds_db_instance_encryption_at_rest_enabled` | `aws_db_instance` | deny | critical |
| `rds_db_instance_prohibit_public_access` | `aws_db_instance` | deny | critical |
| `rds_db_instance_backup_retention_period_less_than_7` | `aws_db_instance`, `aws_rds_cluster` | deny | high |
| `rds_db_instance_deletion_protection_enabled` | `aws_db_instance` | warn | medium |
| `rds_db_cluster_encryption_at_rest_enabled` | `aws_rds_cluster` | deny | critical |
| `rds_db_cluster_deletion_protection_enabled` | `aws_rds_cluster` | warn | medium |
| `ebs_volume_encryption_at_rest_enabled` | `aws_ebs_volume` | deny | critical |
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

## Bundles and exceptions

- **Bundles** are signed bundle 2.0 archives (`.tar.gz` with a manifest and a DSSE signature). The embedded CIS bundle always loads; `control_bundle_path` adds an air-gapped archive. `cmd/ctfbundle` builds, signs and verifies archives.
- **Exception grants** are DSSE-signed files, one per grant, in `exception_grants_dir`. They apply only to controls whose signed coverage allows grants, and only within their org, workspace scope and expiry. A grant naming any control that is unknown or not coverable for grants applies to none of its controls, with a warning per control. Under `floor_mode: airgap` grant expiry and key windows are checked against the latest accepted floor statement, never the local clock.
- **Self-service exceptions** in `exceptions_file` are HCL. Without a signed org profile that lists the control under self-service, the file is ignored with a warning. Each entry selects resources with a CEL `match` expression over `type`, `resource`, `config`, `prior`, `op`, `env` and `provider` (see `examples/exception/exceptions.hcl`); an unknown result waives nothing at plan and is retried at apply, an error waives nothing. A match that reads `op` must hold under every op a control is checked under: apply checks each half of a replace under `replace` and under its own `create` or `delete`, and a `change` under the actual `create` or `update` too. Name the half ops (`op in ['replace', 'create', 'delete']`) or read no `op`; a match that says only `op == 'replace'` waives at plan, where it warns, and blocks at apply. The same holds for grant selectors. The file holds `exception` blocks only: a block or attribute naming a baseline, quarantine, floor or run key fails the load with `self_service_scope`. Under `floor_mode: airgap` break-glass coverability is dropped with a warning per control.
- **Pending exemptions at plan.** When a blocking failure has no exception that applies, plan reports it as a warning (`pending exemption: <kind> <control>`) instead of an error, one per eligible kind, and apply blocks it unless `ctfkit gate sign` lists the final proof. A kind is eligible only when the control's signed coverage allows it and the run can use that kind: `grant` needs `exception_grants_dir`, `self_service` needs the signed org profile to list the control under self-service, `baseline` needs `grandfather` mode and a grandfatherable control, and `break_glass` needs a profile that enables break-glass under `floor_mode: online`. With no eligible kind the failure errors at plan.

### CIS bundle release asset

Each release ships the embedded CIS bundle as `terraform-provider-aws_X.Y.Z_cis-aws.tar.gz`, listed in the release's signed `SHA256SUMS`. The verdict tool refuses a `--bundle-dir` without it, because the provider always loads this bundle. Use the asset of the provider version your lock file pins. The archive holds `manifest.dsse.json` and `controls.json` at its root, so extract it into a directory named after the bundle id:

```bash
V=X.Y.Z
gpg --verify terraform-provider-aws_${V}_SHA256SUMS.sig terraform-provider-aws_${V}_SHA256SUMS
sha256sum --ignore-missing -c terraform-provider-aws_${V}_SHA256SUMS   # macOS: shasum -a 256 --ignore-missing -c
mkdir -p bundles/cis-aws
tar xzf terraform-provider-aws_${V}_cis-aws.tar.gz -C bundles/cis-aws
```

Then pass `--bundle-dir bundles` to the verdict tool, next to one directory per other bundle.

## Diagnostics

A failing control is reported as `[<control id>] <message>`, then the source snippet, then these lines:

| Field | Line | Default |
|-------|------|---------|
| `fix` | `Fix: <how to fix it>`, when the control has one | yes |
| `docs` | `Docs: https://compliance.tf/docs/controls/aws/<control id>/` | yes |
| `waive` | `To waive: add an exception for <control id> in <exceptions_file>`, only when an entry in `exceptions_file` can waive this control: the signed org profile lists it under self-service with `max_lifetime_days`, a trusted workspace is set, and the exceptions clock is known | yes |
| `severity` | `Severity: <severity>` | no |
| `mode` | `Mode: <enforcement mode>` | no |
| `stage` | `Stage: <stage>` (and `Type: <data source type>` for data sources) | no |
| `frameworks` | `Frameworks: <framework references>` | no |

`COMPLIANCETF_DIAGNOSTICS` chooses them: `default` (unset or empty), `minimal` (`fix` only), `full` (all), or a comma list of field names such as `fix,docs,frameworks`. Lines always print in the order above. Unknown names are ignored with one warning. Lines that explain the situation (values unknown until apply, not evaluable, applied but violating, pending exemption) always print. The setting changes only what diagnostics show: verdicts, evidence and exit codes are the same.

## Environment variables

| Name | Meaning |
|------|---------|
| `COMPLIANCETF_DIAGNOSTICS` | Lines of control diagnostics: `default`, `minimal`, `full` or a comma list of fields (see [Diagnostics](#diagnostics)). |
| `COMPLIANCETF_UPSTREAM_PATH` | Explicit path to the `hashicorp/aws` binary, for air-gapped installs. The binary must match the pinned checksum. |
| `COMPLIANCETF_BASELINE_KEY_FILE` | The organization's baseline key: a file owned by the current user that group and others cannot read, holding 64 lowercase hex characters. `baseline_file` needs it to match entries. While it is set, with or without a baseline file, each plan evidence result of a resource that already exists carries `read_digest`, a keyed digest of the attributes the control reads in the prior state, from which ctfkit writes baseline entries. Results of a create, of a control that reads a sensitive attribute and of a read that is unknown carry none. A file that is not a usable key warns and no `read_digest` is written. |
| `COMPLIANCETF_CACHE_DIR` | Directory of the cached signed organization bundles and profiles fetched from the bundle service. Default: `compliancetf` in the user cache directory (`$XDG_CACHE_HOME` or `~/.cache` on Linux, `~/Library/Caches` on macOS, `%LocalAppData%` on Windows). |

On unix systems such as Linux and macOS the cache directory and every directory below it must be owned by the current user and must not be a symlink; the provider creates missing ones with mode 0700, sets existing ones to 0700 when it writes, and does not read one that group or others can write. On Windows the same directories must not be a symlink or junction, must be owned by the current user (or SYSTEM or Administrators) and their ACL must not let anyone else write them or pass write on to the files and directories created in them; a missing cache directory is created with an ACL that only grants the current user, SYSTEM and Administrators, and an existing ACL is never changed. A directory that fails these checks is skipped with a warning and the run goes on without the cache. Cached archives are verified on every load, and when the bundle service cannot be reached the best cached copy that verifies is used, so in CI either persist this directory between jobs (restored with the job user as owner and no group or other write bit) or point it at a fresh per-job directory. The verified `hashicorp/aws` copy, its download and the cached upstream schema do not follow this variable: they stay under `compliancetf` in the user cache directory (see [performance.md](performance.md)).

`COMPLIANCETF_*` variables are not passed to the upstream provider. Variables used only by test builds are listed in [DEVELOPING.md](../DEVELOPING.md#environment-variables).

## Limitations

- **Upstream provider binary required**: the real `hashicorp/aws` binary is found locally or downloaded on first use. Only the exact pinned version is used, and its sha256 must match the pin. For air-gapped installs set `COMPLIANCETF_UPSTREAM_PATH` to a binary of that version.
- **Protocol 5 only**: the provider serves plugin protocol 5, the protocol `hashicorp/aws` speaks.
- **No auto-remediation**: the provider can deny or warn on non-compliant values but cannot fix them.
- **Replacing a resource with an identity needs Terraform 1.16.6 or later**: Terraform 1.12 to 1.16.5 and OpenTofu (checked with 1.13) do not send the prior resource identity when they destroy the old object of a replace (`-replace` or a forced replacement), so the provider cannot confirm which object is destroyed and blocks that apply. Use Terraform 1.16.6 or later, or taint the object first and apply again (`terraform taint <address>` or `tofu taint <address>`): a tainted replace destroys the object by resource id and is not blocked. Plain destroys, and replaces of resource types without an identity, are not affected.
- **On Terraform 1.12 to 1.16.5 and OpenTofu 1.13 an edited saved plan can make the destroy half of a replace match by resource id**: these versions send no identity for the object a replace destroys, so the provider cannot tell from the apply request whether the compliance data in a saved plan was edited to match that destroy by resource id instead of by identity. Such a destroy is then matched to its plan decision by `{"id": id}`, which another object of the same type with the same id could share. Terraform 1.16.6 and later send the identity, and the provider checks it. Terraform before 1.12 sends no usable identity, so its plans match these destroys by id and this check does not apply. Use Terraform 1.16.6 or later.

