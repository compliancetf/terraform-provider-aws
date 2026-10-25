# compliance.tf Terraform Provider

A gRPC delegating provider that enforces compliance controls on raw `aws_*` resources at the Terraform provider level.

> **Status: v2 rebuild in progress**
>
> The provider runs the real `hashicorp/aws` provider binary as a subprocess and forwards Terraform's plugin protocol to it. The upstream binary is the pinned version, found locally or downloaded on first use, and verified against its pinned checksum before it runs. Full AWS schema (~1,300 resource types).
>
> Every controlled resource is evaluated at plan, before apply, after apply, on refresh and on import, against signed bundle 2.0 archives. Each evaluation writes a metadata-only record to a hash-chained evidence log. The embedded CIS bundle is still signed with a test key, so only development builds (`make build-dev`, build tag `ctftest`) load it; a release build fails `terraform plan` at provider configuration instead of running without controls.

## Quick Start

**1. Add the provider to your Terraform configuration:**

```hcl
terraform {
  required_providers {
    aws = {
      source  = "registry.compliance.tf/compliancetf/aws" # was "hashicorp/aws"
      version = "~> 6.67"
    }
  }
}

provider "aws" {
  region = "us-east-1"

  compliance {
    enforcement_mode = "hard_fail"
  }
}
```

compliancetf/aws X.Y.Z runs hashicorp/aws X.Y.Z, so in an existing configuration the only configuration change is `source`: keep your `version` constraint and your lock file workflow. Resources already in state still name `hashicorp/aws`; rebind them once with `terraform state replace-provider registry.terraform.io/hashicorp/aws registry.compliance.tf/compliancetf/aws`.

Proxy-only fixes ship as prereleases `X.Y.Z-compliancetf.N` (betas as `X.Y.Z-beta.N`). Terraform never selects a prerelease from a range constraint, so to use one, pin it exactly:

```hcl
aws = {
  source  = "registry.compliance.tf/compliancetf/aws"
  version = "6.67.0-compliancetf.1"
}
```

**2. Initialize and plan:**

```bash
terraform init
terraform plan
```

The provider automatically downloads the real `hashicorp/aws` provider and proxies all RPCs through its compliance engine.

> **For local development:** See [DEVELOPING.md](DEVELOPING.md) for building from source with `make build` and `dev_overrides`.

## Features

- **Embedded CIS bundle**: 23 controls (18 control ids) on 11 resource types (encryption, public access, backup retention, deletion protection, listener protocol, S3 ACLs, SSH/RDP ingress)
- **Lifecycle evaluation**: plan (on the upstream planned state), apply before forwarding, apply result, refresh and import; destroy runs only deletion guards, so `terraform destroy` works in `hard_fail`
- **4 enforcement modes**: `advisory`, `soft_fail` (default), `grandfather` and `hard_fail`; local settings can only raise the mode
- **Signed bundles and org profiles**: DSSE-signed bundle 2.0 archives and org profiles, verified against a compiled-in keyring with revocations, an anti-rollback floor and expiry
- **Exceptions**: signed grants, plus an unsigned self-service file for the controls a signed org profile allows
- **Evidence chain**: one metadata-only record per evaluation in a per-process hash chain under `evidence_dir`

## Configuration Reference

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

## Enforcement Modes

`enforcement_mode`, `COMPLIANCETF_ENFORCEMENT_MODE` and a signed org profile floor combine to the strictest of them, in the order `advisory < soft_fail < grandfather < hard_fail`. A control blocks when its action is `deny` and its mode is `hard_fail` (or `grandfather`, which acts as `hard_fail` until baselines ship).

| Mode | Blocking `deny` violation | `warn` violation |
|------|---------------------------|------------------|
| `hard_fail` | Error: the plan fails and the apply is not forwarded | Warning |
| `grandfather` | Same as `hard_fail` in this version | Warning |
| `soft_fail` (default) | Warning | Warning |
| `advisory` | No diagnostic, evidence record only | No diagnostic, evidence record only |

The table is the plan and before-apply outcome. After apply and on refresh or import a violation is a warning, except an error after an update; Terraform has already changed the resource at that point. A value that is unknown until apply gives a `pending` warning at plan and is checked again before apply. A control that cannot be evaluated counts as a failure.

## CIS Controls

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

## Bundles and Exceptions

- **Bundles** are signed bundle 2.0 archives (`.tar.gz` with a manifest and a DSSE signature). The embedded CIS bundle always loads; `control_bundle_path` adds an air-gapped archive. `cmd/ctfbundle` builds, signs and verifies archives.
- **Exception grants** are DSSE-signed files, one per grant, in `exception_grants_dir`. They apply only to controls whose signed coverage allows grants, and only within their org, workspace scope and expiry. A grant naming any control that is unknown or not coverable for grants applies to none of its controls, with a warning per control. Under `floor_mode: airgap` grant expiry and key windows are checked against the latest accepted floor statement, never the local clock.
- **Self-service exceptions** in `exceptions_file` are HCL. Without a signed org profile that lists the control under self-service, the file is ignored with a warning. Each entry selects resources with a CEL `match` expression over `type`, `resource`, `config`, `prior`, `op`, `env` and `provider` (see `examples/exception/exceptions.hcl`); an unknown result waives nothing at plan and is retried at apply, an error waives nothing. A match that reads `op` must hold under every op a control is checked under: apply checks each half of a replace under `replace` and under its own `create` or `delete`, and a `change` under the actual `create` or `update` too. Name the half ops (`op in ['replace', 'create', 'delete']`) or read no `op`; a match that says only `op == 'replace'` waives at plan, where it warns, and blocks at apply. The same holds for grant selectors. The file holds `exception` blocks only: a block or attribute naming a baseline, quarantine, floor or run key fails the load with `self_service_scope`. Under `floor_mode: airgap` break-glass coverability is dropped with a warning per control.

## Architecture

```
+----------------+  tfplugin5  +-------------------------------+  tfplugin5  +----------------------+
|                |    gRPC     |  compliance.tf provider        |    gRPC     |                      |
| Terraform or   | <---------> |                               | <---------> | hashicorp/aws        |
| OpenTofu       |             |  intercepted RPCs -> hook     |             | (subprocess)         |
|                |             |  all other RPCs -> raw bytes  |             |                      |
+----------------+             +-------------------------------+             +----------------------+
```

The provider is a raw gRPC proxy. A generated route table, built from the pinned `tfplugin5` protocol definition, classes every RPC:

- **Intercepted** RPCs (schema, provider configure, stop, validate, plan, apply, read, data source read, import, ephemeral open) are decoded, given to the compliance hook, and re-encoded with only the fields the proxy owns changed. The provider schema gains the `compliance {}` block, which is stripped before the configuration reaches the upstream provider.
- **Passthrough** RPCs are forwarded to the upstream provider as undecoded bytes, so fields newer than the pinned protocol survive.
- An RPC that is not in the pinned protocol returns `Unimplemented`; Terraform treats it as an unsupported capability.

Upstream `new_state` returned from apply is passed back byte for byte. Plan-time compliance data travels only in the planned private data, never in state.

## Environment Variables

| Name | Meaning |
|------|---------|
| `COMPLIANCETF_UPSTREAM_PATH` | Explicit path to the `hashicorp/aws` binary, for air-gapped installs. The binary must match the pinned checksum. |

`COMPLIANCETF_*` variables are not passed to the upstream provider. Variables used only by test builds are listed in [DEVELOPING.md](DEVELOPING.md#environment-variables).

## Limitations

- **Release builds fail at configuration**: the embedded CIS bundle is test-signed until a production bundle key exists, so only development builds evaluate controls.
- **Upstream provider binary required**: the real `hashicorp/aws` binary is found locally or downloaded on first use. Only the exact pinned version is used, and its sha256 must match the pin. For air-gapped installs set `COMPLIANCETF_UPSTREAM_PATH` to a binary of that version.
- **Protocol 5 only**: the provider serves plugin protocol 5, the protocol `hashicorp/aws` speaks.
- **No auto-remediation**: the provider can deny or warn on non-compliant values but cannot fix them.
- **Replacing a resource with an identity needs Terraform 1.16.6 or later**: Terraform 1.12 to 1.16.5 and OpenTofu (checked with 1.13) do not send the prior resource identity when they destroy the old object of a replace (`-replace` or a forced replacement), so the provider cannot confirm which object is destroyed and blocks that apply. Use Terraform 1.16.6 or later, or taint the object first and apply again (`terraform taint <address>` or `tofu taint <address>`): a tainted replace destroys the object by resource id and is not blocked. Plain destroys, and replaces of resource types without an identity, are not affected.
- **On Terraform 1.12 to 1.16.5 and OpenTofu 1.13 an edited saved plan can make the destroy half of a replace match by resource id**: these versions send no identity for the object a replace destroys, so the provider cannot tell from the apply request whether the compliance data in a saved plan was edited to match that destroy by resource id instead of by identity. Such a destroy is then matched to its plan decision by `{"id": id}`, which another object of the same type with the same id could share. Terraform 1.16.6 and later send the identity, and the provider checks it. Terraform before 1.12 sends no usable identity, so its plans match these destroys by id and this check does not apply. Use Terraform 1.16.6 or later.

## Development

See [DEVELOPING.md](DEVELOPING.md) for build instructions, test commands and conformance tests.

Pull requests are accepted from collaborators only; everyone else, please open an issue. See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
make build         # build the provider binary
make test          # run all Go tests
make conformance   # run conformance scenarios with the terraform on PATH
```

## License

Mozilla Public License 2.0. See LICENSE for details.
