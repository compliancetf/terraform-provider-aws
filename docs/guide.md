# Using the provider day to day

How to run the compliance.tf provider for AWS in daily work and in CI, and what to do with its findings. Start with the [README](../README.md) to install it. Every setting is in the [reference](reference.md); where this guide is shorter, follow the reference.

## Enforcement modes

The mode decides what a violated control does:

| Mode | Blocking `deny` violation | `warn` violation |
|------|---------------------------|------------------|
| `hard_fail` | Error: the plan fails and the apply is not forwarded | Warning |
| `soft_fail` (default) | Warning | Warning |

The table is the outcome at plan and before apply. An existing resource with no planned change (planned and prior state equal and fully known) is the exception at plan: a blocking violation of it is a warning with the note "No change planned: this violation warns until the resource changes; any change to it is blocked." So turning on `hard_fail` does not fail the plan for non-compliant resources you leave alone, but the plan of any change to them fails.

The mode comes from two places: `enforcement_mode` in the `compliance {}` block and the `COMPLIANCETF_ENFORCEMENT_MODE` variable. The stricter one wins, so `soft_fail` in the configuration cannot lower a `hard_fail` variable.

Use `soft_fail` or `hard_fail`. The provider also accepts two other values:

- `advisory` is ignored. The provider warns that it is below the default `soft_fail`, and the mode is at least `soft_fail`, so findings still warn. A stricter setting from the other place still wins: with `COMPLIANCETF_ENFORCEMENT_MODE=hard_fail`, the run is in `hard_fail`. No organization profile can turn `advisory` on.
- `grandfather` needs signed organization baselines, which are not available. Without them it blocks at apply like `hard_fail`, while plan shows the violations a baseline could cover as `pending exemption: baseline <control id>` warnings. Use `hard_fail` instead.

See [Enforcement modes](reference.md#enforcement-modes) in the reference.

## CI setup

Run the same provider in CI that you run locally. A typical pipeline has a plan job and an apply job:

```bash
# plan job
export COMPLIANCETF_ENFORCEMENT_MODE=hard_fail
terraform init -input=false
terraform plan -input=false -out=tfplan

# apply job, with the same COMPLIANCETF_* variables
terraform apply -input=false tfplan
```

- `COMPLIANCETF_ENFORCEMENT_MODE` makes every configuration the job runs at least that strict, whatever its `compliance {}` block says. Each Terraform run reads the variables itself, so set the same ones in the plan job and the apply job.
- With a saved plan, the provider checks each resource again before apply. A value that is unknown at plan gives a `pending` warning and is checked before apply. A saved plan holds the configuration it was made from: after you change the configuration, plan again.
- Replacing a resource that has an identity needs Terraform 1.16.6 or later; Terraform 1.12 to 1.16.5 and OpenTofu block that apply, and saved plans have a related limit. See [Limitations](reference.md#limitations).
- `COMPLIANCETF_DIAGNOSTICS` chooses the lines each finding prints in the CI log (see [Reading diagnostics](#reading-diagnostics)).

## Caches

The provider caches the `hashicorp/aws` binary that it downloads and verifies, and the upstream schema. These stay under `compliancetf` in the user cache directory (`$XDG_CACHE_HOME` or `~/.cache` on Linux, `~/Library/Caches` on macOS, `%LocalAppData%` on Windows). `COMPLIANCETF_CACHE_DIR` does not move them: it is only for organization bundles and profiles, and organization mode is not available. A `hashicorp/aws` of the pinned version in Terraform's plugin directories is used before any download.

In CI, persist this cache between jobs, or accept that each fresh runner downloads and verifies `hashicorp/aws` again. A restored cache directory must be owned by the job user and not writable by group or others, or the provider skips it with a warning. The ownership and ACL rules are under [Environment variables](reference.md#environment-variables), and [performance.md](performance.md) has the startup costs.

## Evidence files

Every check writes a record to a local evidence directory: `.terraform/compliancetf/evidence` by default, or `evidence_dir` in the `compliance {}` block (`COMPLIANCETF_EVIDENCE_DIR` wins).

A record holds the control, the resource type, the operation, the resource id and identity, the stage, the result and the mode. The resource address is not recorded: a `for_each` key can carry a value, so a record alone does not name the module or the `count` or `for_each` instance. Other attribute values are not recorded. While `COMPLIANCETF_BASELINE_KEY_FILE` is set, plan results of existing resources also carry `read_digest`, a keyed digest of the attributes the control reads, from which baseline entries are written.

Each line is hash-chained to the one before it. A line edited or removed in the middle of a file shows; a file cut short at the end does not. The files stay on the machine that ran Terraform, and a CI runner usually discards `.terraform` when the job ends. If you rely on them as evidence, copy them to write-once storage after each run.

## Reading diagnostics

A failing control prints `[<control id>] <message>`, the source snippet, then a fix line and a docs link:

```
Error: [rds_db_instance_encryption_at_rest_enabled] RDS instances must have storage encryption enabled.

  with aws_db_instance.non_compliant,
  on main.tf line 25, in resource "aws_db_instance" "non_compliant":
  25:   storage_encrypted       = false # deny

Fix: Set storage_encrypted = true.
Docs: https://compliance.tf/docs/controls/aws/rds_db_instance_encryption_at_rest_enabled/
```

`COMPLIANCETF_DIAGNOSTICS` chooses the lines after the snippet:

| Value | Lines |
|---|---|
| `default` (unset or empty) | fix and docs |
| `minimal` | fix only |
| `full` | all, including severity, mode, stage and framework references |
| a comma list, such as `fix,docs,frameworks` | the fields named |

The setting changes only what is shown; results, evidence and exit codes stay the same. Lines that explain the situation, such as a value unknown until apply or a pending exemption, always print. The fields are listed under [Diagnostics](reference.md#diagnostics).

## Upgrading

compliancetf/aws X.Y.Z runs hashicorp/aws X.Y.Z, so upgrading the provider upgrades `hashicorp/aws` to the same version. Keep the `version` constraint and lock file workflow you use for `hashicorp/aws`, and run `terraform init -upgrade` as before. A release can change the embedded controls, so read [CHANGELOG.md](../CHANGELOG.md) first.

Fixes to the compliance.tf layer alone ship as `X.Y.Z-compliancetf.N`, and betas as `X.Y.Z-beta.N`. Terraform never selects a prerelease from a range constraint, so to use one, pin it exactly (`version = "6.70.0-compliancetf.1"`). See [Versions](reference.md#versions).

Upgrading from 0.1.x: a bundle with controls written as a `predicate` does not load. Configure fails with `control_predicate` and the run stops. Rewrite each check as a CEL `expr`, then rebuild and re-sign the bundle with `cmd/ctfbundle`.

## Findings you cannot fix yet

Exceptions are not available. Self-service exceptions, exception grants and grandfather baselines all need a signed organization profile, and organization mode is not available. An `exceptions_file` is ignored with a warning.

Keep the configuration that has the finding on `soft_fail` and make the others `hard_fail`. A CI job that sets `COMPLIANCETF_ENFORCEMENT_MODE=hard_fail` overrides that, so leave the variable off for that configuration's job.

## Modules that require hashicorp/aws

Terraform installs a provider per source address. The provider checks resources in the root module and in child modules that themselves require `registry.compliance.tf/compliancetf/aws`. Every other child module gets `hashicorp/aws`, not compliancetf/aws, even when the root module uses compliancetf/aws:

- A module that lists `hashicorp/aws` in its own `required_providers`. Every terraform-aws-modules module does this.
- A module that declares no `aws` provider requirement at all. Terraform reads its `aws_*` resources as needing `hashicorp/aws` (`terraform providers` shows it), so most in-house modules are in this group too.

The provider never sees those resources, so they are not checked.

You have three options:

- For a module you own, add `aws = { source = "registry.compliance.tf/compliancetf/aws" }` to its own `required_providers`. Its resources then use the root's compliancetf/aws configuration and are checked.
- Use the versions of terraform-aws-modules that compliance.tf serves, with the controls built into the modules.
- Keep such modules unchecked and give them their own `hashicorp/aws` configuration. Add `hashicorp/aws` under a second local name, and copy the settings of your main provider block (region, profile, `assume_role` and so on) into a block for that name:

  ```hcl
  terraform {
    required_providers {
      aws = {
        source  = "registry.compliance.tf/compliancetf/aws"
        version = "6.70.0"
      }
      aws-upstream = {
        source  = "hashicorp/aws"
        version = "6.70.0"
      }
    }
  }

  provider "aws" {
    region = "us-east-1"
  }

  provider "aws-upstream" {
    region = "us-east-1"
  }

  module "vpc" {
    source = "terraform-aws-modules/vpc/aws"
    # no providers argument
  }
  ```

  A module that requires `hashicorp/aws` and has no `providers` argument uses the default `hashicorp/aws` configuration of its parent, here the `aws-upstream` block. Terraform and OpenTofu print a "Duplicate required provider" warning for this layout; the run uses each block for its own provider. Resources in those modules stay unchecked.

A `providers` argument that maps the module's `aws` to a configuration of the root module fails with "Provider type mismatch". `providers = { aws = aws }` fails because the root `aws` is compliancetf/aws. `providers = { aws = aws-upstream }`, or an alias of it, fails too. Remove the argument. Only the default `aws-upstream` configuration reaches such modules.

## Examples

Each directory in [examples/](../examples/) is a complete configuration with a `README.md` and the expected output.

| Example | Shows | Expected plan |
|---------|-------|---------------|
| [basic](../examples/basic) | A compliant RDS instance; a quick setup check | Succeeds, no compliance diagnostics |
| [cis-complete](../examples/cis-complete) | Every resource type the CIS bundle checks, configured to pass every control, with the control id next to each setting | Succeeds, 23 resources, no compliance diagnostics |
| [hard-fail](../examples/hard-fail) | Violations in `hard_fail` mode | Fails with 4 errors and 1 warning |
| [soft-fail](../examples/soft-fail) | The same violations in the default `soft_fail` mode | Succeeds with 5 warnings |
| [exception](../examples/exception) | Self-service exceptions, with every entry attribute and `match` variable explained | Succeeds only with a development build, which trusts the test key that signs its org profile. Organization profiles are not available, so release builds cannot use exceptions |
| [custom-bundle](../examples/custom-bundle) | A signed team bundle next to the embedded CIS bundle | Fails with 1 error and 1 warning; needs a development build |

The 23 resources of cis-complete are more than the 11 checked types: several resources share a type (two security groups, two ingress rules), and the rest are the VPC, subnets, KMS key and other resources they need. The exception and custom-bundle examples sign their profile or bundle with the test key, which only a development build (`make build-dev`) trusts.
