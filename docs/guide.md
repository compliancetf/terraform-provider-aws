# Using the provider day to day

How to run the compliance.tf provider for AWS in daily work and in CI, and what to do with its findings. Start with the [README](../README.md) to install it. Every setting is in the [reference](reference.md); where this guide is shorter, follow the reference.

## Enforcement modes

The mode decides what a violated control does:

| Mode | Blocking `deny` violation | `warn` violation |
|------|---------------------------|------------------|
| `hard_fail` | Error: the plan fails and the apply is not forwarded | Warning |
| `grandfather` | Error, except a violation that a baseline can cover: a warning at plan, and apply blocks it unless a verified verdict lists a matching baseline entry | Warning |
| `soft_fail` (default) | Warning | Warning |
| `advisory` | No diagnostic, evidence record only | No diagnostic, evidence record only |

The table is the outcome at plan and before apply. An existing resource with no planned change (planned and prior state equal and fully known) is the exception at plan: a blocking violation of it is a warning with the note "No change planned: this violation warns until the resource changes; any change to it is blocked." So turning on `hard_fail` does not fail the plan for non-compliant resources you leave alone, but the plan of any change to them fails.

The mode comes from three places: `enforcement_mode` in the `compliance {}` block, the `COMPLIANCETF_ENFORCEMENT_MODE` variable and the floor of a signed organization profile. The strictest one wins, in the order `advisory < soft_fail < grandfather < hard_fail`. So `soft_fail` in the configuration cannot lower a stricter variable or floor.

`grandfather` is for existing resources that an organization accepts for now:

- It blocks like `hard_fail`.
- At plan, a violation is a warning (`pending exemption: baseline <control id>`) instead of an error when the control's signed coverage allows baselines and the control reads no sensitive attribute. This happens even with no baseline file.
- Apply blocks that violation unless a verified verdict lists a matching entry of the signed baseline. A verified verdict is the `compliancetf.verdict/v1` file that `ctfkit gate` writes for a saved plan. It is signed with a key that the signed organization profile lists under `verdict.public_keys`, and the provider checks it at the first apply. A plan can therefore pass with pending warnings while its apply is blocked.
- A `baseline_file` that cannot load fails configuration: the signed profile lists no baseline keys, `COMPLIANCETF_BASELINE_KEY_FILE` is missing or not a usable key, or the signature does not verify.
- With no baseline loaded, the provider warns once that every violation is treated as new.

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
- With an organization, a run that needs a floor statement (a governed organization, or a signed profile that lists bundles) under `floor_mode: online` fetches it from compliance.tf at every start. Such jobs need `COMPLIANCETF_TOKEN` and network access, and fail configuration without them even when the profile and bundles are cached. Only `floor_mode: airgap` with its floor file runs without the service. See [Environment variables](reference.md#environment-variables).
- `COMPLIANCETF_DIAGNOSTICS` chooses the lines each finding prints in the CI log (see [Reading diagnostics](#reading-diagnostics)).

## Caches

The provider keeps two kinds of cached files:

- Signed organization bundles and profiles fetched from compliance.tf. `COMPLIANCETF_CACHE_DIR` sets where they go.
- The `hashicorp/aws` binary that the provider downloads and verifies, and the cached upstream schema. These always stay under `compliancetf` in the user cache directory (`$XDG_CACHE_HOME` or `~/.cache` on Linux, `~/Library/Caches` on macOS, `%LocalAppData%` on Windows); `COMPLIANCETF_CACHE_DIR` does not move them. A `hashicorp/aws` of the pinned version in Terraform's plugin directories is used before any download.

In CI, persist both between jobs, or accept that each fresh runner downloads and verifies `hashicorp/aws` again. A restored cache directory must be owned by the job user and not writable by group or others, or the provider skips it with a warning. The ownership and ACL rules are under [Environment variables](reference.md#environment-variables), and [performance.md](performance.md) has the startup costs.

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
| `default` (unset or empty) | fix, docs, and how to waive when an exception file can |
| `minimal` | fix only |
| `full` | all, including severity, mode, stage and framework references |
| a comma list, such as `fix,docs,frameworks` | the fields named |

The setting changes only what is shown; results, evidence and exit codes stay the same. Lines that explain the situation, such as a value unknown until apply or a pending exemption, always print. The fields are listed under [Diagnostics](reference.md#diagnostics).

## Upgrading

compliancetf/aws X.Y.Z runs hashicorp/aws X.Y.Z, so upgrading the provider upgrades `hashicorp/aws` to the same version. Keep the `version` constraint and lock file workflow you use for `hashicorp/aws`, and run `terraform init -upgrade` as before. A release can change the embedded controls, so read [CHANGELOG.md](../CHANGELOG.md) first.

Fixes to the compliance.tf layer alone ship as `X.Y.Z-compliancetf.N`, and betas as `X.Y.Z-beta.N`. Terraform never selects a prerelease from a range constraint, so to use one, pin it exactly (`version = "6.70.0-compliancetf.1"`). See [Versions](reference.md#versions).

## Findings you cannot fix yet

Without an organization there are no exceptions. Keep the configuration that has the finding on `soft_fail` (or `advisory`) and make the others `hard_fail`. A CI job that sets `COMPLIANCETF_ENFORCEMENT_MODE=hard_fail` overrides that, so leave the variable off for that configuration's job. An `exceptions_file` is ignored with a warning until a signed organization profile allows it.

With an organization, compliance.tf issues a signed profile that can allow:

- Self-service exceptions: entries in `exceptions_file` for the controls the profile lists under self-service, each with an expiry. See [examples/exception](../examples/exception).
- Signed exception grants, one file per grant, in `exception_grants_dir`.
- Grandfather baselines for existing resources, used in `grandfather` mode (see [Enforcement modes](#enforcement-modes)).

Each kind applies only to the controls whose signed coverage allows it. See [Bundles and exceptions](reference.md#bundles-and-exceptions).

## Modules that require hashicorp/aws

Terraform installs a provider per source address. A child module that lists `hashicorp/aws` in its own `required_providers` gets `hashicorp/aws`, not compliancetf/aws, even when the root module uses compliancetf/aws. Every terraform-aws-modules module does this. The provider never sees those resources, so they are not checked.

You have two options:

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
| [exception](../examples/exception) | Self-service exceptions, with every entry attribute and `match` variable explained | Succeeds; needs a signed org profile (signed with the test key for a development build) |
| [custom-bundle](../examples/custom-bundle) | A signed team bundle next to the embedded CIS bundle | Fails with 1 error and 1 warning; needs a development build |

The 23 resources of cis-complete are more than the 11 checked types: several resources share a type (two security groups, two ingress rules), and the rest are the VPC, subnets, KMS key and other resources they need. The exception and custom-bundle examples sign their profile or bundle with the test key, which only a development build (`make build-dev`) trusts.
