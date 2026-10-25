# compliance.tf provider for AWS

`compliancetf/aws` is the AWS provider for Terraform and OpenTofu with compliance controls built in. It runs the official `hashicorp/aws` provider unmodified and checks `aws_*` resources against signed controls before Terraform calls AWS. A resource that breaks a control warns, or fails the plan, with the control id, its framework references and the fix.

It is a product of [compliance.tf](https://compliance.tf), by Anton Babenko, maintainer of terraform-aws-modules.

## Why use it

- You keep your code. Existing `aws_*` resources stay as they are; you change the provider `source`.
- Checks run wherever Terraform runs. The controls are part of the provider, so a local `terraform apply` is checked the same way as a CI run, without a separate pipeline step.
- Violations can be stopped before they reach AWS. In `hard_fail` mode a violated `deny` control found at plan or before apply stops the run, so the resource is not created or changed and there is no finding to clean up later. `warn` controls stay warnings.
- Each finding names its clause. Errors list the control, its framework references (for example `cis_aws:2.2.1`) and the setting to change.
- Nothing is forked. compliancetf/aws X.Y.Z runs hashicorp/aws X.Y.Z, taken from your plugin cache or downloaded from HashiCorp (with its signature checked), and verified against a pinned checksum before it starts. Your version constraints and lock file workflow stay the same.
- You can leave at any time. To switch back to `hashicorp/aws`, change the source back, remove the `compliance {}` block, run the state command in reverse and `terraform init`.

## Get started

1. Change the provider source. Keep your `version` constraint: the version numbers match hashicorp/aws.

   ```hcl
   terraform {
     required_providers {
       aws = {
         source  = "registry.compliance.tf/compliancetf/aws" # was "hashicorp/aws"
         version = "~> 6.67"
       }
     }
   }
   ```

2. If the configuration already has resources in state, point them at the new provider once. This changes only the provider address recorded in state, not your resources.

   ```bash
   terraform state replace-provider registry.terraform.io/hashicorp/aws registry.compliance.tf/compliancetf/aws
   ```

3. Run `terraform init` and `terraform plan` as usual.

By default (`soft_fail`) the provider only warns, so you can see what it finds without blocking anyone; warnings do not change the exit code of `terraform plan`. When you are ready, make violations fail the plan:

```hcl
provider "aws" {
  region = "us-east-1"

  compliance {
    enforcement_mode = "hard_fail"
  }
}
```

You can also set `COMPLIANCETF_ENFORCEMENT_MODE=hard_fail` in CI for every configuration at once; the strictest setting wins. An unencrypted EBS volume then stops the plan:

```
Error: [ebs_volume_encryption_at_rest_enabled] EBS volumes must be encrypted.

  with aws_ebs_volume.data,
  on main.tf line 18, in resource "aws_ebs_volume" "data":
  18:   encrypted         = false

Fix: Set encrypted = true.
Docs: https://compliance.tf/docs/controls/aws/ebs_volume_encryption_at_rest_enabled/
```

`COMPLIANCETF_DIAGNOSTICS` chooses the lines after the source snippet; `full` adds severity, mode, stage and framework references (see [docs/reference.md](docs/reference.md#diagnostics)).

The provider is tested with Terraform 1.5 and later and with OpenTofu; replacing a resource that has an identity needs Terraform 1.16.6 or later (see [Limitations](docs/reference.md#limitations)). The [examples](#examples) are complete configurations to start from.

## What is included

The provider ships with a CIS baseline for AWS: 18 controls on 11 resource types, with checks for encryption, public access, backup retention, deletion protection, and SSH and RDP ingress on those types. It is free, built into the binary, and needs no account or token. Resource types without a control are not checked. The controls are listed in [docs/reference.md](docs/reference.md#cis-controls), and each error links the control's docs page, which names its CIS references.

Bundles for other frameworks, organization rules and exceptions come from [compliance.tf](https://compliance.tf). Without them there are no exceptions: use the default warning mode for resources you cannot fix yet.

## Examples

Each directory in [examples/](examples/) has a `README.md` with how to run it and the expected output.

| Example | Shows | Expected plan |
|---------|-------|---------------|
| [basic](examples/basic) | A compliant RDS instance; a quick setup check | Succeeds, no compliance diagnostics |
| [cis-complete](examples/cis-complete) | Every resource type the CIS bundle checks, configured to pass every control, with the control id next to each setting | Succeeds, 23 resources, no compliance diagnostics |
| [hard-fail](examples/hard-fail) | Violations in `hard_fail` mode | Fails with 4 errors and 1 warning |
| [soft-fail](examples/soft-fail) | The same violations in the default `soft_fail` mode | Succeeds with 5 warnings |
| [exception](examples/exception) | Self-service exceptions, with every entry attribute and `match` variable explained | Succeeds; needs a signed org profile (signed with the test key for a development build) |
| [custom-bundle](examples/custom-bundle) | A signed team bundle next to the embedded CIS bundle | Fails with 1 error and 1 warning; needs a development build |

## What it does not do

- It does not make you compliant with CIS or any other framework. It checks the controls it has, on the resources Terraform manages through it.
- It is not a monitor. It sees a resource only when Terraform plans, applies, refreshes or imports it, and does not discover resources Terraform does not manage. Keep AWS Config, Security Hub or your scanner for continuous detection.
- It does not check resources inside modules that declare `hashicorp/aws` in their own `required_providers`, which includes terraform-aws-modules. Terraform installs `hashicorp/aws` separately for those modules. For terraform-aws-modules, compliance.tf serves versions with the controls built into the modules.
- It checks settings on single resources, not how resources fit together.
- It denies or warns. It never changes a value you wrote.
- Anyone who can edit the configuration can change the provider source or the mode. Protect those lines in code review.

## Data and trust

- `terraform init` downloads the provider from registry.compliance.tf. At run time the provider sends no configuration, state or credentials to compliance.tf. It contacts releases.hashicorp.com only to download hashicorp/aws when the binary is not already cached, and compliance.tf only when you configure an organization (`org_id`), to fetch its signed profile and bundles.
- Control bundles are signed by compliance.tf and verified against keys built into the provider. A bundle that fails verification is not loaded and the run stops.
- Every check writes a record to a local evidence directory (`.terraform/compliancetf/evidence` by default): the control, the resource address and its identifiers (id and identity), the result and the mode. Other attribute values are not recorded. Each line is hash-chained to the one before it, so a line edited or removed in the middle of a file shows; a file cut short at the end does not. The files are local: copy them to write-once storage if you rely on them as evidence.
- Release archives are signed with the compliance.tf release key, which Terraform checks at `terraform init`.

All settings, modes and known limitations are in [docs/reference.md](docs/reference.md).

## Questions and feedback

Open an [issue](https://github.com/compliancetf/terraform-provider-aws/issues) for bugs, questions and feature requests. This repository does not accept pull requests. [CONTRIBUTING.md](CONTRIBUTING.md) lists what to include in an issue.

Report security problems privately through [GitHub security advisories](https://github.com/compliancetf/terraform-provider-aws/security/advisories/new), not in a public issue.

## License

[Mozilla Public License 2.0](LICENSE), the same license as `hashicorp/aws`.
