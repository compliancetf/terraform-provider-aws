# compliance.tf provider for AWS

`compliancetf/aws` is the AWS provider for Terraform and OpenTofu with compliance controls built in. It runs the official `hashicorp/aws` provider unmodified and checks your `aws_*` resources against signed controls before Terraform calls AWS. A resource that breaks a control produces a warning or fails the plan, with the control id, the setting to change and a link to the control's docs.

It is a product of [compliance.tf](https://compliance.tf), by Anton Babenko, maintainer of terraform-aws-modules.

## How it works

- You change the provider `source`. Your resources, code and version numbers stay the same: compliancetf/aws X.Y.Z runs hashicorp/aws X.Y.Z.
- The provider checks each resource when Terraform plans it, again before apply, and on refresh and import. The checks run wherever Terraform runs, locally or in CI, with no extra pipeline step.
- A violated `deny` control fails the run in `hard_fail` mode and warns in the default `soft_fail` mode. A violated `warn` control warns in every mode but `advisory`, which only writes evidence. An existing resource with no planned change only warns, even in `hard_fail`; any change to it is blocked. When the configuration, the `COMPLIANCETF_ENFORCEMENT_MODE` variable and an organization profile set different modes, the strictest one wins.
- It warns or denies, and never changes a value you wrote.

## Before you start

- **Resources in child modules that require `hashicorp/aws` are not checked.** Every terraform-aws-modules module lists `hashicorp/aws` in its own `required_providers`, so Terraform installs `hashicorp/aws` separately for it and those resources bypass the checks. compliance.tf serves versions of terraform-aws-modules with the controls built into the modules. See [Modules that require hashicorp/aws](docs/guide.md#modules-that-require-hashicorpaws) for the options.
- **A module call that passes `providers = { aws = aws }` to such a module fails** with a provider type mismatch once the root `aws` provider is compliancetf/aws. The same guide section shows the fix.
- **What it checks.** The built-in CIS baseline has 18 controls on 11 resource types: encryption, public access, backup retention, deletion protection, and SSH and RDP ingress. Other resource types are not checked. Each check looks at one resource at a time. It is not a monitor: it sees a resource only when Terraform plans, applies, refreshes or imports it.
- **What it contacts.** `terraform init` downloads the provider from registry.compliance.tf. At run time it downloads `hashicorp/aws` from releases.hashicorp.com only when no verified copy is cached, and checks its signature and pinned checksum. It contacts compliance.tf only when you configure an organization. It never sends your configuration, state or AWS credentials to compliance.tf. Details are in [Data and trust](#data-and-trust).
- **Known limit.** Replacing a resource that has an identity needs Terraform 1.16.6 or later. Terraform 1.12 to 1.16.5 and OpenTofu block that apply; tainting the object first works, but destroys and recreates it. See [Limitations](docs/reference.md#limitations). The provider is tested with Terraform 1.5 and later and with OpenTofu.

## Quick start

Run `terraform providers` first. Its "Providers required by state" part shows the address your state records, and the module list shows which modules still require `hashicorp/aws`. The commands below use the Terraform address `registry.terraform.io/hashicorp/aws`; OpenTofu state usually records `registry.opentofu.org/hashicorp/aws`, and `tofu` takes the same commands.

1. Change the provider source. During the switch, pin the exact version you run today; the version numbers match hashicorp/aws.

   ```hcl
   terraform {
     required_providers {
       aws = {
         source  = "registry.compliance.tf/compliancetf/aws" # was "hashicorp/aws"
         version = "6.70.0"
       }
     }
   }
   ```

2. Run `terraform init`. It adds a lock file entry for the new address. If your team or CI runs on other platforms, add their hashes: `terraform providers lock -platform=linux_amd64 -platform=darwin_arm64` (list every platform you use).

3. Only if the configuration already has resources in state: back up the state and point it at the new provider. Do this in every workspace and every state; planning a workspace does not change its state.

   ```bash
   terraform state pull > state-default.backup.tfstate   # holds secrets: keep it out of git and CI logs
   terraform state replace-provider registry.terraform.io/hashicorp/aws registry.compliance.tf/compliancetf/aws
   ```

   This changes only the provider address recorded in state, not your resources. Add `-auto-approve` in non-interactive runs. Do not run it on a state that holds resources of modules that stay on `hashicorp/aws`: the command has no module filter.

4. Run `terraform init` again and review the lock file diff. The `hashicorp/aws` entry is removed only when neither the state nor any module still requires it.

5. Run `terraform plan`. In the default `soft_fail` mode findings are warnings and the exit code of `terraform plan` does not change. To see what findings look like, plan [examples/soft-fail](examples/soft-fail).

If something goes wrong part way, follow [Switch back](#switch-back) for that state, undoing only the steps you already did there; the reverse `replace-provider` is the normal way back. The backup is for last-resort recovery: `terraform state push state-default.backup.tfstate` refuses it once `replace-provider` has written a newer serial, and only `-force` overrides that check. `-force` overwrites whatever the state holds now, so use it only when you are sure nothing else changed that state since the backup.

## Roll out without blocking anyone

Start with the default `soft_fail` everywhere: findings are warnings and no run fails on them. When a configuration is clean, make violations fail the plan, either in the provider block or for every configuration of a CI job at once with `COMPLIANCETF_ENFORCEMENT_MODE=hard_fail`:

```hcl
provider "aws" {
  region = "us-east-1"

  compliance {
    enforcement_mode = "hard_fail"
  }
}
```

An unencrypted RDS instance then stops the plan:

```
Error: [rds_db_instance_encryption_at_rest_enabled] RDS instances must have storage encryption enabled.

  with aws_db_instance.non_compliant,
  on main.tf line 25, in resource "aws_db_instance" "non_compliant":
  25:   storage_encrypted       = false # deny

Fix: Set storage_encrypted = true.
Docs: https://compliance.tf/docs/controls/aws/rds_db_instance_encryption_at_rest_enabled/
```

The [guide](docs/guide.md) covers CI setup, all four modes, reading diagnostics and what to do with a finding you cannot fix yet.

## Switch back

The same steps in reverse, per configuration:

1. Set `source` back to `hashicorp/aws`. If you pinned a prerelease such as `6.70.0-compliancetf.1`, change the pin to the matching `6.70.0`. Remove the `compliance {}` block.
2. Run `terraform init`.
3. In every workspace and state: `terraform state replace-provider registry.compliance.tf/compliancetf/aws registry.terraform.io/hashicorp/aws` (on OpenTofu, the target is usually `registry.opentofu.org/hashicorp/aws`).
4. Run `terraform init` again, review the lock file diff, and run `terraform plan` for each state.

## Examples

Each directory in [examples/](examples/) is a complete configuration with a `README.md` and the expected output: [basic](examples/basic), [cis-complete](examples/cis-complete), [hard-fail](examples/hard-fail), [soft-fail](examples/soft-fail), [exception](examples/exception) and [custom-bundle](examples/custom-bundle). The [guide](docs/guide.md#examples) has the table of what each one shows.

## What it does not do

- It does not make you compliant with CIS or any other framework. It checks the controls it has, on the resources Terraform manages through it.
- It does not replace continuous detection. Keep AWS Config, Security Hub or your scanner for resources Terraform does not manage or that change outside Terraform.
- It checks settings on single resources, not how resources fit together.
- Anyone who can edit the configuration can change the provider source or the mode. Protect those lines in code review.

## Data and trust

- `terraform init` downloads the provider from registry.compliance.tf. Release archives are signed with the compliance.tf release key, which Terraform checks at `terraform init`.
- At run time the provider downloads `hashicorp/aws` from releases.hashicorp.com only when no verified copy is cached. It checks the HashiCorp signature and the pinned checksum before it starts the binary.
- It contacts compliance.tf only when you configure an organization (`org_id` and `COMPLIANCETF_TOKEN`), to fetch the organization's signed profile, bundles and floor statement. Those requests carry the compliance.tf token. Your configuration, state and AWS credentials are never sent.
- Control bundles are signed by compliance.tf and verified against keys built into the provider. A bundle that fails verification is not loaded and the run stops.
- Every check writes a record to a local evidence directory (`.terraform/compliancetf/evidence` by default): the control, the resource type, the operation, the resource id and identity, the result and the mode. The resource address is not recorded, so a record alone does not name the module or the `count` or `for_each` instance. Other attribute values are not recorded. Each line is hash-chained to the one before it, so a line edited or removed in the middle of a file shows; a file cut short at the end does not. The files are local: copy them to write-once storage if you rely on them as evidence.

## Documentation

| Document | For |
|---|---|
| [docs/guide.md](docs/guide.md) | Day-to-day use: modes, CI, caches, evidence, diagnostics, upgrades, findings you cannot fix yet |
| [docs/reference.md](docs/reference.md) | Every setting, mode, control, environment variable and limitation. Where the README or guide is shorter, follow the reference |
| [docs/performance.md](docs/performance.md) | Startup cost, caches and measurements |

## Questions and feedback

Open an [issue](https://github.com/compliancetf/terraform-provider-aws/issues) for bugs, questions and feature requests. This repository does not accept pull requests. [CONTRIBUTING.md](CONTRIBUTING.md) lists what to include in an issue.

Report security problems privately through [GitHub security advisories](https://github.com/compliancetf/terraform-provider-aws/security/advisories/new), not in a public issue.

## License

[Mozilla Public License 2.0](LICENSE), the same license as `hashicorp/aws`.
