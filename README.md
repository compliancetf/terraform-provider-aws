# compliance.tf provider for AWS

`compliancetf/aws` is the AWS provider for Terraform and OpenTofu. It has compliance controls built in. It runs the official `hashicorp/aws` provider unchanged. Before Terraform calls AWS, it checks your `aws_*` resources against signed controls. A resource that breaks a control gets a warning or fails the plan. The message includes the control id, the setting to change, and a link to the control's docs.

This is a product of [compliance.tf](https://compliance.tf), by Anton Babenko, maintainer of terraform-aws-modules. User documentation lives on the **[compliance.tf docs site](https://compliance.tf/docs/provider/)**. This repository holds the source code and the documents for readers of that code.

## Get started

Change the provider source. Keep the version you run today. compliancetf/aws X.Y.Z runs hashicorp/aws X.Y.Z:

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

Then run `terraform init` and `terraform plan`. The default `soft_fail` mode only warns. No run fails on a finding. A config with no resources in state needs nothing more. To see findings, plan [examples/soft-fail](examples/soft-fail).

A config that already has resources in state also needs `terraform state replace-provider`. Do this in every workspace and every state. Follow the **[Quickstart](https://compliance.tf/docs/provider/quickstart/)** for the backup, the OpenTofu address, and how to switch back. That command has no module filter. Do not run it on a state that holds resources of modules that stay on `hashicorp/aws`. Resources of child modules that need `hashicorp/aws`, like every terraform-aws-modules module, are not checked. [Which modules are checked](https://compliance.tf/docs/provider/modules/) lists the options.

## Documentation

**Using the provider**, on the compliance.tf docs site:

| Page | For |
|---|---|
| [Overview](https://compliance.tf/docs/provider/) | What it checks, where it acts, what it does not do, and what it contacts |
| [Quickstart](https://compliance.tf/docs/provider/quickstart/) | Switch one config from `hashicorp/aws`, read a finding, switch back |
| [Roll out and run in CI](https://compliance.tf/docs/provider/roll-out/) | Modes, `hard_fail` in CI, evidence records, caches, upgrades |
| [Which modules are checked](https://compliance.tf/docs/provider/modules/) | Root and child modules, terraform-aws-modules, the `providers` argument |
| [Reference](https://compliance.tf/docs/provider/reference/) | Settings, variables, diagnostics, CIS controls and limits, explained |

**Inside the provider**, in this repository:

| Document | For |
|---|---|
| [docs/architecture.md](docs/architecture.md) | How a request flows through the proxy, how `hashicorp/aws` and bundles are verified, the caches and the evidence format, with the code paths |
| [docs/reference.md](docs/reference.md) | The exact settings, variables, diagnostics fields, controls and limits of this release, frozen with each tag |
| [docs/performance.md](docs/performance.md) | Startup cost, what the caches save, and how to reproduce the measurements |
| [CHANGELOG.md](CHANGELOG.md) | Release notes, newest first |
| [DEVELOPING.md](DEVELOPING.md) | Build, test, conformance and release, for maintainers |

Where the docs site and `docs/reference.md` at your release tag differ on a setting name or value, the tag is right for that release.

## How it works

Terraform starts this provider like it starts any provider. The provider starts the pinned, verified `hashicorp/aws` binary as a subprocess. It sits between the two on the plugin protocol. It checks each resource at plan, before and after apply, and on refresh and import. A violation warns or, in `hard_fail`, fails the plan and stops the apply before it reaches `hashicorp/aws`. The provider never changes a value you wrote. [docs/architecture.md](docs/architecture.md) has the details.

## Examples

Each directory in [examples/](examples/) is a complete config with a `README.md` and the expected output: [basic](examples/basic), [cis-complete](examples/cis-complete), [soft-fail](examples/soft-fail), [hard-fail](examples/hard-fail), [exception](examples/exception) and [custom-bundle](examples/custom-bundle).

## Data and trust

- `terraform init` downloads the provider from registry.compliance.tf. Release archives are signed with the compliance.tf release key ([gpg-public-key.asc](gpg-public-key.asc)). Terraform checks this at `terraform init`.
- At run time the provider downloads `hashicorp/aws` from releases.hashicorp.com. It does this only when no verified copy is found. It checks the HashiCorp signature and the pinned checksum before it starts the binary.
- With `org_id` and `COMPLIANCETF_ORG_ID` unset, the provider does not contact compliance.tf at run time. It never sends your config, state, or AWS credentials to compliance.tf.
- Checks are written to local, hash-chained evidence records. Of each resource they hold the resource id and identity, and no other attribute values.

The verification steps and the record format are in [docs/architecture.md](docs/architecture.md).

## Questions and feedback

Open an [issue](https://github.com/compliancetf/terraform-provider-aws/issues) for bugs, questions, and feature requests. This repository does not accept pull requests. [CONTRIBUTING.md](CONTRIBUTING.md) lists what to include in an issue.

Report security problems privately through [GitHub security advisories](https://github.com/compliancetf/terraform-provider-aws/security/advisories/new). Do not use a public issue.

## License

[Mozilla Public License 2.0](LICENSE). This is the same license as `hashicorp/aws`.
