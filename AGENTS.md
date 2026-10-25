# AGENTS.md

Guidance for coding agents working in this repository. Build, test and architecture details for people are in `DEVELOPING.md`; after editing any doc, run `make doc-drift` (it fails if a name removed in v2 reappears).

## Public repository

Everything committed here is public: code, comments, commit messages, branch names, pull request and issue text. `make test` runs `scripts/check-no-private-content.sh`; keep it passing. Never add references to private repositories, internal tracker ids, local paths, customer names or internal planning notes. Machine-local notes belong in an ignored local file, not in the tree.

The repository does not accept pull requests from outside the maintainer team. Users open issues (see `CONTRIBUTING.md`).
## Repository Overview

This is the **compliance.tf Terraform Provider** (`compliancetf/aws`), a gRPC delegating provider proxy that enforces compliance controls at the Terraform provider level on raw `aws_*` resources.

The proxy sits between Terraform Core and the upstream `hashicorp/aws` provider, intercepting RPCs to validate resource configurations against signed control bundles. It does NOT fork or modify the upstream AWS provider.

## Architecture

```
Terraform Core  <-- tfplugin5 gRPC -->  compliance.tf proxy (this repo)  <-- tfplugin5 gRPC -->  hashicorp/aws (subprocess)
                                              |
                                        hook.Evaluator = lifecycle.Hook
```

- **Raw gRPC proxy** (`internal/proxy/serve.go`, `internal/rawgrpc`): go-plugin serves protocol 5. Intercepted methods (`internal/proxy/server5.go`, `route5*.go`) decode into the generated `internal/tfplugin/tfplugin5` types, change only the fields they own and re-encode; unknown fields survive. Every other method of the pinned proto is forwarded to upstream as undecoded bytes. A method absent from the pinned proto returns `Unimplemented`.
- **Route table**: `internal/tfplugin/routes_gen.go` is generated from the vendored protos; `classes.json` (protected) classes each method `intercept` or `passthrough`. Regenerate with `make proto`.
- **Upstream**: the real `hashicorp/aws` binary runs as a go-plugin subprocess (`internal/upstream/launch.go`); `COMPLIANCETF_*` variables are filtered from its environment.
- **Hook**: `internal/hook` is the evaluator contract (Validate, Plan, Apply stages). `main` serves the lifecycle evaluator (`lifecycle.Hook`), which evaluates the signed bundles at plan, apply, refresh and import.
- **PlannedPrivate envelope** (`internal/proxy/private.go`): plan-time compliance data rides in `planned_private` only, never in state.
- **NOT using** `terraform-plugin-mux` or `tf5server`.

## Key Design Decisions

- **Never overwrite explicit user config values** - Terraform consistency rules forbid it. Deny or warn only. Auto-defaulting null or unset values is not implemented.
- **`compliance {}` nested block** - not top-level attributes. Strip before forwarding to upstream.
- **Control bundles**: Hybrid delivery - CIS baseline embedded in binary, premium bundles fetched from API.
- **License**: MPL 2.0 (see `LICENSE`).

## Build & Development

```bash
make build          # provider binary (release keyring: fails at Configure until a bundle key exists)
make build-dev      # -tags ctftest: test keyring, loads the embedded CIS bundle
make test           # hygiene, doc-drift, go test ./... (plain and -tags ctftest), test/fakeupstream module
GOTOOLCHAIN=go1.26.2 make lint   # golangci-lint is built with go1.26
make conformance    # scenarios against the fake upstream (TF=/path/to/tofu for OpenTofu)
make proto          # re-vendor protos, regenerate types and route table
make doc-drift      # fail on names v2 removed
make release-dry-run   # GoReleaser snapshot, no publish
make test-terraform # validate test/fixtures/ (needs CTFTEST_UPSTREAM_PATH)
make dogfood        # plan test/fixtures/, check the CIS blocks each lists (needs CTFTEST_UPSTREAM_PATH)
make pin VERSION=X.Y.Z   # per-pin artifacts for hashicorp/aws X.Y.Z (scripts/pin.sh; needs terraform, jq, network)

# Run with Terraform - REQUIRED: set TF_CLI_CONFIG_FILE before any terraform command
export TF_CLI_CONFIG_FILE="$PWD/.terraformrc"   # from the repo root
export CTFTEST_UPSTREAM_PATH=/path/to/terraform-provider-aws_v6.x.y_x5   # with make build-dev
terraform -chdir=test/fixtures/non-compliant-rds plan
```

### Terraform Dev Setup

Copy `.terraformrc.example` to `.terraformrc` (ignored by version control) and point its `dev_overrides` at this directory. Always set `TF_CLI_CONFIG_FILE` before running `terraform`:

```bash
export TF_CLI_CONFIG_FILE="$PWD/.terraformrc"   # from the repo root
```

With `dev_overrides`, skip `terraform init` / `tofu init`: both CLIs plan and apply with the local binary directly, and OpenTofu `init` fails for a provider that only has a dev override. No lock file is needed.

### Upstream Provider

The provider always runs the real `hashicorp/aws` binary as a subprocess: the version pinned in `pins.json`, found in Terraform's plugin directories or downloaded and verified against the pin (`upstream.Discover`). Go tests and conformance use the fake upstream in `test/fakeupstream` (a separate Go module) instead.

```bash
# Air-gapped: point at a binary that matches the pin (anything else is fatal).
export COMPLIANCETF_UPSTREAM_PATH=/path/to/terraform-provider-aws_v6.x.y_x5
make build
terraform plan
```

### Environment Variables

| Name | Scope | Meaning |
|---|---|---|
| `COMPLIANCETF_UPSTREAM_PATH` | runtime | explicit upstream binary (air-gap); must match the pin |
| `CTFTEST_UPSTREAM_PATH` | `ctftest` build tag only | unpinned upstream binary for tests; release builds do not compile it |
| `COMPLIANCETF_CONFORMANCE_TAP` | `conformance` build tag only | file the proxy appends one JSON line per apply to (upstream vs returned `new_state` sha256) |
| `COMPLIANCETF_CONFORMANCE_PINS` | `conformance` build tag only | pins file that replaces the embedded `pins.json`; the conformance runner pins the fake upstream with it and passes the binary as `COMPLIANCETF_UPSTREAM_PATH` |
| `COMPLIANCETF_CONFORMANCE_EVALUATOR` | `conformance` build tag only | test evaluator: empty (no-op), `deny:<type>` or `warn:<type>` |
| `COMPLIANCETF_CONFORMANCE_RPCSEQ` | `conformance` build tag only | file the recording evaluator writes the RPC sequence to; exclusive with `COMPLIANCETF_CONFORMANCE_EVALUATOR` |

Release builds must not carry `-tags=conformance` or `-tags=ctftest`. The `COMPLIANCETF_*` variables are stripped from the upstream's environment. `scripts/doc-drift.sh` keeps names removed in v2 out of the tree.

### Conformance

`test/conformance` (build tag `conformance`) builds the proxy and the fake upstream, writes a CLI config with `dev_overrides`, and runs each `scenarios/<name>/steps.json` with the Terraform or OpenTofu binary given by `-tf`:

```bash
make conformance                         # TF defaults to terraform on PATH
make conformance TF=$(command -v tofu)
make conformance RUN=rpcseq UPDATE=1     # rewrite the RPC-sequence goldens of TF's version
```

The binary's version picks its cell in `matrix.json`; a scenario whose `requires` lists a feature the cell lacks is skipped. Scenarios never run `init`. `.github/workflows/conformance.yml` runs every cell on demand (`workflow_dispatch`).

### Releasing

Version parity: compliancetf/aws X.Y.Z proxies hashicorp/aws X.Y.Z exactly. Users migrate by changing only `source` in `required_providers`; their `version` constraint and lock file workflow stay. The release tag `vX.Y.Z` must equal the `pins.json` version: `tools/releasemeta` (run by `release.yml` on every `v*` tag) accepts only the pinned X.Y.Z, X.Y.Z-beta.N or X.Y.Z-compliancetf.N (leading `v` optional) and fails the release otherwise. One release per hashicorp/aws release, forward only from 6.67.0 (no backfill of older upstream versions). Never republish a version: lock files hold its hashes.

Prereleases share the pinned base version:

| Kind | Version | Use |
|---|---|---|
| beta | `X.Y.Z-beta.N` | before the X.Y.Z release |
| proxy-only fix | `X.Y.Z-compliancetf.N` | a fix on top of X.Y.Z; spell `compliancetf` in full |

Terraform never selects a prerelease from a range constraint, so users opt in by pinning the exact version (`version = "6.67.0-compliancetf.1"`).

`min_wrapper_version` (org profile and floor statement) orders versions by `internal/trust/wrapper.go` (vectors in `internal/trust/testdata/wrapper_order.json`): the base X.Y.Z first; within one base `beta.N` < release < `compliancetf.N`, N numeric. Any other prerelease (for example `rc.1`) ranks with the betas, below the release and every `compliancetf.N`; against a beta or another such prerelease of the same base it is unordered, so that pair fails closed. Floor signers issue canonical forms only. A floor can therefore force a proxy fix: `6.67.0-compliancetf.1` refuses `6.67.0` and admits `6.67.0-compliancetf.1`, `6.67.0-compliancetf.2` and `6.68.0`. Bundle `version_range` checks treat `X.Y.Z-beta.N` and `X.Y.Z-compliancetf.N` as X.Y.Z.

```bash
# After the pin PR for X.Y.Z merges (see below), tag the merge commit on master
git tag vX.Y.Z <merge SHA>
git push origin vX.Y.Z
gh release view vX.Y.Z
```

Each release proxies one hashicorp/aws release. Per upstream release, `make pin VERSION=X.Y.Z` (clean tree) regenerates everything that depends on the pin: `pins.json` (`tools/pinupstream`), `testdata/schemas/aws-subset.json` (checked against the new pin), the CIS type table `internal/embedded/testdata/schema_compat.tsv` and manifest `schema_compat_digest` (`tools/cispin`), and `cis_ctftest.tar.gz`. It stops with a message when the pin needs an owner decision (outside the manifest `version_range`, a control read gone or turned Computed). If the CIS manifest changed, commit, then the owner re-signs `cis.tar.gz`: `KEY=<production bundle key PEM> scripts/owner-sign-cis.sh`. Re-running for the current pin changes nothing.

`.github/workflows/upstream-watch.yml` (daily, or dispatched with an optional `version`) opens that PR: `tools/upstreamwatch` picks the oldest hashicorp/aws release newer than `pins.json` from the registry versions API, one pin PR at a time (branch `pin/hashicorp-aws-X.Y.Z`; newer releases wait for it to merge; a pin branch without an open PR fails the run). The workflow runs `make pin`, commits and opens `chore(pin): hashicorp/aws X.Y.Z`, as a draft carrying the message when `make pin` stopped for an owner decision. The PR body says whether `cis.tar.gz` needs re-signing. GITHUB_TOKEN PRs start no workflows; the owner runs the local gate, merges, then tags `vX.Y.Z`. No auto-merge, no auto-tag.

The embedded CIS manifest keeps provider and upstream `version_range` `">= 6.0.0, < 7.0.0"`. Premium bundles support every release from the floor: `releases.json` (repo root) holds the owner-set `floor` (oldest supported release) and the supported `releases`, floor first, pin last; `make pin` appends the new pin and keeps the previous pin's schema subset as `testdata/schemas/aws/<version>.json`. `ctf-bundlegen generate` writes provider and upstream `version_range` `">= <floor>, < <floor major + 1>.0.0"` and fails `E_SUPPORTED_SCHEMA` (naming control, read, version) unless every control holds on the schema of each supported release (`--supported-schemas`, default `testdata/schemas/aws`). To raise the floor: set `floor`, drop the releases below it from `releases` and delete their `testdata/schemas/aws/<version>.json`. A new major starts a new floor: commit `floor` and `releases` set to the new pin, then `make pin`.

Release artifacts (zip archives, SHA256SUMS, GPG signature) are built by GoReleaser.
The provider registry at `registry.compliance.tf` serves download metadata pointing to GitHub Release assets.

### Plugin Protocol Types

The generated `internal/tfplugin/tfplugin5` package is the only registrant of `tfplugin5.proto` in the binary. The proxy links only the `tftypes` and `tfprotov5` value types from `terraform-plugin-go`, never `tf5server`/`tf6server` (which would link its internal proto copy and panic on duplicate registration). `TestNoPluginGoServerLinked` in `internal/proxy/deps_test.go` guards this.

## Project Structure

```
main.go, wrapper.json          entry point: embeds wrapper.json, pins, HashiCorp key, CIS archive; wrapper.Load then wrapper.Serve
pins.json, keys/               pinned hashicorp/aws (tools/pinupstream) and the HashiCorp release key main.go embeds
releases.json                  release floor and supported releases of premium bundles (ctf-bundlegen)
internal/wrapper/              Config, Load (wrapper.json v1), Serve; evaluator.go serves lifecycle.Hook,
                               evaluator_conformance.go the test evaluator
internal/tfplugin/             vendored tfplugin5/6 protos (proto/, SOURCES.json), generated tfplugin5/, tfplugin6/,
                               routes_gen.go + classes.json (route table)
internal/rawgrpc/              raw frame codec and generic stream forwarder
internal/proxy/                serve.go, server5.go + route5*.go (intercepts), schema.go (compliance block),
                               private.go (envelope), classify.go, tap_conformance.go
internal/hook/                 Evaluator interface; hooktest/ recorder for tests
internal/upstream/             launch.go (subprocess), discover.go (pinned discovery), download.go, verify.go,
                               pins.go (pins format), execdir.go (private hashed copy)
internal/bundle, bundlegen,    bundle 2.0 format, generation, engine (celeng), lifecycle,      
  engine, lifecycle, trust,    DSSE trust, org profile, bundle fetch, evidence log
  profile, fetch, evidence/    (internal/lifecycle is the evaluator)
internal/exceptions, embedded/  signed grants and self-service sidecar; embedded CIS bundle (cis/ -> cis.tar.gz release, cis_ctftest.tar.gz ctftest)
pkg/engine/                    public selector engine facade over internal/engine (CompileSelector, Eval,
                               SchemaFromJSON); enginetest/ + testdata/ cross-check vectors for importers
cmd/ctfbundle, ctf-bundlegen/  bundle build/sign/verify and generation CLIs
tools/pinupstream, releasemeta/  write pins.json; release gate
test/fakeupstream/             separate module: fake v5 and v6 upstream binaries
test/conformance/              runner, matrix.json, scenarios/, rpcseq/ goldens, testdata/capabilities.json (build tag conformance)
scripts/                       proto.sh, proto-drift.sh, doc-drift.sh, check-no-private-content.sh, protected-paths.sh, smoke scripts
```

## Conventions

- **Go version**: `go.mod` says 1.26.2 (terraform-plugin-go v0.31.0 needs >= 1.25)
- **Dependencies**: Minimize. Core deps: `terraform-plugin-go` (value types only), `go-plugin`, `grpc`
- **Testing**: Unit tests per package (bufconn and the fake upstream for proxy tests); conformance scenarios for real Terraform/OpenTofu plan/apply cycles
- **Commits**: Follow conventional commits (`feat:`, `fix:`, `test:`, `docs:`)
- **No modifications to the upstream AWS provider** - it is a separate binary, treated as a black box

## External Naming Rule

In user-facing content, write "compliance.tf" (or the `COMPLIANCETF_` prefix for environment variables) and "terraform-aws-modules" in full; no abbreviations.
