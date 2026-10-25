# Developing the compliance.tf Terraform Provider

This guide covers how to build, test, and contribute to the compliance.tf Terraform Provider.

## Prerequisites

- **Go 1.26.2** or newer (`go.mod`; terraform-plugin-go v0.31.0 needs at least Go 1.25). CI reads the version from `go.mod`.
- **Terraform** or **OpenTofu**, for conformance tests and manual testing with `dev_overrides`
- **golangci-lint**, for `make lint`. If your golangci-lint was built with an older Go than your toolchain, pin the toolchain: `GOTOOLCHAIN=go1.26.2 make lint`.

## Quick Start

```bash
git clone https://github.com/compliancetf/terraform-provider-aws.git
cd terraform-provider-aws

make build   # provider binary ./terraform-provider-aws
make test    # all Go tests
```

## Make Targets

| Target | What it does |
|--------|--------------|
| `make build` | Build the provider binary |
| `make build-dev` | Build a local dev binary with `-tags ctftest`: the test keyring, and a non-release version (git describe) meets any well-formed bundle provider range. A plain `make build` checks the range exactly and fails it with a dev version |
| `make test` | `make hygiene` and `make doc-drift`, then `go test -v ./...`, `go test -tags ctftest` on every package but `test/bench` and the `test/fakeupstream` module |
| `make bench-gate` | p99 latency gate: `go run ./test/bench/gen -seed 1 -n 500`, then `TestP99Seeded` (a seeded delay must raise the p99), then `BenchmarkP99` (plan and apply_pre of every instance through a Lifecycle with `testdata/bench/reference-bundle.json`; every iteration is a cold-cache pass: fresh Lifecycle, empty decision memo and document cache; `-count 10`), then `cmd/benchgate`, which fails when the median p99 is above 120% of `test/bench/baseline/<runner-class>.json` or above 50 ms; run on an idle machine, `UPDATE=1 BENCH_NOTE="<how, hardware>"` rewrites the baseline (in a PR labelled `bench-baseline`); the runner class is `GOOS-GOARCH` unless `COMPLIANCETF_BENCH_RUNNER_CLASS` is set, and a missing baseline fails. The committed `darwin-arm64` baseline was recorded under load and is provisional: the owner re-records it on an idle machine |
| `make lint` | `make hygiene`, then `golangci-lint run` |
| `make hygiene` | `scripts/check-no-private-content.sh` (self-test, then the tree): no bundle content outside the synthetic catalog, no agent or issue-tracker state, no home-directory paths or planning task ids, and no match of the uncommitted pattern list in `COMPLIANCETF_PRIVATE_PATTERNS_FILE` (default `.git/info/private-patterns`) |
| `make conformance` | Conformance scenarios against the fake upstream (see below) |
| `make proto` | Re-vendor the pinned `tfplugin5`/`tfplugin6` protos, regenerate Go types and the route table |
| `make doc-drift` | Fail if a removed name (see below) appears outside history |
| `make release-dry-run` | GoReleaser `check` and a snapshot build; no publish, no signing |
| `make test-terraform` | Build with `-tags ctftest`, then `terraform validate` every fixture in `test/fixtures/`; needs `CTFTEST_UPSTREAM_PATH` (see Manual Testing) |
| `make dogfood` | Build with `-tags ctftest`, then `terraform plan` every fixture against the real `hashicorp/aws` and check that the embedded CIS bundle blocks exactly the controls the fixture lists (`# dogfood-blocks: <id>`); needs `CTFTEST_UPSTREAM_PATH` |

## Architecture

```
Terraform / OpenTofu
    |  tfplugin5 gRPC
    v
internal/proxy/serve.go       go-plugin server, protocol 5, raw codec
    |
    +-- intercepted method --> internal/proxy/server5.go, route5*.go
    |                            decode into internal/tfplugin/tfplugin5 types,
    |                            call the hook (internal/hook), change only
    |                            owned fields, re-encode, forward
    |
    +-- passthrough method --> internal/rawgrpc   forward undecoded bytes
    |
    +-- not in pinned proto --> Unimplemented
    |
    v
internal/upstream/launch.go   hashicorp/aws as a go-plugin subprocess
                              (pinned, verified, run from a private hashed copy)
```

- `internal/tfplugin/routes_gen.go` is the route table, generated from the vendored protos by `make proto`. `internal/tfplugin/classes.json` assigns each method `intercept` or `passthrough`; generation fails for a method with no class.
- `internal/hook` defines the `Evaluator` the proxy calls at Configure and at the Validate, Plan and Apply stages. The released binary serves the lifecycle evaluator (`internal/wrapper/evaluator.go`: `lifecycle.Hook`).
- `internal/proxy/private.go` carries plan-time compliance data in `planned_private` and checks it at apply. It never writes into state.
- Apply returns the upstream `new_state` bytes unchanged. `internal/proxy/apply_invariant_test.go` and the conformance tap check this.
- The binary links terraform-plugin-go only for its value types, never `tf5server`/`tf6server`. `TestNoPluginGoServerLinked` (`internal/proxy/deps_test.go`) guards this, so the generated `tfplugin5` package is the only registrant of `tfplugin5.proto`.
- `main` finds the upstream with `upstream.Discover`: the `hashicorp/aws` version pinned in `pins.json` (written by `tools/pinupstream`), from `COMPLIANCETF_UPSTREAM_PATH`, Terraform's plugin directories or a download, verified against the pin before launch.
- `internal/bundle`, `bundlegen`, `engine`, `lifecycle`, `trust`, `profile`, `fetch` and `evidence` are the bundle, engine, trust and evidence packages; `cmd/ctfbundle` and `cmd/ctf-bundlegen` are their CLIs. `internal/lifecycle` is the evaluator on the RPC path.
- `internal/embedded` holds the signed CIS bundle archives built from `cis/` that the lifecycle loads (`cis.tar.gz`, production-signed, in release builds; `cis_ctftest.tar.gz`, test-signed, in `ctftest` builds); `internal/exceptions` reads signed grants and the self-service sidecar.

## Repository Structure

```
.
|-- main.go                     # entry point: wrapper.Load of the embedded inputs, then wrapper.Serve
|-- wrapper.json                # wrapper identity: address, upstream, resource prefix, CIS bundle, sink
|-- pins.json                   # pinned hashicorp/aws (tools/pinupstream), embedded by main.go
|-- keys/                       # HashiCorp release signing key (trust anchor), embedded by main.go
|-- internal/
|   |-- wrapper/                # Config, Load, Serve; evaluator.go (lifecycle.Hook), evaluator_conformance.go (tag conformance)
|   |-- tfplugin/               # vendored protos (proto/, SOURCES.json), generated tfplugin5/ and tfplugin6/,
|   |                           #   routes_gen.go, classes.json, generator tools module (tools/)
|   |-- rawgrpc/                # raw frame codec, generic stream forwarder
|   |-- proxy/                  # serve.go, server5.go, route5*.go, schema.go, private.go, classify.go
|   |-- hook/                   # Evaluator interface; hooktest/ recorder for tests
|   |-- upstream/               # launch.go, discover.go, download.go, verify.go, pins.go, execdir.go
|   `-- bundle/ bundlegen/ engine/ lifecycle/ trust/ profile/ fetch/ evidence/ exceptions/ embedded/   # lifecycle evaluator
|-- cmd/                        # ctfbundle (build/sign/verify bundles), ctf-bundlegen
|-- tools/                      # pinupstream (writes pins.json), releasemeta (release gate)
|-- test/
|   |-- fakeupstream/           # separate Go module: fake v5 and v6 upstream binaries
|   |-- conformance/            # runner, matrix.json, scenarios/, rpcseq/ goldens, testdata/ (build tag conformance)
|   `-- fixtures/               # Terraform configs for the smoke script
|-- examples/                   # example Terraform configurations
|-- scripts/                    # proto.sh, proto-drift.sh, doc-drift.sh, check-no-private-content.sh, protected-paths.sh, bump-goreleaser.sh, smoke scripts
`-- docs/                       # notes
```

## Testing

```bash
make test                                  # hygiene, doc-drift, plain and ctftest Go tests, fake upstream module
go test -tags ctftest ./...                # tests that need the ctftest-only hooks
go test ./internal/proxy/...               # one package
go test ./internal/proxy/ -run Invariant   # one test
cd test/fakeupstream && go test ./...      # the fake upstream module
```

Proxy tests start the fake upstream from `test/fakeupstream` or use in-memory gRPC (bufconn). They never contact AWS and need no Terraform binary.

## Conformance Tests

`test/conformance` builds the proxy (with `-tags conformance`) and the fake upstream, writes a CLI config whose `dev_overrides` point `registry.compliance.tf/compliancetf/aws` at the built proxy, and runs every scenario under `test/conformance/scenarios/` with one Terraform or OpenTofu binary:

```bash
make conformance                          # terraform on PATH
make conformance TF=$(command -v tofu)    # OpenTofu
make conformance RUN=rpcseq UPDATE=1      # rewrite the RPC-sequence goldens of TF's version
go test -count=1 -tags conformance ./test/conformance/... -tf "$(command -v terraform)"
```

- `-tf` is required. The binary's version selects its cell in `test/conformance/matrix.json`; a scenario whose `steps.json` `requires` a feature that cell lacks is skipped.
- Each scenario is a `main.tf` plus `steps.json` (commands, expected exit codes, output substrings to contain or exclude, `state_unchanged`, `expect_applies` (a minimum), `expect_no_applies`).
- Scenarios never run `init`; see the `dev_overrides` note below.
- `test/conformance/testdata/capabilities.json` pins the protocol minor and `server_capabilities` the proxy must advertise.
- `.github/workflows/conformance.yml` runs every matrix cell on demand (`workflow_dispatch` only).
- `test/conformance/nightly/` holds the nightly scenarios against the real `hashicorp/aws` in the sandbox account (`.github/workflows/nightly.yml`, manual `workflow_dispatch` only until pins.json and the sandbox are ready, build tags `conformance,nightly`). Their offline dry run: `go test -count=1 -tags conformance,nightly ./test/conformance/... -run Nightly -plan-only`. Setup and cleanup: `test/conformance/nightly/README.md`.

## Environment Variables

| Name | Build | Meaning |
|------|-------|---------|
| `COMPLIANCETF_UPSTREAM_PATH` | all | Explicit upstream binary (air-gap); must match the pinned checksum, anything else is fatal. |
| `CTFTEST_UPSTREAM_PATH` | `ctftest` tag only | Unpinned upstream binary for tests. Release builds do not compile the code that reads it. |
| `COMPLIANCETF_CONFORMANCE_TAP` | `conformance` tag only | File the proxy appends one JSON line per apply to, with the sha256 of the upstream and the returned `new_state`. |
| `COMPLIANCETF_CONFORMANCE_PINS` | `conformance` tag only | Pins file that replaces the embedded `pins.json`. The conformance runner pins the fake upstream in it and passes the binary as `COMPLIANCETF_UPSTREAM_PATH`, so pinned discovery verifies it as in a release build. |
| `COMPLIANCETF_CONFORMANCE_EVALUATOR` | `conformance` tag only | Test evaluator: empty for the no-op, `deny:<type>` or `warn:<type>`. |
| `COMPLIANCETF_CONFORMANCE_RPCSEQ` | `conformance` tag only | File the recording evaluator writes the RPC sequence to; exclusive with `COMPLIANCETF_CONFORMANCE_EVALUATOR`. |

`internal/upstream/launch.go` drops every `COMPLIANCETF_*` variable from the upstream's environment. Release builds must not be built with `-tags=conformance` or `-tags=ctftest`.

## Manual Testing with Terraform

```bash
make build-dev
export TF_CLI_CONFIG_FILE="$PWD/.terraformrc"
export CTFTEST_UPSTREAM_PATH=/path/to/terraform-provider-aws_v6.x.y_x5
terraform -chdir=test/fixtures/non-compliant-rds plan
```

`.terraformrc` is local to your checkout (ignored by version control). Create it with `dev_overrides` pointing at the repo root so Terraform uses the local binary:

```hcl
provider_installation {
  dev_overrides {
    "registry.terraform.io/compliancetf/aws" = "/path/to/terraform-provider-aws"
  }
  direct {}
}
```

The examples and `test/fixtures/` declare `source = "compliancetf/aws"`, which is `registry.terraform.io/compliancetf/aws`; under OpenTofu the same short source is `registry.opentofu.org/compliancetf/aws`, so add an override for that address too. A config that uses `registry.compliance.tf/compliancetf/aws` needs an override under that address instead. With `dev_overrides`, skip `terraform init` and `tofu init`: both CLIs plan and apply without it, and OpenTofu `init` fails for a provider that only has a dev override.

Use `make build-dev`: it embeds the test-signed CIS bundle and trusts the test keys. `CTFTEST_UPSTREAM_PATH` names an unpinned `hashicorp/aws` 6.x binary (Terraform's plugin cache has one after any `init`); `make test-terraform` and `make dogfood` write their own CLI config and need only `CTFTEST_UPSTREAM_PATH`.

## Doc Drift Check

`scripts/doc-drift.sh` fails when a tracked file names something v2 removed (the patterns are at the top of the script). Run it after editing docs:

```bash
make doc-drift
```

## Embedded CIS Bundle

The CIS controls live in `internal/embedded/cis/` (`controls.json`, `manifest.json`). After editing them, rebuild the test-signed `cis_ctftest.tar.gz`, then run the bundle tests. The owner re-signs `cis.tar.gz` from the same `cis/` with the production bundle key; `TestReleaseKeyGuard` fails until both archives carry the same payload.

```bash
go generate ./internal/embedded/
go test -tags ctftest ./internal/embedded/ ./internal/lifecycle/
```

Control `expr` runs on the CEL engine in `internal/engine/celeng`, registered as the `engine.Compiler` with ID `cel`.

## Code Conventions

- **Go version**: as in `go.mod`
- **Dependencies**: minimize. terraform-plugin-go is linked for value types only; the protocol types are generated in `internal/tfplugin`.
- **Generated code**: never hand-edit `internal/tfplugin/tfplugin5`, `tfplugin6` or `routes_gen.go`; run `make proto`.
- **Protected paths**: changes to route classes, the hook, all of `internal/proxy` and `internal/upstream`, `.golangci.yml`, workflows, crypto modules in `go.mod`/`go.sum` and any `go.mod` change beyond a plain `require` add, remove or bump (parsed by `tools/gomodcheck`, a malformed `go.mod` counts as protected) need owner review. The full list is `.github/protected-paths`. On a PR from anyone but the owner, the `owner-approval` commit status stays pending, auto-merge is off and the PR is labelled `needs-owner` until the owner approves the current head. master is protected by a ruleset requiring the `owner-approval` check. Dependabot PRs run the Test workflow; `dependabot-merge.yml` squash-merges the tested SHA of a verified Go patch/minor PR that adds no module and touches no protected path. Majors, new modules, GitHub Actions bumps and protected changes wait for the owner. Owner PRs pass only when the author, the head repository and every commit belong to the owner's GitHub id (`OWNER_ID` in `protected-paths.yml`).
- **Commits**: conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`)
- **Upstream provider**: a separate binary, treated as a black box; never modified

## Pull Requests

Only maintainers open pull requests. Before opening one, run:

```bash
make test                          # hygiene, doc-drift and all Go tests
go vet ./...
GOTOOLCHAIN=go1.26.2 make lint
make conformance                   # Terraform on PATH; TF=/path/to/tofu for OpenTofu
```

Use conventional commit messages (`feat:`, `fix:`, `test:`, `docs:`, `chore:`). Pull requests that touch a path in `.github/protected-paths` need the code owner's approval.
