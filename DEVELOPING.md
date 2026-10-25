# Developing the compliance.tf provider for AWS

Coding agents write and change all code in this repository; no person works on it by hand. Read this file in full before changing anything, and keep it current: a change to a make target, script, layout, workflow or release step updates this file in the same pull request. `AGENTS.md` points every agent here.

## Rules

- **Public repository.** Everything committed is public: code, comments, commit messages, branch names, pull request and issue text. Never add references to private repositories, internal tracker ids, local paths, customer names or internal planning notes. `scripts/check-no-private-content.sh` enforces part of this (`make hygiene`, the pre-commit hook and `make test`). Use the fake org `bobthecorp` in examples and tests.
- **Pull requests** come from maintainers only; users open issues (`CONTRIBUTING.md`). Every change lands through a pull request to `master`.
- **Git hooks.** Run `make hooks` once per clone. Commits then run the fast checks and pushes run `make test` and `make lint` (`.pre-commit-config.yaml`). Never bypass them with `--no-verify`.
- **Commits** follow conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`, `ci:`).
- **Never overwrite explicit user values.** Terraform consistency rules forbid it: the provider denies or warns only, and does not default null or unset values.
- **The upstream provider is a black box.** `hashicorp/aws` runs as a separate, unmodified binary.
- **Generated code** (`internal/tfplugin/tfplugin5`, `tfplugin6`, `routes_gen.go`) is never edited by hand; run `make proto`.
- **Dependencies:** keep them few. terraform-plugin-go is linked for its value types only; the protocol types are generated in `internal/tfplugin`.
- **Protected paths** (`.github/protected-paths`): route classes, the hook, all of `internal/proxy` and `internal/upstream`, `.golangci.yml`, workflows, crypto modules in `go.mod`/`go.sum`, and any `go.mod` change beyond a plain `require` add, remove or bump (parsed by `tools/gomodcheck`; a malformed `go.mod` counts as protected) need owner review. On a PR from anyone but the owner, the `owner-approval` status stays pending, auto-merge is off and the PR is labelled `needs-owner` until the owner approves the current head. master is protected by a ruleset requiring the `owner-approval` check. Owner PRs pass only when the author, the head repository and every commit belong to the owner's GitHub id (`OWNER_ID` in `protected-paths.yml`).
- **Dependabot** PRs run the Test workflow; `dependabot-merge.yml` squash-merges the tested SHA of a verified Go patch or minor PR that adds no module and touches no protected path. Majors, new modules, GitHub Actions bumps and protected changes wait for the owner.
- **Naming in user-facing text:** write "compliance.tf" (or the `COMPLIANCETF_` prefix for environment variables) and "terraform-aws-modules" in full.

## Setup

- Go as in `go.mod` (1.26.2; terraform-plugin-go v0.31.0 needs at least 1.25). CI reads the version from `go.mod`.
- golangci-lint for `make lint`. When it was built with an older Go than your toolchain, pin the toolchain: `GOTOOLCHAIN=go1.26.2 make lint` (the pre-push hook does this).
- [prek](https://github.com/j178/prek) and shellcheck for the git hooks.
- Terraform or OpenTofu for conformance and fixture runs.

```bash
make hooks   # install the pre-commit and pre-push hooks
make build   # provider binary ./terraform-provider-aws
make test    # the full test gate
```

## Make targets

| Target | What it does |
|--------|--------------|
| `make build` | Build the provider binary |
| `make build-dev` | Build with `-tags ctftest`: the test keyring and the test-signed CIS bundle; a non-release version (git describe) meets any well-formed bundle provider range. A plain `make build` checks the range exactly and fails it with a dev version |
| `make test` | `make hygiene`, then `go test -v ./...`, `go test -tags ctftest` on every package but `test/bench`, the `test/fakeupstream` module and the `test/sdkregion` module |
| `make lint` | `make hygiene` and `make tidy-check`, then `golangci-lint run`, plain and with `--build-tags conformance` |
| `make hygiene` | `scripts/check-no-private-content.sh` (self-test, then the tree): no bundle content outside the synthetic catalog, no agent or issue-tracker state, no home-directory paths or planning task ids, and no match of the uncommitted pattern list in `COMPLIANCETF_PRIVATE_PATTERNS_FILE` (default `.git/info/private-patterns`) |
| `make tidy-check` | `go mod tidy -diff` in every module |
| `make hooks` | `prek install`: the hooks in `.pre-commit-config.yaml` |
| `make conformance` | Conformance scenarios against the fake upstream (see Conformance) |
| `make test-terraform` | `scripts/fixtures.sh validate`: `make build-dev`, then `terraform validate` every fixture in `test/fixtures/`; needs `CTFTEST_UPSTREAM_PATH` |
| `make dogfood` | `scripts/fixtures.sh plan`: `make build-dev`, then `terraform plan` every fixture against the real `hashicorp/aws` and check that the embedded CIS bundle blocks exactly the controls the fixture lists (`# dogfood-blocks: <id>`); needs `CTFTEST_UPSTREAM_PATH` |
| `make bench-gate` | p99 latency gate (see Benchmarks) |
| `make proto` | Re-vendor the pinned `tfplugin5`/`tfplugin6` protos, regenerate Go types and the route table |
| `make pin VERSION=X.Y.Z` | Per-pin artifacts for hashicorp/aws X.Y.Z (see Releasing); needs terraform, jq and network |
| `make schema-subset` | Recapture `testdata/schemas/aws-subset.json` from the registry |
| `make release-dry-run` | GoReleaser `check` and a snapshot build; no publish, no signing |
| `make build-bundlegen`, `make build-all` | `bin/ctf-bundlegen` (records version and commit in build.json); cross-compiled binaries in `dist/` |
| `make fmt` | `gofmt -w .`, and `goimports` when installed |
| `make test-coverage` | `coverage.out` and `coverage.html` |
| `make clean` | Remove the binary, `dist/` and coverage files |
| `make install` | Build and move the binary to `$GOPATH/bin` |

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

- Intercepted methods decode into the generated types, change only the fields they own and re-encode, so unknown fields survive. Every other method of the pinned proto is forwarded as undecoded bytes. The provider does not use `terraform-plugin-mux` or `tf5server`.
- `internal/tfplugin/routes_gen.go` is the route table, generated from the vendored protos by `make proto`. `internal/tfplugin/classes.json` assigns each method `intercept` or `passthrough`; generation fails for a method with no class.
- `internal/hook` defines the `Evaluator` the proxy calls at Configure and at the Validate, Plan and Apply stages. `main` serves the lifecycle evaluator (`internal/wrapper/evaluator.go`: `lifecycle.Hook`), which evaluates the signed bundles at plan, apply, refresh and import.
- The `compliance {}` block is a nested block of the provider schema, stripped before the configuration reaches the upstream.
- `internal/proxy/private.go` carries plan-time compliance data in `planned_private` and checks it at apply. It never writes into state.
- Apply returns the upstream `new_state` bytes unchanged. `internal/proxy/apply_invariant_test.go` and the conformance tap check this.
- The binary links terraform-plugin-go only for its value types, never `tf5server`/`tf6server`, which would link its own proto copy and panic on duplicate registration. `TestNoPluginGoServerLinked` (`internal/proxy/deps_test.go`) guards this, so the generated `tfplugin5` package is the only registrant of `tfplugin5.proto`.
- `main` finds the upstream with `upstream.Discover`: the `hashicorp/aws` version pinned in `pins.json` (written by `tools/pinupstream`), from `COMPLIANCETF_UPSTREAM_PATH`, Terraform's plugin directories or a download, verified against the pin before launch. Go tests and conformance use the fake upstream in `test/fakeupstream` instead.
- `internal/bundle`, `bundlegen`, `engine`, `lifecycle`, `trust`, `profile`, `fetch` and `evidence` are the bundle, engine, trust and evidence packages; `cmd/ctfbundle` and `cmd/ctf-bundlegen` are their CLIs. The CIS baseline is embedded in the binary; organization bundles come from the bundle service.
- `internal/embedded` holds the signed CIS bundle archives built from `cis/` (`cis.tar.gz`, production-signed, in release builds; `cis_ctftest.tar.gz`, test-signed, in `ctftest` builds); `internal/exceptions` reads signed grants and the self-service sidecar. Control `expr` runs on the CEL engine in `internal/engine/celeng`.

## Repository layout

```
main.go, main_test.go       entry point (embeds wrapper.json, pins.json, the HashiCorp key, the CIS archive) and the release guard
wrapper.json                wrapper identity: address, upstream, resource prefix, CIS bundle, sink
pins.json, keys/            pinned hashicorp/aws (tools/pinupstream) and the HashiCorp release key
releases.json               release floor and supported releases of premium bundles (ctf-bundlegen)
capabilities.json           release capabilities shipped with each release (tools/releasemeta)
terraform-registry-manifest.json, .goreleaser.yml   release packaging
internal/
  wrapper/                  Config, Load, Serve; evaluator.go (lifecycle.Hook), evaluator_conformance.go
  tfplugin/                 vendored protos (proto/, SOURCES.json), generated tfplugin5/ and tfplugin6/, routes_gen.go, classes.json, tools/
  rawgrpc/                  raw frame codec, generic stream forwarder
  proxy/                    serve.go, server5.go, route5*.go, schema.go, private.go, classify.go, tap_conformance.go
  hook/                     Evaluator interface; hooktest/ recorder
  upstream/                 launch.go, discover.go, download.go, verify.go, pins.go, execdir.go
  bundle/ bundlegen/ engine/ lifecycle/ trust/ profile/ fetch/ evidence/ exceptions/ embedded/
pkg/engine/                 public selector engine facade over internal/engine; enginetest/ and testdata/ cross-check vectors
cmd/                        ctfbundle (build, sign, verify bundles), ctf-bundlegen, iamcatalog (IAM action catalog), benchgate
tools/                      pinupstream, cispin, releasemeta, releasegate, gomodcheck, upstreamwatch
test/
  fakeupstream/             separate module: fake v5 and v6 upstream binaries
  sdkregion/                separate module: AWS SDK region checks
  conformance/              runner, matrix.json, scenarios/, rpcseq/ goldens, nightly/ (build tag conformance)
  workflows/                checks of .github/workflows and .goreleaser.yml (pinned actions, triggers, release gates)
  crosscheck/               language-neutral control fixtures replayed through the engine
  scrub/                    value-free output checks: no attribute values in diagnostics or evidence
  bench/                    p99 benchmark and baselines
  fixtures/                 Terraform configs for scripts/fixtures.sh
testdata/                   schemas, bundles and other shared test inputs
examples/                   user-facing example configurations
docs/                       user reference and performance notes
scripts/                    see Scripts
```

## Scripts

| Script | Used by |
|---|---|
| `check-no-private-content.sh` | `make hygiene`, pre-commit hook; `--self-test` checks its own rules |
| `fixtures.sh validate\|plan` | `make test-terraform`, `make dogfood` |
| `pin.sh` | `make pin`, the upstream-watch workflow |
| `capture-aws-schema.sh` | `make schema-subset`, `pin.sh`, `tools/cispin` |
| `owner-sign-cis.sh` | the owner, to re-sign `cis.tar.gz` with the production key |
| `proto.sh` | `make proto` |
| `proto-drift.sh` | the proto-drift workflow: alerts when upstream protos change |
| `protected-paths.sh` | the protected-paths workflow; `--self-test` |
| `bump-goreleaser.sh` | release maintenance: bumps the pinned GoReleaser |

Scripts are bash with `set -euo pipefail` and pass `shellcheck --severity=warning` (the pre-commit hook runs it).

## Testing

```bash
make test                                  # the full gate
go test ./internal/proxy/...               # one package
go test ./internal/proxy/ -run Invariant   # one test
go test -tags ctftest ./internal/embedded/ # tests that need the ctftest-only hooks
cd test/fakeupstream && go test ./...      # the fake upstream module
```

Proxy tests start the fake upstream or use in-memory gRPC (bufconn). They never contact AWS and need no Terraform binary.

## Conformance

`test/conformance` (build tag `conformance`) builds the proxy and the fake upstream, writes a CLI config whose `dev_overrides` point `registry.compliance.tf/compliancetf/aws` at the built proxy, and runs every scenario under `test/conformance/scenarios/` with one Terraform or OpenTofu binary:

```bash
make conformance                          # terraform on PATH
make conformance TF=$(command -v tofu)    # OpenTofu
make conformance RUN=rpcseq UPDATE=1      # rewrite the RPC-sequence goldens of TF's version
```

- The binary's version selects its cell in `test/conformance/matrix.json`; a scenario whose `steps.json` `requires` a feature that cell lacks is skipped.
- Each scenario is a `main.tf` plus `steps.json` (commands, expected exit codes, output substrings to contain or exclude, `state_unchanged`, `expect_applies` (a minimum), `expect_no_applies`). Scenarios never run `init`.
- `test/conformance/testdata/capabilities.json` pins the protocol minor and `server_capabilities` the proxy must advertise.
- `.github/workflows/conformance.yml` runs every matrix cell on demand.
- `test/conformance/nightly/` holds the nightly scenarios against the real `hashicorp/aws` in a sandbox account (`.github/workflows/nightly.yml`, manual only, build tags `conformance,nightly`). Offline dry run: `go test -count=1 -tags conformance,nightly ./test/conformance/... -run Nightly -plan-only`. Setup and cleanup: `test/conformance/nightly/README.md`.

## Benchmarks

`make bench-gate` runs `go run ./test/bench/gen -seed 1 -n 500`, then `TestP99Seeded` (a seeded delay must raise the p99), then `BenchmarkP99` (plan and apply_pre of every instance through a Lifecycle with `testdata/bench/reference-bundle.json`, cold caches, `-count 10`), then `cmd/benchgate`, which fails when the median p99 is above 120% of `test/bench/baseline/<runner-class>.json` or above 50 ms. Run it on an idle machine; it is not part of `make test`. `UPDATE=1 BENCH_NOTE="<how, hardware>"` rewrites the baseline (in a PR labelled `bench-baseline`). The runner class is `GOOS-GOARCH` unless `COMPLIANCETF_BENCH_RUNNER_CLASS` is set; a missing baseline fails.

## Environment variables

| Name | Build | Meaning |
|------|-------|---------|
| `COMPLIANCETF_UPSTREAM_PATH` | all | Explicit upstream binary (air-gap); must match the pinned checksum, anything else is fatal |
| `CTFTEST_UPSTREAM_PATH` | `ctftest` tag only | Unpinned upstream binary for tests; release builds do not compile the code that reads it |
| `COMPLIANCETF_CONFORMANCE_TAP` | `conformance` tag only | File the proxy appends one JSON line per apply to, with the sha256 of the upstream and the returned `new_state` |
| `COMPLIANCETF_CONFORMANCE_PINS` | `conformance` tag only | Pins file that replaces the embedded `pins.json`; the runner pins the fake upstream in it and passes the binary as `COMPLIANCETF_UPSTREAM_PATH` |
| `COMPLIANCETF_CONFORMANCE_EVALUATOR` | `conformance` tag only | Test evaluator: empty for the no-op, `deny:<type>` or `warn:<type>` |
| `COMPLIANCETF_CONFORMANCE_RPCSEQ` | `conformance` tag only | File the recording evaluator writes the RPC sequence to; exclusive with `COMPLIANCETF_CONFORMANCE_EVALUATOR` |

`internal/upstream/launch.go` drops every `COMPLIANCETF_*` variable from the upstream's environment. Release builds must not carry `-tags=conformance` or `-tags=ctftest`. User-facing settings are in `docs/reference.md`.

## Manual testing with Terraform

`make test-terraform` and `make dogfood` write their own CLI config and need only `CTFTEST_UPSTREAM_PATH`: an unpinned `hashicorp/aws` 6.x binary (Terraform's plugin cache has one after any `init`). For a manual run, write a CLI config with `dev_overrides` pointing at the repo root:

```bash
make build-dev
cat > /tmp/ctf.tfrc <<EOF
provider_installation {
  dev_overrides {
    "registry.terraform.io/compliancetf/aws" = "$PWD"
    "registry.opentofu.org/compliancetf/aws" = "$PWD"
  }
  direct {}
}
EOF
export TF_CLI_CONFIG_FILE=/tmp/ctf.tfrc
export CTFTEST_UPSTREAM_PATH=/path/to/terraform-provider-aws_v6.x.y_x5
terraform -chdir=test/fixtures/non-compliant-rds plan
```

The fixtures declare `source = "compliancetf/aws"` (`registry.terraform.io/compliancetf/aws`, or `registry.opentofu.org/compliancetf/aws` under OpenTofu). A config that uses `registry.compliance.tf/compliancetf/aws` needs an override under that address. With `dev_overrides`, skip `terraform init` and `tofu init`: both plan and apply without it, and OpenTofu `init` fails for a provider that only has a dev override.

## Embedded CIS bundle

The CIS controls live in `internal/embedded/cis/` (`controls.json`, `manifest.json`). After editing them, rebuild the test-signed `cis_ctftest.tar.gz` and run the bundle tests. The owner re-signs `cis.tar.gz` from the same `cis/` with the production bundle key (`KEY=<key PEM> scripts/owner-sign-cis.sh`); `TestReleaseKeyGuard` fails until both archives carry the same payload.

```bash
go generate ./internal/embedded/
go test -tags ctftest ./internal/embedded/ ./internal/lifecycle/
```

## Releasing

Version parity: compliancetf/aws X.Y.Z proxies hashicorp/aws X.Y.Z exactly. Users migrate by changing only `source` in `required_providers`; their `version` constraint and lock file workflow stay. The release tag `vX.Y.Z` must equal the `pins.json` version: `tools/releasemeta` (run by `release.yml` on every `v*` tag) accepts only the pinned X.Y.Z, X.Y.Z-beta.N or X.Y.Z-compliancetf.N and fails the release otherwise. One release per hashicorp/aws release, forward only. Never republish a version: lock files hold its hashes, and a new GitHub release makes the registry ingest it again.

| Kind | Version | Use |
|---|---|---|
| beta | `X.Y.Z-beta.N` | before the X.Y.Z release |
| proxy-only fix | `X.Y.Z-compliancetf.N` | a fix on top of X.Y.Z; spell `compliancetf` in full |

Terraform never selects a prerelease from a range constraint, so users opt in by pinning the exact version.

`min_wrapper_version` (org profile and floor statement) orders versions by `internal/trust/wrapper.go` (vectors in `internal/trust/testdata/wrapper_order.json`): the base X.Y.Z first; within one base `beta.N` < release < `compliancetf.N`, N numeric. Any other prerelease (for example `rc.1`) ranks with the betas, below the release and every `compliancetf.N`; against a beta or another such prerelease of the same base it is unordered, so that pair fails closed. Floor signers issue canonical forms only. A floor can force a proxy fix: `6.67.0-compliancetf.1` refuses `6.67.0` and admits `6.67.0-compliancetf.1`, `6.67.0-compliancetf.2` and `6.68.0`. Bundle `version_range` checks treat `X.Y.Z-beta.N` and `X.Y.Z-compliancetf.N` as X.Y.Z.

Per upstream release, `make pin VERSION=X.Y.Z` (clean tree) regenerates everything that depends on the pin: `pins.json` (`tools/pinupstream`), `testdata/schemas/aws-subset.json`, the CIS type table `internal/embedded/testdata/schema_compat.tsv` and manifest `schema_compat_digest` (`tools/cispin`), and `cis_ctftest.tar.gz`. It stops with a message when the pin needs an owner decision (outside the manifest `version_range`, a control read gone or turned Computed). If the CIS manifest changed, the owner re-signs `cis.tar.gz`. Re-running for the current pin changes nothing.

`.github/workflows/upstream-watch.yml` (daily, or dispatched with an optional `version`) opens that PR: `tools/upstreamwatch` picks the oldest hashicorp/aws release newer than `pins.json`, one pin PR at a time (branch `pin/hashicorp-aws-X.Y.Z`; newer releases wait for it to merge; a pin branch without an open PR fails the run). The workflow runs `make pin`, commits and opens `chore(pin): hashicorp/aws X.Y.Z`, as a draft when `make pin` stopped for an owner decision. The PR body says whether `cis.tar.gz` needs re-signing. PRs opened with GITHUB_TOKEN start no workflows: run the local gate, merge, then tag the merge commit and approve the `release` environment:

```bash
git tag -a vX.Y.Z <merge SHA> -m vX.Y.Z
git push origin vX.Y.Z
gh release view vX.Y.Z
```

The embedded CIS manifest keeps provider and upstream `version_range` `">= 6.0.0, < 7.0.0"`. Premium bundles support every release from the floor: `releases.json` holds the owner-set `floor` (oldest supported release) and the supported `releases`, floor first, pin last; `make pin` appends the new pin and keeps the previous pin's schema subset as `testdata/schemas/aws/<version>.json`. `ctf-bundlegen generate` writes provider and upstream `version_range` `">= <floor>, < <floor major + 1>.0.0"` and fails `E_SUPPORTED_SCHEMA` unless every control holds on the schema of each supported release. To raise the floor: set `floor`, drop the releases below it from `releases` and delete their schema files. A new major starts a new floor: commit `floor` and `releases` set to the new pin, then `make pin`.

GoReleaser builds the release artifacts (zip archives, SHA256SUMS and its GPG signature). The registry at `registry.compliance.tf` ingests each published GitHub release through a webhook and serves the download metadata.
