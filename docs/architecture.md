# Architecture

This page is for engineers and security reviewers who read the source of the compliance.tf provider for AWS before they adopt it. It follows a Terraform request through the provider, then covers how `hashicorp/aws` and the control bundles are verified, what is cached and what the evidence records hold, and names the code for each. How to use it is on the [docs site](https://compliance.tf/docs/provider/); build and test steps are in [DEVELOPING.md](../DEVELOPING.md).

## Request flow

The provider is a proxy on the Terraform plugin protocol. Terraform starts it as it starts any provider, and it starts the unmodified `hashicorp/aws` binary as a subprocess:

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
                              (pinned, verified, run from a hashed copy shared per sha256)
```

- Intercepted methods decode into the generated types, change only the fields they own and re-encode, so unknown fields survive. The passthrough methods of the pinned proto are forwarded as undecoded bytes. The provider does not use `terraform-plugin-mux` or `tf5server`.
- `internal/tfplugin/classes.json` assigns each protocol method `intercept` or `passthrough`, and `internal/tfplugin/routes_gen.go` is the route table generated from the vendored protos. Generation fails for a method with no class.
- `internal/hook` defines the `Evaluator` the proxy calls at Configure and at the Validate, Plan and Apply stages. `main` serves the lifecycle evaluator (`internal/wrapper/evaluator.go`), which evaluates the signed bundles at plan, before apply, after apply, on refresh and on import.
- The `compliance {}` block is a nested block of the provider schema. It is stripped before the configuration reaches `hashicorp/aws`.
- `internal/upstream/launch.go` drops every `COMPLIANCETF_*` variable from the environment of `hashicorp/aws`.

## Plan and apply

- At plan, the provider first forwards the request. When `hashicorp/aws` returns a plan without errors, the provider evaluates the controls for the resource type and operation against it and adds the results as warnings or errors ([reference](reference.md#enforcement-modes)).
- `internal/proxy/private.go` carries the plan-time compliance data to apply in `planned_private`. It wraps the `planned_private` of the plan response and removes the wrapper before it forwards an apply, or when Terraform passes the value back into another plan, so state never holds it. The envelope has no MAC: each of its fields can only raise enforcement, and the parser rejects anything outside format version 1. The saved-plan limits that follow from this are under [Limitations](reference.md#limitations).
- Before it forwards an apply, the provider checks the resource again, including values that were unknown at plan.
- Apply returns the `new_state` bytes of `hashicorp/aws` unchanged. `internal/proxy/apply_invariant_test.go` and the conformance tap check this. The provider warns or denies; it never changes a value you wrote.

## Finding and verifying hashicorp/aws

`pins.json` pins one `hashicorp/aws` version and its sha256 per release, and the HashiCorp release key is in [keys/](../keys/). `upstream.Discover` (`internal/upstream/discover.go`) first reuses the shared verified copy of the pinned sha256 when there is one (below). Otherwise it tries these sources in order, and hashes every candidate against the pin:

1. `COMPLIANCETF_UPSTREAM_PATH`. A binary there that does not match the pin is fatal.
2. Terraform's plugin directories, at the exact pinned path.
3. The provider's own cache.
4. The pinned zip in a packed mirror.
5. A download from releases.hashicorp.com. The provider checks the HashiCorp signature of `SHA256SUMS` and the pinned checksum before it runs the binary (`internal/upstream/download.go`, `verify.go`).

The verified binary runs from one shared, owner-only copy per sha256 (`internal/upstream/shared.go`). Before each exec the provider checks the copy's owner, mode and stamp, and rehashes the binary when the stamp does not match; when the shared copy cannot be used, it runs a private copy instead. The upstream schema is kept next to it (`internal/proxy/schemafile.go`). Terraform starts the provider three times per plan, so without these a plan paid the copy, the hash and, on macOS, the code-signature check three times; [performance.md](performance.md) has the numbers.

## Caches

| What | Where | Code |
|---|---|---|
| Verified `hashicorp/aws` copy and its schema | `compliancetf/exec/v1-<sha256>/` in the user cache directory | `internal/upstream/shared.go`, `internal/proxy/schemafile.go` |
| Downloaded `hashicorp/aws` | `compliancetf/upstream` in the user cache directory | `internal/upstream/download.go` |
| Organization bundles and profiles (organization mode, not available) | `COMPLIANCETF_CACHE_DIR`, default `compliancetf` in the user cache directory | `internal/fetch` |
| Anti-rollback state `trust-state.json` | `COMPLIANCETF_STATE_DIR`, default `compliancetf` in the user configuration directory | `internal/trust/state.go` |

The user cache directory is `$XDG_CACHE_HOME` or `~/.cache` on Linux, `~/Library/Caches` on macOS and `%LocalAppData%` on Windows. When it publishes a shared copy, the provider removes the shared entries of other pins that were idle for 14 days.

The organization cache (`COMPLIANCETF_CACHE_DIR`) follows these rules. On Linux and macOS, the directory and every directory below it must be owned by the current user and must not be a symlink. The provider creates missing ones with mode 0700, sets existing ones to 0700 when it writes, and does not read one that group or others can write. On Windows the same directories must not be a symlink or junction, must be owned by the current user (or SYSTEM or Administrators), and their ACL must not let anyone else write them or pass write on to what is created in them. A missing directory is created with an ACL that grants only the current user, SYSTEM and Administrators, and an existing ACL is never changed. A directory that fails these checks is skipped with a warning, and the run goes on without it.

## Bundles and trust

- Controls ship as signed bundle 2.0 archives: a `.tar.gz` with a manifest and a DSSE signature (`internal/bundle`). Each control is a CEL `expr` run on the engine in `internal/engine/celeng`; [schema/bundle-control-2.schema.json](../schema/bundle-control-2.schema.json) describes the control format.
- `internal/trust` verifies every bundle against the keyring compiled into the binary and the merged revocation set. When the embedded CIS archive or the archive in `control_bundle_path` fails verification, configuration fails and the run stops. A cached archive that fails verification is skipped.
- The CIS bundle is embedded in the binary (`internal/embedded`, built from `internal/embedded/cis/`) and always loads. `control_bundle_path` adds one archive for air-gapped runs. `cmd/ctfbundle` builds, signs and verifies archives.
- `trust-state.json` records the highest accepted version of each bundle and profile and the revocations. Every merge is monotonic, and a version below the recorded minimum is rejected, so an older bundle cannot be loaded after a newer one. When the state cannot be saved, the provider warns.

### Bundles and exceptions

Exceptions of every kind need a signed organization profile, which compliance.tf does not issue, so none of this runs today. The packages exist and are tested:

- **Exception grants** are DSSE-signed files, one per grant, in `exception_grants_dir`. They apply only to controls whose bundle declares them coverable for grants (`exemption_coverable` in the signed bundle; a `coverable` list in the profile is ignored), and only within their org, workspace scope and expiry. A grant that names any control that is unknown or not coverable applies to none of its controls, with a warning per control. Under `floor_mode: airgap`, grant expiry and key windows are checked against the latest accepted floor statement, never the local clock.
- **Self-service exceptions** in `exceptions_file` are HCL (`internal/exceptions`). Without a signed profile that lists the control under self-service, the file is ignored with a warning. The control's bundle must also declare it coverable for `self_service`; a profile that lists a self-service control its bundle does not declare coverable fails Configure with `self_service_not_coverable`. Each entry selects resources with a CEL `match` over `type`, `resource`, `config`, `prior`, `op`, `env` and `provider` (see [examples/exception](../examples/exception)). An unknown result waives nothing at plan and is retried at apply; an error waives nothing. A match that reads `op` must hold under every op a control is checked under: apply checks each half of a replace under `replace` and under its own `create` or `delete`, and a `change` under the actual `create` or `update` too. The file holds `exception` blocks only; a block or attribute naming a baseline, quarantine, floor or run key fails the load with `self_service_scope`.
- **Pending exemptions.** When a blocking failure has no exception that applies, plan reports it as `pending exemption: <kind> <control>`, one per eligible kind, and apply blocks it unless `ctfkit gate sign` lists the final proof. A kind is eligible only when the control's signed coverage allows it and the run can use it.
- **The service.** With `org_id` and `COMPLIANCETF_TOKEN` set, the provider would fetch the organization's signed profile, bundles and floor statement from the compliance.tf service (`internal/fetch`), sending the token. Without the token it does not contact the service: profile and bundles come from cached copies, and a run that needs a floor statement works only under `floor_mode: airgap` with its floor file. Organization mode is not available: with `org_id` and `COMPLIANCETF_TOKEN` set and `COMPLIANCETF_OFFLINE` not `true`, the service refuses the request and configuration fails.

## Evidence records

The provider records its checks in a local evidence chain (`internal/evidence`), under `evidence_dir`, default `.terraform/compliancetf/evidence`. When a record cannot be written, the provider reports `evidence write failed`. [schema/evidence-record-1.schema.json](../schema/evidence-record-1.schema.json) is the record schema.

- Each configured provider process writes one chain, `<evidence_dir>/<run id>/<chain id>.jsonl`. The run id comes from `COMPLIANCETF_RUN_ID` or the CI run id ([reference](reference.md#environment-variables)).
- Record kinds are `chain_start`, `configure`, `eval`, `chain_break` and `chain_end`. An `eval` record holds the control results, the resource type, the operation, the resource id and identity, the stage and the mode.
- Of the resource, a record holds only the cloud id and the identity attributes. It holds no other attribute values, expected values, messages or raw error text. The resource address is not recorded, because a `for_each` key can carry a value.
- Each line carries `prev`, the sha256 of the bytes of the line before it, without its line feed. Every record encodes as its own RFC 8785 (JCS) form, so that sha256 is also the digest of the record. Verification (`internal/evidence/verify.go`) reports a line edited or removed in the middle of a chain and a partial last line. A chain cut at a line boundary only lacks its `chain_end`.
- A failed write is never retried. The next write starts a new segment with `chain_break`, in a new file `<chain id>.<n>.jsonl` when the failed write reached the old one. Files are never truncated.

The files stay on the machine that ran Terraform. To keep them as evidence, copy them to write-once storage after each run.

## What it contacts

- `terraform init` downloads the provider from registry.compliance.tf. Release archives are signed with the compliance.tf release key ([gpg-public-key.asc](../gpg-public-key.asc)).
- At run time the provider contacts releases.hashicorp.com only when no verified `hashicorp/aws` is found.
- With `org_id` unset, it does not contact compliance.tf at run time. It never sends your configuration, state or AWS credentials to compliance.tf; `hashicorp/aws` talks to AWS as it always does.

## Where to look in the code

| Path | What |
|---|---|
| `main.go` | Entry point; embeds `wrapper.json`, `pins.json`, the HashiCorp key and the CIS archive |
| `internal/proxy`, `internal/rawgrpc`, `internal/tfplugin` | Plugin protocol proxy, raw forwarding, vendored protos and the route table |
| `internal/upstream` | Discovery, download, verification and launch of `hashicorp/aws` |
| `internal/wrapper`, `internal/lifecycle`, `internal/hook` | The evaluator and the check stages |
| `internal/bundle`, `internal/engine`, `internal/trust`, `internal/embedded` | Bundle format, CEL engine, signature checks, the embedded CIS bundle |
| `internal/evidence` | Evidence chains |
| `internal/profile`, `internal/fetch`, `internal/exceptions` | Organization mode, not available |
| `test/conformance` | Conformance runner against a fake upstream |

The full layout is in [DEVELOPING.md](../DEVELOPING.md#repository-layout).
