# Performance

The provider is a proxy: Terraform starts it, and it starts the unmodified `hashicorp/aws` binary as a subprocess. On a warm machine a `terraform plan` takes as long as with `hashicorp/aws` directly.

## Current numbers

macOS arm64, Terraform 1.16.3, hashicorp/aws 6.69.0, `examples/soft-fail` (one `aws_db_instance`, AWS credentials from a profile), median of 8 warm runs:

| Provider | `terraform plan` |
|---|---|
| hashicorp/aws 6.69.0 directly | 2.57 s |
| compliancetf/aws 6.69.0 (the release before this change) | 24.57 s |
| compliancetf/aws with the shared upstream copy | 3.30 s |
| compliancetf/aws with the shared copy and the schema file | 2.59 s |

The first run after a new upstream pin costs about 11 s once. That is the same one-off first-exec cost that hashicorp/aws pays itself after `terraform init` (12 s in the same setup).

## Where the time went

Terraform starts the provider three times per plan: once for the schema, once to validate, once to plan. Every start of ours used to:

1. Copy the pinned 796 MB upstream binary into a fresh per-process directory and hash it as it was written: about 1 s.
2. Exec that new file. macOS validates the code signature of an executable the first time a given file (inode) runs: 9.2 s for this binary. A second exec of the same file takes 0.2 s.

So each plan paid about 3 x 7 s. CPU time was 4.4 s of the 25 s wall time; the rest was waiting.

Measured directly:

| Step | Time |
|---|---|
| first exec of a fresh copy | 9.2 s |
| exec of the same file again | 0.2 s |
| `cp` of the binary | 0.4 s |
| sha256 of the binary (Go) | about 0.5 s |

After that fix, about 0.6 s remained. In the plan process Terraform does not ask for the schema (the upstream sets `get_provider_schema_optional`). The proxy still needs resource schemas to evaluate controls, so it asked the upstream for the full schema: about 0.3 s to build 7.5 MB. Reading the same response from a file takes about 40 ms.

## What the provider does now

- **Shared upstream copy** (`internal/upstream/shared.go`). The first start verifies the copy as before, then publishes it by renaming its private directory to `<user cache>/compliancetf/exec/v1-<sha256>/`. Later starts run that file, so there is no copy, no hash and no new inode. Before every exec the entry is checked: owner-only directory and file, on unix one link and no write bits, and a stamp of size, mtime, device and inode written at verification. A stamp mismatch triggers one rehash. A hash mismatch or a broken entry is replaced. An entry that is not ours, or an I/O error, leads to a private per-process copy as before. `COMPLIANCETF_UPSTREAM_PATH` is still hashed on every start, and a mismatch is still fatal. Entries of other pins are removed after 14 idle days.
- **Schema file** (`internal/proxy/schemafile.go`). The upstream GetSchema response is stored in the same entry, prefixed with its sha256, and later processes read it instead of asking the upstream. A missing, damaged or mismatching file is ignored.

The threat model is unchanged for other local users: the entry and its parents are writable only by the user. A process running as the same user could replace the shared binary or schema file; it could equally replace `terraform`, the CLI config or this provider, so that is out of scope (see the comment at the top of `shared.go`). With an `XDG_RUNTIME_DIR` or a user cache directory that fails the checks, the provider falls back to the old per-process copy.

## Reproducing

```bash
# a release-like build of this checkout
go build -ldflags "-X main.version=6.69.0" -o /tmp/ctf/terraform-provider-aws ./

cat > /tmp/ctf.tfrc <<'EOF'
provider_installation {
  dev_overrides {
    "registry.terraform.io/compliancetf/aws" = "/tmp/ctf"
  }
  direct {}
}
EOF

# warm-up once, then time a few runs
for i in 1 2 3 4; do
  /usr/bin/time -p env TF_CLI_CONFIG_FILE=/tmp/ctf.tfrc \
    terraform -chdir=examples/soft-fail plan -input=false -lock=false >/dev/null
done
```

For the baseline, point a second `dev_overrides` entry for `registry.terraform.io/hashicorp/aws` at a directory holding the same upstream binary named `terraform-provider-aws`, and use a copy of the example with `source = "hashicorp/aws"`.

To find where time goes, `TF_LOG=trace TF_LOG_PATH=...` and look for gaps between consecutive timestamps. Wall time far above CPU time (`time`) means waiting, not computing.
