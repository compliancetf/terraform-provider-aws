#!/usr/bin/env bash
#
# Owner only: re-signs internal/embedded/cis.tar.gz from internal/embedded/cis
# with the production bundle key, then runs the release key guard and the
# tests that load the release archive.
#
# Usage: KEY=/path/to/bundle-key.pem scripts/owner-sign-cis.sh
#
# Refuses a dirty tree, so the signed payload is the committed cis/. Commit
# cis.tar.gz afterwards. manifest.json issued_at must lie inside the key's
# not_before/not_after window (TestReleaseGuard).

set -euo pipefail

cd "$(dirname "$0")/.."

[[ -n "${KEY:-}" ]] || { echo "owner-sign-cis.sh: set KEY to the production bundle key PEM" >&2; exit 2; }
[[ -f "$KEY" ]] || { echo "owner-sign-cis.sh: KEY is not a file" >&2; exit 2; }
key="$(cd "$(dirname "$KEY")" && pwd)/$(basename "$KEY")"
[[ -z "$(git status --porcelain)" ]] || { echo "owner-sign-cis.sh: working tree is dirty; commit or remove changes first" >&2; exit 1; }

(cd internal/embedded && go run ../../cmd/ctfbundle build -src cis -key "$key" -out cis.tar.gz)
go test -count=1 -run '^TestReleaseKeyGuard$' ./internal/embedded/
go test -count=1 ./internal/embedded/ ./internal/wrapper/ .
echo "owner-sign-cis.sh: signed; commit internal/embedded/cis.tar.gz"
