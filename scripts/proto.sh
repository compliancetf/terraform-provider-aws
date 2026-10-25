#!/usr/bin/env bash
#
# Vendors tfplugin5.proto and tfplugin6.proto from the pinned
# terraform-plugin-go module, records their origin and sha256 in
# internal/tfplugin/proto/SOURCES.json, regenerates the Go types with buf and
# rebuilds the route table (internal/tfplugin/routes_gen.go).
#
# Usage: scripts/proto.sh <terraform-plugin-go version>   (make proto)
#
# The generators (buf, protoc-gen-go, protoc-gen-go-grpc) are tool directives
# in internal/tfplugin/tools/go.mod, a separate module so their dependencies
# never enter the provider binary's module graph.

set -euo pipefail

VERSION="${1:?usage: $0 <terraform-plugin-go version>}"
MODULE="github.com/hashicorp/terraform-plugin-go"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROTO_DIR="${ROOT}/internal/tfplugin/proto"
TOOLS_DIR="${ROOT}/internal/tfplugin/tools"

MOD_DIR="$(go mod download -json "${MODULE}@${VERSION}" | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')"
if [[ -z "${MOD_DIR}" || ! -d "${MOD_DIR}" ]]; then
	echo "proto.sh: cannot locate ${MODULE}@${VERSION} in the module cache" >&2
	exit 1
fi

sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }

entries=()
for v in 5 6; do
	src="tfprotov${v}/internal/tfplugin${v}/tfplugin${v}.proto"
	dst="${PROTO_DIR}/tfplugin${v}.proto"
	cp "${MOD_DIR}/${src}" "${dst}"
	chmod 0644 "${dst}"
	entries+=("    \"tfplugin${v}.proto\": {\"module\": \"${MODULE}\", \"version\": \"${VERSION}\", \"path\": \"${src}\", \"sha256\": \"$(sha256 "${dst}")\"}")
done

{
	echo "{"
	echo "${entries[0]},"
	echo "${entries[1]}"
	echo "}"
} > "${PROTO_DIR}/SOURCES.json"

go -C "${TOOLS_DIR}" tool buf generate ../proto --template buf.gen.yaml
go -C "${ROOT}" generate ./internal/tfplugin
