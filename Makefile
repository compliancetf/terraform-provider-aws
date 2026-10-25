# Binary name
BINARY_NAME=terraform-provider-aws
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}"

# Build targets
.PHONY: build
build:
	go build ${LDFLAGS} -o ${BINARY_NAME} ./

# Dev binary: ctftest keyring, and a non-release version (git describe)
# meets the bundle provider range. Never a release build.
.PHONY: build-dev
build-dev:
	go build -tags ctftest ${LDFLAGS} -o ${BINARY_NAME} ./

# ctf-bundlegen records main.version and main.commit in build.json.
.PHONY: build-bundlegen
build-bundlegen:
	go build ${LDFLAGS} -o bin/ctf-bundlegen ./cmd/ctf-bundlegen

.PHONY: build-all
build-all:
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o dist/${BINARY_NAME}-linux-amd64 ./
	GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o dist/${BINARY_NAME}-linux-arm64 ./
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o dist/${BINARY_NAME}-darwin-amd64 ./
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o dist/${BINARY_NAME}-darwin-arm64 ./
	GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o dist/${BINARY_NAME}-windows-amd64.exe ./

.PHONY: test
test: hygiene
	go test -v ./...
	go test -tags ctftest $$(go list -tags ctftest ./... | grep -v /test/bench)
	cd test/fakeupstream && go test ./...
	cd test/sdkregion && go test -count=1 ./... # reads ../../testdata, which the test cache does not track

# p99 latency gate: load-sensitive, so not part of make test; run on
# an idle machine. TestP99Seeded checks that a seeded delay raises the p99;
# BenchmarkP99 evaluates the seed-1 generator fixture with the reference bundle
# on cold caches; cmd/benchgate gates the median p99 of BENCH_COUNT runs against
# test/bench/baseline/<runner-class>.json. UPDATE=1 rewrites the baseline and
# BENCH_NOTE records how and where it was measured. Only p99-ns/resource is
# gated: ns/op also times Configure and the evidence parse.
BENCH_COUNT ?= 10
.PHONY: bench-gate
# BENCH_NOTE and BENCH_COUNT reach the recipe unexpanded through the
# environment, so quotes and dollar signs in them are kept as typed. unexport
# stops make expanding a command-line value (e.g. $(shell ...)) into the recipe
# environment. RUN, TF and AWS_SCHEMA_VERSION below work the same way. UPDATE
# is only tested, through $(value UPDATE), never expanded.
unexport BENCH_NOTE BENCH_COUNT UPDATE
bench-gate: export BENCH_NOTE_RAW := $(value BENCH_NOTE)
bench-gate: export BENCH_COUNT_RAW := $(value BENCH_COUNT)
bench-gate:
	@set -e; d=$$(mktemp -d); trap 'rm -rf "$$d"' EXIT; \
	go run ./test/bench/gen -seed 1 -n 500 -o "$$d/instances.json"; \
	go test -count=1 -tags ctftest -run '^TestP99Seeded$$' ./test/bench -args -instances "$$d/instances.json"; \
	go test -tags ctftest -run '^$$' -bench '^BenchmarkP99$$' -benchtime 3x -count "$$BENCH_COUNT_RAW" ./test/bench \
		-args -instances "$$d/instances.json" > "$$d/bench.txt" || { cat "$$d/bench.txt"; exit 1; }; \
	cat "$$d/bench.txt"; \
	go run ./cmd/benchgate -in "$$d/bench.txt" -count "$$BENCH_COUNT_RAW" $(if $(filter 1,$(value UPDATE)),-update -note "$$BENCH_NOTE_RAW")

# Conformance scenarios against the fake upstream; TF=/path/to/tofu for OpenTofu.
# RUN=rpcseq selects tests by case-insensitive name; UPDATE=1 rewrites the
# rpcseq goldens of TF's version.
# TestStateStore (state_store "fake_store") runs only when TF is a Terraform
# alpha >= v1.16.0-alpha20260513 or a stable release >= minStableStateStore
# (test/conformance/statestore_test.go) and skips otherwise.
TF ?= $(shell command -v terraform)
unexport TF RUN
# Only make's own TF default is expanded; a TF from the command line or the
# environment passes as typed.
conformance: export TF_RAW = $(if $(filter file,$(origin TF)),$(TF),$(value TF))
conformance: export RUN_RAW := $(value RUN)

.PHONY: conformance
conformance:
	go test -count=1 -tags conformance,ctftest ./internal/proxy/ # the conformance-build taps the runner relies on
	go test -count=1 -tags conformance ./test/conformance/... $${RUN_RAW:+-run "(?i)$$RUN_RAW"} -tf "$$TF_RAW" $(if $(value UPDATE),-update)

.PHONY: test-coverage
test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Pinned tfplugin5/6 proto source; see internal/tfplugin/proto/SOURCES.json.
PROTO_PLUGIN_GO_VERSION=v0.31.0

.PHONY: proto
proto:
	./scripts/proto.sh ${PROTO_PLUGIN_GO_VERSION}

# Release dry run: no publish, no GPG key, no token. Fails until
# pins.json holds a real pin (go run ./tools/pinupstream).
GORELEASER ?= go run github.com/goreleaser/goreleaser/v2@v2.18.2

.PHONY: release-dry-run
release-dry-run:
	$(GORELEASER) check
	$(GORELEASER) release --snapshot --clean --skip=publish,sign

.PHONY: lint
lint: hygiene tidy-check
	golangci-lint run
	golangci-lint run --build-tags conformance # conformance-only files (test/conformance, the proxy taps)

# go.mod and go.sum of every module match go mod tidy (stale // indirect
# markers included). GOTOOLCHAIN=auto: lint may pin an older toolchain
# than the tools module needs, so each module picks its own.
.PHONY: tidy-check
tidy-check:
	GOTOOLCHAIN=auto go mod tidy -diff
	cd internal/tfplugin/tools && GOTOOLCHAIN=auto go mod tidy -diff
	cd test/fakeupstream && GOTOOLCHAIN=auto go mod tidy -diff
	cd test/sdkregion && GOTOOLCHAIN=auto go mod tidy -diff

# Recapture testdata/schemas/aws-subset.json from the registry
# (scripts/capture-aws-schema.sh). pins.json wins; 6.67.0 while it pins none.
AWS_SCHEMA_VERSION ?= 6.67.0
.PHONY: schema-subset
unexport AWS_SCHEMA_VERSION
schema-subset: export AWS_SCHEMA_VERSION_RAW := $(value AWS_SCHEMA_VERSION)
schema-subset:
	AWS_SCHEMA_VERSION="$$AWS_SCHEMA_VERSION_RAW" ./scripts/capture-aws-schema.sh

# Per-pin artifacts for hashicorp/aws VERSION (scripts/pin.sh): pins.json,
# the schema subset, the CIS type table and digest, cis_ctftest.tar.gz.
# VERSION must come from the command line (the build VERSION is git describe).
.PHONY: pin
pin: export PIN_VERSION_RAW := $(value VERSION)
pin:
	@[ "$(origin VERSION)" = "command line" ] || { echo "usage: make pin VERSION=X.Y.Z" >&2; exit 2; }
	./scripts/pin.sh "$$PIN_VERSION_RAW"

# The release commit for an older hashicorp/aws VERSION (scripts/backfill.sh):
# pins.json alone, on branch backfill/VERSION, after the CIS controls are
# checked against that release's schema.
.PHONY: backfill
backfill: export PIN_VERSION_RAW := $(value VERSION)
backfill:
	@[ "$(origin VERSION)" = "command line" ] || { echo "usage: make backfill VERSION=X.Y.Z" >&2; exit 2; }
	./scripts/backfill.sh "$$PIN_VERSION_RAW"

# Public-repo hygiene: no paid bundle content, real content inputs or private references.
.PHONY: hygiene
hygiene:
	@out=$$(./scripts/check-no-private-content.sh --self-test) || { echo "$$out"; exit 1; }
	./scripts/check-no-private-content.sh

.PHONY: fmt
fmt:
	gofmt -w .
	@which goimports > /dev/null 2>&1 && goimports -local github.com/compliancetf/terraform-provider-aws -w . || true

.PHONY: clean
clean:
	rm -f ${BINARY_NAME}
	rm -rf dist/
	rm -f coverage.out coverage.html

.PHONY: install
install: build
	mv ${BINARY_NAME} ${GOPATH}/bin/

# Terraform on test/fixtures/ with the ctftest build (scripts/fixtures.sh);
# needs CTFTEST_UPSTREAM_PATH.
.PHONY: test-terraform
test-terraform:
	@./scripts/fixtures.sh validate

.PHONY: dogfood
dogfood:
	@./scripts/fixtures.sh plan

# Git hooks from .pre-commit-config.yaml: fast checks on commit, make test
# and make lint on push.
.PHONY: hooks
hooks:
	prek install
