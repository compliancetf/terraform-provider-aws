# Performance Analysis & Optimizations

## Summary

The compliance.tf provider proxy adds **~3% overhead** over the direct `hashicorp/aws` provider on warm runs. This document records the investigation methodology, root causes, and optimizations applied.

**Benchmark setup:** Apple M1 Max, hashicorp/aws v6.40.0, 1 `aws_s3_bucket` resource, `profile = "demo"`.

| Phase | Direct | Proxy | Overhead |
|---|---|---|---|
| Baseline (no optimizations) | 3.8s | 5.7s | **50%** |
| Round 1 (schema cache + type memo) | 3.8s | 4.1s | **10%** |
| Round 2 (lazy schema + single unmarshal) | 3.9s | 4.0s | **~3%** |

## Root Cause Analysis

### Why a proxy is inherently slower than direct

The direct `hashicorp/aws` provider is a single process. The compliance proxy adds:
1. **Double process launch** — Terraform starts our binary, our binary starts the upstream binary via go-plugin
2. **gRPC hop** — every RPC goes: Terraform → our tf5server → proto conversion → gRPC to upstream → proto conversion back
3. **Schema conversion** — the AWS provider has ~1,638 resource schemas that must be converted between proto and tfprotov5 types

### Why Terraform launches 3 provider processes

Terraform's architecture launches separate provider processes for different lifecycle phases. In our measurements, we consistently observed 3 processes:
1. **Process 1** — schema discovery (GetProviderSchema)
2. **Process 2** — validation + configuration (PrepareProviderConfig, Configure, Validate, Plan)
3. **Process 3** — additional operations

Each process independently starts its own upstream subprocess, pays the go-plugin handshake cost, and needs the schema.

## Profiling Data

### CPU Profile (10 iterations of full schema conversion)

| Function | Flat | Cumulative | Notes |
|---|---|---|---|
| `runtime.madvise` | 21% | 21% | Memory management — large allocation footprint |
| `protobuf.unmarshalPointer` | 2.5% | 21% | Proto reflection during unmarshal |
| `schemaAttributeFromProto` | 1.2% | 6.2% | Our conversion code |

### Memory Profile (670MB total over 10 iterations)

| Allocator | Amount | % | Notes |
|---|---|---|---|
| `reflect.unsafe_New` | 311MB | 46% | Protobuf reflection during unmarshal |
| `os.readFileContents` | 68MB | 10% | Cache file reads |
| `schemaAttributeFromProto` | 65MB | 10% | Per-attribute conversion |
| `schemaBlockFromProto` | 58MB | 9% | Per-block conversion |
| `consumeStringValidateUTF8` | 38MB | 6% | Proto string validation |
| `schemaNestedBlockFromProto` | 33MB | 5% | Nested block conversion |
| `bytesToCtyType` | 18MB | 3% | Type JSON parsing (now memoized) |

### Per-RPC Timing (single resource plan)

| RPC | Time | Notes |
|---|---|---|
| GetProviderSchema | 975ms | 1,638 resources over gRPC + full conversion |
| PrepareProviderConfig (lazy-init) | 260ms → **20ms** (after optimization) | Was loading ALL schemas; now provider-only |
| Configure | 1,007ms | Upstream AWS auth — out of our control |
| ValidateResourceTypeConfig | 8-13ms | Fast — just compliance evaluation |
| PlanResourceChange | 5ms | Fast — compliance evaluation + upstream plan |

## Optimizations Applied

### Round 1: Schema Disk Cache + Type Memoization

**Files:** `internal/upstream/schemacache.go`, `internal/upstream/convert_from_proto.go`

1. **Proto-based disk cache** — first provider process writes the GetProviderSchema proto response (~7MB) to a temp file. Processes 2 and 3 read from cache instead of making a full gRPC call (~1s each). Keyed by upstream binary path hash, 5-minute TTL.

2. **tftypes.ParseJSONType memoization** — AWS schemas repeat the same primitive types (string, bool, number) thousands of times. A `sync.RWMutex`-protected `map[string]tftypes.Type` cache avoids re-parsing identical JSON type bytes.

**Impact:** 50% → 10% overhead

### Round 2: Lazy Schema + Single Unmarshal + Type Cache

**Files:** `internal/upstream/schemacache.go`, `internal/proxy/server.go`, `internal/proxy/config.go`, `internal/proxy/intercept.go`

3. **Lazy provider-only schema loading** — operation processes (2 and 3) read only the provider schema from the disk cache, skipping conversion of 1,638 resource schemas entirely. Resource schemas are loaded on-demand when first accessed by compliance evaluation. This is the single biggest win in round 2.

4. **Combined ParseAndStripComplianceConfig** — `ParseComplianceConfig` and `StripComplianceBlock` both called `config.Unmarshal()` separately. Combined into a single function that unmarshals once and produces both the compliance config and the stripped upstream DynamicValue.

5. **SchemaBlockToType cache** — `SchemaBlockToType(schema.Block)` was called on every ValidateResourceTypeConfig, PlanResourceChange, and ApplyResourceChange RPC, rebuilding the recursive type graph each time. Now cached per resource type name in `map[string]tftypes.Type`.

**Impact:** 10% → ~3% overhead

## Remaining ~3% Overhead

The remaining overhead is the **inherent cost of the go-plugin subprocess architecture**:
- ~300ms for go-plugin process launch + gRPC handshake + AutoMTLS setup
- This cost is paid per provider process (3 processes)
- It runs in parallel with Terraform's own startup, so the observable overhead is less than 3 × 300ms

### Potential future optimizations (not implemented)

| Optimization | Expected Impact | Effort | Notes |
|---|---|---|---|
| Shared upstream daemon | Eliminate 2 of 3 subprocess launches | High | Single upstream shared across Terraform processes via Unix socket. Complex state management. |
| Disable AutoMTLS | ~50ms per connection | Low | Security tradeoff for local-only connections |
| Custom cache format | ~100ms on cache read | Medium | Replace proto unmarshal with a narrow decoder that only extracts needed fields |
| gRPC compression | ~50ms on large schema transfer | Low | May not help — schema is only transferred once per process |

## How to Reproduce Benchmarks

```bash
# Build the provider
make build

# Create benchmark directories
mkdir -p /tmp/bench-direct /tmp/bench-proxy

# Direct benchmark (baseline)
cat > /tmp/bench-direct/main.tf << 'EOF'
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "6.40.0" }
  }
}
provider "aws" { region = "us-east-1"; profile = "demo" }
resource "aws_s3_bucket" "test" { bucket = "perf-test" }
EOF
cd /tmp/bench-direct && terraform init
time terraform plan -input=false

# Proxy benchmark
cat > /tmp/bench-proxy/main.tf << 'EOF'
terraform {
  required_providers {
    aws = { source = "compliancetf/aws" }
  }
}
provider "aws" {
  region = "us-east-1"
  profile = "demo"
  compliance { enforcement_mode = "advisory" }
}
resource "aws_s3_bucket" "test" { bucket = "perf-test" }
EOF
export TF_CLI_CONFIG_FILE=/path/to/terraform-provider-aws/.terraformrc
time terraform -chdir=/tmp/bench-proxy plan -input=false
```

## Reviewed By

- Architecture review: blind spot analysis, identified lazy schema loading + single unmarshal + type cache
- Security review: independent performance review, validated approach correctness
- Profiling: Go pprof CPU + memory profiles on real 1,638-resource AWS schema conversion
