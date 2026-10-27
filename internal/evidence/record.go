// Package evidence writes and verifies the provider's per-process evidence
// chain (spec 10.1, 10.2): one JSONL file per process, each line linked to the
// previous one by sha256 over the previous line's bytes (the bytes between LF
// terminators, LF excluded).
//
// Line format: every struct below declares its JSON fields in byte-sorted key
// order, the only map (resource.identity) has ASCII keys, the only numbers are
// non-negative integers, and a line never contains an escape sequence. A line
// is therefore its own RFC 8785 (JCS) form, so sha256 over the line bytes is
// also the JCS digest of the record.
//
// Records are value-free: no attribute values, expected values, messages or
// raw error text. Only the cloud id and identity identifier attributes.
package evidence

// Kind is the record kind.
type Kind string

const (
	KindChainStart Kind = "chain_start"
	KindConfigure  Kind = "configure"
	KindEval       Kind = "eval"
	KindChainBreak Kind = "chain_break"
	KindChainEnd   Kind = "chain_end"
)

// Record is one evidence line. The writer stamps chain, prev, run, seq, ts
// and v; callers set kind and the kind-specific fields:
// configure {provider, terraform, digests, mode, scope, event, optional
// bundle_sources and cache_skipped};
// eval {digests, mode, scope, stage, resource, results, optional envelope
// and matched}.
type Record struct {
	BundleSources []BundleSource `json:"bundle_sources,omitzero"` // configure only, on bundle_loaded
	CacheSkipped  *CacheSkipped  `json:"cache_skipped,omitempty"` // configure only, on bundle_loaded
	Chain         string         `json:"chain"`
	Digests       *Digests       `json:"digests,omitempty"`
	Envelope      string         `json:"envelope,omitempty"` // eval only: "absent" when the plan carried none
	Event         string         `json:"event,omitempty"`
	Kind          Kind           `json:"kind"`
	LastGood      *Link          `json:"last_good,omitempty"`
	LastSeq       *int64         `json:"last_seq,omitempty"`
	Matched       []Match        `json:"matched,omitzero"` // eval apply_pre only: the verdict lookup of the RPC's own half
	Mode          string         `json:"mode,omitempty"`
	Prev          *string        `json:"prev"`
	Provider      *Provider      `json:"provider,omitempty"`
	Resource      *Resource      `json:"resource,omitempty"`
	Results       []Result       `json:"results,omitzero"`
	Run           Run            `json:"run"`
	Scope         *Scope         `json:"scope,omitempty"`
	Seq           int64          `json:"seq"`
	Stage         string         `json:"stage,omitempty"`
	Terraform     *Terraform     `json:"terraform,omitempty"`
	TS            string         `json:"ts"`
	V             int            `json:"v"`
}

// BundleSource is where a loaded bundle came from: embedded (compiled in),
// local (the air-gap control_bundle_path archive), fetched (the bundle
// service) or cache (a cached archive).
type BundleSource struct {
	Digest string `json:"digest"`
	Source string `json:"source"`
}

// CacheSkipped counts the bundle cache archives that were not used, with
// the sorted distinct reasons. Never a file name or path.
type CacheSkipped struct {
	Count   int64    `json:"count"`
	Reasons []string `json:"reasons"`
}

// Match is one verdict entry an apply RPC's own half matched (apply
// situation table): Entry is its index in the verdict's instances[] (the
// verdict named by digests.verdict), InstanceKey its key for that half
// (instance_key, or delete_key on a destroy RPC). The entry's address is
// never written: a for_each key may carry a value, so ctfkit reads it from
// the verdict by index. An empty list is a lookup that matched nothing.
type Match struct {
	Entry       int64  `json:"entry"`
	InstanceKey string `json:"instance_key"`
}

// Link names a committed line: its seq and its hash.
type Link struct {
	Hash string `json:"hash"`
	Seq  int64  `json:"seq"`
}

// Run identifies the Terraform run. ClassClaimed is unverified.
type Run struct {
	ClassClaimed *string `json:"class_claimed"`
	ID           string  `json:"id"`
	IDSource     string  `json:"id_source"`
}

// Provider is the wrapper and upstream provider identity.
type Provider struct {
	Address         string `json:"address"`
	UpstreamVersion string `json:"upstream_version"`
	Version         string `json:"version"`
}

// Terraform carries the Terraform version from ConfigureProvider.
type Terraform struct {
	Version string `json:"version"`
}

// Digests are sha256:<hex> digests; nil is null. Verdict is null without a verdict.
type Digests struct {
	Bundle          *string  `json:"bundle"`
	Bundles         []string `json:"bundles"`
	Content         *string  `json:"content"`
	ControlVersions *string  `json:"control_versions"`
	Exceptions      []string `json:"exceptions"`
	Profile         *string  `json:"profile"`
	SchemaCompat    *string  `json:"schema_compat"`
	Verdict         *string  `json:"verdict"`
}

// Scope is the run scope; each part nil when unknown. Only sources verdict
// and profile are trusted.
type Scope struct {
	AccountID   *Sourced `json:"account_id"`
	Environment *Sourced `json:"environment"`
	Region      *Sourced `json:"region"`
	Workspace   *Sourced `json:"workspace"`
}

// Sourced is a scope value with the source it came from.
type Sourced struct {
	Source string `json:"source"`
	Value  string `json:"value"`
}

// Resource identifies the evaluated instance. ID is the cloud id attribute
// when known; Identity holds identifier attributes only.
type Resource struct {
	ID           *string           `json:"id"`
	Identity     map[string]string `json:"identity"`
	IdentityKind string            `json:"identity_kind"`
	Op           string            `json:"op"`
	Type         string            `json:"type"`
}

// Result is one control's outcome. Paths are schema attribute paths, never
// map keys or values; Err is an error class. Situation is the apply
// situation table row label of a verdict gate result. ReadDigest is the
// baseline read digest of the control over the prior state (plan stage,
// COMPLIANCETF_BASELINE_KEY_FILE set); "" when not computed.
type Result struct {
	// BreakGlassID is the override_id of the honored break-glass receipt
	// that downgraded this result; "" when none.
	BreakGlassID string     `json:"break_glass_id,omitempty"`
	Control      string     `json:"control"`
	Decision     string     `json:"decision"`
	Err          string     `json:"err,omitempty"`
	Exception    *Exception `json:"exception,omitempty"`
	Half         string     `json:"half,omitempty"`
	Paths        []string   `json:"paths"`
	ReadDigest   string     `json:"read_digest,omitempty"`
	Situation    string     `json:"situation,omitempty"`
	State        string     `json:"state"`
	Version      string     `json:"version"`
}

// Exception records the exception considered for a result.
type Exception struct {
	Digest    string  `json:"digest"`
	Expires   string  `json:"expires"`
	ID        string  `json:"id"`
	Source    string  `json:"source"`
	Status    string  `json:"status"`
	Workspace *string `json:"workspace"`
}
