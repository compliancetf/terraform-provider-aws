// Package hook is the contract between the protocol proxy and the compliance
// evaluator: the proxy decodes nothing itself, builds a Request per
// intercepted RPC and stage, and turns the Result into diagnostics.
package hook

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Stage names the point in an RPC where the proxy calls Evaluate.
type Stage string

const (
	StageValidate      Stage = "validate"
	StagePlan          Stage = "plan"
	StageApplyPre      Stage = "apply_pre"
	StageApplyPost     Stage = "apply_post"
	StageRead          Stage = "read"
	StageDataSource    Stage = "data_source"
	StageEphemeralOpen Stage = "ephemeral_open"
	StageImport        Stage = "import"
	// StageRPC is the verdict gate for a passthrough RPC that the RPC scope does
	// not allowlist (InvokeAction and every unnamed method). The request carries
	// Method, RPCRequest and, as TypeName, the static evidence token of the
	// method; no value is decoded.
	StageRPC Stage = "rpc"
)

// Kind is the kind of Terraform object a request is about.
type Kind string

const (
	KindResource   Kind = "resource"
	KindDataSource Kind = "data_source"
	KindEphemeral  Kind = "ephemeral"
)

// Op is the resource change operation; "" when the request is not a change.
// At apply it combines the plan-time envelope op with the op the request
// shows, so it is evidence only: an evaluator selects blocking controls from
// the request shape (null Prior: create or replace; null Planned: delete or
// replace; both set: update, import or change) and never lets Op, OpChange
// or a missing Envelope narrow that set.
type Op string

const (
	OpCreate  Op = "create"
	OpUpdate  Op = "update"
	OpReplace Op = "replace"
	OpDelete  Op = "delete"
	OpImport  Op = "import"
	OpChange  Op = "change"
)

// Proxy blocks: Request.Blocked names an apply the proxy refused before the
// hook, so the evaluator records it (the synthetic evidence control id).
const (
	BlockEnvelopeInvalid   = "envelope_invalid"   // planned_private carries an unreadable envelope
	BlockEnvelopeDisagrees = "envelope_disagrees" // the envelope disagrees with the prior state
)

// Severity of a hook diagnostic.
type Severity int

const (
	SeverityError Severity = iota
	SeverityWarning
)

// Value decodes lazily and at most once. A nil *Value means "not present at
// this stage".
type Value struct {
	msgpack, json []byte
	typ           func() (tftypes.Type, error)
	once          sync.Once
	v             tftypes.Value
	err           error
}

// NewValue wraps a raw msgpack or JSON value. typ resolves the value's type
// on the first Get only, so an evaluator that reads nothing costs no schema
// lookup.
func NewValue(msgpack, json []byte, typ func() (tftypes.Type, error)) *Value {
	return &Value{msgpack: msgpack, json: json, typ: typ}
}

// Get decodes the value on first use.
func (v *Value) Get() (tftypes.Value, error) {
	v.once.Do(func() {
		if len(v.msgpack) > 0 && len(v.json) > 0 {
			// tfprotov5 decodes JSON first, Terraform Core MsgPack first: a
			// value carrying both could show the hook one object and Core another.
			v.err = errors.New("dynamic value carries both msgpack and json encodings")
			return
		}
		t, err := v.typ()
		if err != nil {
			v.err = err
			return
		}
		v.v, v.err = (&tfprotov5.DynamicValue{MsgPack: v.msgpack, JSON: v.json}).Unmarshal(t)
	})
	return v.v, v.err
}

// EnvelopeHeader is the compliance header of a PlannedPrivate envelope. It
// lives here because Request carries it; internal/proxy/private.go
// reads and writes it. The v1 key set is frozen. The envelope has no MAC:
// every field may only raise enforcement; Imported, Op import and
// PriorIdentity are hints that never grant an allow or exemption, and the
// proxy's prior identity cross-check is consistency, not authentication.
type EnvelopeHeader struct {
	V   int `json:"v"`
	CTF struct {
		Op                    Op              `json:"op"`
		ControlVersionsDigest string          `json:"control_versions_digest,omitempty"`
		PriorIdentity         json.RawMessage `json:"prior_identity,omitempty"`
		PriorIdentityKind     string          `json:"prior_identity_kind,omitempty"` // identity | id | none
		Imported              bool            `json:"imported,omitempty"`
	} `json:"ctf"`
}

// Request is one hook call.
type Request struct {
	Stage                       Stage
	Kind                        Kind
	TypeName                    string
	Op                          Op
	Config, Prior, Planned, New *Value
	RequiresReplace             []*tftypes.AttributePath
	Deferred                    bool            // upstream returned a deferral at plan
	Envelope                    *EnvelopeHeader // apply_pre only; nil when the plan carried none
	// Identity is the resource identity object of the evaluated object
	// (planned at plan and apply_pre, prior for a planned delete, new at
	// apply_post, read and import), nil when absent or unreadable. Evidence
	// only: it never grants an allow or exemption.
	Identity         map[string]any
	TerraformVersion string
	Method           string // StageRPC only: the full gRPC method
	RPCRequest       []byte // StageRPC only: the raw request message, never logged
	// Blocked is set at apply_pre when the proxy already refused the apply
	// (a Block* token). The request then carries only TypeName and the
	// request-shape Op, no value and no envelope: the evaluator records the
	// block and evaluates nothing; the proxy blocks whatever it returns.
	Blocked string
	// Carry, at apply_post only, is the Result.Carry the evaluator returned
	// at apply_pre of the same RPC, handed back unchanged; nil otherwise.
	Carry any
}

// Diagnostic is a hook finding; it must not carry attribute values the user
// did not write into Summary or Detail.
type Diagnostic struct {
	Severity  Severity
	Summary   string
	Detail    string
	Attribute *tftypes.AttributePath
}

// Result is what Evaluate returns.
type Result struct {
	Diagnostics           []Diagnostic
	ControlVersionsDigest string // read at plan only, stamped into the envelope
	// Carry, at apply_pre only, is evaluator state the proxy hands back on
	// the apply_post Request of the same RPC. Opaque to the proxy: never
	// decoded, logged or kept past the RPC.
	Carry any
}

// ConfigureRequest is the provider Configure input.
type ConfigureRequest struct {
	TerraformVersion string
	Compliance       tftypes.Value // the stripped compliance {} object, may be null
	Schemas          SchemaSource  // upstream schemas from the GetSchema cache
	// Region is the region attribute of the upstream provider config;
	// RegionKnown is false when it is null, unknown or absent.
	Region      string
	RegionKnown bool
	// RegionNull is true when the region is null or absent: the upstream
	// provider then takes it from env or the shared config.
	RegionNull bool
	// SharedConfigSet is true when shared_config_files or
	// shared_credentials_files is set (or unknown) in the provider config,
	// or profile is set but not a known non-empty string.
	SharedConfigSet bool
	// Profile is the provider config profile when it is a known non-empty
	// string: the upstream provider then reads it instead of AWS_PROFILE.
	// Never logged.
	Profile string
	// AccountID is the one id of the upstream config allowed_account_ids;
	// AccountKnown is false when that set is null, absent, not wholly
	// known or holds zero or several ids. Never logged.
	AccountID    string
	AccountKnown bool
	// SkipAccountID is true when skip_requesting_account_id is set and not
	// known false: the upstream provider then never checks its credentials
	// against allowed_account_ids.
	SkipAccountID bool
}

// SchemaSource is the shape celeng.SchemaSource reuses.
type SchemaSource interface {
	Resource(typ string) (*tfprotov5.Schema, bool)
	DataSource(typ string) (*tfprotov5.Schema, bool)
	EphemeralResource(typ string) (*tfprotov5.Schema, bool)
}

// Evaluator is implemented by the lifecycle evaluator. It must be safe for concurrent calls,
// and validate may arrive before Configure. An Evaluator that also implements
// io.Closer is closed once after the plugin server returns.
type Evaluator interface {
	Configure(ctx context.Context, req *ConfigureRequest) ([]Diagnostic, error)
	Wants(kind Kind, typeName string) bool
	Evaluate(ctx context.Context, req *Request) (*Result, error)
}

// Noop wants nothing and finds nothing. apply_pre still reaches it.
type Noop struct{}

func (Noop) Configure(context.Context, *ConfigureRequest) ([]Diagnostic, error) { return nil, nil }
func (Noop) Wants(Kind, string) bool                                            { return false }
func (Noop) Evaluate(context.Context, *Request) (*Result, error)                { return &Result{}, nil }

// IsNoop reports whether ev enforces nothing: nil (served as Noop), Noop or
// *Noop. A type that embeds Noop is a real evaluator and is not matched.
func IsNoop(ev Evaluator) bool {
	switch ev.(type) {
	case nil, Noop, *Noop:
		return true
	}
	return false
}
