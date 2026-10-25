// Package engine is the public facade of the provider's exception selector
// engine: the CEL environment, helper library (strings, cidr, tags, semver,
// json; iam.* is rejected in a selector), cost and input caps and value
// conversion the provider runs when it decides whether a signed grant
// `selector` or a self-service sidecar `match` applies. A tool that decides
// exceptions outside the provider (the verdict producer) imports this package
// so both sides compile and evaluate a selector with the same code.
//
// The package holds no provider runtime state and links no plugin server.
// Bundles, trust, profiles and the lifecycle stay internal.
package engine

import (
	"context"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/schemajson"
)

// State is the result of one evaluation. Only Pass applies an exception;
// Unknown leaves it pending for a later stage; Fail and NotEvaluable do not
// apply.
type State = engine.State

const (
	Pass         = engine.Pass
	Fail         = engine.Fail
	Unknown      = engine.Unknown
	NotEvaluable = engine.NotEvaluable
)

// ErrClass says why an outcome is NotEvaluable ("" otherwise).
type ErrClass = engine.ErrClass

const (
	ErrNone            = engine.ErrNone
	ErrTypeError       = engine.ErrTypeError
	ErrLimit           = engine.ErrLimit
	ErrTimeout         = engine.ErrTimeout
	ErrNoSuchAttribute = engine.ErrNoSuchAttribute
	ErrUnresolved      = engine.ErrUnresolved
	ErrScopeUntrusted  = engine.ErrScopeUntrusted
)

// Outcome is State, ErrClass and the read paths that were unknown (never
// values).
type Outcome = engine.Outcome

// ProviderInfo is bound as provider.region, provider.account_id and
// provider.partition; a field not marked known is unknown.
type ProviderInfo = engine.ProviderInfo

// Input is what one selector evaluation binds.
type Input struct {
	Type   string            // resource type, bound as `type`
	Schema *tfprotov5.Schema // upstream schema of Type; nil is no_such_attribute

	// Resource, Config and Prior are values of Schema's type; a zero Value
	// binds null.
	Resource, Config, Prior tftypes.Value

	Op       string // create, update, replace, delete, no-op, import, refresh, change, open, read
	Env      string // trusted environment
	EnvKnown bool   // false: env is unknown, and a selector that needs it is scope_untrusted
	Provider ProviderInfo
}

// Selector is a compiled exception selector. It is immutable and safe for
// concurrent use.
type Selector struct{ s *celeng.Selector }

// CompileSelector compiles expr with the provider's selector environment
// and limits. The error names a position or a fixed reason, never the
// expression text.
func CompileSelector(expr string) (*Selector, error) {
	s, err := celeng.CompileSelector(expr)
	if err != nil {
		return nil, err
	}
	return &Selector{s}, nil
}

// Eval decides the selector for in under ctx's deadline (50 ms when ctx has
// none, the provider's per-resource budget). Past the deadline the outcome is
// not_evaluable / timeout, even for a decided bool.
func (s *Selector) Eval(ctx context.Context, in *Input) Outcome {
	a := &engine.Activation{Resource: in.Resource, Config: in.Config, Prior: in.Prior, Op: engine.Op(in.Op),
		Env: in.Env, EnvKnown: in.EnvKnown, Provider: in.Provider}
	return s.s.Eval(ctx, oneSchema{in.Schema}, bundle.KindResource, in.Type, a)
}

// SchemaFromJSON converts one type's schema object of `terraform providers
// schema -json` (the value under resource_schemas.<type>) the way the bundle
// generator does.
func SchemaFromJSON(raw []byte) (*tfprotov5.Schema, error) { return schemajson.Schema(raw) }

// oneSchema is a celeng.SchemaSource holding the schema of the evaluated type.
type oneSchema struct{ s *tfprotov5.Schema }

func (o oneSchema) Resource(string) (*tfprotov5.Schema, bool)          { return o.s, o.s != nil }
func (o oneSchema) DataSource(string) (*tfprotov5.Schema, bool)        { return o.s, o.s != nil }
func (o oneSchema) EphemeralResource(string) (*tfprotov5.Schema, bool) { return o.s, o.s != nil }
