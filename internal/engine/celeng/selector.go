package celeng

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"cel.dev/cel-go/cel"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
)

// Selector input caps (the v0.1 match caps): a bound
// value with more than selectorMaxElements collection elements in total, a
// string over selectorMaxString bytes, or containers nested deeper than
// selectorMaxDepth makes the selector not_evaluable / limit, so it never
// applies. The depth cap bounds the cap walk itself; the deepest value an AWS
// provider v6.69 schema can type nests 43 containers (aws_wafv2_web_acl_rule,
// aws_quicksight_*), so real values stay below it.
const (
	selectorMaxElements = 10000
	selectorMaxString   = 256 << 10
	selectorMaxDepth    = 64
)

// varType is the exception selector's resource type variable: top level,
// because resource.type collides with real attributes.
const varType = "type"

// Selector is a compiled exception selector: the CEL `selector` of a signed
// grant or `match` of a sidecar
// entry. It is immutable and safe for concurrent use.
type Selector struct {
	ch  *Checked
	prg cel.Program
}

// selectorEnv is the control env plus the type variable.
var selectorEnv = sync.OnceValues(func() (*cel.Env, error) {
	env, err := newEnv()
	if err != nil {
		return nil, err
	}
	return env.Extend(cel.Variable(varType, cel.StringType))
})

// CompileSelector compiles expr at grant or sidecar load. The error names a
// position or a fixed reason, never the expression text. A selector may not
// call iam.*: its unconditional under-approximation is only safe where a
// true result raises enforcement, and a selector's true waives a control.
func CompileSelector(expr string) (*Selector, error) {
	env, err := selectorEnv()
	if err != nil {
		return nil, fmt.Errorf("celeng: selector env: %w", err)
	}
	a, iss := env.Compile(expr)
	if iss.Err() != nil {
		if errs := iss.Errors(); len(errs) > 0 {
			loc := errs[0].Location // column is 0-based, -1 when unknown
			return nil, fmt.Errorf("does not compile at %d:%d", loc.Line(), max(loc.Column(), 0)+1)
		}
		return nil, errors.New("does not compile")
	}
	if t := a.OutputType(); !t.IsExactType(cel.BoolType) && !t.IsExactType(cel.DynType) {
		return nil, errors.New("output type is not bool")
	}
	if callsIAM(a.NativeRep().Expr()) {
		return nil, errors.New("iam.* is not allowed in a selector")
	}
	ch, err := analyze(a)
	if d := (*LoadDiag)(nil); errors.As(err, &d) {
		return nil, errors.New(d.Detail) // a fixed reason, never control text
	} else if err != nil {
		return nil, errors.New("reads analysis failed")
	}
	prg, err := env.Program(a, cel.EvalOptions(cel.OptPartialEval, cel.OptTrackState),
		cel.CostLimit(defaultCostLimit), cel.InterruptCheckFrequency(interruptEvery))
	if err != nil {
		return nil, errors.New("does not plan")
	}
	return &Selector{ch: ch, prg: prg}, nil
}

// Eval decides the selector for one resource of kind and typ with the
// activation the control used (trusted env and provider included). It shares
// the caller's per-resource deadline; past it the outcome is timeout, even
// for a decided bool, so a late true never waives. Pass applies; every other
// state does not.
func (s *Selector) Eval(ctx context.Context, schemas SchemaSource, kind bundle.Kind, typ string, a *engine.Activation) engine.Outcome {
	timeout := engine.Outcome{State: engine.NotEvaluable, Err: engine.ErrTimeout}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultBudget)
		defer cancel()
	}
	if ctx.Err() != nil {
		return timeout
	}
	sc := schemaOf(schemas, kind, typ)
	if sc == nil || sc.Block == nil {
		return engine.Outcome{State: engine.NotEvaluable, Err: engine.ErrNoSuchAttribute}
	}
	deadline, _ := ctx.Deadline()
	in := Bindings{Kind: kind, Type: typ, Resource: a.Resource, Config: a.Config, Prior: a.Prior,
		Op: string(a.Op), Env: a.Env, EnvKnown: a.EnvKnown, Provider: a.Provider}
	for _, v := range []tftypes.Value{a.Resource, a.Config, a.Prior} {
		if overCap(v) {
			return engine.Outcome{State: engine.NotEvaluable, Err: engine.ErrLimit}
		}
	}
	vars, unknown, _, bad := bind(in, sc.Block, deadline)
	if slices.ContainsFunc(s.ch.Vars, func(v string) bool { return bad[v] }) {
		return engine.Outcome{State: engine.NotEvaluable, Err: engine.ErrTypeError}
	}
	vars[varType] = typ
	act, err := cel.PartialVars(vars, unknown...)
	if err != nil {
		return engine.Outcome{State: engine.NotEvaluable, Err: engine.ErrTypeError}
	}
	val, _, err := s.prg.ContextEval(ctx, act)
	state, class, paths := classify(ctx, val, err, s.ch.Reads, sc.Block, in.EnvKnown)
	if ctx.Err() != nil || time.Now().After(deadline) {
		return timeout
	}
	return engine.Outcome{State: state, Err: class, UnknownPaths: paths}
}

// schemaOf is the upstream schema of kind and typ, nil when absent.
func schemaOf(s SchemaSource, kind bundle.Kind, typ string) *tfprotov5.Schema {
	if s == nil {
		return nil
	}
	lookup := s.Resource
	switch kind {
	case bundle.KindDataSource:
		lookup = s.DataSource
	case bundle.KindEphemeral:
		lookup = s.EphemeralResource
	}
	sc, _ := lookup(typ)
	return sc
}

// overCap reports whether v exceeds the selector input caps. Null and
// unknown values hold nothing; object attributes are not elements; map keys
// count against the string cap; every known container, objects included,
// counts one level of depth.
func overCap(v tftypes.Value) bool {
	n := 0
	var walk func(v tftypes.Value, depth int) bool
	walk = func(v tftypes.Value, depth int) bool {
		if v.Type() == nil || v.IsNull() || !v.IsKnown() {
			return false
		}
		var elems []tftypes.Value
		switch v.Type().(type) {
		case tftypes.List, tftypes.Set, tftypes.Tuple:
			_ = v.As(&elems) //nolint:errcheck // the type switch guarantees the shape
			n += len(elems)
		case tftypes.Map, tftypes.Object:
			var m map[string]tftypes.Value
			_ = v.As(&m) //nolint:errcheck // the type switch guarantees the shape
			_, isMap := v.Type().(tftypes.Map)
			if isMap {
				n += len(m)
			}
			for k, e := range m {
				if isMap && len(k) > selectorMaxString { // a map key is data the selector can read
					return true
				}
				elems = append(elems, e)
			}
		default:
			var str string
			return v.Type().Is(tftypes.String) && v.As(&str) == nil && len(str) > selectorMaxString
		}
		if n > selectorMaxElements || depth > selectorMaxDepth {
			return true
		}
		return slices.ContainsFunc(elems, func(e tftypes.Value) bool { return walk(e, depth+1) })
	}
	return walk(v, 1)
}
