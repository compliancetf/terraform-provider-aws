package bundlegen

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
)

// Case is one fixture in the crosscheck case format, single-control
// form, so the replay runner, verify
// and diffcheck read the same files. Schema is the schema file path the
// replay runner loads; Synthesize leaves it to the caller.
type Case struct {
	ID           string         `json:"id"`
	ResourceType string         `json:"resource_type"`
	Schema       string         `json:"schema"`
	Control      bundle.Control `json:"control"`
	Bindings     CaseBindings   `json:"bindings"`
	Expect       CaseExpect     `json:"expect"`
}

// CaseBindings are the case inputs: omitted attributes are null and
// {"$unknown": true} is unknown (P1 rule).
type CaseBindings struct {
	Op       string            `json:"op"`
	Env      json.RawMessage   `json:"env,omitempty"`
	Provider map[string]string `json:"provider"`
	Resource json.RawMessage   `json:"resource,omitempty"`
	Config   json.RawMessage   `json:"config,omitempty"`
	Prior    json.RawMessage   `json:"prior,omitempty"`
}

// CaseExpect is the expected engine result. UnknownPaths is never null.
type CaseExpect struct {
	State        engine.State    `json:"state"`
	ErrClass     engine.ErrClass `json:"err_class"`
	UnknownPaths []string        `json:"unknown_paths"`
}

// Case names Synthesize writes.
const (
	CasePass    = "pass"
	CaseFail    = "fail"
	CaseUnknown = "unknown"
)

// caseID is <control id>.<kind>.<type>.<name>, the crosscheck case id.
func caseID(c bundle.Control, name string) string {
	return c.ID + "." + string(c.Kind) + "." + c.ResourceType + "." + name
}

// CasePath is the output path of case k of bundle id:
// <id>/cases/<control id>/<kind>.<type>.<name>.json.
func CasePath(id string, k Case) string {
	prefix := k.Control.ID + "."
	return id + "/cases/" + k.Control.ID + "/" + strings.TrimPrefix(k.ID, prefix) + ".json"
}

// AddCases writes cs canonically under bundle id. A path already in o is an
// error: a case never overwrites another file.
func (o *Output) AddCases(id string, cs []Case) error {
	if o.Files == nil {
		o.Files = map[string][]byte{}
	}
	for _, k := range cs {
		name, ok := strings.CutPrefix(k.ID, caseID(k.Control, ""))
		if !ok || name == "" || strings.ContainsAny(name, "/\\") {
			return errf("E_FIXTURE", "case %q is not named <control id>.<kind>.<type>.<case>", k.ID)
		}
		data, err := canonicalJSON(k)
		if err != nil {
			return err
		}
		p := CasePath(id, k)
		if _, dup := o.Files[p]; dup {
			return errf("E_FIXTURE", "case %q: %s is already in the output", k.ID, p)
		}
		o.Files[p] = data
	}
	return nil
}

// fixture values (synthesis rules)
const (
	fixtureOrg     = "bobthecorp"
	fixtureInvalid = "BOBTHECORP_INVALID"
	fixtureARN     = "arn:aws:kms:eu-west-1:111111111111:key/bobthecorp"
)

var fixtureProvider = map[string]string{"region": "eu-west-1", "account_id": "111111111111"}

// Synthesize writes the pass, fail and unknown cases of a translated control
// (Translate output: a && chain of ==, in, != null, size and exists terms).
// pass sets every term to its first accepted value; fail breaks the first
// term (negated bool, BOBTHECORP_INVALID, null, zero blocks); every
// Optional+Computed read gets an unknown case on the pass value that
// expects unknown, so it never decides: an effective deny control with such
// a read fails verify (E_OPTIONAL_COMPUTED) until an authored deciding case
// exists. The value binds as both resource and config. Any other expression
// shape is E_FIXTURE_SYNTH: authored controls carry their own cases.
func Synthesize(c bundle.Control, s *tfprotov5.Schema) ([]Case, error) {
	synthErr := func(format string, a ...any) ([]Case, error) {
		return nil, errf("E_FIXTURE_SYNTH", "%s %s %s: %s", c.ID, c.Kind, c.ResourceType, fmt.Sprintf(format, a...))
	}
	if c.Expr == nil || s == nil || s.Block == nil || hasNil(s.Block) {
		return synthErr("no expr or no schema")
	}
	env, err := cel.NewEnv(cel.ClearMacros()) // keep exists() a call
	if err != nil {
		return nil, err
	}
	a, iss := env.Parse(*c.Expr)
	if iss.Err() != nil {
		return synthErr("expr does not parse")
	}
	root := "resource"
	if c.PresenceMode == bundle.PresenceConfigured {
		root = "config"
	}
	terms := conjuncts(a.NativeRep().Expr())
	value := func(failFirst bool) (map[string]any, error) {
		obj := map[string]any{}
		for _, t := range terms {
			if err := applyTerm(obj, s.Block, root, t, true); err != nil {
				return nil, err
			}
		}
		if failFirst {
			return obj, applyTerm(obj, s.Block, root, terms[0], false)
		}
		return obj, nil
	}
	mk := func(name string, obj map[string]any, st engine.State, unknown []string) (Case, error) {
		raw, err := json.Marshal(obj)
		if err != nil {
			return Case{}, err
		}
		return Case{ID: caseID(c, name), ResourceType: c.ResourceType, Control: c,
			Bindings: CaseBindings{Op: string(bundle.OnCreate), Provider: fixtureProvider, Resource: raw, Config: raw},
			Expect:   CaseExpect{State: st, ErrClass: engine.ErrNone, UnknownPaths: unknown}}, nil
	}
	var out []Case
	for _, x := range []struct {
		name string
		fail bool
		st   engine.State
	}{{CasePass, false, engine.Pass}, {CaseFail, true, engine.Fail}} {
		obj, err := value(x.fail)
		if err != nil {
			return synthErr("%v", err)
		}
		k, err := mk(x.name, obj, x.st, []string{})
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	var oc []string
	for _, r := range c.Reads {
		if ocPrefix(s.Block, strings.Split(r, ".")) > 0 {
			oc = append(oc, r)
		}
	}
	for _, r := range oc {
		obj, err := value(false)
		if err != nil {
			return synthErr("%v", err)
		}
		path := strings.Split(r, ".")
		setUnknown(obj, path[:ocPrefix(s.Block, path)])
		name := CaseUnknown
		if len(oc) > 1 {
			// read segments are schema names without '-': injective
			name += "-" + strings.ReplaceAll(r, ".", "-")
		}
		// The engine reports an unknown below a block at the block: exists()
		// iterates it, so partial evaluation stops there.
		k, err := mk(name, obj, engine.Unknown, []string{strings.SplitN(r, ".", 2)[0]})
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// conjuncts flattens a && chain in source order.
func conjuncts(e ast.Expr) []ast.Expr {
	if e.Kind() == ast.CallKind && e.AsCall().FunctionName() == operators.LogicalAnd {
		args := e.AsCall().Args()
		return slices.Concat(conjuncts(args[0]), conjuncts(args[1]))
	}
	return []ast.Expr{e}
}

// field returns name for the select v.name.
func field(e ast.Expr, v string) (string, bool) {
	if e.Kind() != ast.SelectKind || e.AsSelect().IsTestOnly() {
		return "", false
	}
	op := e.AsSelect().Operand()
	if op.Kind() != ast.IdentKind || op.AsIdent() != v {
		return "", false
	}
	return e.AsSelect().FieldName(), true
}

// literal returns the JSON value of a string, bool, int or null literal.
func literal(e ast.Expr) (any, bool) {
	if e.Kind() != ast.LiteralKind {
		return nil, false
	}
	switch v := e.AsLiteral().(type) {
	case types.String, types.Bool, types.Int:
		return v.Value(), true
	case types.Null:
		return nil, true
	}
	return nil, false
}

// applyTerm sets in obj, the value of block blk bound to variable v, the
// pass or fail value of term t.
func applyTerm(obj map[string]any, blk *tfprotov5.SchemaBlock, v string, t ast.Expr, pass bool) error {
	if t.Kind() != ast.CallKind {
		return fmt.Errorf("unsupported term kind %v", t.Kind())
	}
	call := t.AsCall()
	args := call.Args()
	attr := func(e ast.Expr) (*tfprotov5.SchemaAttribute, error) {
		name, ok := field(e, v)
		if at := attrNamed(blk, name); ok && at != nil && at.Type != nil {
			return at, nil
		}
		return nil, fmt.Errorf("%s: operand is not an attribute of %s", call.FunctionName(), v)
	}
	sizeOf := func(e ast.Expr) (ast.Expr, bool) {
		if e.Kind() != ast.CallKind || e.AsCall().FunctionName() != "size" || e.AsCall().IsMemberFunction() || len(e.AsCall().Args()) != 1 {
			return nil, false
		}
		return e.AsCall().Args()[0], true
	}
	switch fn := call.FunctionName(); {
	case (fn == operators.Equals || fn == operators.In) && len(args) == 2:
		at, err := attr(args[0])
		if err != nil {
			return err
		}
		lits := []ast.Expr{args[1]}
		if fn == operators.In {
			if args[1].Kind() != ast.ListKind {
				return fmt.Errorf("%s in: not a list literal", at.Name)
			}
			lits = args[1].AsList().Elements()
		}
		vals := make([]any, len(lits))
		for i, l := range lits {
			x, ok := literal(l)
			if !ok || x == nil {
				return fmt.Errorf("%s %s: values must be string, bool or int literals", at.Name, fn)
			}
			vals[i] = x
		}
		if len(vals) == 0 {
			return fmt.Errorf("%s %s: no values", at.Name, fn)
		}
		if pass {
			obj[at.Name] = vals[0]
		} else {
			obj[at.Name] = failValue(at.Type, vals)
		}
		return nil
	case fn == operators.NotEquals && len(args) == 2:
		at, err := attr(args[0])
		if err != nil {
			return err
		}
		if x, ok := literal(args[1]); !ok || x != nil {
			return fmt.Errorf("%s !=: only != null", at.Name)
		}
		return setSample(obj, at, pass)
	case fn == operators.Greater && len(args) == 2:
		inner, ok := sizeOf(args[0])
		if x, lok := literal(args[1]); !ok || !lok || x != int64(0) {
			return fmt.Errorf("> : only size(attribute) > 0")
		}
		at, err := attr(inner)
		if err != nil {
			return err
		}
		return setSample(obj, at, pass)
	case fn == operators.GreaterEquals && len(args) == 2:
		inner, ok := sizeOf(args[0])
		if x, lok := literal(args[1]); !ok || !lok || x != int64(1) {
			return fmt.Errorf(">=: only size(block) >= 1")
		}
		name, ok := field(inner, v)
		if !ok || blockNamed(blk, name) == nil {
			return fmt.Errorf(">=: operand is not a block of %s", v)
		}
		if !pass {
			obj[name] = []any{}
		} else if l, ok := obj[name].([]any); !ok || len(l) == 0 {
			obj[name] = []any{map[string]any{}}
		}
		return nil
	case fn == "exists" && call.IsMemberFunction() && len(args) == 2:
		name, ok := field(call.Target(), v)
		nb := blockNamed(blk, name)
		if !ok || nb == nil || nb.Block == nil || args[0].Kind() != ast.IdentKind {
			return fmt.Errorf("exists: target is not a block of %s", v)
		}
		if !pass {
			obj[name] = []any{}
			return nil
		}
		elem := firstElem(obj, name)
		for _, sub := range conjuncts(args[1]) {
			if err := applyTerm(elem, nb.Block, args[0].AsIdent(), sub, true); err != nil {
				return err
			}
		}
		obj[name] = []any{elem}
		return nil
	}
	return fmt.Errorf("unsupported term %s", call.FunctionName())
}

// setSample sets attribute at to a non-empty sample value (pass) or null.
func setSample(obj map[string]any, at *tfprotov5.SchemaAttribute, pass bool) error {
	if !pass {
		obj[at.Name] = nil
		return nil
	}
	str := fixtureOrg + "-" + at.Name
	if strings.HasSuffix(at.Name, "_arn") || at.Name == "kms_key_id" {
		str = fixtureARN
	}
	// tftypes List/Set/Map.Is compares the outer kind only: element types
	// are checked through prim.
	prim := func(t tftypes.Type) (any, bool) {
		switch {
		case t.Equal(tftypes.String):
			return str, true
		case t.Equal(tftypes.Bool):
			return true, true
		case t.Equal(tftypes.Number):
			return 1, true
		}
		return nil, false
	}
	var v any
	ok := false
	switch t := at.Type.(type) {
	case tftypes.List:
		if e, eok := prim(t.ElementType); eok {
			v, ok = []any{e}, true
		}
	case tftypes.Set:
		if e, eok := prim(t.ElementType); eok {
			v, ok = []any{e}, true
		}
	case tftypes.Map:
		if e, eok := prim(t.ElementType); eok {
			v, ok = map[string]any{fixtureOrg: e}, true
		}
	default:
		v, ok = prim(t)
	}
	if !ok {
		return fmt.Errorf("%s: no sample value for %s", at.Name, at.Type)
	}
	obj[at.Name] = v
	return nil
}

// failValue is a value of t outside vals: the negated bool,
// BOBTHECORP_INVALID, the largest integer plus one, else null.
func failValue(t tftypes.Type, vals []any) any {
	var cand any
	switch {
	case t.Is(tftypes.Bool):
		cand = vals[0] != true
	case t.Is(tftypes.String):
		cand = fixtureInvalid
	case t.Is(tftypes.Number):
		hi := int64(0)
		for _, v := range vals {
			if n, ok := v.(int64); ok && n > hi {
				hi = n
			}
		}
		cand = hi + 1
	}
	if cand == nil || slices.Contains(vals, cand) {
		return nil
	}
	return cand
}

// optionalComputed reports whether path names an Optional+Computed
// attribute or reads through one (an object-typed attribute), through
// nested blocks.
func optionalComputed(blk *tfprotov5.SchemaBlock, path []string) bool {
	return ocPrefix(blk, path) > 0
}

// ocPrefix is the length of the path prefix that names an Optional+Computed
// attribute, or 0 when the path reads none.
func ocPrefix(blk *tfprotov5.SchemaBlock, path []string) int {
	for i, seg := range path {
		if at := attrNamed(blk, seg); at != nil {
			if at.Optional && at.Computed {
				return i + 1
			}
			return 0 // below a plain attribute nothing is a schema attribute
		}
		nb := blockNamed(blk, seg)
		if nb == nil || nb.Block == nil {
			return 0
		}
		blk = nb.Block
	}
	return 0
}

// setUnknown marks path unknown in obj, through the first element of each
// block on the way (an element is added when the block is empty).
func setUnknown(obj map[string]any, path []string) {
	for _, seg := range path[:len(path)-1] {
		e := firstElem(obj, seg)
		if l, ok := obj[seg].([]any); ok && len(l) > 0 {
			l[0] = e
		} else {
			obj[seg] = []any{e}
		}
		obj = e
	}
	obj[path[len(path)-1]] = map[string]any{"$unknown": true}
}

// firstElem returns the first element of block list obj[name], or a new
// empty element when there is none.
func firstElem(obj map[string]any, name string) map[string]any {
	if l, ok := obj[name].([]any); ok && len(l) > 0 {
		if m, ok := l[0].(map[string]any); ok {
			return m
		}
	}
	return map[string]any{}
}

// controlCases returns the cases of every control in cs by ControlKey, each
// with schema set to caseSchema: Synthesize for a translated control, the
// authored fixtures of its target otherwise (Inputs.AuthoredFixtures).
func controlCases(in Inputs, cs []bundle.Control, translated map[ControlKey]bool, caseSchema string) (map[ControlKey][]Case, error) {
	out := map[ControlKey][]Case{}
	for _, c := range cs {
		var kc []Case
		if translated[keyOf(&c)] {
			sc, ok := in.Schemas.Lookup(c.Kind, c.ResourceType)
			if !ok {
				return nil, errf("E_SCHEMA_TYPE", "%s: %s type %s is not in the upstream schema", c.ID, c.Kind, c.ResourceType)
			}
			var err error
			if kc, err = Synthesize(c, sc); err != nil {
				return nil, err
			}
		} else {
			for _, x := range in.AuthoredFixtures[c.ID] {
				if x.Kind != c.Kind || x.Type != c.ResourceType {
					continue
				}
				k, err := fixtureCase(c, x)
				if err != nil {
					return nil, err
				}
				kc = append(kc, k)
			}
		}
		for i := range kc {
			kc[i].Schema = caseSchema
		}
		out[keyOf(&c)] = kc
	}
	return out, nil
}

// providerKeys are the provider bindings a case sets (caseBindings).
var providerKeys = []string{"account_id", "partition", "region"}

// fixtureCase is authored fixture x of control c in the case format: an
// omitted env or object stays absent, provider values must be strings of
// providerKeys and unknown_paths is never null.
func fixtureCase(c bundle.Control, x Fixture) (Case, error) {
	id := caseID(c, x.Name)
	bad := func(format string, a ...any) (Case, error) {
		return Case{}, errf("E_FIXTURE", "case %s: %s", id, fmt.Sprintf(format, a...))
	}
	k := Case{ID: id, ResourceType: c.ResourceType, Control: c,
		Bindings: CaseBindings{Op: string(x.Bindings.Op), Provider: map[string]string{}},
		Expect:   CaseExpect{State: x.Expect.State, ErrClass: x.Expect.ErrClass, UnknownPaths: slices.Clone(x.Expect.UnknownPaths)}}
	if k.Expect.UnknownPaths == nil {
		k.Expect.UnknownPaths = []string{}
	}
	for key, v := range x.Bindings.Provider {
		s, ok := v.(string)
		if !slices.Contains(providerKeys, key) || !ok {
			return bad("provider.%s: want a string of %v", safeName(key), providerKeys)
		}
		k.Bindings.Provider[key] = s
	}
	if x.Bindings.Env != "" {
		env, err := json.Marshal(x.Bindings.Env)
		if err != nil {
			return bad("env does not encode as JSON")
		}
		k.Bindings.Env = env
	}
	for _, o := range []struct {
		name string
		v    map[string]any
		dst  *json.RawMessage
	}{{"resource", x.Bindings.Resource, &k.Bindings.Resource}, {"config", x.Bindings.Config, &k.Bindings.Config}, {"prior", x.Bindings.Prior, &k.Bindings.Prior}} {
		if o.v == nil {
			continue
		}
		raw, err := json.Marshal(o.v)
		if err != nil {
			return bad("%s does not encode as JSON (non-string keys?)", o.name)
		}
		*o.dst = raw
	}
	return k, nil
}
