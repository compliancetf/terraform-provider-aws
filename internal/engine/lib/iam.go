package lib

import (
	"cmp"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/interpreter"

	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

// DeadlineVar names the activation entry (a time.Time) holding the
// per-resource deadline. iam.parse admits its work against the time left
// until it; absent or past is limit. "#" keeps it out of CEL source.
const DeadlineVar = "#lib.deadline"

// IAM declares iam.parse(string) -> map, iam.grants(map, string) -> bool and
// iam.grants_all(map, string) -> bool.
// iam.parse is bound per program by IAMProgram; without it every call is
// ErrUnresolved. iam.grants and iam.grants_all accept only statements that
// iam.parse returned (a hand-built map is ErrInvalid) and map iampolicy
// errors to the lib sentinels, so a catalog miss is ErrUnresolved, never a
// non-match. Strict like Helpers: unknown arguments make the call unknown.
func IAM() cel.EnvOption {
	stmt := cel.MapType(cel.StringType, cel.DynType)
	return cel.Lib(iamLib{stmt})
}

type iamLib struct{ stmt *cel.Type }

func (l iamLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("iam.parse", cel.Overload("iam_parse_string", []*cel.Type{cel.StringType}, l.stmt,
			cel.UnaryBinding(func(ref.Val) ref.Val { return types.WrapErr(ErrUnresolved) }))),
		cel.Function("iam.grants", cel.Overload("iam_grants_map_string", []*cel.Type{l.stmt, cel.StringType}, cel.BoolType,
			cel.BinaryBinding(grants(iampolicy.Grants)))),
		cel.Function("iam.grants_all", cel.Overload("iam_grants_all_map_string", []*cel.Type{l.stmt, cel.StringType}, cel.BoolType,
			cel.BinaryBinding(grants(iampolicy.GrantsAll)))),
		cel.Function("iam.principal_is", cel.Overload("iam_principal_is_map_string", []*cel.Type{l.stmt, cel.StringType}, cel.BoolType,
			cel.OverloadIsNonStrict(), cel.BinaryBinding(identity(iampolicy.PrincipalIs)))),
		cel.Function("iam.resource_is", cel.Overload("iam_resource_is_map_string", []*cel.Type{l.stmt, cel.StringType}, cel.BoolType,
			cel.OverloadIsNonStrict(), cel.BinaryBinding(identity(iampolicy.ResourceIs)))),
		cel.Function("iam.principals_in_account", cel.Overload("iam_principals_in_account_map_string_string", []*cel.Type{l.stmt, cel.StringType, cel.StringType}, cel.BoolType,
			cel.OverloadIsNonStrict(), cel.FunctionBinding(principalsInAccount))),
	}
}

// principalsInAccount binds iam.principals_in_account(stmt, account,
// partition) like identity: account and partition are both part of the
// queried identity, so either unknown is ErrUnresolved, never unknown.
func principalsInAccount(args ...ref.Val) ref.Val {
	if len(args) != 3 {
		return invalid()
	}
	s, a, p := args[0], args[1], args[2]
	switch {
	case types.IsError(s):
		return s
	case types.IsError(a):
		return a
	case types.IsError(p):
		return p
	case types.IsUnknown(p):
		return types.WrapErr(ErrUnresolved)
	}
	part, ok := p.(types.String)
	if !ok {
		return invalid()
	}
	if !iampolicy.KnownPartition(string(part)) {
		// Checked before identity, which returns an unknown statement as is.
		return types.WrapErr(ErrUnresolved)
	}
	return identity(func(st iampolicy.Statement, account string) (bool, error) {
		return iampolicy.PrincipalsInAccount(st, account, string(part))
	})(s, a)
}

// identity binds iam.principal_is, iam.principals_in_account and
// iam.resource_is. Non-strict so that an
// unknown queried identity (resource.arn at create) is ErrUnresolved, never
// unknown: unresolved identities never yield pending.
// An error argument passes through; an unknown statement (the document is
// unknown) stays unknown only when the queried identity is known.
func identity(f func(iampolicy.Statement, string) (bool, error)) func(s, a ref.Val) ref.Val {
	return func(s, a ref.Val) ref.Val {
		switch {
		case types.IsError(s):
			return s
		case types.IsError(a):
			return a
		case types.IsUnknown(a):
			return types.WrapErr(ErrUnresolved)
		case types.IsUnknown(s):
			return s
		}
		st, ok := s.(*stmtVal)
		name, isStr := a.(types.String)
		if !ok || !isStr {
			return invalid()
		}
		m, err := f(st.st, string(name))
		if err != nil {
			return types.WrapErr(iamErr(err))
		}
		return types.Bool(m)
	}
}

func (iamLib) ProgramOptions() []cel.ProgramOption { return nil }

func grants(f func(iampolicy.Statement, *iampolicy.Catalog, string) (bool, error)) func(s, a ref.Val) ref.Val {
	return func(s, a ref.Val) ref.Val {
		st, ok := s.(*stmtVal)
		name, isStr := a.(types.String)
		if !ok || !isStr {
			return invalid()
		}
		g, err := f(st.st, st.cat, string(name))
		if err != nil {
			return types.WrapErr(iamErr(err))
		}
		return types.Bool(g)
	}
}

// IAMProgram binds iam.parse in one program to the bundle's action catalog
// and content digest: the document cache key covers both, so a catalog or
// content change never reuses a parse. A nil catalog is an error: iam.parse
// without one could not expand actions or back iam.grants.
func IAMProgram(cat *iampolicy.Catalog, contentDigest string) (cel.ProgramOption, error) {
	if cat == nil {
		return nil, errors.New("lib: iam.parse needs an action catalog")
	}
	return cel.CustomDecoratorV2(func(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
		if c, ok := i.(interpreter.InterpretableCall); ok && c.OverloadID() == "iam_parse_string" && len(c.Args()) == 1 {
			return &parseCall{InterpretableCall: c, cat: cat, content: contentDigest}, nil
		}
		return i, nil
	}), nil
}

// IAMFlags wraps every IAM call node that can answer ErrUnresolved, the
// unbound or bound iam.parse included, so the UnresolvedVar flag is set
// with or without an action catalog. Install it after IAMProgram.
func IAMFlags() cel.ProgramOption {
	return cel.CustomDecoratorV2(func(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
		if c, ok := i.(interpreter.InterpretableCall); ok && unresolvedCalls[c.OverloadID()] {
			return &flagCall{c}, nil
		}
		return i, nil
	})
}

// UnresolvedVar names the activation entry (a *bool) that an executed
// iam.grants, iam.grants_all, iam.principal_is, iam.principals_in_account
// or iam.resource_is call sets
// when it returns ErrUnresolved. CEL may absorb that error (err || true,
// err || unknown); the engine reads the flag so an executed unresolved
// answer is never pass and never unknown.
const UnresolvedVar = "#lib.unresolved"

var unresolvedCalls = map[string]bool{"iam_parse_string": true, "iam_grants_map_string": true, "iam_grants_all_map_string": true,
	"iam_principal_is_map_string": true, "iam_principals_in_account_map_string_string": true, "iam_resource_is_map_string": true}

type flagCall struct{ interpreter.InterpretableCall }

func (c *flagCall) Eval(a interpreter.Activation) ref.Val { return c.Exec(interpreter.AsFrame(a)) }

// Exec panics without the UnresolvedVar sink: a flag that cannot be set
// would let CEL absorb an unresolved answer into a pass, and any error value
// could be absorbed the same way. cel-go turns the panic into an evaluation
// error, which the engine maps to not_evaluable.
func (c *flagCall) Exec(f *interpreter.ExecutionFrame) ref.Val {
	p, _ := f.ResolveName(UnresolvedVar)
	b, ok := p.(*bool)
	if !ok || b == nil {
		panic(errNoUnresolvedSink)
	}
	v := c.InterpretableCall.Exec(f)
	if e, ok := v.(*types.Err); ok && errors.Is(e, ErrUnresolved) {
		*b = true
	}
	return v
}

var errNoUnresolvedSink = errors.New("lib: activation has no *bool " + UnresolvedVar + " entry")

// parseCall replaces the iam.parse call node: a CEL function binding sees
// neither the catalog nor the evaluation, the node sees both.
type parseCall struct {
	interpreter.InterpretableCall
	cat     *iampolicy.Catalog
	content string
}

func (p *parseCall) Eval(a interpreter.Activation) ref.Val { return p.Exec(interpreter.AsFrame(a)) }

func (p *parseCall) Exec(f *interpreter.ExecutionFrame) ref.Val {
	arg := p.Args()[0].Exec(f)
	if types.IsUnknownOrError(arg) {
		return arg
	}
	s, ok := arg.(types.String)
	if !ok {
		return invalid()
	}
	var remaining time.Duration
	if d, ok := f.ResolveName(DeadlineVar); ok {
		if t, ok := d.(time.Time); ok {
			remaining = time.Until(t)
		}
	}
	v, err := docs.iam(string(s), p.cat, p.content, remaining)
	if err != nil {
		return types.WrapErr(err)
	}
	return v
}

// iam parses doc through the cache. Key: jsonKey("iam", sha256(content) ||
// sha256(catalog digest), doc). Order: catalog, size, spent budget, cache,
// Normalize (admission, decode, expansion). A spent budget is limit even on a
// cache hit, so the result never depends on cache state. Limits are never cached: admission depends
// on the live budget.
func (c *docCache) iam(doc string, cat *iampolicy.Catalog, content string, remaining time.Duration) (ref.Val, error) {
	if cat == nil {
		return nil, ErrUnresolved
	}
	if len(doc) > MaxDocBytes || remaining <= 0 { // Budget 0 would disable admission
		return nil, ErrLimit
	}
	// Fixed-width key digest: sha256(content) || sha256(catalog digest), so
	// no content string can alias another (content, catalog, doc) triple.
	cd, gd := sha256.Sum256([]byte(content)), sha256.Sum256([]byte(cat.Digest()))
	k := jsonKey("iam", append(cd[:], gd[:]...), doc)
	c.mu.Lock()
	e, hit := c.m[k]
	c.mu.Unlock()
	if hit {
		if v, ok := e.v.(ref.Val); ok && e.err == nil {
			return v, nil
		}
		return nil, cmp.Or(e.err, ErrInvalid)
	}
	p, err := iampolicy.Normalize(doc, iampolicy.Options{Catalog: cat, Budget: remaining})
	if err != nil {
		if err = iamErr(err); err != ErrLimit {
			c.store(k, docEntry{err: err}, len(doc))
		}
		return nil, err
	}
	v, n, err := policyValue(p, cat)
	if err != nil {
		return nil, err
	}
	c.store(k, docEntry{v: v}, len(doc)+n)
	return v, nil
}

// stmtVal is one statement of an iam.parse result: a CEL map that also
// carries the normalized statement and its catalog for iam.grants.
type stmtVal struct {
	traits.Mapper
	st  iampolicy.Statement
	cat *iampolicy.Catalog
}

// policyValue converts a normalized policy to its CEL map through the golden
// JSON shape. n is the cache charge beyond the document: twice the JSON size.
// shortcut: a guess like nodeBytes, measure with the P1 benchmark.
func policyValue(p *iampolicy.Policy, cat *iampolicy.Catalog) (ref.Val, int, error) {
	stmts := make([]ref.Val, len(p.Statements))
	n := 0
	for i, st := range p.Statements {
		b, err := json.Marshal(st)
		if err != nil {
			return nil, 0, ErrInvalid
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, 0, ErrInvalid
		}
		n += 2 * len(b)
		mv, ok := types.DefaultTypeAdapter.NativeToValue(m).(traits.Mapper)
		if !ok {
			return nil, 0, ErrInvalid
		}
		stmts[i] = &stmtVal{Mapper: mv, st: st, cat: cat}
	}
	return types.DefaultTypeAdapter.NativeToValue(map[string]any{
		"version":    p.Version,
		"catalog":    p.Catalog,
		"statements": types.NewRefValList(types.DefaultTypeAdapter, stmts),
	}), n, nil
}

// iamErr maps an iampolicy error to its lib sentinel (class by identity).
func iamErr(err error) error {
	switch {
	case errors.Is(err, iampolicy.ErrLimit):
		return ErrLimit
	case errors.Is(err, iampolicy.ErrUnresolved):
		return ErrUnresolved
	}
	return ErrInvalid
}
