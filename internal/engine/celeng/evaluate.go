package celeng

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/interpreter"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/lib"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/tfval"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

// Interim caps; the lifecycle evaluator fills Options from the
// signed profile. No env var override.
const (
	defaultBudget    = 50 * time.Millisecond
	defaultCostLimit = 1_000_000
	interruptEvery   = 100 // comprehension iterations between deadline checks; never 0
)

// Options are the engine budgets.
type Options struct {
	PerResourceBudget time.Duration // all controls of one resource instance
	CostLimit         uint64        // CEL runtime cost per control
	MemoEntries       int           // prefilter memo cap per Compiled
	// DocCacheBytes caps the process document cache (json.path, iam.parse)
	// shared by every Engine; New sets it when > 0, zero leaves it as is
	// (lib.DefaultDocCacheBytes until set).
	DocCacheBytes int
}

// Engine loads bundles under one set of Options.
type Engine struct{ opts Options }

// New returns an Engine; zero Options fields take the defaults, except
// DocCacheBytes (process-wide, see Options).
func New(opts Options) *Engine {
	if opts.PerResourceBudget <= 0 {
		opts.PerResourceBudget = defaultBudget
	}
	if opts.CostLimit == 0 {
		opts.CostLimit = defaultCostLimit
	}
	if opts.MemoEntries <= 0 {
		opts.MemoEntries = defaultMemoEntries
	}
	if opts.DocCacheBytes > 0 {
		lib.SetDocCacheBytes(opts.DocCacheBytes)
	}
	return &Engine{opts: opts}
}

// Bindings is one resource's input; the lifecycle evaluator picks values per stage and mode.
type Bindings struct {
	Kind     bundle.Kind
	Type     string
	Resource tftypes.Value // a zero Value is bound as null
	Config   tftypes.Value
	Prior    tftypes.Value
	Op       string
	Env      string // trusted environment only
	EnvKnown bool   // false without trusted scope: env is unknown
	Provider ProviderInfo
}

// ProviderInfo is the engine provider binding the lifecycle fills.
type ProviderInfo = engine.ProviderInfo

// Result of one control. UnknownPaths and ErrClass never carry values.
type Result struct {
	ControlID    string
	Version      string
	State        engine.State
	ErrClass     engine.ErrClass
	UnknownPaths []string
	Memoized     bool // prefilter hit
	Elapsed      time.Duration
}

type target struct {
	kind bundle.Kind
	typ  string
}

type program struct {
	c       *bundle.Control
	ch      *Checked
	prg     cel.Program // nil when cel-go refused to plan the checked AST
	missing bool        // a read is not in the upstream schema
}

// Content is the bundle content that decides beside the controls.
type Content struct {
	// Digest is the content digest (bundle.ControlSet.ContentDigest); it
	// keys the prefilter memo and, with the catalog digest, the IAM document
	// cache.
	Digest string
	// IAMCatalog is the bundle's iam-actions.json. nil rejects a bundle
	// with any iam.* control (iam_catalog_missing).
	IAMCatalog *iampolicy.Catalog
}

// Compiled is one loaded bundle, immutable and safe for concurrent use. Its
// programs are planned per (kind, type) on first use: the (digest, type) cache.
type Compiled struct {
	opts     Options
	schemas  *tfprotov5.GetProviderSchemaResponse
	programs map[target]func() []program
	digest   string // memo key part: Content.Digest
	memo     *memo  // per Compiled: the content digest does not cover schemas
}

// Load runs the package Load checks and returns the evaluable bundle.
func (e *Engine) Load(cs []bundle.Control, s *tfprotov5.GetProviderSchemaResponse, content Content) (*Compiled, []LoadDiag, error) {
	return e.load(cs, s, content, true)
}

// LoadMutant is Load without the control_iam_unconditional_polarity lint,
// every other check on. It is for the generator's verify only
// (internal/bundlegen): the negated mutant
// !(expr) of an iam.grants control breaks the lint by construction, and
// verify must still evaluate it. The provider never calls it
// (TestLoadMutantCallers); its results never enter the shared AST cache.
func (e *Engine) LoadMutant(cs []bundle.Control, s *tfprotov5.GetProviderSchemaResponse, content Content) (*Compiled, []LoadDiag, error) {
	return e.load(cs, s, content, false)
}

func (e *Engine) load(cs []bundle.Control, s *tfprotov5.GetProviderSchemaResponse, content Content, lintPolarity bool) (*Compiled, []LoadDiag, error) {
	checked, diags, err := loadLint(cs, s, lintPolarity)
	if err != nil {
		return nil, diags, err
	}
	if content.IAMCatalog == nil {
		for i, ch := range checked {
			if callsIAM(ch.Ast.NativeRep().Expr()) {
				return nil, diags, &LoadDiag{ControlID: cs[i].ID, Code: "iam_catalog_missing",
					Detail: "the bundle has iam.* controls and no iam-actions.json"}
			}
		}
	}
	opts := []cel.ProgramOption{
		cel.EvalOptions(cel.OptPartialEval, cel.OptTrackState),
		cel.CostLimit(e.opts.CostLimit),
		cel.InterruptCheckFrequency(interruptEvery),
	}
	if content.IAMCatalog != nil {
		iam, err := lib.IAMProgram(content.IAMCatalog, content.Digest)
		if err != nil {
			return nil, diags, err
		}
		opts = append(opts, iam)
	}
	opts = append(opts, lib.IAMFlags()) // after IAMProgram: it must wrap the parse node too
	cs = slices.Clone(cs)
	groups := map[target][]int{}
	for i := range cs {
		t := target{cs[i].Kind, cs[i].ResourceType}
		groups[t] = append(groups[t], i)
	}
	c := &Compiled{opts: e.opts, schemas: s, programs: map[target]func() []program{},
		digest: content.Digest, memo: newMemo(e.opts.MemoEntries)}
	for t, idx := range groups {
		c.programs[t] = sync.OnceValue(func() []program {
			env, err := newEnv()
			sc := kindSchemas(t.kind, s)[t.typ] // nil: Evaluate reports the type missing
			out := make([]program, len(idx))
			for j, i := range idx {
				out[j] = program{c: &cs[i], ch: checked[i]}
				if sc != nil {
					// Load accepted the uses; an error here keeps the control unevaluated.
					reads, rerr := schemaReads(sc.Block, checked[i])
					out[j].missing = rerr != nil || missingRead(sc.Block, reads)
				}
				if err != nil {
					continue
				}
				prg, err := env.Program(checked[i].Ast, opts...)
				if err == nil {
					out[j].prg = prg
				}
			}
			return out
		})
	}
	return c, diags, nil
}

// Evaluate runs the controls of in.Kind and in.Type that keep selects (nil
// keeps all) under one PerResourceBudget. One control's error never aborts
// the others; once the budget is spent every remaining control is timeout.
func (c *Compiled) Evaluate(ctx context.Context, in Bindings, keep func(*bundle.Control) bool) []Result {
	get := c.programs[target{in.Kind, in.Type}]
	if get == nil {
		return nil
	}
	progs := get() // planned once per (kind, type), outside the resource budget
	ctx, cancel := context.WithTimeout(ctx, c.opts.PerResourceBudget)
	defer cancel()
	deadline, _ := ctx.Deadline()
	act, vals, bad, found := c.activation(in, deadline)
	var block *tfprotov5.SchemaBlock
	if sc := kindSchemas(in.Kind, c.schemas)[in.Type]; sc != nil {
		block = sc.Block
	}
	var out []Result
	for _, p := range progs {
		if keep != nil && !keep(p.c) {
			continue
		}
		start := time.Now()
		r := Result{ControlID: p.c.ID, Version: p.c.Version, State: engine.NotEvaluable}
		switch {
		case ctx.Err() != nil:
			r.ErrClass = engine.ErrTimeout
		case !found || p.missing: // not in the schema; never evaluated, has() would decide it
			r.ErrClass = engine.ErrNoSuchAttribute
		case p.prg == nil || act == nil || slices.ContainsFunc(p.ch.Vars, func(v string) bool { return bad[v] }):
			r.ErrClass = engine.ErrTypeError
		default:
			key, memoOK := c.key(&p, in, vals)
			if s, hit := c.memo.get(key); memoOK && hit { // skips work; the stored decision is the evaluated one
				r.State, r.Memoized = s, true
				break // leaves the switch
			}
			sink, _ := act.ResolveName(lib.UnresolvedVar)
			hit, ok := sink.(*bool)
			if ok {
				*hit = false
			}
			val, _, err := p.prg.ContextEval(ctx, act)
			r.State, r.ErrClass, r.UnknownPaths = classify(ctx, val, err, p.ch.Reads, block, in.EnvKnown)
			// An executed unresolved IAM answer that CEL absorbed (err || true,
			// err || unknown) is never pass and never unknown; fail stands.
			if ok && *hit && (r.State == engine.Pass || r.State == engine.Unknown) {
				r.State, r.ErrClass, r.UnknownPaths = engine.NotEvaluable, engine.ErrUnresolved, nil
			}
			if memoOK && r.ErrClass == engine.ErrNone {
				c.memo.put(key, r.State) // pass and fail only
			}
		}
		r.Elapsed = time.Since(start)
		out = append(out, r)
	}
	return out
}

// missingRead reports whether any read does not resolve in the schema block,
// following blocks and then the attribute's type: object fields must exist,
// list and set element steps are implicit, map and dynamic keys are data.
func missingRead(b *tfprotov5.SchemaBlock, reads []Read) bool {
	return slices.ContainsFunc(reads, func(r Read) bool {
		a, _, rest, found, err := resolve(b, r.Path)
		return !found || err != nil || (a != nil && !typeHas(a.Type, rest))
	})
}

func typeHas(t tftypes.Type, segs []string) bool {
	for _, seg := range segs {
		t = elem(elem(t)) // list or set steps are implicit
		switch c := t.(type) {
		case tftypes.Map:
			t = c.ElementType // seg is a key (data); the value type below is the schema's
		case tftypes.Object:
			if t = c.AttributeTypes[seg]; t == nil {
				return false
			}
		default:
			return t != nil && t.Is(tftypes.DynamicPseudoType)
		}
	}
	return true
}

// mapCut fails closed to the longest prefix of data path p the schema
// resolves without stepping below a map: reads.go keeps a constant index
// shaped like an attribute name as a step, and below a map that step is a
// key, which never leaves the engine (evidence.Result paths).
// It stops at an attribute value that is not an object (a map, or a
// dynamic value that may hold one), at a map-nested block and at the first
// step the schema lacks. The first step names a top-level attribute or
// block, never a key, so it is always kept: with no schema p is cut to it
// (as diagnostics attrPath). List and set steps are implicit.
func mapCut(b *tfprotov5.SchemaBlock, p string) string {
	segs := strings.Split(p, ".")
	return strings.Join(segs[:mapKeep(b, segs)], ".")
}

// mapKeep is how many steps of segs mapCut keeps: at least one.
func mapKeep(b *tfprotov5.SchemaBlock, segs []string) int {
	keep := 1
	var t tftypes.Type // set once the walk is inside an attribute value
	for i, seg := range segs {
		switch {
		case b == nil:
			return keep
		case t != nil:
			o, ok := elem(elem(t)).(tftypes.Object)
			if !ok || o.AttributeTypes[seg] == nil {
				return keep
			}
			t = o.AttributeTypes[seg]
		case attr(b, seg) != nil:
			t = attr(b, seg).Type
		default:
			nb := block(b, seg)
			if nb == nil || nb.Block == nil {
				return keep
			}
			if nb.Nesting == tfprotov5.SchemaNestedBlockNestingModeMap {
				return i + 1 // the next step is a key
			}
			b = nb.Block
		}
		keep = i + 1
	}
	return keep
}

func elem(t tftypes.Type) tftypes.Type {
	switch c := t.(type) {
	case tftypes.List:
		return c.ElementType
	case tftypes.Set:
		return c.ElementType
	}
	return t
}

// activation converts the bindings once per resource and carries the
// resource deadline for iam.parse admission. vals holds each converted data
// variable for the prefilter; bad names data variables whose value could not
// be converted; found is false when the upstream schema lacks the type.
func (c *Compiled) activation(in Bindings, deadline time.Time) (interpreter.PartialActivation, map[string]tfval.Converted, map[string]bool, bool) {
	sc := kindSchemas(in.Kind, c.schemas)[in.Type]
	if sc == nil || sc.Block == nil {
		return nil, nil, nil, false
	}
	vars, unknown, vals, bad := bind(in, sc.Block, deadline)
	act, err := cel.PartialVars(vars, unknown...)
	if err != nil {
		return nil, nil, bad, true
	}
	return act, vals, bad, true
}

// bind converts the bindings against the upstream schema block: the
// variables, the unknown attribute patterns, each converted data variable
// and the data variables whose value could not be converted.
func bind(in Bindings, block *tfprotov5.SchemaBlock, deadline time.Time) (map[string]any, []*cel.AttributePatternType, map[string]tfval.Converted, map[string]bool) {
	vars := map[string]any{varOp: in.Op, lib.DeadlineVar: deadline, lib.UnresolvedVar: new(bool)}
	var unknown []*cel.AttributePatternType
	bad := map[string]bool{}
	vals := map[string]tfval.Converted{}
	for name, v := range map[string]tftypes.Value{varResource: in.Resource, varConfig: in.Config, varPrior: in.Prior} {
		if v.Type() == nil {
			vars[name] = nil
			vals[name] = tfval.Converted{Variable: name, Known: true}
			continue
		}
		conv, err := tfval.Convert(name, v, block)
		if err != nil {
			bad[name] = true
			continue
		}
		vals[name] = conv
		if conv.Known {
			vars[name] = conv.Value
		}
		unknown = append(unknown, conv.Patterns()...)
	}
	if in.EnvKnown {
		vars[varEnv] = in.Env
	} else {
		unknown = append(unknown, cel.AttributePattern(varEnv))
	}
	provider := map[string]any{}
	for _, p := range []struct {
		key, val string
		known    bool
	}{{"region", in.Provider.Region, in.Provider.RegionKnown}, {"account_id", in.Provider.AccountID, in.Provider.AccountKnown},
		{"partition", in.Provider.Partition, in.Provider.PartitionKnown}} {
		if p.known {
			provider[p.key] = p.val
		} else {
			unknown = append(unknown, cel.AttributePattern(varProvider).QualString(p.key))
		}
	}
	vars[varProvider] = provider
	return vars, unknown, vals, bad
}

// classify maps one CEL outcome to a state. Order matters: a cost abort is
// limit even past the deadline; past
// the deadline an error or unknown is timeout (an unknown may have absorbed
// the interrupt), while a decided bool stands, because the logic that decided
// it did not depend on the interrupted branch.
func classify(ctx context.Context, val ref.Val, err error, reads []Read, b *tfprotov5.SchemaBlock, envKnown bool) (engine.State, engine.ErrClass, []string) {
	if e, ok := val.(*types.Err); ok && err == nil {
		err = e
	}
	var ce interpreter.EvalCancelledError
	if errors.As(err, &ce) && ce.Cause == interpreter.CostLimitExceeded {
		return engine.NotEvaluable, engine.ErrLimit, nil
	}
	u, unknown := val.(*types.Unknown)
	if ctx.Err() != nil && (err != nil || unknown) {
		return engine.NotEvaluable, engine.ErrTimeout, nil
	}
	if err != nil {
		return engine.NotEvaluable, errClass(err), nil
	}
	if unknown {
		// An untrusted env in the residual wins over unknown resource
		// attributes (crosscheck S-04): the result is not_evaluable /
		// scope_untrusted, never unknown, so it cannot become pending, and
		// it carries no unknown paths, which only an unknown result lists.
		if !envKnown && slices.ContainsFunc(trails(u), func(t *types.AttributeTrail) bool { return t.Variable() == varEnv }) {
			return engine.NotEvaluable, engine.ErrScopeUntrusted, nil
		}
		return engine.Unknown, engine.ErrNone, unknownPaths(u, reads, b)
	}
	if b, ok := val.(types.Bool); ok {
		if b {
			return engine.Pass, engine.ErrNone, nil
		}
		return engine.Fail, engine.ErrNone, nil
	}
	return engine.NotEvaluable, engine.ErrTypeError, nil
}

// errClass reads the error type, never its text: the CEL error wrapper is
// unwrapped once, our sentinels match by identity and cel-go's attribute
// resolution failure (missing key, attribute or index) by its Go type, pinned
// by the errors crosscheck group. Everything else is type_error.
func errClass(err error) engine.ErrClass {
	if te := (*types.Err)(nil); errors.As(err, &te) {
		err = te.Unwrap()
	}
	switch {
	case errors.Is(err, lib.ErrUnresolved):
		return engine.ErrUnresolved
	case errors.Is(err, lib.ErrLimit):
		return engine.ErrLimit
	}
	if t := reflect.TypeOf(err); t != nil && t.Kind() == reflect.Pointer &&
		t.Elem().PkgPath() == "cel.dev/cel-go/interpreter" && t.Elem().Name() == "resolutionError" {
		return engine.ErrNoSuchAttribute
	}
	return engine.ErrTypeError // incl. lib.ErrInvalid
}

func trails(u *types.Unknown) []*types.AttributeTrail {
	var out []*types.AttributeTrail
	for _, id := range u.IDs() {
		ts, _ := u.GetAttributeTrails(id)
		out = append(out, ts...)
	}
	return out
}

// unknownPaths maps unknown attribute trails back to read paths. A data
// variable trail becomes the longest AST read that is a segment prefix of it
// (so a map key below a read is never output), else the trail itself when it
// is a prefix of a read, else every read of a wholly unknown variable, else
// the bare variable, each cut at its first map step in b (mapCut). Data
// paths carry no variable prefix; provider and env trails keep theirs.
// Element indexes are implicit steps and dropped.
func unknownPaths(u *types.Unknown, reads []Read, b *tfprotov5.SchemaBlock) []string {
	var out []string
	for _, t := range trails(u) {
		var segs []string
		for _, q := range t.QualifierPath() {
			if s, ok := q.(string); ok {
				segs = append(segs, s)
			}
		}
		v, path := t.Variable(), strings.Join(segs, ".")
		if !isData(v) {
			out = append(out, strings.Join(append([]string{v}, segs...), "."))
			continue
		}
		for _, p := range readPaths(v, path, reads) {
			out = append(out, mapCut(b, p))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func readPaths(v, path string, reads []Read) []string {
	best, prefix := "", false
	var all []string
	for _, r := range reads {
		if r.Var != v {
			continue
		}
		all = append(all, r.Path)
		if path != "" && segPrefix(r.Path, path) && len(r.Path) > len(best) {
			best = r.Path
		}
		prefix = prefix || (path != "" && segPrefix(path, r.Path))
	}
	switch {
	case best != "":
		return []string{best}
	case prefix:
		return []string{path}
	case path == "" && len(all) > 0:
		return all
	}
	return []string{v}
}
