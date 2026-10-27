package celeng

import (
	"cmp"
	"regexp"
	"slices"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/overloads"
	"cel.dev/cel-go/common/types"
)

// dataPath is a data path: a data variable and the field steps below it. A nil
// *dataPath in a scope marks a comprehension variable that is not a data path.
// elem counts element steps below segs: an iteration variable or an int
// index denotes an element of the value at segs, not the value itself.
type dataPath struct {
	v    string
	segs []string
	elem int
}

func (r *dataPath) child(s string) *dataPath {
	return &dataPath{v: r.v, segs: append(slices.Clip(r.segs), s)}
}

// useOp is how an expression uses a data value other than through a field
// select. On an object or block value each of them depends on its set of
// keys, which is the schema's, so a field missing from the schema could
// decide the result. Load checks every use against the schema.
type useOp uint8

const (
	useWhole   useOp = iota // function argument, equality, list or map element
	useIn                   // right operand of in
	useKeys                 // comprehension range or size()
	useCompare              // operand of ==, != or in where both sides may hold maps
)

// use is one non-select use of a data path. Key is the constant attribute
// name an in test checks, else "".
type use struct {
	Var, Path string
	Elem      int
	Op        useOp
	Key       string
}

type analyzer struct {
	ast   *ast.AST
	vs    varSet // the variables of the expression's environment
	reads map[Read]bool
	uses  map[use]bool
	vars  map[string]bool
	used  map[*dataPath]bool // comprehension bindings referenced in a body
	keys  map[Read][]string  // string keys indexed directly below a read
	// tainted: an iteration variable bound to erased was referenced.
	tainted bool
	// erasedErr: the first rejection in walk order (a select or index below
	// a computed value of data, a comparison that may hold objects, key
	// iteration of a computed map, a non-constant index, a whole variable,
	// a shadowing or two-variable comprehension, a data index into a fixed
	// shape). The walk goes on so the reads stay complete for checkSchema,
	// and Load reports control_computed_only when that rule applies too.
	erasedErr error
	// from memoizes fromData per node, shared with every sub-analyzer: the
	// walk goes on past a rejection, and without it each nesting level of
	// a computed value would walk its operand again (exponential).
	from map[int64]fromResult
}

type fromResult struct {
	d   bool
	err error
	rej error // the sub-analyzer's erasedErr
}

func newAnalyzer(a *ast.AST, vs varSet) *analyzer {
	return &analyzer{ast: a, vs: vs, reads: map[Read]bool{}, uses: map[use]bool{}, vars: map[string]bool{}, used: map[*dataPath]bool{},
		keys: map[Read][]string{}, from: map[int64]fromResult{}}
}

// erased binds an iteration variable that ranges over a computed value
// derived from data (filter, map, ternary, dyn): its elements have no path.
var erased = &dataPath{}

// fixed binds an iteration variable that ranges over a value derived from
// iam.parse: its fields are the fixed normalized IAM shape, not data paths.
var fixed = &dataPath{}

// fixedShape reports whether e selects or indexes, at any depth, into an
// iam.parse result or a fixed iteration variable. The parse argument is
// still visited, so its data path is a read; fixedIndex checks the keys.
func fixedShape(e ast.Expr, sc scope) bool {
	for {
		switch e.Kind() {
		case ast.IdentKind:
			return sc[e.AsIdent()] == fixed
		case ast.SelectKind:
			e = e.AsSelect().Operand()
		case ast.CallKind:
			c := e.AsCall()
			if c.FunctionName() == "iam.parse" {
				return true
			}
			if c.FunctionName() != operators.Index || len(c.Args()) != 2 {
				return false
			}
			e = c.Args()[0]
		default:
			return false
		}
	}
}

type scope map[string]*dataPath

// analyze walks the checked AST of a control expr once.
func analyze(a *cel.Ast) (*Checked, error) { return analyzeIn(a, resourceVars) }

// analyzeIn walks the checked AST once, compiled in an environment binding vs.
func analyzeIn(a *cel.Ast, vs varSet) (*Checked, error) {
	z := newAnalyzer(a.NativeRep(), vs)
	if err := z.visit(a.NativeRep().Expr(), scope{}); err != nil {
		return nil, err
	}
	c := &Checked{Ast: a, Keys: z.keys}
	c.sortReads(z)
	return c, z.erasedErr
}

// sortReads fills Reads and Vars sorted, and sorts the keys per read.
func (c *Checked) sortReads(z *analyzer) {
	for _, ks := range z.keys {
		slices.Sort(ks)
	}
	for r := range z.reads {
		c.Reads = append(c.Reads, r)
	}
	slices.SortFunc(c.Reads, func(x, y Read) int {
		return strings.Compare(x.Var+"\x00"+x.Path, y.Var+"\x00"+y.Path)
	})
	for v := range z.vars {
		c.Vars = append(c.Vars, v)
	}
	slices.Sort(c.Vars)
	for u := range z.uses {
		c.uses = append(c.uses, u)
	}
	slices.SortFunc(c.uses, func(x, y use) int {
		return cmp.Or(strings.Compare(x.Var, y.Var), strings.Compare(x.Path, y.Path),
			cmp.Compare(x.Elem, y.Elem), cmp.Compare(x.Op, y.Op), strings.Compare(x.Key, y.Key))
	})
}

func dynamic(format string, a ...any) error {
	return &LoadDiag{Code: "control_dynamic_access", Detail: detailf(format, a...)}
}

var attrRe = regexp.MustCompile(`^[a-z0-9_]+$`)

// varSet is the variables an environment binds and, among them, the data
// variables whose paths are reads.
type varSet struct{ bound, data []string }

var (
	resourceVars  = varSet{[]string{varResource, varConfig, varPrior, varOp, varEnv, varProvider}, []string{varResource, varConfig, varPrior}}
	companionVars = varSet{[]string{varCompanion}, []string{varCompanion}}
)

// isData reports whether v is a data variable of a control expr.
func isData(v string) bool { return slices.Contains(resourceVars.data, v) }

// path resolves e to a data path when it is a select/constant-index chain
// rooted at a data variable or a comprehension variable bound to one.
func (z *analyzer) path(e ast.Expr, sc scope) (*dataPath, error) {
	switch e.Kind() {
	case ast.IdentKind:
		name := e.AsIdent()
		if r, ok := sc[name]; ok {
			if r == erased {
				z.tainted = true
				return nil, nil
			}
			if r == fixed {
				return nil, nil
			}
			z.used[r] = true
			return r, nil
		}
		if !slices.Contains(z.vs.bound, name) {
			return nil, nil // a type or other declared name, not a variable
		}
		z.vars[name] = true
		if slices.Contains(z.vs.data, name) {
			return &dataPath{v: name}, nil
		}
	case ast.SelectKind:
		s := e.AsSelect()
		r, err := z.path(s.Operand(), sc)
		if r == nil || err != nil {
			return nil, err
		}
		return r.child(s.FieldName()), nil
	case ast.CallKind:
		call := e.AsCall()
		if call.FunctionName() != operators.Index || len(call.Args()) != 2 {
			return nil, nil
		}
		r, err := z.path(call.Args()[0], sc)
		if r == nil || err != nil {
			return nil, err
		}
		idx := call.Args()[1]
		if idx.Kind() != ast.LiteralKind {
			z.reject(dynamic("non-constant index into %s", r.name()))
			return nil, nil
		}
		s, isStr := idx.AsLiteral().(types.String)
		switch {
		case isStr && len(r.segs) == 0: // a variable is an object: the key names an attribute
			if !attrRe.MatchString(string(s)) {
				z.reject(dynamic("a constant index into %s is not an attribute name", r.v))
				return nil, nil
			}
			return r.child(string(s)), nil
		case isStr && attrRe.MatchString(string(s)):
			// A map entry or an object attribute: typeHas reads a map
			// step as a key and an object step as an attribute, and
			// UnknownPaths cut at the map (mapCut).
			return r.child(string(s)), nil
		case isStr:
			// A key that is not an attribute name can only be a map key
			// (data); the read ends at the map, and erases rejects a
			// select or index below it. The key is kept for the schema
			// check (Checked.Keys).
			if err := z.record(r); err != nil {
				return nil, err
			}
			rd := Read{Var: r.v, Path: strings.Join(r.segs, ".")}
			if !slices.Contains(z.keys[rd], string(s)) {
				z.keys[rd] = append(z.keys[rd], string(s))
			}
			return nil, nil
		}
		return &dataPath{v: r.v, segs: r.segs, elem: r.elem + 1}, nil // a list element: not a path step
	}
	return nil, nil
}

// erases rejects a select or index into e when e is a computed value derived
// from data (dyn(), a ternary, a macro result, an erased iteration variable):
// the field below has no path, so neither reads coverage nor the schema check
// could see it, and has() on a field missing from the schema would pass.
// Select/constant-index chains keep their path and are left to path().
func (z *analyzer) erases(e ast.Expr, sc scope) error {
	if (chain(e) && !z.erasedIdent(e, sc) && !opaqueKey(e)) || fixedShape(e, sc) {
		return nil
	}
	d, err := z.fromData(e, sc)
	if err != nil {
		return err
	}
	if d {
		z.reject(dynamic("field or index selected from a computed value of data; select through a path instead"))
	}
	return nil
}

// reject keeps the first rejection; the walk goes on (erasedErr).
func (z *analyzer) reject(err error) {
	if z.erasedErr == nil {
		z.erasedErr = err
	}
}

// fixedIndex rejects a data-derived index into a fixed shape (an iam.parse
// result or a fixed iteration variable): the key would pick a field or
// element by data, so the reads analysis rejects it on its own, never
// relying on the identity lint.
func (z *analyzer) fixedIndex(args []ast.Expr, sc scope) error {
	if args[1].Kind() == ast.LiteralKind || !fixedShape(args[0], sc) {
		return nil
	}
	d, err := z.fromData(args[1], sc)
	if d && err == nil {
		z.reject(dynamic("index into an iam.parse result derived from data"))
	}
	return err
}

// fromData reports whether e reads data or an erased iteration variable.
// A node is always reached under the same scope, so the result is memoized
// by node id.
func (z *analyzer) fromData(e ast.Expr, sc scope) (bool, error) {
	r, ok := z.from[e.ID()]
	if !ok {
		sub := newAnalyzer(z.ast, z.vs)
		sub.from = z.from
		if r.err = sub.visit(e, sc); r.err == nil {
			r.d = len(sub.reads) > 0 || sub.tainted
		}
		r.rej = sub.erasedErr
		z.from[e.ID()] = r
	}
	// A rejection below e stays first in walk order.
	if r.rej != nil {
		z.reject(r.rej)
	}
	return r.d, r.err
}

// keyed handles the operand of a key test (in) or key enumeration (size; a
// comprehension range is handled in comprehension). A data path becomes a
// use that Load checks against the schema.
func (z *analyzer) keyed(e ast.Expr, sc scope, op useOp, key string) error {
	r, err := z.path(e, sc)
	if err != nil {
		return err
	}
	if r != nil {
		z.use(r, op, key)
		return z.record(r)
	}
	if err := z.visit(e, sc); err != nil {
		return err
	}
	return z.listLike(e, sc)
}

// listLike rejects a computed value of data whose checked type could be a
// map: its keys could be an object's, and no schema check sees them.
func (z *analyzer) listLike(e ast.Expr, sc scope) error {
	if fixedShape(e, sc) {
		return nil
	}
	d, err := z.fromData(e, sc)
	if !d || err != nil {
		return err
	}
	switch z.ast.GetType(e.ID()).Kind() {
	case types.ListKind, types.StringKind, types.BytesKind:
		return nil
	}
	z.reject(dynamic("key test or key enumeration on a computed value of data; use a path"))
	return nil
}

func (z *analyzer) use(r *dataPath, op useOp, key string) {
	if len(r.segs) == 0 {
		return // a whole variable: record rejects it
	}
	if op != useIn || !attrRe.MatchString(key) {
		key = ""
	}
	z.uses[use{Var: r.v, Path: strings.Join(r.segs, "."), Elem: r.elem, Op: op, Key: key}] = true
}

func isNull(e ast.Expr) bool {
	return e.Kind() == ast.LiteralKind && e.AsLiteral() == types.NullValue
}

func literalString(e ast.Expr) string {
	if e.Kind() == ast.LiteralKind {
		if s, ok := e.AsLiteral().(types.String); ok {
			return string(s)
		}
	}
	return ""
}

// chain reports whether e is a select / constant-index chain on an identifier.
func chain(e ast.Expr) bool {
	switch e.Kind() {
	case ast.IdentKind:
		return true
	case ast.SelectKind:
		return chain(e.AsSelect().Operand())
	case ast.CallKind:
		c := e.AsCall()
		return c.FunctionName() == operators.Index && len(c.Args()) == 2 &&
			c.Args()[1].Kind() == ast.LiteralKind && chain(c.Args()[0])
	}
	return false
}

// opaqueKey reports whether chain e indexes with a string key that is not an
// attribute name: the path ends there, so nothing below it is checked.
func opaqueKey(e ast.Expr) bool {
	for e.Kind() != ast.IdentKind {
		if e.Kind() == ast.SelectKind {
			e = e.AsSelect().Operand()
			continue
		}
		args := e.AsCall().Args()
		if s, ok := args[1].AsLiteral().(types.String); ok && !attrRe.MatchString(string(s)) {
			return true
		}
		e = args[0]
	}
	return false
}

// erasedIdent reports whether the root identifier of chain e is erased.
func (z *analyzer) erasedIdent(e ast.Expr, sc scope) bool {
	for e.Kind() != ast.IdentKind {
		if e.Kind() == ast.SelectKind {
			e = e.AsSelect().Operand()
		} else {
			e = e.AsCall().Args()[0]
		}
	}
	return sc[e.AsIdent()] == erased
}

func (r *dataPath) name() string {
	return strings.Join(append([]string{r.v}, r.segs...), ".")
}

func (z *analyzer) record(r *dataPath) error {
	if len(r.segs) == 0 {
		z.reject(dynamic("%s is used whole; read its attributes instead", r.v))
		return nil
	}
	z.reads[Read{Var: r.v, Path: strings.Join(r.segs, ".")}] = true
	return nil
}

func (z *analyzer) visit(e ast.Expr, sc scope) error {
	r, err := z.path(e, sc)
	if err != nil {
		return err
	}
	if r != nil {
		if err := z.record(r); err != nil {
			return err
		}
		if e.Kind() == ast.SelectKind && e.AsSelect().IsTestOnly() {
			// has(p.f) tests presence only; it is the key test "f" in p.
			if p, err := z.path(e.AsSelect().Operand(), sc); err != nil {
				return err
			} else if p != nil && len(p.segs) > 0 {
				z.use(p, useIn, e.AsSelect().FieldName())
			}
			return nil
		}
		// The value itself flows on (compared, returned by a macro,
		// iterated after a transform): everything below r is read.
		z.use(r, useWhole, "")
		return nil
	}
	switch e.Kind() {
	case ast.SelectKind:
		if err := z.erases(e.AsSelect().Operand(), sc); err != nil {
			return err
		}
		return z.visit(e.AsSelect().Operand(), sc)
	case ast.CallKind:
		call := e.AsCall()
		args := call.Args()
		if call.FunctionName() == operators.Index && len(args) == 2 {
			if err := z.erases(args[0], sc); err != nil {
				return err
			}
			if err := z.fixedIndex(args, sc); err != nil {
				return err
			}
		}
		if call.IsMemberFunction() {
			args = append([]ast.Expr{call.Target()}, args...)
		}
		switch fn := call.FunctionName(); {
		case fn == operators.In && len(args) == 2:
			if err := z.deepCompare(args, sc); err != nil {
				return err
			}
			if err := z.visit(args[0], sc); err != nil {
				return err
			}
			return z.keyed(args[1], sc, useIn, literalString(args[0]))
		case fn == overloads.Size && len(args) == 1:
			return z.keyed(args[0], sc, useKeys, "")
		case (fn == operators.Equals || fn == operators.NotEquals) && len(args) == 2 && (isNull(args[0]) || isNull(args[1])):
			return z.nullTest(args, sc)
		case fn == operators.Equals || fn == operators.NotEquals:
			if err := z.deepCompare(args, sc); err != nil {
				return err
			}
		}
		for _, a := range args {
			if err := z.visit(a, sc); err != nil {
				return err
			}
		}
	case ast.ListKind:
		for _, a := range e.AsList().Elements() {
			if err := z.visit(a, sc); err != nil {
				return err
			}
		}
	case ast.MapKind:
		for _, en := range e.AsMap().Entries() {
			m := en.AsMapEntry()
			if err := z.visit(m.Key(), sc); err != nil {
				return err
			}
			if err := z.visit(m.Value(), sc); err != nil {
				return err
			}
		}
	case ast.StructKind:
		for _, f := range e.AsStruct().Fields() {
			if err := z.visit(f.AsStructField().Value(), sc); err != nil {
				return err
			}
		}
	case ast.ComprehensionKind:
		return z.comprehension(e.AsComprehension(), sc)
	}
	return nil
}

// comprehension binds the iteration variable to the range path, so
// resource.a.exists(x, x.b == 1) reads a.b. When the body reads nothing
// below the range (exists(x, true)), the range itself is the read.
func (z *analyzer) comprehension(c ast.ComprehensionExpr, sc scope) error {
	rng, err := z.path(c.IterRange(), sc)
	if err != nil {
		return err
	}
	bind := (*dataPath)(nil)
	switch {
	case rng == nil:
		d, err := z.fromData(c.IterRange(), sc)
		if err != nil {
			return err
		}
		if d {
			bind = erased
		}
		if fixedShape(c.IterRange(), sc) {
			bind = fixed
		}
		if err := z.visit(c.IterRange(), sc); err != nil {
			return err
		}
		// Iterating a map yields its keys; a computed map of data is untyped.
		if err := z.listLike(c.IterRange(), sc); err != nil {
			return err
		}
	case len(rng.segs) == 0:
		// Its keys have no path: bind erased, so nothing below is a read.
		z.reject(dynamic("comprehension over %s as a whole", rng.v))
		rng, bind = nil, erased
	default:
		z.use(rng, useKeys, "")
	}
	if err := z.visit(c.AccuInit(), sc); err != nil {
		return err
	}
	// The checker drops the leading dot of ".resource", so a shadowed
	// variable could not be told apart from the iteration variable.
	if c.HasIterVar2() { // not in the env; its value variable would carry no path
		z.reject(dynamic("two-variable comprehension"))
	}
	var shadow []string
	for _, v := range []string{c.IterVar(), c.IterVar2()} {
		if slices.Contains(z.vs.bound, v) {
			z.reject(dynamic("iteration variable %s shadows a bound variable", v))
			shadow = append(shadow, v)
		}
	}
	inner := scope{}
	for k, v := range sc {
		inner[k] = v
	}
	// A fresh binding per comprehension: when the range is itself an outer
	// iteration variable, resolving it already marked the outer binding used.
	if rng != nil {
		bind = &dataPath{v: rng.v, segs: rng.segs, elem: rng.elem + 1}
	}
	inner[c.IterVar()] = bind
	if c.HasIterVar2() {
		inner[c.IterVar2()] = nil
		if bind == erased {
			inner[c.IterVar2()] = erased
		}
	}
	// A shadowing variable binds erased: a read through it (or through the
	// absolute name the checker cannot tell apart) is not a read.
	for _, v := range shadow {
		inner[v] = erased
	}
	inner[c.AccuVar()] = nil
	outer := z.reads
	z.reads = map[Read]bool{}
	for _, part := range []ast.Expr{c.LoopCondition(), c.LoopStep(), c.Result()} {
		if err := z.visit(part, inner); err != nil {
			return err
		}
	}
	body := z.reads
	z.reads = outer
	for rd := range body {
		z.reads[rd] = true
	}
	// Every use of the iteration variable records a read at or below the
	// range. An unused one still depends on the range (its size).
	if bind != nil && bind != erased && bind != fixed && !z.used[bind] {
		return z.record(rng)
	}
	return nil
}

// nullTest visits x == null / x != null: a data path there tests the
// value's presence, not its keys, so it is a read without a use.
func (z *analyzer) nullTest(args []ast.Expr, sc scope) error {
	for _, a := range args {
		r, err := z.path(a, sc)
		if err == nil && r != nil {
			err = z.record(r)
		} else if err == nil {
			err = z.visit(a, sc)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// deepCompare checks an equality or membership test whose operands may both
// hold maps: CEL compares maps by key set, so a computed value of data that
// may hold an object has no path the schema check could type. Data paths
// become whole or in uses that Load checks.
func (z *analyzer) deepCompare(args []ast.Expr, sc scope) error {
	if slices.ContainsFunc(args, z.scalar) {
		return nil
	}
	for _, a := range args {
		r, err := z.path(a, sc)
		if err != nil {
			return err
		}
		if r != nil {
			z.use(r, useCompare, "")
			continue
		}
		d, err := z.fromData(a, sc)
		if err != nil {
			return err
		}
		if d {
			z.reject(dynamic("comparison of a computed value of data that may hold objects; compare its attributes instead"))
		}
	}
	return nil
}

// scalar reports whether e's checked type cannot hold a map.
func (z *analyzer) scalar(e ast.Expr) bool { return noMap(z.ast.GetType(e.ID())) }

// noMap reports whether a value of checked type t cannot hold a map: a
// scalar, or a list of such (e.g. the literal [443]).
func noMap(t *types.Type) bool {
	switch t.Kind() {
	case types.BoolKind, types.IntKind, types.UintKind, types.DoubleKind, types.StringKind,
		types.BytesKind, types.NullTypeKind, types.TimestampKind, types.DurationKind, types.TypeKind:
		return true
	case types.ListKind:
		return len(t.Parameters()) == 1 && noMap(t.Parameters()[0])
	}
	return false
}
