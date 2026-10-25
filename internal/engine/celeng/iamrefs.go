package celeng

import (
	"fmt"
	"maps"
	"strings"

	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/types"
)

// IAMCatalogRefs returns the catalog lookups expr makes statically: the
// action argument of iam.grants and the service argument of
// iam.grants_all, each a string literal or the iteration variable of a
// one-variable comprehension over a list of string literals, resolved by
// scope (an inner comprehension that rebinds the name hides it). Any other
// argument (computed, a two-variable comprehension, string concatenation;
// cel.bind is off in this env) is not listed; a catalog miss there is
// ErrUnresolved at evaluation, never a pass. bundlegen checks the listed
// ones against the bundle's iam-actions.json.
func IAMCatalogRefs(expr string) (actions, services []string, err error) {
	env, err := newEnv()
	if err != nil {
		return nil, nil, fmt.Errorf("celeng: env: %w", err)
	}
	a, iss := env.Parse(expr)
	if iss.Err() != nil {
		return nil, nil, iss.Err()
	}
	walkIAMRefs(a.NativeRep().Expr(), nil, func(fn string, vals []string) {
		switch fn {
		case "grants":
			actions = append(actions, vals...)
		case "grants_all":
			services = append(services, vals...)
		}
	})
	return actions, services, nil
}

// walkIAMRefs visits e in evaluation scope: scope maps a comprehension
// variable bound to a literal string list to that list.
func walkIAMRefs(e ast.Expr, scope map[string][]string, add func(fn string, vals []string)) {
	walk := func(x ast.Expr) { walkIAMRefs(x, scope, add) }
	switch e.Kind() {
	case ast.CallKind:
		c := e.AsCall()
		if fn, ok := iamLookup(c); ok {
			arg := c.Args()[1]
			if s, ok := stringLiteral(arg); ok {
				add(fn, []string{s})
			} else if vals, ok := scope[arg.AsIdent()]; ok && arg.Kind() == ast.IdentKind { // .a is the global a
				add(fn, vals)
			}
		}
		if c.IsMemberFunction() {
			walk(c.Target())
		}
		for _, x := range c.Args() {
			walk(x)
		}
	case ast.ComprehensionKind:
		c := e.AsComprehension()
		walk(c.IterRange())
		walk(c.AccuInit())
		inner := maps.Clone(scope)
		if inner == nil {
			inner = map[string][]string{}
		}
		for _, v := range []string{c.IterVar(), c.IterVar2(), c.AccuVar()} {
			delete(inner, v)
		}
		if vals, ok := stringList(c.IterRange()); ok && !c.HasIterVar2() {
			inner[c.IterVar()] = vals
		}
		for _, x := range []ast.Expr{c.LoopCondition(), c.LoopStep(), c.Result()} {
			walkIAMRefs(x, inner, add)
		}
	case ast.ListKind:
		for _, x := range e.AsList().Elements() {
			walk(x)
		}
	case ast.MapKind:
		for _, x := range e.AsMap().Entries() {
			walk(x.AsMapEntry().Key())
			walk(x.AsMapEntry().Value())
		}
	case ast.StructKind:
		for _, x := range e.AsStruct().Fields() {
			walk(x.AsStructField().Value())
		}
	case ast.SelectKind:
		walk(e.AsSelect().Operand())
	}
}

// iamLookup reports an iam.grants or iam.grants_all call with two
// arguments, parsed (member call on the identifier iam) or checked form.
func iamLookup(c ast.CallExpr) (string, bool) {
	fn := strings.TrimPrefix(c.FunctionName(), ".")
	if c.IsMemberFunction() {
		if c.Target().Kind() != ast.IdentKind || identName(c.Target()) != "iam" {
			return "", false
		}
		fn = "iam." + fn
	}
	name, ok := strings.CutPrefix(fn, "iam.")
	return name, ok && (name == "grants" || name == "grants_all") && len(c.Args()) == 2
}

func identName(e ast.Expr) string {
	if e.Kind() != ast.IdentKind {
		return ""
	}
	return strings.TrimPrefix(e.AsIdent(), ".")
}

func stringLiteral(e ast.Expr) (string, bool) {
	if e.Kind() != ast.LiteralKind {
		return "", false
	}
	s, ok := e.AsLiteral().(types.String)
	return string(s), ok
}

func stringList(e ast.Expr) ([]string, bool) {
	if e.Kind() != ast.ListKind {
		return nil, false
	}
	var out []string
	for _, el := range e.AsList().Elements() {
		s, ok := stringLiteral(el)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}
