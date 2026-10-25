package celeng

import (
	"strconv"

	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
)

// constant reports a deny control condition that is provably always true or
// always false and decides the result alone: "" when there is
// none, else the load warning detail. Flagged: a constant expression, an
// operand of && or || that absorbs it (x && false: x never matters), and a
// ternary on a constant condition. A redundant operand (x && true) is not.
// A conservative AST check, never an evaluation (cel-go constant folding
// evaluates comprehensions with no cost limit): bool literals through !,
// && and ||, a ternary on a constant condition, membership in an empty list
// literal, and == / != of two scalar literals of one type. CEL's && and ||
// absorb an error on the other side, so x && false is false for every x. A
// comprehension is never constant here, and its accumulator steps are not
// conditions the author wrote, so all(x, false) and exists(x, true) are
// not flagged.
func constant(a *ast.AST) string {
	known := map[int64]bool{} // value of each constant node, by id
	internal := map[int64]bool{}
	ast.PostOrderVisit(a.Expr(), ast.NewExprVisitor(func(e ast.Expr) {
		if e.Kind() == ast.ComprehensionKind {
			c := e.AsComprehension()
			for _, x := range []ast.Expr{c.AccuInit(), c.LoopCondition(), c.LoopStep(), c.Result()} {
				internal[x.ID()] = true
			}
		}
		if v, ok := constBool(e, known); ok {
			known[e.ID()] = v
		}
	}))
	if v, ok := known[a.Expr().ID()]; ok {
		return detailf("deny control expr is always %s", strconv.FormatBool(v))
	}
	sub := ""
	ast.PreOrderVisit(a.Expr(), ast.NewExprVisitor(func(e ast.Expr) {
		if sub != "" || e.Kind() != ast.CallKind || internal[e.ID()] {
			return
		}
		c := e.AsCall()
		args := c.Args()
		switch c.FunctionName() {
		case operators.LogicalAnd, operators.LogicalOr:
			absorb := c.FunctionName() == operators.LogicalOr
			for _, x := range args {
				if v, ok := known[x.ID()]; ok && v == absorb {
					sub = strconv.FormatBool(v)
				}
			}
		case operators.Conditional:
			if v, ok := known[args[0].ID()]; ok {
				sub = strconv.FormatBool(v)
			}
		}
	}))
	if sub != "" {
		return detailf("deny control expr has a condition that is always %s; check it for a vacuous test", sub)
	}
	return ""
}

// constBool reports the value of e when it is constant, given the values
// of its constant children (known).
func constBool(e ast.Expr, known map[int64]bool) (bool, bool) {
	switch e.Kind() {
	case ast.LiteralKind:
		b, ok := e.AsLiteral().(types.Bool)
		return bool(b), ok
	case ast.CallKind:
	default:
		return false, false
	}
	c := e.AsCall()
	args := c.Args()
	arg := func(i int) (bool, bool) { v, ok := known[args[i].ID()]; return v, ok }
	switch c.FunctionName() {
	case operators.LogicalNot:
		v, ok := arg(0)
		return !v, ok
	case operators.LogicalAnd, operators.LogicalOr:
		absorb := c.FunctionName() == operators.LogicalOr // true || x, false && x
		all := true
		for i := range args {
			v, ok := arg(i)
			if ok && v == absorb {
				return absorb, true
			}
			all = all && ok
		}
		return !absorb, all
	case operators.Conditional:
		if v, ok := arg(0); ok {
			if v {
				return arg(1)
			}
			return arg(2)
		}
	case operators.In:
		// in does not absorb errors or unknowns, so only a literal left side folds.
		if args[0].Kind() == ast.LiteralKind && args[1].Kind() == ast.ListKind && args[1].AsList().Size() == 0 {
			return false, true
		}
	case operators.Equals, operators.NotEquals:
		x, y := args[0], args[1]
		if x.Kind() != ast.LiteralKind || y.Kind() != ast.LiteralKind || x.AsLiteral().Type() != y.AsLiteral().Type() {
			return false, false
		}
		switch x.AsLiteral().(type) {
		case types.Bool, types.Int, types.Uint, types.String:
			eq := x.AsLiteral().Equal(y.AsLiteral()) == types.True
			return eq == (c.FunctionName() == operators.Equals), true
		}
	}
	return false, false
}
