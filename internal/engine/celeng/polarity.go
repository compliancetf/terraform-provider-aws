package celeng

import (
	"strings"

	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
)

// polarity is the control_iam_unconditional_polarity lint.
// The iam.parse flag unconditional
// under-approximates ("certainly applies"): it is safe only where the control
// result can only rise with it, which is the requirement polarity. The lint
// does not ask the control for its polarity; it reads it from the position:
//   - unconditional is selected on a statement variable (the iteration
//     variable of a comprehension over iam.parse(...).statements), not tested
//     with has() and not indexed;
//   - every ancestor up to the root is a && chain or the predicate of an all
//     or exists comprehension, so no negation, ||, ternary, comparison,
//     exists_one, map or filter sits above it;
//   - its && chain holds a *_all field of the same variable and no *_any
//     field of it at any depth.
//
// ambiguous is diagnostic output and is never read.
//
// In an expression that calls iam.parse, conditions follows the unconditional
// rule (a count or emptiness test on it is !unconditional; computed keys are
// rejected by identityDirect). iam.grants / iam.grants_all sit under at most
// one negation and keyed conditions tests under an even number, both only
// below &&, ||, ! and all/exists predicates (a negated grant in a prohibition
// form is a requirement on a narrower grant, and a key test there narrows the
// prohibition to keyed statements: either passes Allow *:*). Any other read
// of conditions (all, exists_one, map, filter, size, ==, has, an index) is
// rejected. The lint is about direction only: a control that is vacuous by
// construction (true, or a conjunct that is always false) reads no
// under-approximated field the wrong way and is an authoring review concern.
func polarity(e ast.Expr) error {
	if !callsIAMParse(e) {
		return lintPolarity(e, true, nil, map[string]bool{})
	}
	if err := lintGrants(e, 0, true); err != nil {
		return err
	}
	if err := lintPolarity(e, true, nil, map[string]bool{iamKey: true}); err != nil {
		return err
	}
	return identityDirect(e)
}

// iamKey is the stmts entry that marks an expression calling iam.parse; ""
// is never a CEL identifier.
const iamKey = ""

func callsIAMParse(e ast.Expr) bool {
	return calls(e, func(fn string) bool { return fn == "iam.parse" })
}

// callsIAM reports whether e calls any iam.* function: such a control needs
// the bundle's action catalog (iam_catalog_missing).
func callsIAM(e ast.Expr) bool {
	return calls(e, func(fn string) bool { return strings.HasPrefix(fn, "iam.") })
}

// parsedCallsIAM is callsIAM over a parsed, unchecked expression, where
// iam.parse(x) is still the member call parse on the identifier iam (or
// .iam, the root-qualified form).
func parsedCallsIAM(e ast.Expr) bool {
	found := false
	ast.PreOrderVisit(e, ast.NewExprVisitor(func(x ast.Expr) {
		if found || x.Kind() != ast.CallKind {
			return
		}
		c := x.AsCall()
		found = strings.HasPrefix(strings.TrimPrefix(c.FunctionName(), "."), "iam.") ||
			c.IsMemberFunction() && c.Target().Kind() == ast.IdentKind && strings.TrimPrefix(c.Target().AsIdent(), ".") == "iam"
	}))
	return found
}

func calls(e ast.Expr, match func(string) bool) bool {
	found := false
	ast.PreOrderVisit(e, ast.NewExprVisitor(func(x ast.Expr) {
		found = found || (x.Kind() == ast.CallKind && match(x.AsCall().FunctionName()))
	}))
	return found
}

// lintGrants checks the position of every iam.grants / iam.grants_all call
// and every comprehension over a conditions field: neg counts the ! above it,
// mono says every ancestor is &&, ||, ! or an all/exists predicate. A
// conditions test sits under an even number of negations, so the result can
// only rise with it: a prohibition narrowed to statements that carry a key
// passes Allow *:*.
func lintGrants(e ast.Expr, neg int, mono bool) error {
	switch e.Kind() {
	case ast.CallKind:
		c := e.AsCall()
		switch fn := c.FunctionName(); fn {
		case "iam.grants", "iam.grants_all":
			if !mono || neg > 1 {
				return polarityErr(fn + " is read only below &&, ||, all or exists and under at most one negation; " + unconditionalRule)
			}
		case operators.LogicalNot:
			return lintGrants(c.Args()[0], neg+1, mono)
		case operators.LogicalAnd, operators.LogicalOr:
			for _, a := range c.Args() {
				if err := lintGrants(a, neg, mono); err != nil {
					return err
				}
			}
			return nil
		}
		args := c.Args()
		if c.IsMemberFunction() {
			args = append([]ast.Expr{c.Target()}, args...)
		}
		for _, a := range args {
			if err := lintGrants(a, neg, false); err != nil {
				return err
			}
		}
	case ast.ComprehensionKind:
		cm := e.AsComprehension()
		if conditionsRange(cm) && (!mono || neg%2 != 0) {
			return polarityErr("a conditions test is read only below &&, ||, all or exists and under an even number of negations; " + unconditionalRule)
		}
		rest := []ast.Expr{cm.IterRange(), cm.AccuInit(), cm.LoopCondition(), cm.LoopStep(), cm.Result()}
		if pred := monotonePredicate(cm); pred != nil {
			if err := lintGrants(pred, neg, mono); err != nil {
				return err
			}
			rest = []ast.Expr{cm.IterRange(), cm.AccuInit(), cm.LoopCondition(), cm.Result()}
		}
		for _, a := range rest {
			if err := lintGrants(a, neg, false); err != nil {
				return err
			}
		}
	default:
		// a list, map, struct or select is never monotone: nothing below it
		// may be a grant or a conditions test.
		var err error
		ast.PreOrderVisit(e, ast.NewExprVisitor(func(x ast.Expr) {
			switch {
			case err != nil || x.ID() == e.ID():
			case x.Kind() == ast.CallKind && (x.AsCall().FunctionName() == "iam.grants" || x.AsCall().FunctionName() == "iam.grants_all"):
				err = polarityErr(x.AsCall().FunctionName() + " is read only below &&, ||, all or exists and under at most one negation; " + unconditionalRule)
			case x.Kind() == ast.ComprehensionKind && conditionsRange(x.AsComprehension()):
				err = polarityErr("a conditions test is read only below &&, ||, all or exists and under an even number of negations; " + unconditionalRule)
			}
		}))
		return err
	}
	return nil
}

func conditionsRange(cm ast.ComprehensionExpr) bool {
	r := cm.IterRange()
	return r.Kind() == ast.SelectKind && r.AsSelect().FieldName() == "conditions"
}

func polarityErr(detail string) error {
	return &LoadDiag{Code: "control_iam_unconditional_polarity", Detail: detail}
}

const unconditionalRule = "unconditional is read only as a conjunct with a *_all field of the same statement, never negated or under ||, ?:, ==, has() or an index, and without *_any"

// lintPolarity walks e; pos says every ancestor keeps the result monotone in
// e, conj is the flattened && chain e belongs to, stmts names the statement
// variables in scope.
func lintPolarity(e ast.Expr, pos bool, conj []ast.Expr, stmts map[string]bool) error {
	switch e.Kind() {
	case ast.SelectKind:
		s := e.AsSelect()
		switch s.FieldName() {
		case "ambiguous":
			return polarityErr("ambiguous is diagnostic output, never a control input")
		case "conditions":
			if !stmts[iamKey] {
				break
			}
			fallthrough
		case "unconditional":
			if !pos || s.IsTestOnly() || !conjoinedWithAll(s.Operand(), conj, stmts) {
				return polarityErr(unconditionalRule)
			}
		}
		if isStmt(s.Operand(), stmts) {
			return nil
		}
		return lintPolarity(s.Operand(), false, nil, stmts)
	case ast.IdentKind:
		if stmts[e.AsIdent()] {
			return polarityErr("a statement variable is read only through a field select, a constant key or as the first argument of iam.grants, iam.grants_all, iam.principal_is, iam.principals_in_account or iam.resource_is")
		}
	case ast.CallKind:
		c := e.AsCall()
		if c.FunctionName() == operators.LogicalAnd {
			chain := flattenAnd(e, nil)
			for _, a := range chain {
				if err := lintPolarity(a, pos, chain, stmts); err != nil {
					return err
				}
			}
			return nil
		}
		args := c.Args()
		if c.FunctionName() == operators.Index && len(args) == 2 {
			if k := literalString(args[1]); k == "unconditional" || k == "ambiguous" || (k == "conditions" && stmts[iamKey]) {
				return polarityErr(k + " read through an index; " + unconditionalRule)
			}
			if isStmt(args[0], stmts) {
				if literalString(args[1]) == "" {
					return polarityErr("a statement variable is indexed only with a constant key")
				}
				return nil
			}
		}
		if fn := c.FunctionName(); identityCall[fn] && len(args) >= 2 && isStmt(args[0], stmts) {
			return lintAll(args[1:], stmts)
		}
		if c.IsMemberFunction() {
			args = append([]ast.Expr{c.Target()}, args...)
		}
		return lintAll(args, stmts)
	case ast.ComprehensionKind:
		cm := e.AsComprehension()
		inner := make(map[string]bool, len(stmts)+1)
		for k, v := range stmts {
			inner[k] = v
		}
		inner[cm.IterVar()] = statementsRange(cm.IterRange()) && !cm.HasIterVar2()
		if cm.HasIterVar2() {
			inner[cm.IterVar2()] = false
		}
		inner[cm.AccuVar()] = false
		// a keyed conditions range is a select on a statement variable: nothing to lint.
		pre := []ast.Expr{cm.IterRange(), cm.AccuInit()}
		if keyedConditions(cm, stmts) {
			pre = pre[1:]
		}
		if err := lintAll(pre, stmts); err != nil {
			return err
		}
		if pred := monotonePredicate(cm); pred != nil {
			if err := lintPolarity(pred, pos, nil, inner); err != nil {
				return err
			}
			return lintAll([]ast.Expr{cm.LoopCondition(), cm.Result()}, inner)
		}
		return lintAll([]ast.Expr{cm.LoopCondition(), cm.LoopStep(), cm.Result()}, inner)
	case ast.ListKind:
		return lintAll(e.AsList().Elements(), stmts)
	case ast.MapKind:
		for _, en := range e.AsMap().Entries() {
			m := en.AsMapEntry()
			if err := lintAll([]ast.Expr{m.Key(), m.Value()}, stmts); err != nil {
				return err
			}
		}
	case ast.StructKind:
		for _, f := range e.AsStruct().Fields() {
			if err := lintPolarity(f.AsStructField().Value(), false, nil, stmts); err != nil {
				return err
			}
		}
	}
	return nil
}

func isStmt(e ast.Expr, stmts map[string]bool) bool {
	return e.Kind() == ast.IdentKind && stmts[e.AsIdent()]
}

// lintAll lints each expression in a non-monotone position.
func lintAll(es []ast.Expr, stmts map[string]bool) error {
	for _, e := range es {
		if err := lintPolarity(e, false, nil, stmts); err != nil {
			return err
		}
	}
	return nil
}

func flattenAnd(e ast.Expr, out []ast.Expr) []ast.Expr {
	if e.Kind() == ast.CallKind && e.AsCall().FunctionName() == operators.LogicalAnd {
		for _, a := range e.AsCall().Args() {
			out = flattenAnd(a, out)
		}
		return out
	}
	return append(out, e)
}

// monotonePredicate returns the predicate of an all or exists macro: accu
// starts as a bool literal, steps as accu && p or accu || p, and is the
// result. exists_one, map and filter return nil.
func monotonePredicate(cm ast.ComprehensionExpr) ast.Expr {
	isAccu := func(x ast.Expr) bool { return x.Kind() == ast.IdentKind && x.AsIdent() == cm.AccuVar() }
	if cm.AccuInit().Kind() != ast.LiteralKind || !isAccu(cm.Result()) || cm.LoopStep().Kind() != ast.CallKind {
		return nil
	}
	step := cm.LoopStep().AsCall()
	// all starts true and steps with &&, exists starts false and steps with ||.
	init, ok := cm.AccuInit().AsLiteral().(types.Bool)
	if fn := step.FunctionName(); !ok || len(step.Args()) != 2 ||
		fn != map[bool]string{true: operators.LogicalAnd, false: operators.LogicalOr}[bool(init)] {
		return nil
	}
	switch a := step.Args(); {
	case isAccu(a[0]) && !isAccu(a[1]):
		return a[1]
	case isAccu(a[1]) && !isAccu(a[0]):
		return a[0]
	}
	return nil
}

// keyedConditions reports whether cm is s.conditions.exists(c, ... && c.key
// == "k" && ...) on a statement variable s with a non-empty constant k: a test
// for one condition key, never an emptiness or count test.
func keyedConditions(cm ast.ComprehensionExpr, stmts map[string]bool) bool {
	r := cm.IterRange()
	if !stmts[iamKey] || cm.HasIterVar2() || r.Kind() != ast.SelectKind || r.AsSelect().FieldName() != "conditions" ||
		r.AsSelect().IsTestOnly() || !isStmt(r.AsSelect().Operand(), stmts) {
		return false
	}
	pred := monotonePredicate(cm)
	if pred == nil || cm.LoopStep().AsCall().FunctionName() != operators.LogicalOr {
		return false
	}
	for _, x := range flattenAnd(pred, nil) {
		if x.Kind() != ast.CallKind || x.AsCall().FunctionName() != operators.Equals {
			continue
		}
		a := x.AsCall().Args()
		if a[0].Kind() == ast.SelectKind && a[0].AsSelect().FieldName() == "key" && !a[0].AsSelect().IsTestOnly() &&
			a[0].AsSelect().Operand().Kind() == ast.IdentKind && a[0].AsSelect().Operand().AsIdent() == cm.IterVar() &&
			literalString(a[1]) != "" {
			return true
		}
	}
	return false
}

// statementsRange reports whether e is iam.parse(...).statements or
// iam.parse(...)["statements"].
func statementsRange(e ast.Expr) bool {
	var op ast.Expr
	switch {
	case e.Kind() == ast.SelectKind && e.AsSelect().FieldName() == "statements" && !e.AsSelect().IsTestOnly():
		op = e.AsSelect().Operand()
	case e.Kind() == ast.CallKind && e.AsCall().FunctionName() == operators.Index && len(e.AsCall().Args()) == 2 &&
		literalString(e.AsCall().Args()[1]) == "statements":
		op = e.AsCall().Args()[0]
	default:
		return false
	}
	return op.Kind() == ast.CallKind && op.AsCall().FunctionName() == "iam.parse"
}

// conjoinedWithAll reports whether operand is a statement variable whose &&
// chain selects one of its *_all fields and none of its *_any fields.
func conjoinedWithAll(operand ast.Expr, conj []ast.Expr, stmts map[string]bool) bool {
	if operand.Kind() != ast.IdentKind || !stmts[operand.AsIdent()] {
		return false
	}
	v := operand.AsIdent()
	isV := func(x ast.Expr) bool { return x.Kind() == ast.IdentKind && x.AsIdent() == v }
	// field names a select or constant-key index of v; an index counts for
	// *_any (it must not hide one) but never as the *_all conjunct.
	field := func(x ast.Expr) string {
		if x.Kind() == ast.SelectKind && isV(x.AsSelect().Operand()) && !x.AsSelect().IsTestOnly() {
			return x.AsSelect().FieldName()
		}
		if x.Kind() == ast.CallKind && x.AsCall().FunctionName() == operators.Index && len(x.AsCall().Args()) == 2 && isV(x.AsCall().Args()[0]) {
			return "[" + literalString(x.AsCall().Args()[1]) + "]"
		}
		return ""
	}
	all, anyFlag := false, false
	for _, c := range conj {
		switch field(c) {
		case "action_all", "principal_all", "resource_all":
			all = true
		}
		ast.PreOrderVisit(c, ast.NewExprVisitor(func(x ast.Expr) {
			f := strings.TrimSuffix(field(x), "]")
			anyFlag = anyFlag || strings.HasSuffix(f, "_any")
		}))
	}
	return all && !anyFlag
}

// identityCall are the functions that may take a statement variable as
// their first argument.
var identityCall = map[string]bool{"iam.grants": true, "iam.grants_all": true, "iam.principal_is": true,
	"iam.principals_in_account": true, "iam.resource_is": true}

// identityField are the statement fields a control may not read: principals
// and resources are compared only through iam.principal_is,
// iam.principals_in_account / iam.resource_is.
var identityField = map[string]bool{"principals": true, "not_principals": true, "resources": true,
	"not_resources": true, "unresolved_principals": true, "unresolved_resources": true}

func identityErr() error {
	return &LoadDiag{Code: "control_iam_identity_direct",
		Detail: "principals and resources of an iam.parse statement are read only through iam.principal_is / iam.resource_is"}
}

// identityDirect is the control_iam_identity_direct lint. In an expression
// that calls iam.parse, no select, has() or constant-key index may name an
// identity field and no index key may be computed, whatever the operand: a
// statement reached through filter, map, ["statements"] or a list index
// cannot hide the read. A data attribute with one of these names next to
// iam.parse is rejected too (fail closed), and so is format, which would
// render principals and resources as text.
func identityDirect(e ast.Expr) error {
	parses := false
	ast.PreOrderVisit(e, ast.NewExprVisitor(func(x ast.Expr) {
		parses = parses || (x.Kind() == ast.CallKind && x.AsCall().FunctionName() == "iam.parse")
	}))
	if !parses {
		return nil
	}
	var err error
	ast.PreOrderVisit(e, ast.NewExprVisitor(func(x ast.Expr) {
		switch {
		case err != nil:
		case x.Kind() == ast.SelectKind && identityField[x.AsSelect().FieldName()]:
			err = identityErr()
		// format renders a parse result as text, identities included; it is
		// the env's only map-to-string path. shortcut: banned beside any
		// iam.parse, track its arguments if a control needs format there.
		case x.Kind() == ast.CallKind && x.AsCall().FunctionName() == "format":
			err = identityErr()
		case x.Kind() == ast.CallKind && x.AsCall().FunctionName() == operators.Index && len(x.AsCall().Args()) == 2:
			k := x.AsCall().Args()[1]
			if k.Kind() != ast.LiteralKind || identityField[literalString(k)] {
				err = identityErr()
			}
		}
	}))
	return err
}
