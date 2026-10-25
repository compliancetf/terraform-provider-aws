package bundlegen

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/tryfunc"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
	"github.com/zclconf/go-cty/cty/gocty"

	"github.com/compliancetf/terraform-provider-aws/internal/engine"
)

// postFuncs are the Terraform functions content postconditions call, as
// Terraform's function table (internal/lang/functions.go) binds them:
// try, can, contains, lower and jsondecode are the same hcl/go-cty
// functions; alltrue, anytrue, coalesce, length, one and startswith are
// ports of internal/lang/funcs below; tobool, tonumber and tolist use the
// stdlib MakeToFunc, which differs from funcs.MakeToFunc only in sensitive
// and ephemeral marks, which fixtures never carry. A postcondition calling
// any other function does not evaluate (E_DIFFCHECK_EVAL).
var postFuncs = map[string]function.Function{
	"alltrue":    allTrueFunc,
	"anytrue":    anyTrueFunc,
	"can":        tryfunc.CanFunc,
	"coalesce":   coalesceFunc,
	"contains":   stdlib.ContainsFunc,
	"jsondecode": stdlib.JSONDecodeFunc,
	"length":     lengthFunc,
	"lower":      stdlib.LowerFunc,
	"one":        oneFunc,
	"startswith": startsWithFunc,
	"tobool":     stdlib.MakeToFunc(cty.Bool),
	"tolist":     stdlib.MakeToFunc(cty.List(cty.DynamicPseudoType)),
	"tonumber":   stdlib.MakeToFunc(cty.Number),
	"try":        tryfunc.TryFunc,
}

// postcondition is a parsed content resource_postcondition condition.
type postcondition struct{ expr hclsyntax.Expression }

// parsePostcondition parses src and checks that every function it calls
// is in postFuncs; the error names a diagnostic summary or a function name,
// never a value.
func parsePostcondition(src string) (postcondition, error) {
	e, diags := hclsyntax.ParseExpression([]byte(src), "postcondition", hcl.InitialPos)
	if diags.HasErrors() {
		return postcondition{}, fmt.Errorf("does not parse: %s", diags[0].Summary)
	}
	diags = hclsyntax.VisitAll(e, func(n hclsyntax.Node) hcl.Diagnostics {
		if fc, ok := n.(*hclsyntax.FunctionCallExpr); ok {
			if _, ok := postFuncs[fc.Name]; !ok {
				return hcl.Diagnostics{{Severity: hcl.DiagError, Summary: safeName(fc.Name)}}
			}
		}
		return nil
	})
	if diags.HasErrors() {
		return postcondition{}, fmt.Errorf("calls %s, which diffcheck does not implement", diags[0].Summary)
	}
	return postcondition{e}, nil
}

// validateSelf checks every reference of the condition, inside try and can
// too, the way Terraform validates a postcondition before evaluating it
// (internal/terraform/node_resource_validate.go validateCheckRules,
// internal/lang/eval.go evalContext StaticValidateReferences,
// internal/terraform/evaluate_valid.go staticValidateResourceReference): a
// reference is self (the only name diffcheck binds) and its remaining steps
// pass Block.StaticValidateTraversal against the resource schema. The error
// names a diagnostic summary only.
func (p postcondition) validateSelf(b *tfprotov5.SchemaBlock) error {
	for _, tr := range p.expr.Variables() {
		if tr.RootName() != "self" {
			return fmt.Errorf("references %s, which diffcheck does not bind", safeName(tr.RootName()))
		}
		if err := staticValidateTraversal(b, tr[1:]); err != nil {
			return fmt.Errorf("self reference: %w", err)
		}
	}
	return nil
}

// staticValidateTraversal is a port of Terraform's
// internal/configs/configschema/validate_traversal.go
// (Block.StaticValidateTraversal, NestedBlock.staticValidateTraversal) over
// a tfprotov5 schema block.
func staticValidateTraversal(b *tfprotov5.SchemaBlock, tr hcl.Traversal) error {
	if len(tr) == 0 {
		return nil
	}
	var name string
	switch step := tr[0].(type) {
	case hcl.TraverseAttr:
		name = step.Name
	case hcl.TraverseIndex:
		return fmt.Errorf("Invalid index operation") //nolint:staticcheck // Terraform's summary
	default:
		return fmt.Errorf("Invalid operation") //nolint:staticcheck // Terraform's summary
	}
	after := tr[1:]
	for _, a := range b.Attributes {
		if a != nil && a.Name == name {
			ty, err := ctyType(a.ValueType())
			if err != nil {
				return err
			}
			if _, diags := after.TraverseRel(cty.UnknownVal(ty)); diags.HasErrors() {
				return fmt.Errorf("%s", diags[0].Summary)
			}
			return nil
		}
	}
	for _, nb := range b.BlockTypes {
		if nb == nil || nb.TypeName != name {
			continue
		}
		switch nb.Nesting {
		case tfprotov5.SchemaNestedBlockNestingModeSingle, tfprotov5.SchemaNestedBlockNestingModeGroup:
			return staticValidateTraversal(nb.Block, after)
		}
		if len(after) == 0 {
			return nil
		}
		switch nb.Nesting {
		case tfprotov5.SchemaNestedBlockNestingModeSet:
			return fmt.Errorf("Cannot index a set value") //nolint:staticcheck // Terraform's summary
		case tfprotov5.SchemaNestedBlockNestingModeList:
			if _, ok := after[0].(hcl.TraverseIndex); !ok {
				return fmt.Errorf("Invalid operation") //nolint:staticcheck // Terraform's summary
			}
			return staticValidateTraversal(nb.Block, after[1:])
		case tfprotov5.SchemaNestedBlockNestingModeMap:
			return staticValidateTraversal(nb.Block, after[1:])
		}
		return nil
	}
	return fmt.Errorf("Unsupported attribute") //nolint:staticcheck // Terraform's summary
}

// eval evaluates the condition (HCL with the fixed postFuncs table, no
// file or network access) with self bound to self, as Terraform does
// after apply: true is pass, false fail, an unknown result unknown (the
// check is deferred). An evaluation error or a null or non-bool result
// fails the apply in Terraform, so it is fail, with why naming the
// diagnostic summary only. The error is for a self that does not convert.
func (p postcondition) eval(self tftypes.Value) (st engine.State, why string, err error) {
	sv, err := ctyValue(self)
	if err != nil {
		return 0, "", err
	}
	v, diags := p.expr.Value(&hcl.EvalContext{Variables: map[string]cty.Value{"self": sv}, Functions: postFuncs})
	switch {
	case diags.HasErrors():
		return engine.Fail, diags[0].Summary, nil
	case !v.IsKnown():
		return engine.Unknown, "", nil
	case v.IsNull():
		return engine.Fail, "null result", nil
	}
	b, err := convert.Convert(v, cty.Bool)
	if err != nil {
		return engine.Fail, v.Type().FriendlyName() + " result", nil
	}
	if b.True() {
		return engine.Pass, "", nil
	}
	return engine.Fail, "", nil
}

// ctyType is the cty type of a tftypes schema type.
func ctyType(t tftypes.Type) (cty.Type, error) {
	switch t := t.(type) {
	case tftypes.Object:
		at := map[string]cty.Type{}
		for k, e := range t.AttributeTypes {
			c, err := ctyType(e)
			if err != nil {
				return cty.NilType, err
			}
			at[k] = c
		}
		return cty.Object(at), nil
	case tftypes.List, tftypes.Set, tftypes.Map:
		var et tftypes.Type
		mk := cty.List
		switch t := t.(type) {
		case tftypes.List:
			et = t.ElementType
		case tftypes.Set:
			et, mk = t.ElementType, cty.Set
		case tftypes.Map:
			et, mk = t.ElementType, cty.Map
		}
		c, err := ctyType(et)
		return mk(c), err
	case tftypes.Tuple:
		ets := make([]cty.Type, len(t.ElementTypes))
		for i, e := range t.ElementTypes {
			c, err := ctyType(e)
			if err != nil {
				return cty.NilType, err
			}
			ets[i] = c
		}
		return cty.Tuple(ets), nil
	}
	switch {
	case t.Is(tftypes.String):
		return cty.String, nil
	case t.Is(tftypes.Number):
		return cty.Number, nil
	case t.Is(tftypes.Bool):
		return cty.Bool, nil
	case t.Is(tftypes.DynamicPseudoType):
		return cty.DynamicPseudoType, nil
	}
	return cty.NilType, fmt.Errorf("no cty type for %s", t)
}

// ctyValue converts a fixture value (fixturejson.Value) to cty, keeping
// typed nulls and unknowns.
func ctyValue(v tftypes.Value) (cty.Value, error) {
	ty, err := ctyType(v.Type())
	if err != nil {
		return cty.NilVal, err
	}
	switch {
	case !v.IsKnown():
		return cty.UnknownVal(ty), nil
	case v.IsNull():
		return cty.NullVal(ty), nil
	case ty.Equals(cty.String):
		var s string
		err := v.As(&s)
		return cty.StringVal(s), err
	case ty.Equals(cty.Bool):
		var b bool
		err := v.As(&b)
		return cty.BoolVal(b), err
	case ty.Equals(cty.Number):
		f := new(big.Float)
		if err := v.As(&f); err != nil {
			return cty.NilVal, err
		}
		return cty.NumberVal(f), nil
	case ty.IsObjectType():
		var m map[string]tftypes.Value
		if err := v.As(&m); err != nil {
			return cty.NilVal, err
		}
		out := map[string]cty.Value{}
		for k, e := range m {
			if out[k], err = ctyValue(e); err != nil {
				return cty.NilVal, err
			}
		}
		return cty.ObjectVal(out), nil
	case ty.IsMapType():
		var m map[string]tftypes.Value
		if err := v.As(&m); err != nil {
			return cty.NilVal, err
		}
		if len(m) == 0 {
			return cty.MapValEmpty(ty.ElementType()), nil
		}
		out := map[string]cty.Value{}
		for k, e := range m {
			if out[k], err = ctyValue(e); err != nil {
				return cty.NilVal, err
			}
		}
		return cty.MapVal(out), nil
	}
	var l []tftypes.Value
	if err := v.As(&l); err != nil {
		return cty.NilVal, err
	}
	out := make([]cty.Value, len(l))
	for i, e := range l {
		if out[i], err = ctyValue(e); err != nil {
			return cty.NilVal, err
		}
	}
	switch {
	case ty.IsTupleType():
		return cty.TupleVal(out), nil
	case len(out) == 0 && ty.IsSetType():
		return cty.SetValEmpty(ty.ElementType()), nil
	case len(out) == 0:
		return cty.ListValEmpty(ty.ElementType()), nil
	case ty.IsSetType():
		return cty.SetVal(out), nil
	}
	return cty.ListVal(out), nil
}

// The functions below are ports of hashicorp/terraform
// internal/lang/funcs (collection.go: LengthFunc, AllTrueFunc, AnyTrueFunc,
// CoalesceFunc, OneFunc; string.go: StartsWithFunc), without mark handling:
// fixture values carry no marks.

func refineNotNull(b *cty.RefinementBuilder) *cty.RefinementBuilder { return b.NotNull() }

// oneFunc is Terraform's one: null for an empty list, set or tuple, the
// element for one, an error for more; unknown when the length is unknown.
var oneFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "list", Type: cty.DynamicPseudoType}},
	Type: func(args []cty.Value) (cty.Type, error) {
		ty := args[0].Type()
		switch {
		case ty.IsListType() || ty.IsSetType():
			return ty.ElementType(), nil
		case ty.IsTupleType():
			switch etys := ty.TupleElementTypes(); len(etys) {
			case 0:
				return cty.DynamicPseudoType, nil
			case 1:
				return etys[0], nil
			}
		}
		return cty.NilType, function.NewArgErrorf(0, "must be a list, set, or tuple value with either zero or one elements")
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		val := args[0]
		ty := val.Type()
		switch {
		case ty.IsListType() || ty.IsSetType():
			lenVal := val.Length()
			if !lenVal.IsKnown() {
				return cty.UnknownVal(retType), nil
			}
			var l int
			if err := gocty.FromCtyValue(lenVal, &l); err != nil {
				return cty.NilVal, fmt.Errorf("invalid collection length: %w", err)
			}
			switch l {
			case 0:
				return cty.NullVal(retType), nil
			case 1:
				var ret cty.Value
				for it := val.ElementIterator(); it.Next(); {
					_, ret = it.Element()
				}
				return ret, nil
			}
		case ty.IsTupleType():
			switch len(ty.TupleElementTypes()) {
			case 0:
				return cty.NullVal(retType), nil
			case 1:
				return val.Index(cty.NumberIntVal(0)), nil
			}
		}
		return cty.NilVal, function.NewArgErrorf(0, "must be a list, set, or tuple value with either zero or one elements")
	},
})

// allTrueFunc is Terraform's alltrue: true for an empty list; unknown at the
// first unknown element, false at the first null or false one.
var allTrueFunc = function.New(&function.Spec{
	Params:       []function.Parameter{{Name: "list", Type: cty.List(cty.Bool)}},
	Type:         function.StaticReturnType(cty.Bool),
	RefineResult: refineNotNull,
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		result := cty.True
		for it := args[0].ElementIterator(); it.Next(); {
			_, v := it.Element()
			if !v.IsKnown() {
				return cty.UnknownVal(cty.Bool), nil
			}
			if v.IsNull() {
				return cty.False, nil
			}
			result = result.And(v)
			if result.False() {
				return cty.False, nil
			}
		}
		return result, nil
	},
})

// anyTrueFunc is Terraform's anytrue: false for an empty list, true at a
// true element, nulls skipped, else unknown when an element is unknown.
var anyTrueFunc = function.New(&function.Spec{
	Params:       []function.Parameter{{Name: "list", Type: cty.List(cty.Bool)}},
	Type:         function.StaticReturnType(cty.Bool),
	RefineResult: refineNotNull,
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		result := cty.False
		var hasUnknown bool
		for it := args[0].ElementIterator(); it.Next(); {
			_, v := it.Element()
			if !v.IsKnown() {
				hasUnknown = true
				continue
			}
			if v.IsNull() {
				continue
			}
			result = result.Or(v)
			if result.True() {
				return cty.True, nil
			}
		}
		if hasUnknown {
			return cty.UnknownVal(cty.Bool), nil
		}
		return result, nil
	},
})

// coalesceFunc is Terraform's coalesce: the first argument that is neither
// null nor, for a string result, "" (go-cty's skips only nulls); unknown at
// the first unknown argument; an error when every argument is skipped.
var coalesceFunc = function.New(&function.Spec{
	VarParam: &function.Parameter{Name: "vals", Type: cty.DynamicPseudoType, AllowUnknown: true, AllowDynamicType: true, AllowNull: true},
	Type: func(args []cty.Value) (cty.Type, error) {
		argTypes := make([]cty.Type, len(args))
		for i, val := range args {
			argTypes[i] = val.Type()
		}
		retType, _ := convert.UnifyUnsafe(argTypes)
		if retType == cty.NilType {
			return cty.NilType, fmt.Errorf("all arguments must have the same type")
		}
		return retType, nil
	},
	RefineResult: refineNotNull,
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		for _, argVal := range args {
			argVal, err := convert.Convert(argVal, retType)
			if err != nil { // Type unified the arguments; Terraform ignores this error
				return cty.NilVal, err
			}
			if !argVal.IsKnown() {
				return cty.UnknownVal(retType), nil
			}
			if argVal.IsNull() {
				continue
			}
			if retType == cty.String && argVal.RawEquals(cty.StringVal("")) {
				continue
			}
			return argVal, nil
		}
		return cty.NilVal, fmt.Errorf("no non-null, non-empty-string arguments")
	},
})

// startsWithFunc is Terraform's startswith, including its known result for
// an unknown string with a known prefix.
var startsWithFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "str", Type: cty.String, AllowUnknown: true},
		{Name: "prefix", Type: cty.String},
	},
	Type:         function.StaticReturnType(cty.Bool),
	RefineResult: refineNotNull,
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		prefix := args[1].AsString()
		if !args[0].IsKnown() {
			if prefix == "" {
				return cty.True, nil
			}
			if known := args[0].Range().StringPrefix(); known != "" {
				if strings.HasPrefix(known, prefix) {
					return cty.True, nil
				}
				if len(known) >= len(prefix) {
					return cty.False, nil
				}
			}
			return cty.UnknownVal(cty.Bool), nil
		}
		return cty.BoolVal(strings.HasPrefix(args[0].AsString(), prefix)), nil
	},
})

// lengthFunc is Terraform's length: characters of a string, elements of a
// collection, the attribute or element count of an object or tuple type
// (known even for an unknown value).
var lengthFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "value", Type: cty.DynamicPseudoType, AllowDynamicType: true, AllowUnknown: true}},
	Type: func(args []cty.Value) (cty.Type, error) {
		ty := args[0].Type()
		if ty == cty.String || ty.IsTupleType() || ty.IsObjectType() || ty.IsListType() || ty.IsMapType() || ty.IsSetType() || ty == cty.DynamicPseudoType {
			return cty.Number, nil
		}
		return cty.Number, fmt.Errorf("argument must be a string, a collection type, or a structural type")
	},
	RefineResult: refineNotNull,
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		coll := args[0]
		ty := coll.Type()
		switch {
		case ty == cty.DynamicPseudoType:
			return cty.UnknownVal(cty.Number), nil
		case ty.IsTupleType():
			return cty.NumberIntVal(int64(len(ty.TupleElementTypes()))), nil
		case ty.IsObjectType():
			return cty.NumberIntVal(int64(len(ty.AttributeTypes()))), nil
		case ty == cty.String:
			return stdlib.Strlen(coll)
		}
		return coll.Length(), nil
	},
})
