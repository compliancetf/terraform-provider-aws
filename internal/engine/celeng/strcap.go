package celeng

import (
	"errors"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/functions"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/ext"
	"cel.dev/cel-go/interpreter"

	"github.com/compliancetf/terraform-provider-aws/internal/engine/lib"
)

// maxStringBytes caps the output of the ext.Strings functions whose output
// can outgrow their inputs many times over: replace, join and format, and of
// string and bytes +. cel-go charges cost only after a function returns, so
// a few chained replaces can ask for gigabytes under the cost limit. Interim
// cap like defaultCostLimit.
const maxStringBytes = 1 << 20

// maxListElements caps the element count of a list + result, the selector
// input cap (selectorMaxElements). Over it is lib.ErrLimit. cel-go
// builds the map and filter macro results with + too, so they share the cap.
const maxListElements = selectorMaxElements

// fmtScalarBytes bounds one formatted double or any other scalar without a
// tighter bound in fmtFits: a double with %f at the maximum precision 100 is
// at most 1 + 309 + 1 + 100 bytes.
const fmtScalarBytes = 512

var errSizeLimit = types.WrapErr(lib.ErrLimit)

// stringCaps rebinds replace, join and format with the same signatures
// (cel-go replaces a binding whose signature matches) and wraps string /
// bytes + (ProgramOptions), so the output size is checked before anything
// is built. Over the cap is lib.ErrLimit. Must follow ext.Strings() in the
// env options.
func stringCaps() (cel.EnvOption, error) {
	base, err := cel.NewEnv(ext.Strings())
	if err != nil {
		return nil, err
	}
	bs, err := base.Functions()["format"].Bindings()
	if err != nil {
		return nil, err
	}
	var format functions.FunctionOp
	for _, b := range bs {
		if b.Operator == "string_format" {
			format = b.Function
		}
	}
	if format == nil {
		return nil, errors.New("ext.Strings: no string_format binding")
	}
	str, strList := cel.StringType, cel.ListType(cel.StringType)
	return cel.Lib(stringCapsLib{
		cel.Function("replace",
			cel.MemberOverload("string_replace_string_string",
				[]*cel.Type{str, str, str}, str, cel.FunctionBinding(replaceCapped)),
			cel.MemberOverload("string_replace_string_string_int",
				[]*cel.Type{str, str, str, cel.IntType}, str, cel.FunctionBinding(replaceCapped))),
		cel.Function("join",
			cel.MemberOverload("list_join", []*cel.Type{strList}, str,
				cel.UnaryBinding(func(l ref.Val) ref.Val { return joinCapped(l, types.String("")) })),
			cel.MemberOverload("list_join_string", []*cel.Type{strList, str}, str,
				cel.BinaryBinding(joinCapped))),
		cel.Function("format",
			cel.MemberOverload("string_format", []*cel.Type{str, cel.ListType(cel.DynType)}, str,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					s, ok := args[0].(types.String)
					if !ok {
						return types.MaybeNoSuchOverloadErr(args[0])
					}
					k, known := fmtFactor(string(s))
					n := len(s)
					if !known || !fmtFits(args[1], &n, k) {
						return errSizeLimit
					}
					return format(args...)
				}))),
	}), nil
}

type stringCapsLib []cel.EnvOption

func (l stringCapsLib) CompileOptions() []cel.EnvOption { return l }

// ProgramOptions caps +: the standard library binds _+_ once for every
// type (a singleton), so no overload can be rebound; the call node is
// wrapped instead, in every program of the env.
func (stringCapsLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{cel.CustomDecoratorV2(func(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
		if c, ok := i.(interpreter.InterpretableCall); ok && c.Function() == operators.Add && len(c.Args()) == 2 {
			return &addCall{c}, nil
		}
		return i, nil
	})}
}

// addCall is the standard _+_ (strict, Adder trait) with the size of a
// string, bytes or list result checked before it is built. Maps have no +.
type addCall struct{ interpreter.InterpretableCall }

func (c *addCall) Eval(a interpreter.Activation) ref.Val { return c.Exec(interpreter.AsFrame(a)) }

func (c *addCall) Exec(f *interpreter.ExecutionFrame) ref.Val {
	args := c.Args()
	l := args[0].Exec(f)
	if types.IsError(l) {
		return l
	}
	r := args[1].Exec(f)
	if types.IsError(r) {
		return r
	}
	var unk *types.Unknown
	unk, _ = types.MaybeMergeUnknowns(l, unk)
	if unk, _ = types.MaybeMergeUnknowns(r, unk); unk != nil {
		return unk
	}
	add, ok := l.(traits.Adder)
	if !ok || !l.Type().HasTrait(traits.AdderType) {
		return types.NewErrWithNodeID(c.ID(), "no such overload: %s", operators.Add)
	}
	switch lv := l.(type) {
	case types.String:
		if rv, ok := r.(types.String); ok && len(lv)+len(rv) > maxStringBytes {
			return errSizeLimit
		}
	case types.Bytes:
		if rv, ok := r.(types.Bytes); ok && len(lv)+len(rv) > maxStringBytes {
			return errSizeLimit
		}
	case traits.Lister:
		if rv, ok := r.(traits.Lister); ok {
			ln, lok := lv.Size().(types.Int)
			rn, rok := rv.Size().(types.Int)
			if !lok || !rok || ln+rn > maxListElements { // a size that is not an int never fails open
				return errSizeLimit
			}
		}
	}
	return types.LabelErrNode(c.ID(), add.Add(r))
}

// fmtFactor returns how many output bytes a format template writes per
// string or bytes input byte: 2 with a %x or %X verb, else 1. It follows
// cel-go's format V2 clause grammar: %% is a literal percent, a clause is %,
// an optional .precision (1 to 3 digits, at most fmtMaxPrecision), then one
// verb letter (no width, no %q). Anything else (a width, a flag, a longer
// precision, a missing verb, a verb outside s d f e b o x X; cel-go rejects
// all of these today) returns ok false, so syntax a cel-go upgrade adds is
// refused until it is bounded here.
func fmtFactor(s string) (k int, ok bool) {
	k = 1
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		if i++; i < len(s) && s[i] == '%' {
			continue
		}
		if i < len(s) && s[i] == '.' {
			p, start := 0, i+1
			for i = start; i < len(s) && i-start < 4 && s[i] >= '0' && s[i] <= '9'; i++ {
				p = p*10 + int(s[i]-'0')
			}
			if i == start || p > fmtMaxPrecision {
				return 0, false
			}
		}
		switch {
		case i >= len(s):
			return 0, false
		case s[i] == 'x' || s[i] == 'X':
			k = 2
		case !strings.ContainsRune("sdfebo", rune(s[i])):
			return 0, false
		}
	}
	return k, true
}

// fmtMaxPrecision is cel-go's ext.Strings precision cap; the scalar bounds in
// fmtFits assume it.
const fmtMaxPrecision = 100

// replaceCapped is ext.Strings replace(old, new[, n]) with the output size
// computed from the match count first.
func replaceCapped(args ...ref.Val) ref.Val {
	var v [3]string
	for i := range v {
		s, ok := args[i].(types.String)
		if !ok {
			return types.MaybeNoSuchOverloadErr(args[i])
		}
		v[i] = string(s)
	}
	s, old, nw := v[0], v[1], v[2]
	m := int64(strings.Count(s, old)) // runes+1 for an empty old, like strings.Replace
	if len(args) == 4 {
		n, ok := args[3].(types.Int)
		if !ok {
			return types.MaybeNoSuchOverloadErr(args[3])
		}
		if n >= 0 && int64(n) < m {
			m = int64(n)
		}
	}
	// Output is len(s) + m*grow; compare by division so nothing overflows.
	if grow := int64(len(nw)) - int64(len(old)); grow > 0 && m > 0 &&
		(int64(len(s)) > maxStringBytes || m > (maxStringBytes-int64(len(s)))/grow) {
		return errSizeLimit
	}
	return types.String(strings.Replace(s, old, nw, int(m)))
}

// joinCapped is ext.Strings join with the output size summed first.
func joinCapped(list, sep ref.Val) ref.Val {
	l, ok := list.(traits.Lister)
	if !ok {
		return types.MaybeNoSuchOverloadErr(list)
	}
	d, ok := sep.(types.String)
	if !ok {
		return types.MaybeNoSuchOverloadErr(sep)
	}
	cnt, ok := l.Size().(types.Int)
	if !ok {
		return types.MaybeNoSuchOverloadErr(list)
	}
	parts := make([]string, 0, cnt)
	total := 0
	for i := range cnt {
		s, ok := l.Get(i).(types.String)
		if !ok {
			return types.NewErr("join: invalid input: %v", l.Get(i))
		}
		if i > 0 {
			total += len(d)
		}
		if total += len(s); total > maxStringBytes {
			return errSizeLimit
		}
		parts = append(parts, string(s))
	}
	return types.String(strings.Join(parts, string(d)))
}

// fmtFits adds to *n an upper bound of what format writes for v (strings
// and bytes k times their length, k = 2 when %x can hex them; lists and maps
// their elements plus separators) and reports whether *n stays within
// maxStringBytes. Each verb consumes one argument, so the bound covers the
// whole output.
func fmtFits(v ref.Val, n *int, k int) bool {
	switch v := v.(type) {
	case types.String:
		*n += k * len(v)
	case types.Bytes:
		*n += k * len(v)
	case traits.Mapper:
		*n += 2
		for it := v.Iterator(); it.HasNext() == types.True; {
			key := it.Next()
			*n += 4
			if !fmtFits(key, n, k) || !fmtFits(v.Get(key), n, k) {
				return false
			}
		}
	case traits.Lister:
		*n += 2
		for it := v.Iterator(); it.HasNext() == types.True; {
			*n += 2
			if !fmtFits(it.Next(), n, k) {
				return false
			}
		}
	case types.Bool, types.Null:
		*n += 8
	case types.Int, types.Uint:
		*n += 128 // %b: sign and 64 digits; %.100f: sign, 20 digits, point, 100
	case types.Duration, types.Timestamp:
		*n += 64 // %s only: seconds and "s", or RFC 3339 with nanoseconds
	default:
		*n += fmtScalarBytes
	}
	return *n <= maxStringBytes
}
