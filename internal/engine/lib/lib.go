package lib

import (
	"slices"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
)

// Helpers is the CEL library of cidr.contains, cidr.overlaps, tags.has and
// semver.compare. Every function is
// strict: an unknown or error argument short-circuits before the function
// runs, so the call is unknown (or the error), never a decided bool.
// Malformed input is ErrInvalid (type_error), never a non-match. Each call is
// linear in its string arguments and costs the CEL default of one unit.
func Helpers() cel.EnvOption {
	return cel.Lib(helpers{})
}

type helpers struct{}

func (helpers) CompileOptions() []cel.EnvOption {
	return slices.Concat(cidrFuncs(), tagsFuncs(), semverFuncs())
}

func (helpers) ProgramOptions() []cel.ProgramOption { return nil }

// invalid is the value-free type_error result: the error text names the
// class only, never the input.
func invalid() ref.Val { return types.WrapErr(ErrInvalid) }

// strs returns the arguments as Go strings, or false when one is not a string.
func strs(args ...ref.Val) ([]string, bool) {
	out := make([]string, len(args))
	for i, a := range args {
		s, ok := a.(types.String)
		if !ok {
			return nil, false
		}
		out[i] = string(s)
	}
	return out, true
}
