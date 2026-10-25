package lib

import (
	"strings"
	"unicode"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
)

// semverFuncs declares semver.compare(a, b) -> -1/0/1: a dotted-segment
// compare, not strict SemVer, so engine versions such as
// 5.7.mysql_aurora.2.11.2 order as AWS lists them.
func semverFuncs() []cel.EnvOption {
	return []cel.EnvOption{cel.Function("semver.compare",
		cel.Overload("semver_compare_string_string", []*cel.Type{cel.StringType, cel.StringType}, cel.IntType,
			cel.BinaryBinding(func(a, b ref.Val) ref.Val {
				s, ok := strs(a, b)
				if !ok {
					return invalid()
				}
				x, ok1 := segments(s[0])
				y, ok2 := segments(s[1])
				if !ok1 || !ok2 {
					return invalid()
				}
				for i := range max(len(x), len(y)) {
					if c := compareSeg(seg(x, i), seg(y, i)); c != 0 {
						return types.Int(c)
					}
				}
				return types.IntZero
			})),
	)}
}

// segments strips one leading v and splits on . and -. An empty version,
// an empty segment or any whitespace is malformed.
func segments(s string) ([]string, bool) {
	if strings.ContainsFunc(s, unicode.IsSpace) {
		return nil, false
	}
	segs := strings.FieldsFunc(strings.TrimPrefix(s, "v"), func(r rune) bool { return r == '.' || r == '-' })
	if len(segs) == 0 || len(segs) != strings.Count(s, ".")+strings.Count(s, "-")+1 {
		return nil, false
	}
	return segs, true
}

// seg is segment i, or "0" past the end.
func seg(segs []string, i int) string {
	if i < len(segs) {
		return segs[i]
	}
	return "0"
}

// compareSeg compares two numeric segments numerically, at any length, and
// anything else byte-wise.
func compareSeg(a, b string) int {
	if numeric(a) && numeric(b) {
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		if len(a) != len(b) {
			if len(a) < len(b) {
				return -1
			}
			return 1
		}
	}
	return strings.Compare(a, b)
}

func numeric(s string) bool {
	return strings.Trim(s, "0123456789") == ""
}
