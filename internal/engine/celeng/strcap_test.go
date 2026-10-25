package celeng

import (
	"runtime"
	"strings"
	"testing"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
)

// TestStringExpansionCap: replace, join and format refuse an output over
// maxStringBytes before building it (limit), and keep ext.Strings semantics
// below the cap. "big" is a 900,000-byte string built by three replaces,
// under the default cost limit. No cost limit here: the cap alone must
// reject, and the heap must not grow by the refused output.
func TestStringExpansionCap(t *testing.T) {
	a100 := `"` + strings.Repeat("a", 100) + `"`
	a90 := `"` + strings.Repeat("a", 90) + `"`
	big := `"a".replace("a", ` + a100 + `).replace("a", ` + a100 + `).replace("a", ` + a90 + `)`
	// A chain where a fourth replace by 3000 "a"s would
	// build ~3 GB.
	chain := big + `.replace("a", "` + strings.Repeat("a", 3000) + `")`
	a60 := `"` + strings.Repeat("a", 60) + `"`
	mid := `"a".replace("a", ` + a100 + `).replace("a", ` + a100 + `).replace("a", ` + a60 + `)` // 600,000 bytes
	ints := "[" + strings.Repeat("1234, ", 2999) + "1234]"
	list := func(n int) string { return "[" + strings.Repeat("0, ", n-1) + "0]" }
	l5000, l5001, l10001 := list(5000), list(5001), list(10001)

	cases := []struct {
		name, expr string
		want       string // "true" or the error class
	}{
		{"replace under cap", `"abcb".replace("b", "xx") == "axxcxx" && "abcb".replace("b", "x", 1) == "axcb"`, "true"},
		{"replace big under cap", `size(` + big + `) == 900000`, "true"},
		{"replace over cap", `size(` + big + `.replace("a", "aa")) > 0`, "limit"},
		{"replaceN over cap", `size(` + big + `.replace("a", "aa", -1)) > 0`, "limit"},
		{"replaceN bounded by n", `size("a".replace("a", ` + a100 + `).replace("a", ` + a100 + `).replace("a", "aa", 10)) == 10010`, "true"},
		{"replace chain", `size(` + chain + `) > 0`, "limit"},
		{"join under cap", `["a", "b"].join("-") == "a-b" && ["a", "b"].join() == "ab"`, "true"},
		{"join over cap", `size([` + big + `, ` + big + `].join()) > 0`, "limit"},
		{"format under cap", `"%d-%s".format([1, "x"]) == "1-x"`, "true"},
		{"format over cap", `size("%s%s".format([` + big + `, ` + big + `])) > 0`, "limit"},
		{"format string near cap", `size("%s".format([` + big + `])) == 900000`, "true"},
		{"format hex over cap", `size("%x".format([` + big + `])) > 0`, "limit"},
		{"format list over cap", `size("%s".format([[` + big + `, ` + big + `]])) > 0`, "limit"},
		// only a %x / %X verb doubles strings; scalars count by type.
		{"format literal x is not hex", `size("x=%s".format([` + mid + `])) == 600002`, "true"},
		{"format escaped %%x is not hex", `size("%%x %s".format([` + mid + `])) == 600003`, "true"},
		{"format hex with precision", `size("%.2x".format([` + mid + `])) > 0`, "limit"},
		{"format upper hex", `size("%X".format([` + mid + `])) > 0`, "limit"},
		// Format V2 has no width and caps precision at 100.
		{"format width is not a clause", `("%" + "1000000s").format(["a"]) == "a"`, "limit"},
		{"format precision over 100", `("%" + ".1000000f").format([1.5]) == ""`, "limit"},
		{"format trailing percent", `("a" + "%").format(["x"]) == "a"`, "limit"},
		{"format precision without digits", `("%" + ".x").format(["x"]) == ""`, "limit"},
		{"format precision 101", `("%" + ".101f").format([1.5]) == ""`, "limit"},
		{"format width 5", `("%" + "5s").format(["a"]) == "a"`, "limit"},
		{"format zero-padded width", `("%" + "05.2f").format([1.5]) == ""`, "limit"},
		{"format hex of non-ASCII is 2 per byte", `"%x".format(["é"]) == "c3a9"`, "true"},
		{"format integer verbs", `"%d %b %o %x %X %b".format([-255, 5, 8, 255, 255, true]) == "-255 101 10 ff FF 1"`, "true"},
		{"format precision on a string ignored", `("%" + ".100s").format(["a"]) == "a"`, "true"},
		{"format max precision double", `("%" + ".100f").format([-1.7976931348623157e308]).size() == 411`, "true"},
		{"format %v refused", `("%" + "v").format(["a"]) == "a"`, "limit"},
		{"format %g refused", `("%" + "g").format([1.5]) == "1.5"`, "limit"},
		{"format %c refused", `("%" + "c").format([65]) == "A"`, "limit"},
		{"format unknown verb refused", `("%" + "q").format(["a"]) == "a"`, "limit"}, // a literal template is checked at compile time
		{"format 3000 ints", `size("%s".format([` + ints + `])) == 18000`, "true"},
		{"format int fixed precision", `"%.100f".format([-9223372036854775807]).size() == 121`, "true"},
		// string and bytes + refuse an output over the cap.
		{"concat under cap", `size(` + big + ` + "b") == 900001 && "a" + "b" == "ab"`, "true"},
		{"concat over cap", `size(` + big + ` + ` + big + `) > 0`, "limit"},
		{"dyn concat over cap", `size(dyn(` + big + `) + dyn(` + big + `)) > 0`, "limit"},
		{"concat in a comprehension", `[1, 2].all(i, size(` + big + ` + ` + big + `) > i)`, "limit"},
		{"other + unchanged", `1 + 2 == 3 && [1] + [2] == [1, 2] && 1.5 + 1.0 == 2.5`, "true"},
		{"+ type mismatch", `dyn(1) + dyn("a") == 1`, "type_error"},
		{"bytes concat under cap", `b"a" + b"b" == b"ab"`, "true"},
		{"bytes concat over cap", `size(bytes(` + big + `) + bytes(` + big + `)) > 0`, "limit"},
		// list + refuses a result over maxListElements; map and
		// filter build their results with + and share the cap.
		{"list concat at cap", `size(` + l5000 + ` + ` + l5000 + `) == 10000`, "true"},
		{"list concat over cap", `size(` + l5000 + ` + ` + l5000 + ` + [1]) > 0`, "limit"},
		{"dyn list concat over cap", `size(dyn(` + l5000 + `) + dyn(` + l5001 + `)) > 0`, "limit"},
		{"list concat in a comprehension", `[1, 2].all(i, size(` + l5000 + ` + ` + l5001 + `) > i)`, "limit"},
		{"map at cap", `size((` + l5000 + ` + ` + l5000 + `).map(x, x)) == 10000`, "true"},
		{"map over cap", `size(` + l10001 + `.map(x, x)) > 0`, "limit"},
		{"filter over cap", `size(` + l10001 + `.filter(x, true)) > 0`, "limit"},
		{"filter result under cap", `size(` + l10001 + `.filter(x, x == 1)) == 0`, "true"},
		{"all over a large list", `` + l10001 + `.all(x, x >= 0)`, "true"},
		{"map + unsupported", `dyn({"a": 1}) + dyn({"b": 2}) == {}`, "type_error"},
	}
	env, err := newEnv()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, iss := env.Compile(tc.expr)
			if iss.Err() != nil {
				t.Fatal(iss.Err())
			}
			prg, err := env.Program(a, cel.CostTracking(nil))
			if err != nil {
				t.Fatal(err)
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			val, _, err := prg.Eval(map[string]any{})
			runtime.ReadMemStats(&after)
			if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
				t.Fatalf("allocated %d bytes", grew)
			}
			got := ""
			switch {
			case err != nil:
				got = string(errClass(err))
			case val.Value() == true:
				got = "true"
			default:
				got = val.Type().TypeName()
			}
			if got != tc.want {
				t.Fatalf("got %s (err %v), want %s", got, err, tc.want)
			}
		})
	}
}

// TestAddCostTracked: the capped + still reaches the cost tracker; a
// concatenation is charged by its operand sizes.
func TestAddCostTracked(t *testing.T) {
	env, err := newEnv()
	if err != nil {
		t.Fatal(err)
	}
	a100 := `"` + strings.Repeat("a", 100) + `"`
	s := `"a".replace("a", ` + a100 + `).replace("a", ` + a100 + `)` // 10,000 bytes
	cost := func(expr string) uint64 {
		a, iss := env.Compile(expr)
		if iss.Err() != nil {
			t.Fatal(iss.Err())
		}
		prg, err := env.Program(a, cel.CostTracking(nil))
		if err != nil {
			t.Fatal(err)
		}
		_, det, err := prg.Eval(map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		return *det.ActualCost()
	}
	if plain, cat := cost(`size(`+s+`) > 0`), cost(`size(`+s+` + `+s+`) > 0`); cat < 2*plain+1000 { // two builds, then 20,000 bytes concatenated at 0.1 per byte
		t.Fatalf("cost of + not charged: %d vs %d", cat, plain)
	}
}

// TestFmtFactor pins the template scan the format precheck relies on.
func TestFmtFactor(t *testing.T) {
	for tmpl, want := range map[string]int{
		"x=%s": 1, "%%x %s": 1, "%x": 2, "%.2X": 2, "%s %d %f %e %b %o": 1,
		"%s%x": 2, "%": 0, "%.": 0, "%.3": 0, "%.x": 0, "%.101x": 0, "%.999999999x": 0, "%.100f": 1, "%.0s": 1, "%%": 1, "%q": 0, "%5s": 0, "%-s": 0, "%*s": 0, "%.3v": 0,
	} {
		k, ok := fmtFactor(tmpl)
		if !ok {
			k = 0
		}
		if k != want {
			t.Errorf("fmtFactor(%q) = %d, want %d", tmpl, k, want)
		}
	}
	n := 0
	if !fmtFits(types.Int(1), &n, 1) || n != 128 {
		t.Fatalf("int bound %d, want 128", n)
	}
}
