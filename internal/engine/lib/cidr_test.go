package lib

import (
	"errors"
	"strings"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
)

// helperCase is one row of the helper tables: expr evaluates to want, or
// fails with err: a sentinel of this package, matched by identity, or
// errNoOverload, cel-go's runtime type guard, which celeng maps to type_error.
type helperCase struct {
	expr string
	want any
	err  error
}

var errNoOverload = errors.New("no such overload")

// runHelperCases evaluates each row in an env with only the helpers and a
// dyn variable v (data variables are dyn in celeng).
func runHelperCases(t *testing.T, v any, cases []helperCase) {
	t.Helper()
	env, err := cel.NewEnv(Helpers(), JSON(), cel.Variable("v", cel.DynType))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			a, iss := env.Compile(tc.expr)
			if iss.Err() != nil {
				t.Fatal(iss.Err())
			}
			prg, err := env.Program(a)
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := prg.Eval(map[string]any{"v": v, DeadlineVar: time.Now().Add(time.Minute)}) // json.path admits nothing without one
			if tc.err == errNoOverload {
				if err == nil || !strings.HasPrefix(err.Error(), "no such overload") {
					t.Fatalf("got %v, %v; want a no such overload error", got, err)
				}
				return
			}
			if tc.err != nil {
				if err == nil || !errors.Is(err, tc.err) {
					t.Fatalf("got %v, %v; want error %v", got, err, tc.err)
				}
				// value-free: the error carries the class only, never the input
				if s := err.Error(); s != tc.err.Error() {
					t.Fatalf("error text %q carries more than the class %q", s, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}
			if got.Equal(types.DefaultTypeAdapter.NativeToValue(tc.want)) != types.True {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCIDR(t *testing.T) {
	runHelperCases(t, nil, []helperCase{
		// contains: an address or prefix inside a prefix
		{`cidr.contains("10.0.0.0/8", "10.1.2.3")`, true, nil},
		{`cidr.contains("10.0.0.0/8", "10.1.0.0/16")`, true, nil},
		{`cidr.contains("10.0.0.0/8", "10.0.0.0/8")`, true, nil},
		{`cidr.contains("10.0.0.0/8", "11.0.0.1")`, false, nil},
		{`cidr.contains("10.1.0.0/16", "10.0.0.0/8")`, false, nil},
		{`cidr.contains("0.0.0.0/0", "192.0.2.1")`, true, nil},
		{`cidr.contains("2001:db8::/32", "2001:db8:1::/48")`, true, nil},
		{`cidr.contains("2001:db8::/32", "2001:db9::1")`, false, nil},
		// families never match
		{`cidr.contains("::/0", "10.0.0.1")`, false, nil},
		{`cidr.contains("0.0.0.0/0", "2001:db8::1")`, false, nil},
		// IPv4-mapped IPv6 is unmapped first
		{`cidr.contains("10.0.0.0/8", "::ffff:10.1.2.3")`, true, nil},
		{`cidr.contains("::ffff:10.0.0.0/104", "10.1.2.3")`, true, nil},
		{`cidr.contains("0.0.0.0/0", "::ffff:0.0.0.0/96")`, true, nil},
		{`cidr.contains("::ffff:0.0.0.0/96", "0.0.0.0/0")`, true, nil},
		{`cidr.contains("::/0", "::ffff:10.1.2.3")`, false, nil},
		{`cidr.contains("::/0", "::ffff:0.0.0.0/80")`, true, nil}, // shorter than /96 stays IPv6
		// prefixes with host bits set are masked
		{`cidr.contains("10.1.2.3/8", "10.200.0.0/16")`, true, nil},
		{`cidr.contains("10.0.0.0/8", "10.1.2.3/0")`, false, nil},
		{`cidr.contains("10.0.0.1/0", "192.0.2.0/24")`, true, nil},
		// invalid input
		{`cidr.contains("10.0.0.1", "10.0.0.1")`, nil, ErrInvalid}, // outer must be a prefix
		{`cidr.contains("", "10.0.0.1")`, nil, ErrInvalid},
		{`cidr.contains("10.0.0.0/8", "")`, nil, ErrInvalid},
		{`cidr.contains("10.0.0.0/33", "10.0.0.1")`, nil, ErrInvalid},
		{`cidr.contains("10.0.0.0/8", "10.0.0.256")`, nil, ErrInvalid},
		{`cidr.contains("10.0.0.0/8", "not-an-ip")`, nil, ErrInvalid},
		{`cidr.contains("fe80::/10", "fe80::1%eth0")`, nil, ErrInvalid}, // zones never match a prefix
		{`cidr.contains("fe80::1%eth0/10", "fe80::1")`, nil, ErrInvalid},
		{`cidr.contains(" 10.0.0.0/8", "10.0.0.1")`, nil, ErrInvalid},
		// overlaps
		{`cidr.overlaps("10.0.0.0/8", "10.1.0.0/16")`, true, nil},
		{`cidr.overlaps("10.1.0.0/16", "10.0.0.0/8")`, true, nil},
		{`cidr.overlaps("10.0.0.0/16", "10.1.0.0/16")`, false, nil},
		{`cidr.overlaps("0.0.0.0/0", "192.0.2.0/24")`, true, nil},
		{`cidr.overlaps("::/0", "0.0.0.0/0")`, false, nil},
		{`cidr.overlaps("::ffff:10.0.0.0/104", "10.200.0.0/16")`, true, nil},
		{`cidr.overlaps("10.1.2.3/8", "10.200.0.0/16")`, true, nil},
		{`cidr.overlaps("10.0.0.0/8", "10.0.0.5")`, nil, ErrInvalid}, // both must be prefixes
		{`cidr.overlaps("10.0.0.0/8", "bogus")`, nil, ErrInvalid},
		{`cidr.overlaps("", "10.0.0.0/8")`, nil, ErrInvalid},
	})
}
