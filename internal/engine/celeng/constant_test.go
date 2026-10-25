package celeng

import (
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// TestCompileConstantDeny: a deny control with a condition that
// constant folding proves always true or always false is a load warning
// control_constant; it is never a load error, and a condition that is not
// provably constant is never flagged.
func TestCompileConstantDeny(t *testing.T) {
	const (
		sub   = "deny control expr has a condition that is always %s; check it for a vacuous test"
		whole = "deny control expr is always %s"
	)
	cases := []struct {
		name, expr string
		action     bundle.Action
		detail     string // "" is no warning
	}{
		// The prohibition is vacuous, every policy passes.
		{"grants_all and false", `iam.parse(resource.policy).statements.all(s, !(s.effect == "Allow" && (iam.grants_all(s, "kms") && false)))`, bundle.ActionDeny, detailf(sub, "false")},
		{"negated grants_all and false", `iam.parse(resource.policy).statements.all(s, !(iam.grants_all(s, "kms") && false))`, bundle.ActionDeny, detailf(sub, "false")},
		{"and false", `resource.policy != "" && false`, bundle.ActionDeny, detailf(whole, "false")},
		{"or true", `resource.policy == "" || true`, bundle.ActionDeny, detailf(whole, "true")},
		{"literal comparison", `resource.policy == "" && 1 == 2 || resource.policy == "x"`, bundle.ActionDeny, detailf(sub, "false")},
		{"empty list membership of a literal", `!("a" in [])`, bundle.ActionDeny, detailf(whole, "true")},
		{"literal true", `true`, bundle.ActionDeny, detailf(whole, "true")},
		{"warn control", `resource.policy != "" && false`, bundle.ActionWarn, ""},
		// Not provably constant: never flagged.
		{"plain", `resource.policy != ""`, bundle.ActionDeny, ""},
		{"exists true is non-empty", `resource.policy.exists(c, true)`, bundle.ActionDeny, ""},
		{"all false is empty", `!resource.policy.all(c, false)`, bundle.ActionDeny, ""},
		{"and true is the other side", `resource.policy != "" && true`, bundle.ActionDeny, ""},
		{"redundant constant operands", `resource.policy != "" && true && true && (1 == 1)`, bundle.ActionDeny, ""},
		{"or false is the other side", `resource.policy == "" || 1 == 2`, bundle.ActionDeny, ""},
		{"ternary literal branches", `op == "create" ? true : resource.policy != ""`, bundle.ActionDeny, ""},
		{"self comparison of data", `resource.policy == resource.policy`, bundle.ActionDeny, ""},
		// in does not absorb an error or unknown left side.
		{"empty list membership of data", `!(resource.policy in [])`, bundle.ActionDeny, ""},
		{"constant iam.parse is not folded", `iam.parse("{}").version == "" && resource.policy != ""`, bundle.ActionDeny, ""},
		// Comprehensions are never evaluated at load: no flag, no load cost.
		{"constant range is not evaluated", `[1].all(x, x > 0) && resource.policy != ""`, bundle.ActionDeny, ""},
		{"double literals are not compared", `1.0 == 2.0 || resource.policy != ""`, bundle.ActionDeny, ""},
		{"ternary on constant", `(1 == 1 ? false : true) || resource.policy != ""`, bundle.ActionDeny, detailf(sub, "true")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testControl(bundle.KindResource, bundle.PresenceEffective, tc.expr, "policy")
			c.Action = tc.action
			_, diags, err := Compile(c)
			if err != nil {
				t.Fatal(err)
			}
			var got string
			for _, d := range diags {
				if d.Code == "control_constant" {
					got = d.Detail
				}
			}
			if got != tc.detail {
				t.Fatalf("control_constant detail %q, want %q (diags %v)", got, tc.detail, diags)
			}
		})
	}
}
