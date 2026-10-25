package celeng

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

// TestPolarityAllowAll: a deny control the polarity lint loads fails on
// Allow *:*; one that would pass it does not load. A control
// that is vacuous by construction (true, or a conjunct that is always false)
// is out of the lint's reach: it does not read an under-approximated field.
func TestPolarityAllowAll(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/iam/actions-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := iampolicy.LoadCatalog(raw)
	if err != nil {
		t.Fatal(err)
	}
	const st = `iam.parse(resource.kms_key_id).statements`
	for _, tc := range []struct{ name, expr, want string }{
		{"keyed exists unnegated in a prohibition", st + `.all(s, !(s.effect == "Allow" && s.conditions.exists(c, c.key == "aws:sourcevpc")))`, "rejected"},
		{"contradictory keyed exists unnegated", st + `.all(s, !(s.effect == "Allow" && s.conditions.exists(c, c.key == "aws:sourcevpc" && c.key == "aws:sourceip")))`, "rejected"},
		{"keyed exists missing in a prohibition", st + `.all(s, !(s.effect == "Allow" && !s.conditions.exists(c, c.key == "aws:sourcevpc")))`, "probe=fail/"},
		{"contradictory keyed exists missing", st + `.all(s, !(s.effect == "Allow" && !s.conditions.exists(c, c.key == "aws:sourcevpc" && c.key == "aws:sourceip")))`, "probe=fail/"},
		{"keyed exists missing, always-false key test", st + `.all(s, !(s.effect == "Allow" && !s.conditions.exists(c, c.key == "aws:sourcevpc" && false)))`, "probe=fail/"},
		{"keyed exists as a requirement", st + `.exists(s, s.effect == "Deny" && s.conditions.exists(c, c.key == "aws:sourcevpc"))`, "probe=fail/"},
		// Only keyed exists reaches conditions.
		{"conditions all under ||", st + `.all(s, s.effect != "Allow" || s.conditions.all(c, c.key != "aws:sourcevpc"))`, "rejected"},
		{"conditions all negated in a prohibition", st + `.all(s, !(s.effect == "Allow" && !s.conditions.all(c, c.key != "aws:sourcevpc")))`, "rejected"},
		{"conditions all double negated", `!` + st + `.exists(s, s.effect == "Allow" && !s.conditions.all(c, c.key != "aws:sourcevpc"))`, "rejected"},
		{"conditions exists_one", st + `.all(s, !(s.effect == "Allow" && !s.conditions.exists_one(c, c.key == "aws:sourcevpc")))`, "rejected"},
		{"conditions size", st + `.all(s, !(s.effect == "Allow" && s.conditions.size() > 0))`, "rejected"},
		{"conditions empty", st + `.all(s, s.effect != "Allow" || s.conditions == [])`, "rejected"},
		{"conditions has", st + `.all(s, !(s.effect == "Allow" && has(s.conditions)))`, "rejected"},
		{"conditions keyed exists with a negated key test", st + `.all(s, !(s.effect == "Allow" && !s.conditions.exists(c, c.key == "aws:sourcevpc" && !(c.key == "aws:sourcevpc"))))`, "probe=fail/"},
		// Aliases and parity wrappers.
		{"keyed exists on a list alias", st + `.all(s, [s].all(t, !(t.effect == "Allow" && t.conditions.exists(c, c.key == "aws:sourcevpc"))))`, "rejected"},
		{"keyed exists on a filter alias", st + `.filter(s, true).all(t, !(t.effect == "Allow" && t.conditions.exists(c, c.key == "aws:sourcevpc")))`, "rejected"},
		{"keyed exists double negated in a prohibition", st + `.all(s, !(s.effect == "Allow" && !!s.conditions.exists(c, c.key == "aws:sourcevpc")))`, "rejected"},
		{"keyed exists compared to false", st + `.all(s, !(s.effect == "Allow" && s.conditions.exists(c, c.key == "aws:sourcevpc") == false))`, "rejected"},
		// lintGrants' default branch skipped conditions comprehensions.
		{"keyed exists in a prohibition inside a list", `[` + st + `.all(s, !(s.effect == "Allow" && s.conditions.exists(c, c.key == "k")))][0]`, "rejected"},
		{"keyed exists in a prohibition inside a map", `{"a": ` + st + `.all(s, !(s.effect == "Allow" && s.conditions.exists(c, c.key == "k")))}["a"]`, "rejected"},
		{"keyed exists missing inside a list", `[` + st + `.all(s, !(s.effect == "Allow" && !s.conditions.exists(c, c.key == "k")))][0]`, "rejected"},
		// Candidate wrappers, all rejected.
		{"conditions size inside a list", `[` + st + `.all(s, !(s.effect == "Allow" && size(s.conditions) > 0))][0]`, "rejected"},
		{"conditions not empty inside a list", `[` + st + `.all(s, !(s.effect == "Allow" && s.conditions != []))][0]`, "rejected"},
		{"conditions range through a list index", `[` + st + `.all(s, !(s.effect == "Allow" && [s.conditions][0].exists(c, c.key == "k")))][0]`, "rejected"},
		{"unconditional inside a list", `[` + st + `.all(s, !(s.effect == "Allow" && s.unconditional))][0]`, "rejected"},
		{"grants_all inside a list", `[` + st + `.all(s, !(s.effect == "Allow" && !iam.grants_all(s, "kms")))][0]`, "rejected"},
		{"keyed exists through a map", `{true: ` + st + `.all(s, !(s.effect == "Allow" && s.conditions.exists(c, c.key == "k")))}[true]`, "rejected"},
		{"keyed exists through a list all", `[` + st + `.all(s, !(s.effect == "Allow" && s.conditions.exists(c, c.key == "k")))].all(x, x)`, "rejected"},
		{"negated unconditional beside an all field", st + `.exists(s, s.principal_all && !s.unconditional)`, "rejected"},
		{"unconditional compared to false", st + `.exists(s, s.principal_all && s.unconditional == false)`, "rejected"},
		{"negated keyed exists in a requirement", st + `.exists(s, s.action_all && !s.conditions.exists(c, c.key == "k"))`, "rejected"},
		{"conditions size zero beside an all field", st + `.exists(s, s.action_all && size(s.conditions) == 0)`, "rejected"},
		{"negated conjunction with unconditional", st + `.all(s, !(s.principal_all && s.unconditional))`, "rejected"},
		{"unconditional under a ternary", st + `.exists(s, s.principal_all && (s.unconditional ? false : true))`, "rejected"},
		{"unconditional reversed comparison", st + `.exists(s, s.principal_all && false == s.unconditional)`, "rejected"},
		{"unconditional not equal true", st + `.exists(s, s.principal_all && s.unconditional != true)`, "rejected"},
		{"unconditional in a list", st + `.exists(s, s.principal_all && s.unconditional in [false])`, "rejected"},
		{"unconditional as a map key", st + `.exists(s, s.principal_all && {true: false, false: true}[s.unconditional])`, "rejected"},
		{"conditions size below one", st + `.exists(s, s.action_all && size(s.conditions) < 1)`, "rejected"},
		{"conditions all keyed", st + `.exists(s, s.action_all && s.conditions.all(c, c.key == "k"))`, "rejected"},
		{"grants_all in a prohibition", st + `.all(s, !(s.effect == "Allow" && iam.grants_all(s, "kms")))`, "probe=fail/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := "rejected"
			comp, _, err := New(Options{PerResourceBudget: time.Second}).Load([]bundle.Control{dbControl("probe", tc.expr, "kms_key_id")},
				awsSubset(t), Content{Digest: "sha256:probe", IAMCatalog: cat})
			if err == nil {
				b := dbBindings(t, `{"kms_key_id": "{\"Statement\":{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}}"}`)
				got = states(comp.Evaluate(context.Background(), b, nil))
			} else if diagCode(err) != "control_iam_unconditional_polarity" {
				t.Fatalf("load: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Allow *:*: got %s, want %s", got, tc.want)
			}
		})
	}
}
