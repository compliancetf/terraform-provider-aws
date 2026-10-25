package celeng

import (
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// TestPolarity is the control_iam_unconditional_polarity oracle:
// unconditional is read only as a
// conjunct with a *_all field of the same statement, in a position where the
// result can only rise with it; ambiguous is never read.
func TestPolarity(t *testing.T) {
	const st = `iam.parse(resource.policy).statements`
	const polarity = "control_iam_unconditional_polarity"
	for _, tc := range []struct{ name, expr, code string }{
		{"requirement: deny all principals unconditionally", st + `.exists(s, s.effect == "Deny" && s.principal_all && s.unconditional)`, ""},
		{"requirement under all and &&", st + `.size() > 0 && ` + st + `.all(s, s.effect == "Deny" && (s.action_all && s.unconditional))`, ""},
		{"prohibition without unconditional", st + `.all(s, !(s.effect == "Allow" && s.principal_any))`, ""},
		{"attribute named unconditional is data", `resource.policy != "unconditional"`, ""},
		{"negation", st + `.exists(s, s.principal_all && !s.unconditional)`, polarity},
		{"negated conjunction", st + `.all(s, !(s.principal_all && s.unconditional))`, polarity},
		{"negated comprehension", `!` + st + `.exists(s, s.principal_all && s.unconditional)`, polarity},
		{"or", st + `.exists(s, s.principal_all && (s.unconditional || s.effect == "Deny"))`, polarity},
		{"ternary", st + `.exists(s, s.principal_all && (s.unconditional ? true : false))`, polarity},
		{"comparison to false", st + `.exists(s, s.principal_all && s.unconditional == false)`, polarity},
		{"comparison to true", st + `.exists(s, s.principal_all && s.unconditional == true)`, polarity},
		{"alone", st + `.exists(s, s.unconditional)`, polarity},
		{"principal_any and unconditional", st + `.exists(s, s.principal_any && s.unconditional)`, polarity},
		{"all, any and unconditional", st + `.exists(s, s.principal_all && s.resource_any && s.unconditional)`, polarity},
		{"through map macro", st + `.map(s, s.principal_all && s.unconditional).exists(u, u)`, polarity},
		{"through filter macro", st + `.filter(s, s.principal_all && s.unconditional).size() == 0`, polarity},
		{"through exists_one", st + `.exists_one(s, s.principal_all && s.unconditional)`, polarity},
		{"through comprehension variable", st + `.exists(s, [s].exists(t, t.principal_all && t.unconditional))`, polarity},
		{"cross-statement", st + `[0].principal_all && ` + st + `[1].unconditional`, polarity},
		{"cross-statement variables", st + `.exists(s, ` + st + `.exists(r, s.principal_all && r.unconditional))`, polarity},
		{"indexed any in the chain", st + `.exists(s, s.principal_all && s["resource_any"] && s.unconditional)`, polarity},
		{"indexed all is not the conjunct", st + `.exists(s, s["principal_all"] && s.unconditional)`, polarity},
		{"shadowed by a non-statement range", st + `.exists(s, s.principal_all && [{"unconditional": true}].exists(s, s.unconditional))`, polarity},
		{"shadowed by another statements range", st + `.exists(s, s.principal_all && ` + st + `.exists(s, s.unconditional))`, polarity},
		{"computed key", `["principal_any"].all(k, ` + st + `.exists(s, s.action_all && s.unconditional && s[k]))`, polarity},
		{"aliased into a list", st + `.exists(s, s.action_all && s.unconditional && [s].all(t, t.principal_any))`, polarity},
		{"has is not the all conjunct", st + `.exists(s, has(s.principal_all) && s.unconditional)`, polarity},
		{"nested any in the chain", st + `.exists(s, s.action_all && s.unconditional && s.conditions.all(c, s.principal_any))`, polarity},
		{"grants beside the requirement", st + `.exists(s, s.effect == "Deny" && s.principal_all && s.unconditional && iam.grants(s, "s3:getobject"))`, ""},
		{"predicate negated", st + `.all(s, !s.unconditional)`, polarity},
		{"index read", st + `.exists(s, s.principal_all && s["unconditional"])`, polarity},
		{"has read", st + `.exists(s, s.principal_all && has(s.unconditional))`, polarity},
		{"ambiguous read", st + `.all(s, !("conditional" in s.ambiguous))`, polarity},
		{"ambiguous size", st + `.exists(s, size(s.ambiguous) == 0)`, polarity},
		{"ambiguous index", st + `.exists(s, s["ambiguous"].size() == 0)`, polarity},
		// Three deny controls that loaded and passed Allow *:*.
		{"computed key through indexed statements", `iam.parse(resource.policy)["statements"].all(s, !(s.effect == "Allow" && iam.grants_all(s, "kms") && s["un" + "conditional"] == false))`, polarity},
		{"computed key on an aliased statement", st + `.filter(s, true).all(t, !(t.effect == "Allow" && t["un" + "conditional"] == false))`, polarity},
		{"indexed statements requirement", `iam.parse(resource.policy)["statements"].exists(s, s.effect == "Deny" && s.principal_all && s.unconditional)`, ""},
		{"indexed statements negation", `iam.parse(resource.policy)["statements"].exists(s, s.principal_all && !s.unconditional)`, polarity},
		{"negated grants_all in a prohibition", st + `.all(s, !(s.effect == "Allow" && !iam.grants_all(s, "kms")))`, polarity},
		{"negated grants in a prohibition", st + `.all(s, !(s.effect == "Allow" && !["kms:decrypt"].exists(a, iam.grants(s, a))))`, polarity},
		{"grants compared to false", st + `.all(s, !(s.effect == "Allow" && iam.grants_all(s, "kms") == false))`, polarity},
		{"grants_all in a prohibition", st + `.all(s, !(s.effect == "Allow" && iam.grants_all(s, "kms")))`, ""},
		{"grants under exists in a prohibition", st + `.all(s, !(s.effect == "Allow" && s.resource_any && ["kms:decrypt", "kms:reencryptfrom"].exists(a, iam.grants(s, a))))`, ""},
		{"conditions size not zero", st + `.all(s, !(s.effect == "Allow" && s.action_any && s.resource_any && s.conditions.size() != 0))`, polarity},
		{"conditions size greater than zero", st + `.all(s, !(s.effect == "Allow" && s.action_any && size(s.conditions) > 0))`, polarity},
		{"conditions not empty list", st + `.all(s, !(s.effect == "Allow" && s.action_any && s.conditions != []))`, polarity},
		{"conditions through an index", st + `.all(s, !(s.effect == "Allow" && s.action_any && s["conditions"].size() != 0))`, polarity},
		{"conditions keyed exists in a prohibition", st + `.all(s, !(s.effect == "Allow" && !s.conditions.exists(c, c.key == "aws:sourcevpc")))`, ""},
		{"conditions exists without a key", st + `.all(s, !(s.effect == "Allow" && s.action_any && s.conditions.exists(c, true)))`, polarity},
		{"conditions all with a key", st + `.all(s, !(s.effect == "Allow" && s.action_any && !s.conditions.all(c, c.key == "k")))`, polarity},
		{"conditions keyed exists or anything", st + `.all(s, !(s.effect == "Allow" && s.action_any && s.conditions.exists(c, c.key == "k" || true)))`, polarity},
		// Candidate bypasses, all rejected.
		{"key computed by a list index", `iam.parse(resource.policy)["statements"].all(s, !(s.effect == "Allow" && iam.grants_all(s, "kms") && s[["unconditional"][0]] == false))`, polarity},
		{"unconditional not equal true", st + `.all(s, !(s.effect == "Allow" && iam.grants_all(s, "kms") && s.unconditional != true))`, polarity},
		{"grants under a ternary", st + `.all(s, !(s.effect == "Allow" && (iam.grants_all(s, "kms") ? false : true)))`, polarity},
		{"conditions size at least one", st + `.all(s, !(s.effect == "Allow" && s.action_any && s.conditions.size() >= 1))`, polarity},
		// A keyed conditions test reads only where the result rises with it.
		{"keyed exists unnegated in a prohibition", st + `.all(s, !(s.effect == "Allow" && s.conditions.exists(c, c.key == "aws:sourcevpc")))`, polarity},
		{"contradictory keyed exists unnegated in a prohibition", st + `.all(s, !(s.effect == "Allow" && s.conditions.exists(c, c.key == "aws:sourcevpc" && c.key == "aws:sourceip")))`, polarity},
		{"keyed exists under a negated exists", `!` + st + `.exists(s, s.effect == "Allow" && s.conditions.exists(c, c.key == "aws:sourcevpc"))`, polarity},
		{"keyed exists under || in a prohibition", st + `.all(s, !(s.effect == "Allow" && (s.conditions.exists(c, c.key == "k") || s.action_any)))`, polarity},
		{"keyed exists compared to true", st + `.all(s, !(s.effect == "Allow" && s.conditions.exists(c, c.key == "k") == true))`, polarity},
		{"keyed exists as a requirement", st + `.exists(s, s.effect == "Deny" && s.conditions.exists(c, c.key == "aws:sourcevpc"))`, ""},
		{"keyed exists missing under a negated exists", `!` + st + `.exists(s, s.effect == "Allow" && !s.conditions.exists(c, c.key == "aws:sourcevpc"))`, ""},
		{"contradictory keyed exists missing in a prohibition", st + `.all(s, !(s.effect == "Allow" && !s.conditions.exists(c, c.key == "aws:sourcevpc" && c.key == "aws:sourceip")))`, ""},
		// cel.bind is not in the env, so a let never loads.
		{"let", `cel.bind(u, ` + st + `[0].unconditional, u)`, "control_expr"},
		// Optional types are not in the env either: no s.?unconditional route.
		{"optional select", st + `.exists(s, s.principal_all && s.?unconditional.orValue(false))`, "control_expr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := *testControl(bundle.KindResource, bundle.PresenceEffective, tc.expr, "policy")
			_, _, err := Compile(&c)
			if got := diagCode(err); got != tc.code {
				t.Fatalf("got %q (%v), want %q", got, err, tc.code)
			}
			if err != nil && tc.code == polarity && !strings.Contains(err.Error(), "unconditional") && !strings.Contains(err.Error(), "ambiguous") {
				t.Fatalf("detail does not name the field: %v", err)
			}
		})
	}
}

// TestIdentityDirect is the control_iam_identity_direct oracle:
// principals and resources are compared only through iam.principal_is /
// iam.resource_is, never read from the statement.
func TestIdentityDirect(t *testing.T) {
	const st = `iam.parse(resource.policy).statements`
	const direct = "control_iam_identity_direct"
	for _, tc := range []struct{ name, expr, code string }{
		{"principal_is", st + `.all(s, !(s.effect == "Allow" && iam.principal_is(s, "arn:aws:iam::222222222222:root")))`, ""},
		{"principals_in_account", st + `.all(s, !(s.effect == "Allow" && !iam.principals_in_account(s, provider.account_id, provider.partition)))`, ""},
		{"resource_is", st + `.all(s, !(s.principal_any && iam.resource_is(s, "arn:aws:s3:::bobthecorp-logs")))`, ""},
		{"principals select", st + `.all(s, !("arn:aws:iam::222222222222:root" in s.principals.aws))`, direct},
		{"not_principals select", st + `.all(s, size(s.not_principals) == 0)`, direct},
		{"resources select", st + `.all(s, !("*" in s.resources))`, direct},
		{"not_resources index", st + `.all(s, size(s["not_resources"]) == 0)`, direct},
		{"unresolved_principals", st + `.all(s, size(s.unresolved_principals) == 0)`, direct},
		{"unresolved_resources has", st + `.all(s, !has(s.unresolved_resources))`, direct},
		{"indexed statement", st + `[0].resources.size() == 0`, direct},
		{"indexed statement index", st + `[0]["principals"].size() == 0`, direct},
		{"through map macro", st + `.map(s, s.resources).all(r, size(r) == 0)`, direct},
		{"string-keyed statements", `iam.parse(resource.policy)["statements"].all(s, !("arn:aws:s3:::x/y" in s.resources))`, direct},
		{"computed key", st + `[0]["res" + "ources"].size() == 0`, direct},
		{"whole statement compared", `iam.parse(resource.policy)["statements"].all(s, s != iam.parse("{}").statements[0])`, "control_iam_unconditional_polarity"},
		{"through filter then all", st + `.filter(s, s.effect == "Allow").all(t, !("x" in t.principals.aws))`, "control_iam_unconditional_polarity"},
		{"filter then index", st + `.filter(s, s.effect == "Allow")[0].principals.aws.size() == 0`, "control_iam_unconditional_polarity"},
		{"statement aliased into helper", st + `.all(s, iam.principal_is([s][0], "arn:aws:iam::222222222222:root"))`, "control_iam_unconditional_polarity"},
		{"attribute named resources is data", `resource.policy != "resources"`, ""},
		// format renders a parse result as text, principals and resources
		// included: a substring test would read identities directly.
		{"formatted policy", `!"%s".format([iam.parse(resource.policy)]).contains("arn:aws:iam::222222222222:root")`, direct},
		{"formatted statement", `!"%s".format([` + st + `[0]]).contains("bobthecorp")`, direct},
		{"format beside parse", st + `.all(s, s.effect == "Deny") && "%s".format([resource.policy]) != ""`, direct},
		{"format without parse", `"%s".format([resource.policy]) != ""`, ""},
		// Whole-statement equality and membership would compare identities
		// too; reads analysis rejects them.
		{"statement equality", st + `[0] != {"effect": "Allow"}`, "control_dynamic_access"},
		{"statement membership", `!({"effect": "Allow"} in ` + st + `)`, "control_dynamic_access"},
		{"aliased through a list", `[iam.parse(resource.policy)].all(p, p.statements[0] != {"effect": "Allow"})`, "control_dynamic_access"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := *testControl(bundle.KindResource, bundle.PresenceEffective, tc.expr, "policy")
			_, _, err := Compile(&c)
			if got := diagCode(err); got != tc.code {
				t.Fatalf("got %q (%v), want %q", got, err, tc.code)
			}
		})
	}
}
