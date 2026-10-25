package celeng

import (
	"slices"
	"testing"
)

// TestIAMCatalogRefs: literal arguments and comprehension variables over a
// literal list are listed; a computed argument is not.
func TestIAMCatalogRefs(t *testing.T) {
	for _, c := range []struct {
		expr              string
		actions, services []string
	}{
		{`iam.parse(resource.policy).statements.all(s, !(s.effect == "Allow" && iam.grants_all(s, "kms")))`, nil, []string{"kms"}},
		{`iam.parse(resource.policy).statements.all(s, !["kms:Decrypt", "kms:reencryptfrom"].exists(a, iam.grants(s, a)) && !iam.grants(s, "s3:GetObject"))`,
			[]string{"kms:Decrypt", "kms:reencryptfrom", "s3:GetObject"}, nil},
		// An inner comprehension that rebinds a hides the outer binding; the
		// root-qualified .a is not the comprehension variable.
		{`iam.parse(resource.policy).statements.all(s, ["kms:Decrypt"].exists(a, [resource.x].exists(a, iam.grants(s, a))))`, nil, nil},
		{`iam.parse(resource.policy).statements.all(s, ["kms:Decrypt"].exists(a, iam.grants(s, .a)))`, nil, nil},
		{`iam.parse(resource.policy).statements.all(s, ["kms:Decrypt"].exists(a, [resource.x].exists(b, iam.grants(s, a))))`, []string{"kms:Decrypt"}, nil},
		// A two-variable exists (not a macro in this env) and concatenation
		// are not extracted.
		{`iam.parse(resource.policy).statements.all(s, ["kms:Decrypt"].exists(i, a, iam.grants(s, a)))`, nil, nil},
		{`iam.parse(resource.policy).statements.all(s, iam.grants(s, "kms:" + "decrypt"))`, nil, nil},
		{`iam.parse(resource.policy).statements.all(s, !iam.grants(s, resource.action) && ![resource.action].exists(a, iam.grants(s, a)))`, nil, nil},
		{`resource.name == "x"`, nil, nil},
	} {
		actions, services, err := IAMCatalogRefs(c.expr)
		if err != nil || !slices.Equal(actions, c.actions) || !slices.Equal(services, c.services) {
			t.Errorf("%s: %v %v (%v), want %v %v", c.expr, actions, services, err, c.actions, c.services)
		}
	}
	if _, _, err := IAMCatalogRefs(`iam.grants(`); err == nil {
		t.Error("a parse error is not reported")
	}
}
