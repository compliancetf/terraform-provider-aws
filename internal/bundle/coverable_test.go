package bundle

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// TestCoverableConflict: controls sharing an id must declare the same
// exemption_coverable list across every bundle, kind and resource type
// (control_coverable_conflict); Coverable lists every loaded id.
func TestCoverableConflict(t *testing.T) {
	a := goodBundle(t)
	id := a.Controls[0].ID
	mk := func(kinds ...ExemptionKind) Control {
		c := a.Controls[0]
		c.ResourceType, c.ExemptionCoverable = "aws_rds_cluster", append([]ExemptionKind{}, kinds...)
		return c
	}
	same := second(t, "bobthecorp-extra", sha("same"), []Control{mk(a.Controls[0].ExemptionCoverable...)})
	set, _, err := NewControlSet("bobthecorp", now, trust.NoRevocations(), a, same)
	if err != nil {
		t.Fatal(err)
	}
	cov := set.Coverable()
	if !slices.Equal(cov[id], a.Controls[0].ExemptionCoverable) || len(cov) == 0 {
		t.Fatalf("Coverable: %v", cov)
	}
	if len(cov[id]) == 0 {
		t.Fatal("fixture control declares no coverable kind")
	}
	want := slices.Clone(cov[id])
	cov[id][0] = "mutated" // a deep copy: the set is unchanged
	if !slices.Equal(set.Coverable()[id], want) {
		t.Fatal("Coverable not cloned")
	}
	other := []ExemptionKind{CoverBaseline, CoverGrant}
	if slices.Equal(other, a.Controls[0].ExemptionCoverable) {
		other = []ExemptionKind{}
	}
	diff := second(t, "bobthecorp-extra", sha("diff"), []Control{mk(other...)})
	if _, _, err := NewControlSet("bobthecorp", now, trust.NoRevocations(), a, diff); err == nil || !strings.Contains(err.Error(), "control_coverable_conflict") {
		t.Fatalf("conflict: %v", err)
	}
}

// TestCoverableLoadErrors: a boolean exemption_coverable and an unknown kind
// are load errors.
func TestCoverableLoadErrors(t *testing.T) {
	for _, name := range []string{"coverable_bool", "coverable_unknown_kind"} {
		data, err := os.ReadFile(filepath.Join(fixtures, "invalid", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseControls(data); err == nil || !strings.Contains(err.Error(), "control_coverable") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
