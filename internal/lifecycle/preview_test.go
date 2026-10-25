package lifecycle

import (
	"slices"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// TestPreviewWarnings: verdict_required warns preview until the GA
// flag is set; without it, or with no profile, nothing is said. This build
// ships with the flag off.
func TestPreviewWarnings(t *testing.T) {
	req := &profile.Profile{VerdictRequired: true}
	for _, c := range []struct {
		p    *profile.Profile
		ga   bool
		want []string
	}{
		{nil, false, nil},
		{&profile.Profile{}, false, nil},
		{req, false, []string{PreviewVerdictRequired}},
		{req, true, nil},
	} {
		if got := previewWarnings(c.p, c.ga); !slices.Equal(got, c.want) {
			t.Errorf("%+v ga %v: %q, want %q", c.p, c.ga, got, c.want)
		}
	}
	if verdictRequiredGA {
		t.Error("verdict_required GA flag is on before the GA checklist")
	}
}
