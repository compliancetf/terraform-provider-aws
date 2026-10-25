package exceptions

import (
	"path/filepath"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// TestWaivable: diagnostics offer the waive hint only for a control an
// entry in this sidecar could waive, so every entry-independent check of
// add must hold; each failing one turns it off.
func TestWaivable(t *testing.T) {
	path := filepath.Join("testdata", "applied.hcl")
	for name, tc := range map[string]struct {
		edit func(*SidecarInput)
		want bool
	}{
		"all_hold":            {func(*SidecarInput) {}, true},
		"not_self_service":    {func(in *SidecarInput) { in.Table.SidecarControls = []string{"other_control"} }, false},
		"not_coverable":       {func(in *SidecarInput) { in.Coverable = Coverability{} }, false},
		"no_lifetime":         {func(in *SidecarInput) { in.Table.Exceptions = &profile.Exceptions{SelfService: []string{rdsEnc}} }, false},
		"no_exceptions":       {func(in *SidecarInput) { in.Table.Exceptions = nil }, false},
		"untrusted_workspace": {func(in *SidecarInput) { in.Table.Workspace = profile.Dim{} }, false},
		"unknown_clock":       {func(in *SidecarInput) { in.Clock = Clock{why: "no floor timestamp"} }, false},
	} {
		t.Run(name, func(t *testing.T) {
			in := scopeInput()
			in.Coverable, _ = NewCoverability(map[string][]bundle.ExemptionKind{rdsEnc: {bundle.CoverSelfService}}, in.Table.Exceptions)
			tc.edit(&in)
			sc, _, err := LoadSidecar(path, in)
			if err != nil {
				t.Fatal(err)
			}
			if got := sc.Waivable(rdsEnc); got != tc.want {
				t.Errorf("Waivable(%s) = %v, want %v", rdsEnc, got, tc.want)
			}
		})
	}
	if (*Sidecar)(nil).Waivable(rdsEnc) {
		t.Error("a nil sidecar waives nothing")
	}
}
