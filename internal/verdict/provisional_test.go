package verdict

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

const provisionalControl = "s3_bucket_versioning_enabled"

// provisionalCase is one plan eligibility fixture: the compliance.tf-signed
// inputs (bundle list, profile exceptions, floor mode, mode, break-glass
// enablement, the profile self_service listing) and whether
// exception_grants_dir is set. No exemption artifact is an input.
type provisionalCase struct {
	Bundle      []bundle.ExemptionKind `json:"bundle"`
	Profile     *profile.Exceptions    `json:"profile"`
	FloorMode   string                 `json:"floor_mode"`
	Grandfather bool                   `json:"grandfather"`
	BreakGlass  bool                   `json:"break_glass"`
	Grants      bool                   `json:"grants"`
	SelfService bool                   `json:"self_service"`
	Want        []string               `json:"want"`
	Warnings    int                    `json:"warnings"`
}

// TestProvisionalEligibility runs testdata/provisional: the
// exemption kinds a blocking failure is eligible for at plan, from the
// effective signed coverable map built as Configure builds it.
func TestProvisionalEligibility(t *testing.T) {
	files, _ := filepath.Glob("testdata/provisional/*.json")
	if len(files) < 16 {
		t.Fatalf("%d provisional fixtures", len(files))
	}
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".json"), func(t *testing.T) {
			var c provisionalCase
			b, err := os.ReadFile(f)
			if err == nil {
				err = json.Unmarshal(b, &c)
			}
			if err != nil {
				t.Fatal(err)
			}
			mode := c.FloorMode
			if mode == "" {
				mode = profile.FloorOnline
			}
			cov, warns := exceptions.NewCoverability(map[string][]bundle.ExemptionKind{provisionalControl: c.Bundle}, c.Profile, mode, mode)
			if len(warns) != c.Warnings {
				t.Fatalf("coverability warnings %q, want %d", warns, c.Warnings)
			}
			got := PendingKinds(Eligibility{Coverable: func(k string) bool { return cov.Coverable(provisionalControl, k) },
				Grandfather: c.Grandfather, BreakGlass: c.BreakGlass, Grants: c.Grants, SelfService: c.SelfService})
			if !slices.Equal(got, c.Want) && len(got)+len(c.Want) > 0 {
				t.Fatalf("pending kinds %q, want %q", got, c.Want)
			}
		})
	}
}

// TestProvisionalNoInput: a nil Coverable covers nothing, whatever else
// holds, so a run without the signed map never downgrades a block.
func TestProvisionalNoInput(t *testing.T) {
	if got := PendingKinds(Eligibility{Grandfather: true, BreakGlass: true}); len(got) != 0 {
		t.Fatalf("pending kinds %q, want none", got)
	}
	if got := PendingSummary("break_glass", provisionalControl); got != "pending exemption: break_glass "+provisionalControl {
		t.Fatal(got)
	}
}
