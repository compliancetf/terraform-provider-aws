package verdict

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// failClosedGolden is one testdata/failclosed golden. test/conformance/verdict TestFailClosed runs
// the same goldens end to end through Terraform: plan succeeds with the
// plan warnings, the apply blocks before upstream with the errors and the
// apply_pre record holds the evidence results.
type failClosedGolden struct {
	Description string `json:"description"`
	Plan        struct {
		Warnings []string `json:"warnings"`
	} `json:"plan"`
	Apply struct {
		Errors []struct {
			Summary string `json:"summary"`
			Detail  string `json:"detail"`
		} `json:"errors"`
		Evidence struct {
			Op      string `json:"op"`
			Results []struct {
				Control   string `json:"control"`
				Version   string `json:"version"`
				State     string `json:"state"`
				Decision  string `json:"decision"`
				Situation string `json:"situation"`
			} `json:"results"`
		} `json:"evidence"`
	} `json:"apply"`
	// Situation is the apply RPC's situation input of a gate case; nil for
	// a resource-local provisional decision (decided in internal/lifecycle).
	Situation *situationCase `json:"situation"`
	// Eligibility is the signed coverable kinds of the failing control at
	// plan; nil when plan has no blocking failure.
	Eligibility *struct {
		Coverable []string `json:"coverable"`
	} `json:"eligibility"`
	Address string `json:"address"` // the provisional entry's address
}

// gateControl and gateSummary are the evidence control and diagnostic
// summary of a gate row (internal/lifecycle).
const (
	gateControl = "verdict_required"
	gateSummary = "Verdict required"
)

// TestFailClosed checks each fail-closed golden against this package: plan
// warns only with the pending exemptions the signed eligibility allows and
// otherwise not at all, every apply error blocks, and each row of the
// situation table (or the unproven text) is the golden's exact error and
// evidence situation.
func TestFailClosed(t *testing.T) {
	names := []string{"plan-no-verdict", "apply-missing-entry", "missing-decision", "exemption-no-proof"}
	if files, _ := filepath.Glob("testdata/failclosed/*.json"); len(files) != len(names) {
		t.Fatalf("%d fail-closed goldens, want %v", len(files), names)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join("testdata", "failclosed", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			var g failClosedGolden
			if err := dec.Decode(&g); err != nil {
				t.Fatal(err)
			}
			res := g.Apply.Evidence.Results
			if len(g.Apply.Errors) == 0 || len(res) != len(g.Apply.Errors) {
				t.Fatalf("%d errors for %d results: every case blocks with one error per result", len(g.Apply.Errors), len(res))
			}
			for _, r := range res {
				if r.Decision != "blocked" {
					t.Fatalf("result %+v: a fail-closed apply blocks", r)
				}
			}
			var warns []string
			if g.Eligibility != nil {
				e := Eligibility{Coverable: func(k string) bool { return slices.Contains(g.Eligibility.Coverable, k) }}
				for _, k := range PendingKinds(e) {
					warns = append(warns, PendingSummary(k, res[0].Control))
				}
			}
			if !slices.Equal(g.Plan.Warnings, warns) {
				t.Fatalf("plan warnings %q, want %q", g.Plan.Warnings, warns)
			}
			if g.Situation == nil {
				if g.Address == "" || len(res) != 1 || g.Apply.Errors[0].Detail != "" || res[0].Situation != SitUnproven || g.Apply.Errors[0].Summary != UnprovenText(res[0].Control, g.Address) {
					t.Fatalf("a resource-local case is one unproven provisional decision: %+v", g)
				}
				return
			}
			rows := Situation(g.Situation.apply())
			if len(rows) != len(res) {
				t.Fatalf("rows %+v, want %d", rows, len(res))
			}
			for i, r := range rows {
				e := g.Apply.Errors[i]
				text, control, ok := e.Summary, r.Control, e.Detail == ""
				if r.Control == "" { // a gate row: summary gateSummary, the text its detail
					text, control, ok = e.Detail, gateControl, e.Summary == gateSummary
				}
				if !ok || r.Severity != SevError || r.Result != res[i].Situation || control != res[i].Control || r.Text != text {
					t.Errorf("row %d %+v, want an error %s %s %q", i, r, res[i].Control, res[i].Situation, text)
				}
			}
		})
	}
}
