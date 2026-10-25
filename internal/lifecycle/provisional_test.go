//go:build unix

// Verdict files load only on unix (internal/verdict file_other.go).

package lifecycle

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/breakglass"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
)

// provControl fails on provPlanned; every other stage control passes.
const (
	provControl = "rds_db_instance_encryption_at_rest_enabled"
	provPlanned = `{"storage_encrypted":false,"kms_key_id":"arn:aws:kms:us-east-1:111122223333:key/bobthecorp-rds","engine":"postgres","deletion_protection":true}`
)

// provSetup gives the run the signed coverable list kinds for provControl
// under floor mode fm (the Configure wiring), and enables break_glass in
// the profile when bg, with receipt keys pins.
func provSetup(t *testing.T, r *situationRun, kinds []bundle.ExemptionKind, fm string, bg bool, pins ...profile.SignerKey) []string {
	t.Helper()
	cov, warns := exceptions.NewCoverability(map[string][]bundle.ExemptionKind{provControl: kinds}, nil, fm, fm)
	c := r.l.cfg
	c.Coverability = cov
	p := c.Resolution.Profile
	p.FloorMode = fm
	p.BreakGlass = &profile.BreakGlass{Enabled: bg, ReceiptKeys: pins}
	c.BreakGlass = breakglass.Policy{Profile: p, FloorMode: fm, Revocations: trust.NoRevocations(), Coverable: func(id string) bool { return cov.Coverable(id, string(bundle.CoverBreakGlass)) }}
	return warns
}

// provEval runs stage for an aws_db_instance create of provPlanned and
// returns the diagnostics and provControl's evidence result.
func provEval(t *testing.T, r *situationRun, stage hook.Stage) ([][2]string, evidence.Result) {
	t.Helper()
	return provEvalOf(t, r, stage, provPlanned)
}

func provEvalOf(t *testing.T, r *situationRun, stage hook.Stage, planned string) ([][2]string, evidence.Result) {
	t.Helper()
	req := &hook.Request{Stage: stage, Kind: hook.KindResource, TypeName: "aws_db_instance", Op: hook.OpCreate,
		Config: dynValue(t, json.RawMessage(planned)), Prior: dynValue(t, json.RawMessage("null")), Planned: dynValue(t, json.RawMessage(planned))}
	res, err := r.l.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var got evidence.Result
	for _, x := range r.lastEval(t).Results {
		if x.Control == provControl {
			got = x
		}
	}
	return sevSummaries(res.Diagnostics), got
}

func pending(kinds ...string) [][2]string {
	out := [][2]string{}
	for _, k := range kinds {
		out = append(out, [2]string{"warning", verdict.PendingSummary(k, provControl)})
	}
	return out
}

// TestProvisionalPlan: a blocking failure eligible for an exemption
// warns once per eligible kind at plan, without the artifact, from the
// compliance.tf-signed coverable list only; with no eligible kind it errors.
func TestProvisionalPlan(t *testing.T) {
	g, b, bg, ss := bundle.CoverGrant, bundle.CoverBaseline, bundle.CoverBreakGlass, bundle.CoverSelfService
	for name, tc := range map[string]struct {
		kinds       []bundle.ExemptionKind
		grandfather bool
		bg          bool
		airgap      bool
		want        [][2]string // nil: the plan error
	}{
		"grant":                         {kinds: []bundle.ExemptionKind{g}, want: pending("grant")},
		"self_service":                  {kinds: []bundle.ExemptionKind{ss}, want: pending("self_service")},
		"baseline under grandfather":    {kinds: []bundle.ExemptionKind{b}, grandfather: true, want: pending("baseline")},
		"baseline-only under hard_fail": {kinds: []bundle.ExemptionKind{b}, bg: true},
		"break_glass enabled online":    {kinds: []bundle.ExemptionKind{bg}, bg: true, want: pending("break_glass")},
		"break_glass not enabled":       {kinds: []bundle.ExemptionKind{bg}},
		"break_glass not in the list":   {kinds: []bundle.ExemptionKind{g}, bg: true, want: pending("grant")},
		"airgap drops break_glass":      {kinds: []bundle.ExemptionKind{bg, g}, airgap: true, want: pending("grant")},
		"hard_fail, empty list":         {kinds: []bundle.ExemptionKind{}, grandfather: true, bg: true},
		"every kind":                    {kinds: []bundle.ExemptionKind{b, bg, g, ss}, grandfather: true, bg: true, want: pending("baseline", "break_glass", "grant", "self_service")},
	} {
		t.Run(name, func(t *testing.T) {
			r := newSituationRun(t, false)
			fm := profile.FloorOnline
			if tc.airgap {
				fm = profile.FloorAirgap
			}
			warns := provSetup(t, r, tc.kinds, fm, tc.bg && !tc.airgap)
			if tc.airgap != (len(warns) == 1) {
				t.Fatalf("coverability warnings %q", warns)
			}
			if tc.grandfather {
				r.l.cfg.Table.RunMode = profile.Grandfather
			}
			d, res := provEval(t, r, hook.StagePlan)
			if tc.want == nil {
				if len(d) != 1 || d[0][0] != "error" || !strings.HasPrefix(d[0][1], "["+provControl+"] ") || res.Decision != "blocked" {
					t.Fatalf("diagnostics %v, result %+v: want the plan error", d, res)
				}
				return
			}
			if !slices.Equal(d, tc.want) || res.State != "fail" || res.Decision != "warning" {
				t.Fatalf("diagnostics %v, result %s/%s, want %v fail/warning", d, res.State, res.Decision, tc.want)
			}
		})
	}
}

// TestProvisionalPlanLocalGrant: a grant on provControl waives at plan under
// the local exemption rules; under verdict_required only a verdict-listed exemption
// counts, so the failure stays a pending exemption. A grant on a
// baseline-only control is never loaded and the plan errors.
func TestProvisionalPlanLocalGrant(t *testing.T) {
	now := verdictIssued.Add(time.Hour)
	sel := "type == 'aws_db_instance'"
	for name, tc := range map[string]struct {
		required bool
		kinds    []bundle.ExemptionKind
		want     string
	}{
		"0B: the grant waives":             {kinds: []bundle.ExemptionKind{bundle.CoverGrant}, want: "excepted"},
		"verdict_required: pending":        {required: true, kinds: []bundle.ExemptionKind{bundle.CoverGrant}, want: "warning"},
		"grant on a baseline-only control": {kinds: []bundle.ExemptionKind{bundle.CoverBaseline}, want: "blocked"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newSituationRun(t, tc.required)
			declared := map[string][]bundle.ExemptionKind{provControl: tc.kinds}
			n := withGrantCov(t, r.l, provControl, sel, now, declared)
			if tc.kinds[0] != bundle.CoverGrant && len(n.Warnings) == 0 {
				t.Fatal("grant on a baseline-only control loaded")
			}
			provSetup(t, r, tc.kinds, profile.FloorOnline, false)
			d, res := provEval(t, r, hook.StagePlan)
			if res.Decision != tc.want {
				t.Fatalf("decision %s, want %s (diagnostics %v)", res.Decision, tc.want, d)
			}
			if tc.want == "warning" && !slices.Equal(d, pending("grant")) {
				t.Fatalf("diagnostics %v", d)
			}
		})
	}
}

// TestProvisionalApply: at apply a provisional decision passes
// only with its final proof, with or without verdict_required, whatever the
// control evaluates to: a grant the verdict lists for the instance or an
// embedded, verified receipt covering a control whose signed list holds
// break_glass. A missing provisional decision, an unlisted grant, a receipt
// on a control without break_glass and a baseline digest the verdict lists
// without a loaded baseline all block.
func TestProvisionalApply(t *testing.T) {
	now := verdictIssued.Add(time.Hour)
	prov := []verdict.Decision{{Control: provControl, Version: "2.1.0", Result: verdict.ResultProvisional, Action: "deny"}}
	for name, tc := range map[string]struct {
		kinds       []bundle.ExemptionKind
		grant       bool // a loaded grant; listed by the verdict when listGrant
		listGrant   bool
		receipt     bool
		noDecision  bool
		failResult  bool // the entry records fail, not provisional
		grandfather bool
		baseline    bool // the verdict lists a baseline digest (no baseline file loaded)
		notRequired bool // a verdict supplied without verdict_required
		passes      bool // the control passes at apply
		want        string
		bgID        string
	}{
		"listed grant":                      {kinds: []bundle.ExemptionKind{bundle.CoverGrant}, grant: true, listGrant: true, want: "excepted"},
		"unlisted grant":                    {kinds: []bundle.ExemptionKind{bundle.CoverGrant}, grant: true, want: "blocked"},
		"no proof":                          {kinds: []bundle.ExemptionKind{bundle.CoverGrant}, want: "blocked"},
		"receipt":                           {kinds: []bundle.ExemptionKind{bundle.CoverBreakGlass}, receipt: true, want: "excepted", bgID: "ovr-01"},
		"receipt, decision missing":         {kinds: []bundle.ExemptionKind{bundle.CoverBreakGlass}, receipt: true, noDecision: true, want: "blocked"},
		"receipt, decision not provisional": {kinds: []bundle.ExemptionKind{bundle.CoverBreakGlass}, receipt: true, failResult: true, want: "blocked"},
		"receipt, control lacks the kind":   {kinds: []bundle.ExemptionKind{bundle.CoverGrant}, receipt: true, want: "blocked"},
		"not required, unlisted grant":      {kinds: []bundle.ExemptionKind{bundle.CoverGrant}, grant: true, notRequired: true, want: "blocked"},
		"not required, listed grant":        {kinds: []bundle.ExemptionKind{bundle.CoverGrant}, grant: true, listGrant: true, notRequired: true, want: "excepted"},
		"passes at apply, no proof":         {kinds: []bundle.ExemptionKind{bundle.CoverGrant}, passes: true, want: "blocked"},
		"passes at apply, listed grant":     {kinds: []bundle.ExemptionKind{bundle.CoverGrant}, grant: true, listGrant: true, passes: true, want: "logged"},
		"baseline listed, none loaded":      {kinds: []bundle.ExemptionKind{bundle.CoverBaseline}, grandfather: true, baseline: true, want: "blocked"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newSituationRun(t, !tc.notRequired)
			planned := provPlanned
			if tc.passes {
				planned = strings.Replace(provPlanned, `"storage_encrypted":false`, `"storage_encrypted":true`, 1)
			}
			key := r.keyOf(t, "aws_db_instance", verdict.FormCreate, planned, "")
			b := verdictBinding(r.l)
			in := verdict.Instance{Address: "aws_db_instance.a", Type: "aws_db_instance", Action: "create", PriorIdentityKind: verdict.KindNone,
				InstanceKey: key, Decisions: prov}
			if tc.noDecision {
				in.Decisions = nil
			}
			if tc.failResult {
				in.Decisions = []verdict.Decision{{Control: provControl, Version: "2.1.0", Result: verdict.ResultFail, Action: "deny"}}
			}
			if tc.grant {
				withGrantCov(t, r.l, provControl, "type == 'aws_db_instance'", now, map[string][]bundle.ExemptionKind{provControl: tc.kinds})
				if tc.listGrant {
					d := r.l.cfg.Grants.Digests()[0]
					in.Exceptions = []string{d}
					b.Exceptions = json.RawMessage(`[{"digest":"` + d + `","source":"grant","expires":"2026-10-20T00:00:00Z"}]`)
				}
			}
			var pins []profile.SignerKey
			if tc.receipt {
				raw, digest, pin := signedReceipt(t, r.l, "ovr-01", provControl, key)
				pins = append(pins, pin)
				b.Receipts = json.RawMessage("[" + string(raw) + "]")
				in.BreakGlass = []string{digest}
			}
			if tc.baseline {
				d := "sha256:" + strings.Repeat("6", 64)
				in.Baselines = []string{d}
				b.Baselines = json.RawMessage(`[{"digest":"` + d + `"}]`)
			}
			provSetup(t, r, tc.kinds, profile.FloorOnline, tc.receipt, pins...)
			if tc.grandfather {
				r.l.cfg.Table.RunMode = profile.Grandfather
			}
			r.signWith(t, b, in)
			d, res := provEvalOf(t, r, hook.StageApplyPre, planned)
			if res.Decision != tc.want || res.BreakGlassID != tc.bgID {
				t.Fatalf("result %s/%s break_glass_id %q, want %s %q (diagnostics %v)", res.State, res.Decision, res.BreakGlassID, tc.want, tc.bgID, d)
			}
			if blocked := slices.ContainsFunc(d, func(x [2]string) bool { return x[0] == "error" }); blocked != (tc.want == "blocked") {
				t.Fatalf("diagnostics %v", d)
			}
		})
	}
}
