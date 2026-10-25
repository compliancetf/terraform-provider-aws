package lifecycle

import (
	"context"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// TestProxyBlockedRecord: an apply the proxy refused before the hook writes
// one apply_pre record whose result is the block token, with the request
// op and no resource id or identity. Under evidence.required a
// failed write adds the blocking diagnostic; an unknown token is an error.
func TestProxyBlockedRecord(t *testing.T) {
	configured := func(t *testing.T, required bool) *Lifecycle {
		l := New(Options{})
		l.cfg = &Configured{Table: profile.ModeTable{RunMode: profile.HardFail}, Controls: stageControlSet(t)}
		l.cfg.Resolution.Profile = &profile.Profile{Evidence: profile.Evidence{Required: required}}
		return l
	}
	for _, tc := range []struct {
		block string
		op    hook.Op
		want  string
	}{
		{hook.BlockEnvelopeInvalid, hook.OpUpdate, "update"},
		{hook.BlockEnvelopeDisagrees, hook.OpDelete, "delete"},
		{hook.BlockEnvelopeDisagrees, "", "change"},
	} {
		t.Run(tc.block+"/"+tc.want, func(t *testing.T) {
			l := configured(t, true)
			dir := t.TempDir()
			w, err := evidence.Open(evidence.Options{Dir: dir, Run: evidence.Run{ID: "r1", IDSource: "compliancetf"}})
			if err != nil {
				t.Fatal(err)
			}
			l.ev = w
			res, err := l.Evaluate(context.Background(), &hook.Request{Stage: hook.StageApplyPre, Kind: hook.KindResource,
				TypeName: "aws_s3_bucket", Op: tc.op, Blocked: tc.block})
			if err != nil || len(res.Diagnostics) != 0 {
				t.Fatalf("Evaluate = %+v, %v; want a record and no diagnostic", res, err)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			recs := readChain(t, dir)
			checkEvalRecord(t, recs, "apply_pre", "aws_s3_bucket", &wantEvidence{Op: tc.want,
				Results: []wantResult{{Control: tc.block, State: "fail", Decision: "blocked"}}})
			for _, r := range recs {
				if r.Kind == evidence.KindEval && (r.Resource.ID != nil || r.Resource.Identity != nil || r.Resource.IdentityKind != "none" || r.Envelope != "") {
					t.Errorf("resource %+v envelope %q, want no id, identity or envelope", r.Resource, r.Envelope)
				}
			}
		})
	}
	t.Run("required write fails", func(t *testing.T) {
		l := configured(t, true) // no chain: the write fails
		res, err := l.Evaluate(context.Background(), &hook.Request{Stage: hook.StageApplyPre, TypeName: "aws_s3_bucket", Op: hook.OpCreate, Blocked: hook.BlockEnvelopeInvalid})
		if err != nil || len(res.Diagnostics) != 1 || res.Diagnostics[0].Severity != hook.SeverityError || res.Diagnostics[0].Summary != "Evidence required" {
			t.Fatalf("Evaluate = %+v, %v; want the Evidence required error", res, err)
		}
	})
	t.Run("unknown block", func(t *testing.T) {
		if _, err := configured(t, false).Evaluate(context.Background(), &hook.Request{Stage: hook.StageApplyPre, TypeName: "aws_s3_bucket", Blocked: "other"}); err == nil {
			t.Fatal("Evaluate accepted an unknown block token")
		}
	})
}
