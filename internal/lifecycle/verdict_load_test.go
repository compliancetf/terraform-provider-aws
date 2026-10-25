//go:build unix

// Verdict files load only on unix (internal/verdict file_other.go).

package lifecycle

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
)

var verdictIssued = time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)

// verdictLifecycle is a configured Lifecycle whose profile trusts k.
func verdictLifecycle(t *testing.T, k verdicttest.Key) *Lifecycle {
	t.Helper()
	l := New(Options{ProviderVersion: "2.0.0", WrapperName: "compliancetf/aws", UpstreamName: "hashicorp/aws", UpstreamVersion: "6.14.1", Now: func() time.Time { return verdictIssued.Add(time.Hour) }})
	l.testPerResource = 10 * time.Second
	l.cfg = &Configured{Table: profile.ModeTable{RunMode: profile.HardFail}, Controls: stageControlSet(t),
		Block: Block{ExceptionsFile: "compliance-exceptions.hcl"}, Schemas: dbSchemas{},
		Content: "sha256:3333333333333333333333333333333333333333333333333333333333333333"}
	l.cfg.Resolution.Profile = &profile.Profile{OrgID: "bobthecorp", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		Verdict: &profile.Verdict{PublicKeys: []profile.SignerKey{k.Signer}}}
	w, err := evidence.Open(evidence.Options{Dir: t.TempDir(), Run: evidence.Run{ID: "r1", IDSource: "compliancetf"}})
	if err != nil {
		t.Fatal(err)
	}
	l.ev = w
	t.Cleanup(func() { l.Close() }) //nolint:errcheck // test cleanup
	return l
}

func verdictBinding(l *Lifecycle) verdicttest.Binding {
	return verdicttest.Binding{OrgID: "bobthecorp", ProfileDigest: l.cfg.Resolution.Profile.Digest, BundleDigest: l.cfg.Controls.Digest(),
		ContentDigest: l.cfg.Content, Wrapper: "2.0.0", Upstream: "6.14.1", IssuedAt: verdictIssued}
}

// evalZeroControl runs a zero-control create at stage and returns its
// diagnostics as summary/detail pairs.
func evalZeroControl(t *testing.T, l *Lifecycle, stage hook.Stage) [][2]string {
	t.Helper()
	cfg := json.RawMessage(`{"engine":"postgres"}`)
	res, err := l.Evaluate(context.Background(), &hook.Request{Stage: stage, Kind: hook.KindResource, TypeName: "aws_s3_bucket", Op: hook.OpCreate,
		Config: dynValue(t, cfg), Prior: dynValue(t, json.RawMessage("null")), Planned: dynValue(t, cfg)})
	if err != nil {
		t.Fatal(err)
	}
	out := [][2]string{}
	for _, d := range res.Diagnostics {
		out = append(out, [2]string{d.Summary, d.Detail})
	}
	return out
}

// TestVerdictLoadOnlyAtApply: plan never reads COMPLIANCETF_VERDICT,
// so a broken one is not latched there; the first apply loads it, and an
// unsafe file blocks that and every later apply, verdict_required or not,
// even after the environment changes.
func TestVerdictLoadOnlyAtApply(t *testing.T) {
	k := verdicttest.NewKey(t, verdictIssued.Add(-24*time.Hour))
	l := verdictLifecycle(t, k)
	t.Setenv(verdict.EnvVerdict, filepath.Join(t.TempDir(), "absent.json"))
	if d := evalZeroControl(t, l, hook.StagePlan); len(d) != 0 {
		t.Fatalf("plan diagnostics %v", d)
	}
	// Plan latched nothing: a valid verdict set now is the one apply loads.
	vpath, kpath := verdicttest.Write(t, t.TempDir(), k, verdictBinding(l))
	t.Setenv(verdict.EnvVerdict, vpath)
	t.Setenv(verdict.EnvKeyFile, kpath)
	if d := evalZeroControl(t, l, hook.StageApplyPre); len(d) != 0 {
		t.Fatalf("apply with a valid verdict, not required: %v", d)
	}
	l.cfg.Table.VerdictRequired = true
	want := [2]string{gateSummary, "No verdict entry matches this aws_s3_bucket instance; the profile requires a verdict for every change. Re-run plan and ctfkit gate."}
	if d := evalZeroControl(t, l, hook.StageApplyPre); len(d) != 1 || d[0] != want {
		t.Fatalf("apply with a valid verdict, required: %v, want %v", d, want)
	}

	l = verdictLifecycle(t, k)
	if err := os.Chmod(vpath, 0o644); err != nil {
		t.Fatal(err)
	}
	want = [2]string{verdict.SummaryInvalid, "The verdict file mode must be exactly 0600."}
	for i, env := range []string{vpath, ""} {
		if env == "" {
			if err := os.Unsetenv(verdict.EnvVerdict); err != nil { // t.Setenv above restores it
				t.Fatal(err)
			}
		}
		if d := evalZeroControl(t, l, hook.StageApplyPre); len(d) != 1 || d[0] != want {
			t.Fatalf("apply %d with an unsafe verdict, not required: %v, want %v", i, d, want)
		}
	}
}
