package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

const (
	opEncryption = "rds_db_instance_encryption_at_rest_enabled"
	opGuard      = "rds_instance_deletion_guard"
)

var (
	opBad  = json.RawMessage(`{"storage_encrypted":false,"kms_key_id":"k","engine":"postgres","deletion_protection":true,"id":"db-1"}`)
	opNull = json.RawMessage(`null`)
)

// opLifecycle is a hard-fail lifecycle with one exception on control
// matching match: a sidecar entry bobthecorp-op, or with grant a signed
// grant (withGrant covers opEncryption only). It writes evidence to the
// returned directory.
func opLifecycle(t *testing.T, control, match string, grant bool) (*Lifecycle, string) {
	t.Helper()
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	cs := stageControlSet(t)
	c := &Configured{Table: profile.ModeTable{RunMode: profile.HardFail}, Controls: cs, Schemas: dbSchemas{}}
	l := New(Options{Now: func() time.Time { return now }})
	l.testPerResource = 10 * time.Second // verdicts, not the 50 ms budget under load
	l.cfg = c
	evDir := t.TempDir()
	w, err := evidence.Open(evidence.Options{Dir: evDir, Run: evidence.Run{ID: "r1", IDSource: "compliancetf"}})
	if err != nil {
		t.Fatal(err)
	}
	l.ev = w
	t.Cleanup(func() { _ = w.Close() }) // Windows cannot remove the TempDir of an open chain
	if grant {
		withGrant(t, l, match, now)
		return l, evDir
	}
	withSidecar(t, l, control, match, now)
	return l, evDir
}

// withSelfService is cs.Coverable with self_service added for ids, as if
// the bundle declared it: only the bundle declares coverability.
func withSelfService(cs *bundle.ControlSet, ids ...string) map[string][]bundle.ExemptionKind {
	declared := cs.Coverable()
	for _, id := range ids {
		declared[id] = append(declared[id], bundle.CoverSelfService)
	}
	return declared
}

// withSidecar installs in l a sidecar entry bobthecorp-op on control with
// selector match, self-service and scoped to the trusted workspace
// bobthecorp-reporting-prod.
func withSidecar(t *testing.T, l *Lifecycle, control, match string, now time.Time) {
	t.Helper()
	l.opt.Now = func() time.Time { return now }
	c := *l.cfg
	side := filepath.Join(t.TempDir(), "exceptions.hcl")
	if err := os.WriteFile(side, fmt.Appendf(nil, `exception "bobthecorp-op" {
  controls  = [%q]
  match     = %q
  workspace = "bobthecorp-reporting-prod"
  reason    = "OPS-4411"
  expires   = "2027-01-01"
}
`, control, match), 0o600); err != nil {
		t.Fatal(err)
	}
	c.Block = Block{ExceptionsFile: side}
	c.Table.Exceptions = &profile.Exceptions{SelfService: []string{control}, MaxLifetimeDays: 180}
	c.Table.SidecarControls = []string{control}
	c.Table.Workspace = profile.Dim{Value: "bobthecorp-reporting-prod", Source: "profile"}
	cov, warns := exceptions.NewCoverability(withSelfService(c.Controls, control), c.Table.Exceptions)
	if len(warns) != 0 {
		t.Fatalf("coverability: %v", warns)
	}
	s, _, err := loadSidecar(c.Block, c.Table, c.Controls, cov, now, exceptions.Clock{})
	if err != nil || s == nil {
		t.Fatalf("sidecar: %v", err)
	}
	c.Sidecar = s
	l.cfg = &c
}

// diagnosed is the first diagnostic of control in res, or nil.
func diagnosed(res *hook.Result, control string) *hook.Diagnostic {
	i := slices.IndexFunc(res.Diagnostics, func(d hook.Diagnostic) bool { return strings.HasPrefix(d.Summary, "["+control+"]") })
	if i < 0 {
		return nil
	}
	return &res.Diagnostics[i]
}

// TestSelectorOpNeverWidens: at apply the envelope steers
// Request.Op to replace or change, and the lifecycle also evaluates each control
// under the RPC shape op. An exception selector must match under every op
// the control ran under, so a selector reading op never waives on an op the
// RPC shape does not give. A replace exception that names the half it waives
// keeps working at both halves.
func TestSelectorOpNeverWidens(t *testing.T) {
	cases := []struct {
		name           string
		match          string
		stage          hook.Stage
		op             hook.Op
		prior, planned json.RawMessage
		control        string
		grant          bool
		excepted       bool
	}{
		// A plain create whose envelope claims replace or change.
		{"create steered to replace", `op == 'replace'`, hook.StageApplyPre, hook.OpReplace, nil, opBad, opEncryption, false, false},
		{"create steered to change", `op == 'change'`, hook.StageApplyPre, hook.OpChange, nil, opBad, opEncryption, false, false},
		{"update steered to change", `op == 'change'`, hook.StageApplyPre, hook.OpChange, opBad, opBad, opEncryption, false, false},
		{"delete steered to replace", `op == 'replace'`, hook.StageApplyPre, hook.OpReplace, opBad, opNull, opGuard, false, false},
		// The shape op itself still waives.
		{"create", `op == 'create'`, hook.StageApplyPre, hook.OpCreate, nil, opBad, opEncryption, false, true},
		{"update steered to change, shape op named", `op in ['change', 'update']`, hook.StageApplyPre, hook.OpChange, opBad, opBad, opEncryption, false, true},
		// A replace exception naming its halves waives both RPCs of a replace.
		{"replace create half", `op in ['replace', 'create', 'delete']`, hook.StageApplyPre, hook.OpReplace, nil, opBad, opEncryption, false, true},
		{"replace delete half", `op in ['replace', 'create', 'delete']`, hook.StageApplyPre, hook.OpReplace, opBad, opNull, opGuard, false, true},
		{"replace create half, op-free selector", `resource.engine == 'postgres'`, hook.StageApplyPre, hook.OpReplace, nil, opBad, opEncryption, false, true},
		{"replace delete half, op-free selector", `prior.engine == 'postgres'`, hook.StageApplyPre, hook.OpReplace, opBad, opNull, opGuard, false, true},
		// A signed grant takes the same path.
		{"grant: create steered to replace", `op == 'replace'`, hook.StageApplyPre, hook.OpReplace, nil, opBad, opEncryption, true, false},
		{"grant: replace create half", `op in ['replace', 'create']`, hook.StageApplyPre, hook.OpReplace, nil, opBad, opEncryption, true, true},
		// apply_post of change stands for a create or an update: a selector
		// must match both.
		{"apply_post change", `op == 'change'`, hook.StageApplyPost, hook.OpChange, nil, opBad, opEncryption, false, false},
		{"apply_post change, shape ops named", `op in ['change', 'create', 'update']`, hook.StageApplyPost, hook.OpChange, nil, opBad, opEncryption, false, true},
	}
	cs := stageControlSet(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := opLifecycle(t, tc.control, tc.match, tc.grant)
			env := &hook.EnvelopeHeader{V: 1}
			env.CTF.Op, env.CTF.ControlVersionsDigest = tc.op, cs.VersionsDigest("aws_db_instance")
			req := &hook.Request{Stage: tc.stage, Kind: hook.KindResource, TypeName: "aws_db_instance", Op: tc.op,
				Config: dynValue(t, tc.planned), Prior: dynValue(t, tc.prior), Planned: dynValue(t, tc.planned), Envelope: env}
			if tc.stage == hook.StageApplyPost {
				req.Config, req.Prior, req.Planned = nil, nil, nil
				req.New = dynValue(t, tc.planned)
			}
			res, err := l.Evaluate(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			d := diagnosed(res, tc.control)
			switch {
			case tc.excepted && d != nil:
				t.Errorf("match %s on op %q: diagnostic %+v, want excepted", tc.match, tc.op, d)
			case !tc.excepted && (d == nil || tc.stage == hook.StageApplyPre && d.Severity != hook.SeverityError):
				t.Errorf("match %s on op %q: diagnostic %+v, want blocked (diagnostics %v)", tc.match, tc.op, d, res.Diagnostics)
			}
		})
	}
}

// TestSelectorOpEvidence: when an alt op refuses an entry that
// applied under Request.Op, the evidence still names that entry, recorded
// rejected; an entry waiving under every op is recorded applied.
func TestSelectorOpEvidence(t *testing.T) {
	cs := stageControlSet(t)
	for _, tc := range []struct{ match, decision, status string }{
		{`op == 'replace'`, "", exceptions.StatusRejected},
		{`op in ['replace', 'create']`, "excepted", exceptions.StatusApplied},
	} {
		t.Run(tc.match, func(t *testing.T) {
			l, evDir := opLifecycle(t, opEncryption, tc.match, false)
			env := &hook.EnvelopeHeader{V: 1}
			env.CTF.Op, env.CTF.ControlVersionsDigest = hook.OpReplace, cs.VersionsDigest("aws_db_instance")
			if _, err := l.Evaluate(context.Background(), &hook.Request{Stage: hook.StageApplyPre, Kind: hook.KindResource,
				TypeName: "aws_db_instance", Op: hook.OpReplace, Config: dynValue(t, opBad), Prior: dynValue(t, nil),
				Planned: dynValue(t, opBad), Envelope: env}); err != nil {
				t.Fatal(err)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			var got *evidence.Result
			for _, r := range readChain(t, evDir) {
				for i := range r.Results {
					if r.Results[i].Control == opEncryption {
						got = &r.Results[i]
					}
				}
			}
			switch {
			case got == nil:
				t.Fatal("no result for " + opEncryption)
			case got.Exception == nil || got.Exception.ID != "bobthecorp-op" || got.Exception.Status != tc.status:
				t.Errorf("exception %+v, want bobthecorp-op %s", got.Exception, tc.status)
			case (got.Decision == "excepted") != (tc.decision == "excepted"):
				t.Errorf("decision %s, want excepted %v", got.Decision, tc.decision == "excepted")
			}
		})
	}
}

// TestPlanReplaceHalfWarns: at plan a replace binds op replace,
// so an op == 'replace' exception waives both halves there, but apply runs
// each half under its own op as well and blocks. Plan still waives and
// warns, naming the exception; a selector naming the half ops or reading
// no op does not warn.
func TestPlanReplaceHalfWarns(t *testing.T) {
	for _, tc := range []struct {
		name, control, match string
		warn                 bool
	}{
		{"create half, op == replace", opEncryption, `op == 'replace'`, true},
		{"delete half, op == replace", opGuard, `op == 'replace'`, true},
		{"create half, half ops named", opEncryption, `op in ['replace', 'create', 'delete']`, false},
		{"delete half, half ops named", opGuard, `op in ['replace', 'create', 'delete']`, false},
		{"create half, op-free", opEncryption, `resource.engine == 'postgres'`, false},
		{"create half, reads prior", opEncryption, `prior.engine == 'postgres'`, true},
		// Apply checks the create RPC under replace (no prior) and create.
		{"create half, prior read only under replace", opEncryption, `op == 'create' || (op == 'replace' && prior.engine == 'postgres')`, true},
		{"create half, both apply ops", opEncryption, `op == 'create' || (op == 'replace' && resource.engine == 'postgres')`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := opLifecycle(t, tc.control, tc.match, false)
			res, err := l.Evaluate(context.Background(), &hook.Request{Stage: hook.StagePlan, Kind: hook.KindResource,
				TypeName: "aws_db_instance", Op: hook.OpReplace, Config: dynValue(t, opBad), Prior: dynValue(t, opBad),
				Planned: dynValue(t, opBad)})
			if err != nil {
				t.Fatal(err)
			}
			d := diagnosed(res, tc.control)
			switch {
			case !tc.warn && d != nil:
				t.Errorf("unexpected diagnostic %+v", d)
			case tc.warn && (d == nil || d.Severity != hook.SeverityWarning || !strings.Contains(d.Summary, "exception bobthecorp-op")):
				t.Errorf("diagnostic %+v, want a warning naming bobthecorp-op", d)
			}
		})
	}
}
