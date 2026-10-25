//go:build unix

// Verdict files load only on unix (internal/verdict file_other.go).

package lifecycle

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
)

var pabGraph = bundle.Control{ID: "s3_bucket_public_access_block_present", Version: "1.0.0", Kind: bundle.KindGraph,
	ResourceType: "aws_s3_bucket", Action: bundle.ActionDeny, Severity: bundle.SeverityHigh, Message: "S3 bucket has no public access block.",
	Graph: &bundle.Graph{Rule: bundle.GraphCompanionPresent, CompanionType: "aws_s3_bucket_public_access_block", LinkAttr: "bucket",
		TargetAttrs: []string{"id", "bucket"}}, ExemptionCoverable: []bundle.ExemptionKind{}}

const (
	bucketCfg  = `{"engine":"postgres","id":"db-1"}`
	bucketPrio = `{"engine":"postgres","id":"db-1"}`
)

// situationRun is a configured Lifecycle under a signed verdict holding
// instances, with its evidence dir.
type situationRun struct {
	l      *Lifecycle
	evDir  string
	leaf   [32]byte
	secret []byte
	signer verdicttest.Key
}

func newSituationRun(t *testing.T, required bool, extra ...bundle.Control) *situationRun {
	t.Helper()
	k := verdicttest.NewKey(t, verdictIssued.Add(-24*time.Hour))
	l := New(Options{ProviderVersion: "2.0.0", WrapperName: "compliancetf/aws", UpstreamName: "hashicorp/aws", UpstreamVersion: "6.14.1", Now: func() time.Time { return verdictIssued.Add(time.Hour) }})
	l.testPerResource = 10 * time.Second
	l.cfg = &Configured{Table: profile.ModeTable{RunMode: profile.HardFail, VerdictRequired: required}, Controls: stageControlSetDigest(t, "ab", extra...),
		Block: Block{ExceptionsFile: "compliance-exceptions.hcl"}, Schemas: dbSchemas{},
		Content: "sha256:3333333333333333333333333333333333333333333333333333333333333333"}
	l.cfg.Resolution.Profile = &profile.Profile{OrgID: "bobthecorp", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		Verdict: &profile.Verdict{PublicKeys: []profile.SignerKey{k.Signer}}}
	r := &situationRun{l: l, evDir: t.TempDir(), secret: make([]byte, 32)}
	if _, err := rand.Read(r.secret); err != nil {
		t.Fatal(err)
	}
	r.leaf = verdicttest.Leaf(t, r.secret)
	w, err := evidence.Open(evidence.Options{Dir: r.evDir, Run: evidence.Run{ID: "r1", IDSource: "compliancetf"}})
	if err != nil {
		t.Fatal(err)
	}
	l.ev = w
	t.Cleanup(func() { l.Close() }) //nolint:errcheck // test cleanup
	for _, k := range []string{verdict.EnvVerdict, verdict.EnvKeyFile} {
		t.Setenv(k, "")
		os.Unsetenv(k) //nolint:errcheck,usetesting // verdict = none until sign; t.Setenv restores it
	}
	r.signer = k
	return r
}

// sign writes the verdict holding instances and points the env at it.
func (r *situationRun) sign(t *testing.T, instances ...verdict.Instance) {
	t.Helper()
	r.signWith(t, verdictBinding(r.l), instances...)
}

func (r *situationRun) signWith(t *testing.T, b verdicttest.Binding, instances ...verdict.Instance) {
	t.Helper()
	for i := range instances {
		in := &instances[i]
		for _, s := range []*[]string{&in.Exceptions, &in.Baselines, &in.BreakGlass} {
			if *s == nil {
				*s = []string{}
			}
		}
		if in.UnknownPaths == nil {
			in.UnknownPaths = [][]string{}
		}
		if in.Decisions == nil {
			in.Decisions = []verdict.Decision{}
		}
		if in.NotEvaluable == nil {
			in.NotEvaluable = []verdict.NotEvaluable{}
		}
		if in.Refreshed == "" {
			in.Refreshed = "true"
		}
	}
	raw, err := json.Marshal(append([]verdict.Instance{}, instances...))
	if err != nil {
		t.Fatal(err)
	}
	b.Instances, b.Secret = raw, r.secret
	vpath, kpath := verdicttest.Write(t, t.TempDir(), r.signer, b)
	t.Setenv(verdict.EnvVerdict, vpath)
	t.Setenv(verdict.EnvKeyFile, kpath)
}

func (r *situationRun) key(t *testing.T, form verdict.Form, planned string, prior string) string {
	t.Helper()
	return r.keyOf(t, "aws_s3_bucket", form, planned, prior)
}

func (r *situationRun) keyOf(t *testing.T, typ string, form verdict.Form, planned string, prior string) string {
	t.Helper()
	var p json.RawMessage
	if prior != "" {
		p = json.RawMessage(prior)
	}
	k, err := verdict.Key(r.leaf, typ, form, objValue(t, json.RawMessage(planned)), nil, p)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// apply runs apply_pre for aws_s3_bucket: prior and planned are JSON
// objects or "null"; a non-null prior carries an envelope of kind id.
func (r *situationRun) apply(t *testing.T, prior, planned string) []hook.Diagnostic {
	t.Helper()
	req := &hook.Request{Stage: hook.StageApplyPre, Kind: hook.KindResource, TypeName: "aws_s3_bucket", Op: hook.OpCreate,
		Config: dynValue(t, json.RawMessage(bucketCfg)), Prior: dynValue(t, json.RawMessage(prior)), Planned: dynValue(t, json.RawMessage(planned))}
	if prior != "null" {
		env := &hook.EnvelopeHeader{V: 1}
		env.CTF.Op, env.CTF.PriorIdentityKind = hook.OpUpdate, "id"
		req.Op, req.Envelope = hook.OpUpdate, env
		if planned == "null" {
			req.Op, env.CTF.Op = hook.OpDelete, hook.OpDelete
		}
	}
	res, err := r.l.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return res.Diagnostics
}

func (r *situationRun) lastEval(t *testing.T) evidence.Record {
	t.Helper()
	var last evidence.Record
	for _, rec := range readChain(t, r.evDir) {
		if rec.Kind == evidence.KindEval {
			last = rec
		}
	}
	return last
}

func sevSummaries(ds []hook.Diagnostic) [][2]string {
	out := [][2]string{}
	for _, d := range ds {
		sev := "error"
		if d.Severity == hook.SeverityWarning {
			sev = "warning"
		}
		out = append(out, [2]string{sev, d.Summary})
	}
	return out
}

// TestVerdictSituationsApply runs the situation table through
// apply_pre with a signed verdict: keys are recomputed from the request,
// every row writes the eval record with the verdict digest.
func TestVerdictSituationsApply(t *testing.T) {
	const prior = `{"id":"db-1"}`
	noMatch := "No verdict entry matches this aws_s3_bucket instance; the profile requires a verdict for every change. Re-run plan and ctfkit gate."

	t.Run("required create matches a zero-control entry", func(t *testing.T) {
		r := newSituationRun(t, true)
		r.sign(t, verdict.Instance{Address: "aws_s3_bucket.a", Type: "aws_s3_bucket", Action: "create", PriorIdentityKind: verdict.KindNone,
			InstanceKey: r.key(t, verdict.FormCreate, bucketCfg, "")})
		if d := r.apply(t, "null", bucketCfg); len(d) != 0 {
			t.Fatalf("diagnostics %v", sevSummaries(d))
		}
		if rec := r.lastEval(t); rec.Digests == nil || rec.Digests.Verdict == nil || *rec.Digests.Verdict != r.l.loaded.Peek().Digest {
			t.Fatalf("eval record digests %+v, want the verdict digest", rec.Digests)
		}
	})
	t.Run("required update rejects the create-form entry (H2)", func(t *testing.T) {
		r := newSituationRun(t, true)
		r.sign(t, verdict.Instance{Address: "aws_s3_bucket.a", Type: "aws_s3_bucket", Action: "create", PriorIdentityKind: verdict.KindNone,
			InstanceKey: r.key(t, verdict.FormCreate, bucketCfg, "")})
		if d := r.apply(t, bucketPrio, bucketCfg); len(d) != 1 || d[0].Detail != noMatch {
			t.Fatalf("diagnostics %+v", d)
		}
	})
	t.Run("required update matches its update-form entry", func(t *testing.T) {
		r := newSituationRun(t, true)
		r.sign(t, verdict.Instance{Address: "aws_s3_bucket.a", Type: "aws_s3_bucket", Action: "update", PriorIdentityKind: verdict.KindID,
			InstanceKey: r.key(t, verdict.FormUpdate, bucketCfg, prior)})
		if d := r.apply(t, bucketPrio, bucketCfg); len(d) != 0 {
			t.Fatalf("diagnostics %v", sevSummaries(d))
		}
	})
	t.Run("required delete without its entry", func(t *testing.T) {
		r := newSituationRun(t, true)
		r.sign(t, verdict.Instance{Address: "aws_s3_bucket.a", Type: "aws_s3_bucket", Action: "update", PriorIdentityKind: verdict.KindID,
			InstanceKey: r.key(t, verdict.FormUpdate, bucketCfg, prior)})
		if d := r.apply(t, bucketPrio, "null"); len(d) != 1 || d[0].Detail != noMatch {
			t.Fatalf("diagnostics %+v", d)
		}
		if rec := r.lastEval(t); !slices.Equal(resultsOf(rec), []string{"verdict_required/fail/blocked"}) {
			t.Fatalf("results %v", resultsOf(rec))
		}
	})
	t.Run("required delete matches delete_key", func(t *testing.T) {
		r := newSituationRun(t, true)
		r.sign(t, verdict.Instance{Address: "aws_s3_bucket.a", Type: "aws_s3_bucket", Action: "delete", PriorIdentityKind: verdict.KindID,
			DeleteKey: r.key(t, verdict.FormDelete, "null", prior), DeleteDecisions: []verdict.Decision{}})
		if d := r.apply(t, bucketPrio, "null"); len(d) != 0 {
			t.Fatalf("diagnostics %v", sevSummaries(d))
		}
	})
	t.Run("graph fail blocks without verdict_required", func(t *testing.T) {
		r := newSituationRun(t, false, pabGraph)
		r.sign(t, verdict.Instance{Address: "aws_s3_bucket.a", Type: "aws_s3_bucket", Action: "create", PriorIdentityKind: verdict.KindNone,
			InstanceKey: r.key(t, verdict.FormCreate, bucketCfg, ""),
			Decisions:   []verdict.Decision{{Control: pabGraph.ID, Version: pabGraph.Version, Result: verdict.ResultFail, Action: "deny"}}})
		want := [][2]string{{"error", "s3_bucket_public_access_block_present: S3 bucket has no public access block. (graph control, decided by ctfkit gate for aws_s3_bucket.a)"}}
		if d := sevSummaries(r.apply(t, "null", bucketCfg)); !slices.Equal(d, want) {
			t.Fatalf("diagnostics %v, want %v", d, want)
		}
		if got := resultsOf(r.lastEval(t)); !slices.Equal(got, []string{"s3_bucket_public_access_block_present/fail/blocked"}) {
			t.Fatalf("results %v", got)
		}
	})
	t.Run("graph decision missing", func(t *testing.T) {
		r := newSituationRun(t, true, pabGraph)
		r.sign(t, verdict.Instance{Address: "aws_s3_bucket.a", Type: "aws_s3_bucket", Action: "create", PriorIdentityKind: verdict.KindNone,
			InstanceKey: r.key(t, verdict.FormCreate, bucketCfg, "")})
		want := [][2]string{{"error", "Verdict entry for aws_s3_bucket.a has no decision for s3_bucket_public_access_block_present@1.0.0; re-run plan and ctfkit gate."}}
		if d := sevSummaries(r.apply(t, "null", bucketCfg)); !slices.Equal(d, want) {
			t.Fatalf("diagnostics %v, want %v", d, want)
		}
	})
	t.Run("no verdict, not required, graph control", func(t *testing.T) {
		r := newSituationRun(t, false, pabGraph)
		want := [][2]string{{"warning", verdict.TextNotEnforced}}
		if d := sevSummaries(r.apply(t, "null", bucketCfg)); !slices.Equal(d, want) {
			t.Fatalf("diagnostics %v, want %v", d, want)
		}
		if got := resultsOf(r.lastEval(t)); !slices.Equal(got, []string{"s3_bucket_public_access_block_present/not_evaluable/warning"}) {
			t.Fatalf("results %v", got)
		}
	})
	t.Run("no verdict, required", func(t *testing.T) {
		r := newSituationRun(t, true)
		if d := r.apply(t, "null", bucketCfg); len(d) != 1 || d[0].Detail != verdict.TextNoVerdict {
			t.Fatalf("diagnostics %+v", d)
		}
	})
	t.Run("destroy RPC ignores create-half decisions", func(t *testing.T) {
		r := newSituationRun(t, true, pabGraph)
		r.sign(t, verdict.Instance{Address: "aws_s3_bucket.a", Type: "aws_s3_bucket", Action: "replace", PriorIdentityKind: verdict.KindID,
			InstanceKey: r.key(t, verdict.FormCreate, bucketCfg, ""), DeleteKey: r.key(t, verdict.FormDelete, "null", prior),
			Decisions:       []verdict.Decision{{Control: pabGraph.ID, Version: pabGraph.Version, Result: verdict.ResultFail, Action: "deny"}},
			DeleteDecisions: []verdict.Decision{}})
		if d := r.apply(t, bucketPrio, "null"); len(d) != 0 {
			t.Fatalf("destroy RPC: %v", sevSummaries(d))
		}
		if d := r.apply(t, "null", bucketCfg); len(d) != 1 || d[0].Severity != hook.SeverityError {
			t.Fatalf("create RPC: %v", sevSummaries(d))
		}
	})
}

// TestVerdictDeletionGuardOnCompanion: a companion_absent_forbidden guard
// is decided on the delete half of its companion_type (the deleted
// companion), never of its resource_type (the kept target), as ctfkit gate
// sign records it in the companion's delete_decisions.
func TestVerdictDeletionGuardOnCompanion(t *testing.T) {
	const prior = `{"id":"db-1"}`
	// bucket is the guarded companion of a trail; pabKept guards the
	// bucket's own companion, so a bucket delete never decides it.
	trailKept, pabKept := pabGraph, pabGraph
	trailKept.ID, trailKept.ResourceType, trailKept.Message = "cloudtrail_bucket_kept", "aws_cloudtrail", "The bucket of a kept trail must not be deleted."
	trailKept.Graph = &bundle.Graph{Rule: bundle.GraphCompanionAbsentForbidden, CompanionType: "aws_s3_bucket", LinkAttr: "bucket", TargetAttrs: []string{"s3_bucket_name"}}
	pabKept.ID = "s3_bucket_public_access_block_kept"
	pabKept.Graph = &bundle.Graph{Rule: bundle.GraphCompanionAbsentForbidden, CompanionType: "aws_s3_bucket_public_access_block", LinkAttr: "bucket", TargetAttrs: []string{"id"}}
	entry := func(r *situationRun, result string) verdict.Instance {
		return verdict.Instance{Address: "aws_s3_bucket.a", Type: "aws_s3_bucket", Action: "delete", PriorIdentityKind: verdict.KindID,
			DeleteKey:       r.key(t, verdict.FormDelete, "null", prior),
			DeleteDecisions: []verdict.Decision{{Control: trailKept.ID, Version: trailKept.Version, Result: result, Action: "deny"}}}
	}
	t.Run("companion delete passes on its guard decision", func(t *testing.T) {
		r := newSituationRun(t, false, trailKept, pabKept)
		r.sign(t, entry(r, verdict.ResultPass))
		if d := r.apply(t, bucketPrio, "null"); len(d) != 0 {
			t.Fatalf("diagnostics %v", sevSummaries(d))
		}
		if got := resultsOf(r.lastEval(t)); !slices.Contains(got, trailKept.ID+"/pass/logged") || slices.ContainsFunc(got, func(s string) bool { return strings.HasPrefix(s, pabKept.ID) }) {
			t.Fatalf("results %v", got)
		}
	})
	t.Run("companion delete blocks on a failing guard", func(t *testing.T) {
		r := newSituationRun(t, false, trailKept, pabKept)
		r.sign(t, entry(r, verdict.ResultFail))
		want := [][2]string{{"error", "cloudtrail_bucket_kept: The bucket of a kept trail must not be deleted. (graph control, decided by ctfkit gate for aws_s3_bucket.a)"}}
		if d := sevSummaries(r.apply(t, bucketPrio, "null")); !slices.Equal(d, want) {
			t.Fatalf("diagnostics %v, want %v", d, want)
		}
	})
	t.Run("companion delete without the guard decision fails closed", func(t *testing.T) {
		r := newSituationRun(t, false, trailKept)
		in := entry(r, verdict.ResultPass)
		in.DeleteDecisions = []verdict.Decision{}
		r.sign(t, in)
		if d := r.apply(t, bucketPrio, "null"); len(d) != 1 || d[0].Severity != hook.SeverityError {
			t.Fatalf("diagnostics %v", sevSummaries(d))
		}
	})
	t.Run("target delete looks up no guard", func(t *testing.T) {
		r := newSituationRun(t, false, pabKept)
		if d := r.apply(t, bucketPrio, "null"); len(d) != 0 {
			t.Fatalf("diagnostics %v", sevSummaries(d))
		}
	})
}

func resultsOf(rec evidence.Record) []string {
	out := []string{}
	for _, r := range rec.Results {
		out = append(out, r.Control+"/"+r.State+"/"+r.Decision)
	}
	return out
}

// TestVerdictListedExceptions: under verdict_required apply honors
// an exception only when the verdict lists its digest for the matched
// instance with the same source and expiry, and a self-service expiry must
// precede the verdict's expires_at.
func TestVerdictListedExceptions(t *testing.T) {
	const planned = `{"storage_encrypted":false,"kms_key_id":"arn:aws:kms:us-east-1:111122223333:key/bobthecorp-rds","engine":"postgres","deletion_protection":true}`
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	encryption := "rds_db_instance_encryption_at_rest_enabled"
	for name, tc := range map[string]struct {
		notRequired, listed bool
		want, status        string
		expires             string // sidecar expiry; set: the verdict is issued 5h later so it outlives the entry
	}{
		"not required: the 0B rules": {true, false, "fail/excepted", exceptions.StatusApplied, ""},
		"not listed":                 {false, false, "fail/blocked", exceptions.StatusRejected, ""},
		// The sidecar entry expires 2027-01-01, after the verdict (literal rule).
		"listed, self-service outlives the verdict": {false, true, "fail/blocked", exceptions.StatusRejected, ""},
		// The verdict lists the entry digest (B8) the gate computes.
		"listed, entry digest": {false, true, "fail/excepted", exceptions.StatusApplied, "2026-10-19"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newSituationRun(t, !tc.notRequired)
			c := r.l.cfg
			c.Block.ExceptionsFile = filepath.Join("testdata", "stages", "exception_sidecar.hcl")
			b := verdictBinding(r.l)
			listedExpires := "2027-01-01T00:00:00Z"
			if tc.expires != "" {
				src, err := os.ReadFile(c.Block.ExceptionsFile)
				if err != nil {
					t.Fatal(err)
				}
				c.Block.ExceptionsFile = filepath.Join(t.TempDir(), "exceptions.hcl")
				src = []byte(strings.Replace(string(src), `"2027-01-01"`, `"`+tc.expires+`"`, 1))
				if err := os.WriteFile(c.Block.ExceptionsFile, src, 0o600); err != nil {
					t.Fatal(err)
				}
				b.IssuedAt = verdictIssued.Add(5 * time.Hour)
				r.l.opt.Now = func() time.Time { return b.IssuedAt.Add(time.Hour) }
				listedExpires = tc.expires + "T00:00:00Z"
			}
			c.Table.Workspace = profile.Dim{Value: "bobthecorp-reporting-prod", Source: "profile"}
			c.Table.Exceptions = &profile.Exceptions{SelfService: []string{encryption}, MaxLifetimeDays: 180,
				Coverable: map[string][]string{encryption: {"self_service"}}}
			c.Table.SidecarControls = []string{encryption}
			cov, _ := exceptions.NewCoverability(c.Controls.Coverable(), c.Table.Exceptions)
			side, _, err := loadSidecar(c.Block, c.Table, c.Controls, cov, now, exceptions.Clock{})
			if err != nil {
				t.Fatal(err)
			}
			c.Sidecar = side
			in := verdict.Instance{Address: "aws_db_instance.a", Type: "aws_db_instance", Action: "create", PriorIdentityKind: verdict.KindNone,
				InstanceKey: r.keyOf(t, "aws_db_instance", verdict.FormCreate, planned, "")}
			if tc.listed {
				d := side.Digests()[0] // the file holds one entry
				in.Exceptions = []string{d}
				b.Exceptions = json.RawMessage(`[{"digest":"` + d + `","source":"self_service","expires":"` + listedExpires + `"}]`)
			}
			r.signWith(t, b, in)
			req := &hook.Request{Stage: hook.StageApplyPre, Kind: hook.KindResource, TypeName: "aws_db_instance", Op: hook.OpCreate,
				Config: dynValue(t, json.RawMessage(planned)), Prior: dynValue(t, json.RawMessage("null")), Planned: dynValue(t, json.RawMessage(planned))}
			if _, err := r.l.Evaluate(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			got := ""
			for _, res := range r.lastEval(t).Results {
				if res.Control == encryption {
					got = res.State + "/" + res.Decision
					if res.Exception == nil || res.Exception.Status != tc.status {
						t.Errorf("exception %+v, want status %s", res.Exception, tc.status)
					}
				}
			}
			if got != tc.want {
				t.Fatalf("%s: %s, want %s", encryption, got, tc.want)
			}
		})
	}
}

// TestListingAllows: digest, source and expiry must match the listed
// exception; a self-service one must expire before the verdict.
func TestListingAllows(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	v := &verdict.Verdict{Doc: verdict.Document{ExpiresAt: "2026-10-18T22:00:00Z",
		Exceptions: []verdict.ExceptionRef{{Digest: d, Source: "self_service", Expires: "2026-10-18T20:00:00Z"}}}}
	s := &listing{v: v, digests: map[string]bool{d: true}}
	ok := evidence.Exception{Digest: d, Source: "self_service", Expires: "2026-10-18T20:00:00Z"}
	if !s.allows(&ok) {
		t.Fatal("listed self-service exception refused")
	}
	for name, e := range map[string]evidence.Exception{
		"other digest":  {Digest: "sha256:" + strings.Repeat("b", 64), Source: "self_service", Expires: ok.Expires},
		"other source":  {Digest: d, Source: "grant", Expires: ok.Expires},
		"other expires": {Digest: d, Source: "self_service", Expires: "2026-10-18T21:00:00Z"},
	} {
		if s.allows(&e) {
			t.Errorf("%s: allowed", name)
		}
	}
	v.Doc.Exceptions[0].Expires, ok.Expires = "2026-10-19T00:00:00Z", "2026-10-19T00:00:00Z"
	if s.allows(&ok) {
		t.Error("self-service exception outliving the verdict allowed")
	}
	v.Doc.Exceptions[0].Source, ok.Source = "grant", "grant"
	if !s.allows(&ok) {
		t.Error("listed grant refused")
	}
	if (&listing{v: v, digests: map[string]bool{}}).allows(&ok) {
		t.Error("unlisted grant allowed")
	}
}

// TestVerdictGraphRowExcepted: an exception whose selector
// matches the planned value waives a no_match row of its graph control;
// the verdict gate row under verdict_required is never waived.
func TestVerdictGraphRowExcepted(t *testing.T) {
	const planned = `{"storage_encrypted":true,"kms_key_id":"arn:aws:kms:us-east-1:111122223333:key/bobthecorp-rds","engine":"postgres","deletion_protection":true}`
	ctl := pabGraph
	ctl.ID, ctl.ResourceType = "rds_db_instance_backup_plan_present", "aws_db_instance"
	ctl.Graph = &bundle.Graph{Rule: bundle.GraphCompanionPresent, CompanionType: "aws_backup_selection", LinkAttr: "resources", TargetAttrs: []string{"arn"}}
	dir := t.TempDir()
	side := filepath.Join(dir, "exceptions.hcl")
	sideBody := []byte(`exception "backup-later" {
  controls  = ["rds_db_instance_backup_plan_present"]
  match     = "type == 'aws_db_instance' && resource.deletion_protection == true"
  workspace = "bobthecorp-reporting-prod"
  reason    = "Backup plan lands in OPS-4412"
  expires   = "2027-01-01"
}
`)
	if err := os.WriteFile(side, sideBody, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		required    bool
		want, block string
	}{
		"not required: no_match waived": {false, "rds_db_instance_backup_plan_present/fail/excepted", ""},
		"required: gate row never waived": {true, "verdict_required/fail/blocked",
			"No verdict entry matches this aws_db_instance instance; the profile requires a verdict for every change. Re-run plan and ctfkit gate."},
	} {
		t.Run(name, func(t *testing.T) {
			r := newSituationRun(t, tc.required, ctl)
			c := r.l.cfg
			c.Block.ExceptionsFile = side
			c.Table.Workspace = profile.Dim{Value: "bobthecorp-reporting-prod", Source: "profile"}
			c.Table.Exceptions = &profile.Exceptions{SelfService: []string{ctl.ID}, MaxLifetimeDays: 180,
				Coverable: map[string][]string{ctl.ID: {"self_service"}}}
			c.Table.SidecarControls = []string{ctl.ID}
			cov, _ := exceptions.NewCoverability(c.Controls.Coverable(), c.Table.Exceptions)
			sc, _, err := loadSidecar(c.Block, c.Table, c.Controls, cov, verdictIssued, exceptions.Clock{})
			if err != nil {
				t.Fatal(err)
			}
			c.Sidecar = sc
			r.sign(t) // a verdict with no entry: no_match
			req := &hook.Request{Stage: hook.StageApplyPre, Kind: hook.KindResource, TypeName: "aws_db_instance", Op: hook.OpCreate,
				Config: dynValue(t, json.RawMessage(planned)), Prior: dynValue(t, json.RawMessage("null")), Planned: dynValue(t, json.RawMessage(planned))}
			res, err := r.l.Evaluate(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			block := ""
			for _, d := range res.Diagnostics {
				if d.Severity == hook.SeverityError {
					block = d.Detail
				}
			}
			got := resultsOf(r.lastEval(t))
			if block != tc.block || len(got) == 0 || got[0] != tc.want {
				t.Fatalf("block %q, results %v; want %q, %s", block, got, tc.block, tc.want)
			}
		})
	}
}

// TestBaselineInstance: the baseline matcher gets the one
// matched verdict entry, the envelope identity and the provider binding; an
// unknown account leaves the scope empty, so no entry matches.
func TestBaselineInstance(t *testing.T) {
	d := "sha256:" + strings.Repeat("e", 64)
	v := &verdict.Verdict{Doc: verdict.Document{OrgID: "bobthecorp", Workspace: "prod", Baselines: []verdict.BaselineRef{{Digest: d}}}}
	in := &verdict.Instance{Address: "aws_db_instance.a", PreviousAddress: "aws_db_instance.old", Action: "update", Refreshed: "true", Baselines: []string{d}}
	env := &hook.EnvelopeHeader{V: 1}
	env.CTF.PriorIdentityKind, env.CTF.PriorIdentity = "identity", json.RawMessage(`{"arn":"arn:aws:rds:us-east-1:111111111111:db:a"}`)
	req := &hook.Request{TypeName: "aws_db_instance", Envelope: env}
	l := New(Options{Now: func() time.Time { return verdictIssued }})
	c := &Configured{Schemas: dbSchemas{}, Provider: engine.ProviderInfo{AccountID: "111111111111", AccountKnown: true, Region: "us-east-1", RegionKnown: true}}
	prior := objValue(t, json.RawMessage(`{"engine":"postgres","id":"db-1"}`))
	key, why := instanceKey(req, prior, prior)
	if why != "" {
		t.Fatal(why)
	}
	bi := l.baselineInstance(c, v, in, key, req, prior, prior, &engine.Activation{Resource: prior})
	if bi.OrgID != "bobthecorp" || bi.Workspace != "prod" || bi.Address != in.Address || bi.PreviousAddress != in.PreviousAddress ||
		bi.Action != "update" || bi.Refreshed != "true" || !slices.Equal(bi.Listed, []string{d}) || !slices.Equal(bi.Matched, []string{d}) ||
		bi.AccountID != "111111111111" || bi.Region != "us-east-1" || bi.Type != "aws_db_instance" || bi.IdentityKind != "identity" ||
		string(bi.PriorIdentity) != string(env.CTF.PriorIdentity) || bi.Schema == nil || !bi.Now.Equal(verdictIssued) {
		t.Fatalf("baseline instance %+v", bi)
	}
	// The create half of a replace carries the destroyed object's identity in
	// its envelope; the baseline takes the create key's kind none.
	null := tftypes.NewValue(prior.Type(), nil)
	key, why = instanceKey(req, null, prior)
	if why != "" {
		t.Fatal(why)
	}
	if bi := l.baselineInstance(c, v, in, key, req, null, prior, &engine.Activation{Resource: prior}); bi.IdentityKind != "none" || bi.PriorIdentity != nil {
		t.Fatalf("create half baseline identity %q %s, want kind none", bi.IdentityKind, bi.PriorIdentity)
	}
	c.Provider.AccountKnown = false
	if bi := l.baselineInstance(c, v, in, key, req, prior, prior, &engine.Activation{Resource: prior}); bi.AccountID != "" || bi.Region != "" {
		t.Fatalf("unknown account bound scope %q/%q", bi.AccountID, bi.Region)
	}
}

// TestVerdictGraphExceptionShape: a graph exception is
// checked under the op the envelope steers (replace) and under the RPC
// shape (create, delete), as for the change controls, so a selector naming
// only replace waives neither replacement half.
func TestVerdictGraphExceptionShape(t *testing.T) {
	const planned = `{"storage_encrypted":true,"kms_key_id":"arn:aws:kms:us-east-1:111122223333:key/bobthecorp-rds","engine":"postgres","deletion_protection":true,"id":"db-1"}`
	present, guard := pabGraph, pabGraph
	present.ID, present.ResourceType = "rds_db_instance_backup_plan_present", "aws_db_instance"
	present.Graph = &bundle.Graph{Rule: bundle.GraphCompanionPresent, CompanionType: "aws_backup_selection", LinkAttr: "resources", TargetAttrs: []string{"arn"}}
	// The guard's companion is the instance the delete half destroys.
	guard.ID, guard.ResourceType = "rds_cluster_instance_kept", "aws_rds_cluster"
	guard.Graph = &bundle.Graph{Rule: bundle.GraphCompanionAbsentForbidden, CompanionType: "aws_db_instance", LinkAttr: "cluster_identifier", TargetAttrs: []string{"cluster_identifier"}}
	ids := []string{present.ID, guard.ID}
	for name, tc := range map[string]struct {
		match  string
		waived bool
	}{
		"replace only":       {"type == 'aws_db_instance' && op == 'replace'", false},
		"replace and halves": {"type == 'aws_db_instance' && op in ['replace', 'create', 'delete']", true},
	} {
		for _, half := range []string{"create", "delete"} {
			t.Run(name+"/"+half, func(t *testing.T) {
				side := filepath.Join(t.TempDir(), "exceptions.hcl")
				body := `exception "backup-later" {
  controls  = ["` + present.ID + `", "` + guard.ID + `"]
  match     = "` + tc.match + `"
  workspace = "bobthecorp-reporting-prod"
  reason    = "Backup plan lands in OPS-4412"
  expires   = "2027-01-01"
}
`
				if err := os.WriteFile(side, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				r := newSituationRun(t, false, present, guard)
				c := r.l.cfg
				c.Block.ExceptionsFile = side
				c.Table.Workspace = profile.Dim{Value: "bobthecorp-reporting-prod", Source: "profile"}
				c.Table.Exceptions = &profile.Exceptions{SelfService: ids, MaxLifetimeDays: 180,
					Coverable: map[string][]string{present.ID: {"self_service"}, guard.ID: {"self_service"}}}
				c.Table.SidecarControls = ids
				cov, _ := exceptions.NewCoverability(c.Controls.Coverable(), c.Table.Exceptions)
				sc, _, err := loadSidecar(c.Block, c.Table, c.Controls, cov, verdictIssued, exceptions.Clock{})
				if err != nil {
					t.Fatal(err)
				}
				c.Sidecar = sc
				r.sign(t) // no entry: no_match on the half's graph control
				env := &hook.EnvelopeHeader{V: 1}
				env.CTF.Op, env.CTF.PriorIdentityKind = hook.OpReplace, "none"
				req := &hook.Request{Stage: hook.StageApplyPre, Kind: hook.KindResource, TypeName: "aws_db_instance", Op: hook.OpReplace, Envelope: env,
					Config: dynValue(t, json.RawMessage(planned)), Prior: dynValue(t, json.RawMessage("null")), Planned: dynValue(t, json.RawMessage(planned))}
				ctl := present.ID
				if half == "delete" {
					env.CTF.PriorIdentityKind = "id"
					req.Prior, req.Planned = dynValue(t, json.RawMessage(planned)), dynValue(t, json.RawMessage("null"))
					ctl = guard.ID
				}
				res, err := r.l.Evaluate(context.Background(), req)
				if err != nil {
					t.Fatal(err)
				}
				// Only the graph row counts; the change controls of the stage set
				// have their own outcome on this request.
				blocked := slices.ContainsFunc(res.Diagnostics, func(d hook.Diagnostic) bool {
					return d.Severity == hook.SeverityError && strings.HasPrefix(d.Summary, "No verdict entry matches")
				})
				want := ctl + "/not_evaluable/blocked"
				if tc.waived {
					want = ctl + "/fail/excepted"
				}
				if got := resultsOf(r.lastEval(t)); blocked == tc.waived || len(got) == 0 || got[0] != want {
					t.Fatalf("blocked %v, results %v; want waived %v, %s", blocked, got, tc.waived, want)
				}
			})
		}
	}
}
