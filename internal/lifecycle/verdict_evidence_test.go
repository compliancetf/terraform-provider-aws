//go:build unix

// Verdict files load only on unix (internal/verdict file_other.go).

package lifecycle

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
	"github.com/compliancetf/terraform-provider-aws/test/scrub/scrubtest"
)

// TestVerdictEvidenceMatched: every situation row records the
// verdict digest, the matched entries (index and the key of the RPC's own
// half) and the row label on each gate result.
func TestVerdictEvidenceMatched(t *testing.T) {
	const prior = `{"id":"db-1"}`
	fail := []verdict.Decision{{Control: pabGraph.ID, Version: pabGraph.Version, Result: verdict.ResultFail, Action: "deny"}}
	pass := []verdict.Decision{{Control: pabGraph.ID, Version: pabGraph.Version, Result: verdict.ResultPass, Action: "deny"}}
	other := func(r *situationRun) verdict.Instance { // never matched by these RPCs
		return verdict.Instance{Address: "aws_s3_bucket.other", Type: "aws_s3_bucket", Action: "update", PriorIdentityKind: verdict.KindID,
			InstanceKey: r.key(t, verdict.FormUpdate, `{"id":"db-2"}`, `{"id":"db-2"}`)}
	}
	create := func(r *situationRun, addr string, d []verdict.Decision) verdict.Instance {
		return verdict.Instance{Address: addr, Type: "aws_s3_bucket", Action: "create", PriorIdentityKind: verdict.KindNone,
			InstanceKey: r.key(t, verdict.FormCreate, bucketCfg, ""), Decisions: d}
	}
	type want struct {
		entries    []int64
		situations []string
		noVerdict  bool // digests.verdict null, matched absent
	}
	for name, tc := range map[string]struct {
		required    bool
		graph       bool
		prior, plan string
		entries     func(r *situationRun) []verdict.Instance // nil: verdict none
		want        want
	}{
		"create, zero-control entry": {required: true, prior: "null", plan: bucketCfg,
			entries: func(r *situationRun) []verdict.Instance {
				return []verdict.Instance{other(r), create(r, "aws_s3_bucket.a", nil)}
			},
			want: want{entries: []int64{1}, situations: []string{}}},
		"graph fail": {graph: true, prior: "null", plan: bucketCfg,
			entries: func(r *situationRun) []verdict.Instance {
				return []verdict.Instance{create(r, "aws_s3_bucket.a", fail)}
			},
			want: want{entries: []int64{0}, situations: []string{verdict.SitFail}}},
		"no match": {required: true, prior: "null", plan: bucketCfg,
			entries: func(r *situationRun) []verdict.Instance { return []verdict.Instance{other(r)} },
			want:    want{entries: []int64{}, situations: []string{verdict.SitNoMatch}}},
		"identical collision": {graph: true, prior: "null", plan: bucketCfg,
			entries: func(r *situationRun) []verdict.Instance {
				return []verdict.Instance{create(r, "aws_s3_bucket.a", pass), other(r), create(r, "aws_s3_bucket.b", pass)}
			},
			want: want{entries: []int64{0, 2}, situations: []string{verdict.SitPass}}},
		"collision": {graph: true, prior: "null", plan: bucketCfg,
			entries: func(r *situationRun) []verdict.Instance {
				return []verdict.Instance{create(r, "aws_s3_bucket.a", pass), create(r, "aws_s3_bucket.b", fail)}
			},
			want: want{entries: []int64{0, 1}, situations: []string{verdict.SitCollision}}},
		"destroy half records delete_key": {required: true, prior: bucketPrio, plan: "null",
			entries: func(r *situationRun) []verdict.Instance {
				return []verdict.Instance{other(r), {Address: "aws_s3_bucket.a", Type: "aws_s3_bucket", Action: "replace", PriorIdentityKind: verdict.KindID,
					InstanceKey: r.key(t, verdict.FormCreate, bucketCfg, ""), DeleteKey: r.key(t, verdict.FormDelete, "null", prior),
					DeleteDecisions: []verdict.Decision{}}}
			},
			want: want{entries: []int64{1}, situations: []string{}}},
		"no verdict, required": {required: true, prior: "null", plan: bucketCfg,
			want: want{noVerdict: true, situations: []string{verdict.SitNoVerdict}}},
		"no verdict, graph control": {graph: true, prior: "null", plan: bucketCfg,
			want: want{noVerdict: true, situations: []string{verdict.SitNoVerdict}}},
	} {
		t.Run(name, func(t *testing.T) {
			var r *situationRun
			if tc.graph {
				r = newSituationRun(t, tc.required, pabGraph)
			} else {
				r = newSituationRun(t, tc.required)
			}
			var ins []verdict.Instance
			if tc.entries != nil {
				ins = tc.entries(r)
				r.sign(t, ins...)
			}
			r.apply(t, tc.prior, tc.plan)
			rec := r.lastEval(t)
			sits := []string{}
			for _, res := range rec.Results {
				sits = append(sits, res.Situation)
			}
			if !slices.Equal(sits, tc.want.situations) {
				t.Errorf("situations %v, want %v", sits, tc.want.situations)
			}
			if tc.want.noVerdict {
				if rec.Digests.Verdict != nil || rec.Matched != nil {
					t.Fatalf("verdict none: digests.verdict %v, matched %v", rec.Digests.Verdict, rec.Matched)
				}
				return
			}
			if rec.Digests.Verdict == nil || *rec.Digests.Verdict != r.l.loaded.Peek().Digest {
				t.Fatalf("digests.verdict %v", rec.Digests.Verdict)
			}
			if rec.Matched == nil {
				t.Fatal("matched absent")
			}
			got := []int64{}
			for _, m := range rec.Matched {
				got = append(got, m.Entry)
				if want := ins[m.Entry].Key(tc.plan == "null"); m.InstanceKey != want {
					t.Errorf("entry %d key %s, want %s", m.Entry, m.InstanceKey, want)
				}
			}
			if !slices.Equal(got, tc.want.entries) {
				t.Errorf("matched entries %v, want %v", got, tc.want.entries)
			}
		})
	}
}

// TestVerdictEvidenceScrub: a marker in the matched entry's address (a
// for_each key) and in the planned values never reaches the evidence chain;
// only the entry index and the digest key do.
func TestVerdictEvidenceScrub(t *testing.T) {
	planned := `{"engine":"` + scrubtest.Marker(1) + `","id":"db-1"}`
	r := newSituationRun(t, true, pabGraph)
	r.sign(t, verdict.Instance{Address: `aws_s3_bucket.a["` + scrubtest.Marker(2) + `"]`, Type: "aws_s3_bucket", Action: "create",
		PriorIdentityKind: verdict.KindNone, InstanceKey: r.key(t, verdict.FormCreate, planned, ""),
		Decisions: []verdict.Decision{{Control: pabGraph.ID, Version: pabGraph.Version, Result: verdict.ResultFail, Action: "deny"}}})
	r.apply(t, "null", planned)
	if rec := r.lastEval(t); len(rec.Matched) != 1 || rec.Results[0].Situation != verdict.SitFail {
		t.Fatalf("matched %v, results %+v", rec.Matched, rec.Results)
	}
	if err := r.l.Close(); err != nil {
		t.Fatal(err)
	}
	files := 0
	err := filepath.WalkDir(r.evDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		files++
		scrubtest.NoMarker(t, "evidence "+d.Name(), string(b))
		return err
	})
	if err != nil || files == 0 {
		t.Fatalf("evidence files %d: %v", files, err)
	}
}
