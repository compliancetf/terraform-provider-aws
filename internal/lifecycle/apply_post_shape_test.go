package lifecycle

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// applyPostDiags runs apply_post under op on newState in hard_fail and
// returns its diagnostics keyed by control ID.
func applyPostDiags(t *testing.T, cs *bundle.ControlSet, op hook.Op, newState json.RawMessage) map[string]hook.Diagnostic {
	t.Helper()
	l := New(Options{})
	l.testPerResource = 10 * time.Second // verdicts, not the 50 ms budget under load
	l.cfg = &Configured{Table: profile.ModeTable{RunMode: profile.HardFail}, Controls: cs, Schemas: dbSchemas{}}
	res, err := l.Evaluate(context.Background(), &hook.Request{Stage: hook.StageApplyPost, Kind: hook.KindResource,
		TypeName: "aws_db_instance", Op: op, New: dynValue(t, newState)})
	if err != nil {
		t.Fatalf("op %q: %v", op, err)
	}
	got := map[string]hook.Diagnostic{}
	for _, d := range res.Diagnostics {
		id, _, _ := strings.Cut(strings.TrimPrefix(d.Summary, "["), "]")
		got[id] = d
	}
	return got
}

// TestApplyPostChangeShapeSplit: at apply_post an op change is a
// create or an update, unknown which. A control that fails under one shape
// and passes under the other warns, naming the control and that the outcome
// depends on the shape; one that fails under both keeps its error; one that
// passes under both reports nothing.
func TestApplyPostChangeShapeSplit(t *testing.T) {
	bad := json.RawMessage(`{"storage_encrypted":false,"kms_key_id":null,"engine":"postgres","deletion_protection":false,"id":"db-1"}`)
	cs := opControlSet(t)
	update := applyPostDiags(t, cs, hook.OpUpdate, bad)
	change := applyPostDiags(t, cs, hook.OpChange, bad)

	for _, id := range []string{"rds_op_create_encrypted", "rds_op_update_deletion_protection"} {
		d, ok := change[id]
		switch {
		case !ok:
			t.Errorf("%s: not reported under change (got %v)", id, change)
		case d.Severity != hook.SeverityWarning:
			t.Errorf("%s: severity %v under change, want warning", id, d.Severity)
		case !strings.Contains(d.Summary, "["+id+"]") || !strings.HasPrefix(d.Detail, shapeSplitNote):
			t.Errorf("%s: diagnostic %q / %q does not name the control and the shape split", id, d.Summary, d.Detail)
		case strings.Contains(d.Summary+d.Detail, "postgres") || strings.Contains(d.Summary+d.Detail, "db-1"):
			t.Errorf("%s: diagnostic carries a resource value: %q / %q", id, d.Summary, d.Detail)
		}
	}

	allFail := 0
	for id, d := range update {
		if d.Severity != hook.SeverityError || strings.HasPrefix(id, "rds_op_") {
			continue
		}
		allFail++
		if c, ok := change[id]; !ok || c.Severity != hook.SeverityError || strings.Contains(c.Detail, shapeSplitNote) {
			t.Errorf("%s: fails under both shapes, want today's error under change, got %+v", id, c)
		}
	}
	if allFail == 0 {
		t.Fatalf("no control fails under both shapes, the all-fail oracle proves nothing (update %v)", update)
	}

	good := json.RawMessage(`{"storage_encrypted":true,"kms_key_id":"k","engine":"postgres","deletion_protection":true,"id":"db-1"}`)
	if got := applyPostDiags(t, cs, hook.OpChange, good); len(got) != 0 {
		t.Errorf("all shapes pass: want no diagnostics, got %v", got)
	}
}

// TestApplyPostChangeShapeSplitEvidence: a shape split lowers the
// diagnostic only; evidence records the worse outcome as before.
func TestApplyPostChangeShapeSplitEvidence(t *testing.T) {
	cs := opControlSet(t)
	l := New(Options{})
	l.testPerResource = 10 * time.Second
	l.cfg = &Configured{Table: profile.ModeTable{RunMode: profile.HardFail}, Controls: cs, Schemas: dbSchemas{}}
	i := slices.IndexFunc(cs.All(), func(c bundle.Control) bool { return c.ID == "rds_op_create_encrypted" })
	ctl := cs.All()[i]
	bad := dynValue(t, json.RawMessage(`{"storage_encrypted":false,"kms_key_id":null,"engine":"postgres","deletion_protection":false,"id":"db-1"}`))
	newState, err := bad.Get()
	if err != nil {
		t.Fatal(err)
	}
	null := tftypes.NewValue(tftypes.DynamicPseudoType, nil)
	col := &collected{alt: postShapes(engine.OpChange)}
	l.check(context.Background(), l.cfg, StageApplyPost, &ctl,
		&engine.Activation{Resource: newState, Config: null, Prior: null, Op: engine.OpChange}, "", "", col)
	if len(col.results) != 1 || col.results[0].State != "fail" || col.results[0].Decision != "post_apply_violation" {
		t.Fatalf("results %+v, want one fail / post_apply_violation", col.results)
	}
	if len(col.diags) != 1 || col.diags[0].Severity != hook.SeverityWarning {
		t.Fatalf("diags %+v, want one warning", col.diags)
	}
}

// shapeProgram returns a fixed state per op: create, update and any other
// op (change itself) as given.
type shapeProgram struct{ create, update, change engine.State }

func (p shapeProgram) Eval(_ context.Context, a *engine.Activation) engine.Outcome {
	switch a.Op {
	case engine.OpCreate:
		return engine.Outcome{State: p.create}
	case engine.OpUpdate:
		return engine.Outcome{State: p.update}
	}
	return engine.Outcome{State: p.change}
}

// TestApplyPostChangeSplitOnlyPassFail: only a pass under one
// shape and a fail under the other warns. A pass beside not_evaluable or
// unknown is no split: the diagnostic is the one both shapes at the worse
// state give, with no shape note, so it never fails open.
func TestApplyPostChangeSplitOnlyPassFail(t *testing.T) {
	run := func(p shapeProgram) []hook.Diagnostic {
		t.Helper()
		var n atomic.Int32
		l := budgetLifecycle(t, profile.Budgets{}, p, &n)
		l.testPerResource = 10 * time.Second
		ctl := l.cfg.Controls.All()[0]
		null := tftypes.NewValue(tftypes.DynamicPseudoType, nil)
		col := &collected{alt: postShapes(engine.OpChange)}
		l.check(context.Background(), l.cfg, StageApplyPost, &ctl,
			&engine.Activation{Resource: tftypes.NewValue(dbType, nil), Config: null, Prior: null, Op: engine.OpChange}, "", "", col)
		return col.diags
	}
	if d := run(shapeProgram{engine.Pass, engine.Fail, engine.Pass}); len(d) != 1 || d[0].Severity != hook.SeverityWarning || !strings.HasPrefix(d[0].Detail, shapeSplitNote) {
		t.Fatalf("pass/fail: diags %+v, want one warning with the shape note", d)
	}
	for _, worse := range []engine.State{engine.NotEvaluable, engine.Unknown} {
		for _, p := range []shapeProgram{{engine.Pass, worse, engine.Pass}, {worse, engine.Pass, engine.Pass}} {
			want := run(shapeProgram{worse, worse, engine.Pass})
			got := run(p)
			if len(got) != len(want) || (len(got) == 1 && (got[0].Severity != want[0].Severity || strings.Contains(got[0].Detail, shapeSplitNote))) {
				t.Errorf("%v/%v: diags %+v, want %+v (the worse state's, no shape note)", p.create, p.update, got, want)
			}
		}
		if worse == engine.NotEvaluable {
			if d := run(shapeProgram{engine.Pass, worse, engine.Pass}); len(d) != 1 || d[0].Severity != hook.SeverityError {
				t.Errorf("pass/not_evaluable: diags %+v, want one error", d)
			}
		}
	}
	if d := run(shapeProgram{engine.Fail, engine.Fail, engine.Pass}); len(d) != 1 || d[0].Severity != hook.SeverityError || strings.Contains(d[0].Detail, shapeSplitNote) {
		t.Errorf("fail/fail: diags %+v, want one error with no shape note", d)
	}
	// A pass/fail split whose evaluation under change itself is not_evaluable
	// or unknown is no split: the worst outcome (fail row) keeps its error,
	// with no shape note.
	for _, worse := range []engine.State{engine.NotEvaluable, engine.Unknown} {
		for _, p := range []shapeProgram{{engine.Pass, engine.Fail, worse}, {engine.Fail, engine.Pass, worse}} {
			if d := run(p); len(d) != 1 || d[0].Severity != hook.SeverityError || strings.Contains(d[0].Detail, shapeSplitNote) {
				t.Errorf("%v/%v under change %v: diags %+v, want one error with no shape note", p.create, p.update, p.change, d)
			}
		}
	}
}

// TestPostShapesExcludeChange: the shapes of an apply_post op
// change are create and update, never change itself, so a split is decided
// on the two shapes only.
func TestPostShapesExcludeChange(t *testing.T) {
	if got := postShapes(engine.OpChange); !slices.Equal(got, []engine.Op{engine.OpCreate, engine.OpUpdate}) {
		t.Fatalf("postShapes(change) = %v, want [create update]", got)
	}
}
