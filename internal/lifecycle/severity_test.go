package lifecycle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

type severityRow struct {
	Stage    Stage         `json:"stage"`
	Op       engine.Op     `json:"op"`
	Mode     profile.Mode  `json:"mode"`
	Action   bundle.Action `json:"action"`
	State    engine.State  `json:"state"`
	Severity Severity      `json:"severity"`
	Forward  bool          `json:"forward"`
}

// stageOps lists the ops each stage can see (0A classify.go; read records refresh).
var stageOps = map[Stage][]engine.Op{
	StagePlan:      {engine.OpCreate, engine.OpUpdate, engine.OpReplace, engine.OpDelete},
	StageApplyPre:  {engine.OpCreate, engine.OpUpdate, engine.OpReplace, engine.OpDelete, engine.OpChange},
	StageApplyPost: {engine.OpCreate, engine.OpUpdate, engine.OpReplace, engine.OpChange},
	StageRead:      {engine.OpRefresh},
	// ephemeral_open takes the apply_pre column.
	StageEphemeralOpen: {engine.OpOpen},
}

func TestSeverityMatrix(t *testing.T) {
	raw, err := os.ReadFile("testdata/severity_matrix.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Rows []severityRow `json:"rows"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&golden); err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for _, r := range golden.Rows {
		key := fmt.Sprintf("%s/%s/%s/%s/%s", r.Stage, r.Op, r.Mode, r.Action, r.State)
		if seen[key] {
			t.Errorf("duplicate golden row %s", key)
		}
		seen[key] = true
		got := Classify(r.Mode, r.Action, r.State, r.Stage, r.Op, false)
		want := Cell{Severity: r.Severity, Forward: r.Forward}
		if got != want {
			t.Errorf("%s: got %+v, want %+v", key, got, want)
		}
	}

	// The golden must cover the full cross product, so no cell is left implicit.
	modes := []profile.Mode{profile.Advisory, profile.SoftFail, profile.Grandfather, profile.HardFail}
	actions := []bundle.Action{bundle.ActionDeny, bundle.ActionWarn}
	states := []engine.State{engine.Pass, engine.Fail, engine.Unknown, engine.NotEvaluable}
	for stage, ops := range stageOps {
		for _, op := range ops {
			for _, m := range modes {
				for _, a := range actions {
					for _, s := range states {
						key := fmt.Sprintf("%s/%s/%s/%s/%s", stage, op, m, a, s)
						if !seen[key] {
							t.Errorf("golden misses row %s", key)
						}
					}
				}
			}
		}
	}
}

// TestSeverityNotEvaluableNeverBetterThanFail checks the never-better-than-fail rule across the whole matrix.
func TestSeverityNotEvaluableNeverBetterThanFail(t *testing.T) {
	for stage, ops := range stageOps {
		for _, op := range ops {
			for _, m := range []profile.Mode{profile.Advisory, profile.SoftFail, profile.Grandfather, profile.HardFail} {
				for _, a := range []bundle.Action{bundle.ActionDeny, bundle.ActionWarn} {
					f := Classify(m, a, engine.Fail, stage, op, false)
					ne := Classify(m, a, engine.NotEvaluable, stage, op, false)
					if ne != f {
						t.Errorf("%s/%s/%s/%s: not_evaluable %+v differs from fail %+v", stage, op, m, a, ne, f)
					}
					if bad := Classify(m, a, engine.State(99), stage, op, false); bad != f {
						t.Errorf("%s/%s/%s/%s: invalid state %+v differs from fail %+v", stage, op, m, a, bad, f)
					}
				}
			}
		}
	}
}
