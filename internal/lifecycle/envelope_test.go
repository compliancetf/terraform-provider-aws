package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// TestEnvelopeNeverNarrows pins the obligations: blocking
// controls follow the RPC shape. In hard_fail and grandfather (this version
// grandfathers nothing, so both block), for each shape (create, update, delete) the
// baseline is the shape's own op with no envelope; every other Request.Op
// (change included), every envelope op and a missing, empty or stale
// control_versions_digest must block at least the baseline's controls.
// The controls compile against dbSchemas, and three of them read op:
// the envelope steers Request.Op to replace or change, and a
// control such as op == "create" && !encrypted must not pass on that.
func TestEnvelopeNeverNarrows(t *testing.T) {
	bad := json.RawMessage(`{"storage_encrypted":false,"kms_key_id":null,"engine":"postgres","deletion_protection":false,"id":"db-1"}`)
	guarded := json.RawMessage(`{"storage_encrypted":true,"kms_key_id":"k","engine":"postgres","deletion_protection":true,"id":"db-1"}`)
	shapes := []struct {
		name                   string
		op                     hook.Op
		prior, planned, config json.RawMessage
	}{
		{"create", hook.OpCreate, nil, bad, bad},
		{"update", hook.OpUpdate, guarded, bad, bad},
		{"delete", hook.OpDelete, guarded, json.RawMessage(`null`), json.RawMessage(`null`)},
	}
	ops := []hook.Op{"", hook.OpCreate, hook.OpUpdate, hook.OpReplace, hook.OpDelete, hook.OpImport, hook.OpChange}
	cs := opControlSet(t)
	current := cs.VersionsDigest("aws_db_instance")
	run := func(t *testing.T, mode profile.Mode, stage hook.Stage, s int, op hook.Op, env *hook.EnvelopeHeader) []string {
		t.Helper()
		sh := shapes[s]
		l := New(Options{})
		// The baseline is the oracle: a baseline control that timed out under
		// load blocked as not_evaluable and then "no longer blocks" once it
		// passes on time. TestTimeoutNeverWaives pins timeouts.
		l.testPerResource = 10 * time.Second
		l.cfg = &Configured{Table: profile.ModeTable{RunMode: mode}, Controls: cs, Schemas: dbSchemas{}}
		req := &hook.Request{Stage: stage, Kind: hook.KindResource, TypeName: "aws_db_instance", Op: op,
			Config: dynValue(t, sh.config), Prior: dynValue(t, sh.prior), Planned: dynValue(t, sh.planned), Envelope: env}
		res, err := l.Evaluate(context.Background(), req)
		if err != nil {
			t.Fatalf("%s %s op %q: %v", stage, sh.name, op, err)
		}
		var blocked []string
		for _, d := range res.Diagnostics {
			if d.Severity == hook.SeverityError {
				blocked = append(blocked, strings.SplitN(d.Summary, "]", 2)[0])
			}
		}
		return blocked
	}
	for _, mode := range []profile.Mode{profile.HardFail, profile.Grandfather} {
		for s, sh := range shapes {
			for _, stage := range []hook.Stage{hook.StagePlan, hook.StageApplyPre} {
				base := run(t, mode, stage, s, sh.op, nil)
				if !slices.Contains(base, "["+opReading[s]) {
					t.Fatalf("%s %s: baseline does not block %s, the oracle proves nothing (got %v)", stage, sh.name, opReading[s], base)
				}
				envs := []*hook.EnvelopeHeader{nil}
				if stage == hook.StageApplyPre {
					for _, d := range []string{current, "", "sha256:stale"} {
						for _, eop := range ops[1:] {
							e := &hook.EnvelopeHeader{V: 1}
							e.CTF.Op, e.CTF.ControlVersionsDigest = eop, d
							envs = append(envs, e)
						}
					}
				}
				for _, op := range ops {
					if stage == hook.StagePlan && sh.prior == nil && (op == hook.OpReplace || op == hook.OpDelete) {
						continue // a replace or delete hint on a null Prior is a Go error (fails closed)
					}
					for _, env := range envs {
						got := run(t, mode, stage, s, op, env)
						for _, id := range base {
							if stage == hook.StagePlan && strings.HasPrefix(id, "[rds_op_") {
								continue // a plan op is the RPC shape (a replace is one), never the envelope's
							}
							if !slices.Contains(got, id) {
								t.Errorf("%s %s %s op %q envelope %s: %s no longer blocks (got %v)", mode, stage, sh.name, op, envName(env), id, got)
							}
						}
					}
				}
			}
		}
	}
}

// opReading is, per shape (create, update, delete), the op-reading control
// of opControlSet that fails on that shape's bad value under its own op.
var opReading = []string{"rds_op_create_encrypted", "rds_op_update_deletion_protection", "rds_op_delete_guard"}

// opControlSet is the stage control set plus three controls that pass under
// any op other than the one they name.
func opControlSet(t *testing.T) *bundle.ControlSet {
	t.Helper()
	extra, err := bundle.ParseControls([]byte(`[
  {"id": "rds_op_create_encrypted", "version": "1.0.0", "kind": "resource", "resource_type": "aws_db_instance",
   "reads": ["storage_encrypted"], "presence_mode": "effective", "on": ["create", "update"],
   "expr": "!(op == \"create\" && resource.storage_encrypted != true)", "action": "deny", "severity": "high",
   "message": "Encrypt at create.", "exemption_coverable": []},
  {"id": "rds_op_update_deletion_protection", "version": "1.0.0", "kind": "resource", "resource_type": "aws_db_instance",
   "reads": ["deletion_protection"], "presence_mode": "effective", "on": ["create", "update"],
   "expr": "op != \"update\" || resource.deletion_protection == true", "action": "deny", "severity": "high",
   "message": "Keep deletion protection on update.", "exemption_coverable": []},
  {"id": "rds_op_delete_guard", "version": "1.0.0", "kind": "deletion_guard", "resource_type": "aws_db_instance",
   "reads": ["deletion_protection"], "on": ["delete"],
   "expr": "op != \"delete\" || prior.deletion_protection == false", "action": "deny", "severity": "high",
   "message": "Disable deletion_protection before destroying.", "exemption_coverable": []}
]`))
	if err != nil {
		t.Fatal(err)
	}
	return stageControlSetDigest(t, "ab", extra...)
}

// TestApplyPostOpNeverNarrows: apply_post has no Prior, so its
// shape comes only from the proxy op, which the envelope steers to replace
// (the create half) or change (create or update). Every op the proxy can
// send for a shape must report at least the controls the shape's own op
// reports.
func TestApplyPostOpNeverNarrows(t *testing.T) {
	bad := json.RawMessage(`{"storage_encrypted":false,"kms_key_id":null,"engine":"postgres","deletion_protection":false,"id":"db-1"}`)
	cs := opControlSet(t)
	run := func(op hook.Op) []string {
		l := New(Options{})
		l.testPerResource = 10 * time.Second // verdicts, not the 50 ms budget under load
		l.cfg = &Configured{Table: profile.ModeTable{RunMode: profile.HardFail}, Controls: cs, Schemas: dbSchemas{}}
		res, err := l.Evaluate(context.Background(), &hook.Request{Stage: hook.StageApplyPost, Kind: hook.KindResource,
			TypeName: "aws_db_instance", Op: op, New: dynValue(t, bad)})
		if err != nil {
			t.Fatalf("op %q: %v", op, err)
		}
		var reported []string
		for _, d := range res.Diagnostics {
			reported = append(reported, strings.SplitN(d.Summary, "]", 2)[0])
		}
		return reported
	}
	for _, c := range []struct {
		shape hook.Op
		id    string
		ops   []hook.Op // what applyOp can give for this shape
	}{
		{hook.OpCreate, "rds_op_create_encrypted", []hook.Op{hook.OpReplace, hook.OpChange}},
		{hook.OpUpdate, "rds_op_update_deletion_protection", []hook.Op{hook.OpChange}},
	} {
		base := run(c.shape)
		if !slices.Contains(base, "["+c.id) {
			t.Fatalf("apply_post %s: baseline does not report %s, the oracle proves nothing (got %v)", c.shape, c.id, base)
		}
		for _, op := range c.ops {
			got := run(op)
			for _, id := range base {
				if !slices.Contains(got, id) {
					t.Errorf("apply_post %s shape, op %q: %s no longer reported (got %v)", c.shape, op, id, got)
				}
			}
		}
	}
}

func envName(e *hook.EnvelopeHeader) string {
	if e == nil {
		return "absent"
	}
	return fmt.Sprintf("{op %q digest %.16q}", e.CTF.Op, e.CTF.ControlVersionsDigest)
}
