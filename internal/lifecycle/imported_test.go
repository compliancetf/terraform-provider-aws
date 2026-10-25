package lifecycle

import (
	"bytes"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
)

// TestImportStampNeverChangesDecision reruns the plan, apply and
// evidence stage goldens as if the object had been imported in the plan
// process: an update plan carries op import, and every apply_pre envelope
// carries imported true (an update one also op import, which the proxy
// combines back to update). Every diagnostic must equal the golden's; only
// the plan eval record's resource.op of an update becomes import. The
// unauthenticated envelope mark never changes an apply record.
func TestImportStampNeverChangesDecision(t *testing.T) {
	stamped := 0
	for _, pattern := range []string{"plan_*.json", "apply_*.json", "evidence_*.json"} {
		runStages(t, pattern, func(t *testing.T, g *stageGolden, _ *Lifecycle) {
			if g.NotEvaluable != nil || g.VerdictRequired || g.Method != "" || g.TrustedEnv != nil || g.Exception != nil {
				t.Skip("needs its own setup")
			}
			switch {
			case g.Stage == hook.StagePlan && present(g.Prior) && present(g.Planned) && len(g.Replace) == 0 &&
				(g.Op == "" || g.Op == hook.OpUpdate):
				g.Op = hook.OpImport
			case g.Stage == hook.StageApplyPre && g.Envelope != nil:
				g.Envelope.Imported = true
				if g.Envelope.Op == hook.OpUpdate {
					g.Envelope.Op = hook.OpImport
				}
				stamped++
				return
			default:
				return
			}
			stamped++
			if e := g.Want.Evidence; e != nil && (e.Op == "update" || e.Op == "no-op") {
				e.Op = "import"
				if e.Resource != nil {
					e.Resource.Op = "import"
				}
			}
		})
	}
	if stamped == 0 {
		t.Fatal("no golden was stamped")
	}
}

// present reports whether a golden value is set and not null.
func present(v []byte) bool {
	v = bytes.TrimSpace(v)
	return len(v) > 0 && string(v) != "null"
}
