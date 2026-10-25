package lifecycle

import (
	"context"
	"errors"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// countVerdict refuses every key and counts Match calls.
type countVerdict struct{ calls int }

func (v *countVerdict) Match(context.Context, InstanceKey) error {
	v.calls++
	return errors.New("no entry")
}

// TestStateUpgradeRPCsNoRecord: under verdict_required with evidence.required
// the state upgrade RPCs pass with no Match and no stage rpc record,
// while another gated RPC is refused and recorded.
func TestStateUpgradeRPCsNoRecord(t *testing.T) {
	for _, tc := range []struct {
		method, token string
		allowed       bool
	}{
		{"/tfplugin5.Provider/UpgradeResourceState", "rpc_upgrade_resource_state", true},
		{"/tfplugin5.Provider/UpgradeResourceIdentity", "rpc_upgrade_resource_identity", true},
		{"/tfplugin5.Provider/MoveResourceState", "rpc_move_resource_state", false},
	} {
		t.Run(tc.token, func(t *testing.T) {
			v := &countVerdict{}
			l := New(Options{})
			l.verdict = v
			l.cfg = &Configured{Table: profile.ModeTable{RunMode: profile.HardFail, VerdictRequired: true}, Controls: stageControlSet(t)}
			l.cfg.Resolution.Profile = &profile.Profile{Evidence: profile.Evidence{Required: true}}
			dir := t.TempDir()
			w, err := evidence.Open(evidence.Options{Dir: dir, Run: evidence.Run{ID: "r1", IDSource: "compliancetf"}})
			if err != nil {
				t.Fatal(err)
			}
			l.ev = w
			res, err := l.Evaluate(context.Background(), &hook.Request{Stage: hook.StageRPC, Method: tc.method, TypeName: tc.token, RPCRequest: []byte("req-1")})
			if err != nil {
				t.Fatal(err)
			}
			if cerr := l.Close(); cerr != nil {
				t.Fatal(cerr)
			}
			rpcRecs := 0
			for _, r := range readChain(t, dir) {
				if r.Stage == "rpc" {
					rpcRecs++
				}
			}
			if tc.allowed {
				if v.calls != 0 || rpcRecs != 0 || len(res.Diagnostics) != 0 {
					t.Fatalf("allowlisted: Match calls %d, rpc records %d, diags %+v", v.calls, rpcRecs, res.Diagnostics)
				}
				return
			}
			if v.calls != 1 || rpcRecs != 1 || len(res.Diagnostics) == 0 || res.Diagnostics[0].Summary != gateSummary {
				t.Fatalf("gated: Match calls %d, rpc records %d, diags %+v", v.calls, rpcRecs, res.Diagnostics)
			}
		})
	}
}
