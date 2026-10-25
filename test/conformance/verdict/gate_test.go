//go:build conformance

package verdict

// The gate stand-in (harness.GatePlan, harness.GateSign) with this suite's
// defaults: the planfile gate.tfplan and the binding the provider loaded.

import (
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
)

// gatePlan gates `plan -out=gate.tfplan` with args (harness.GatePlan).
func (r *run) gatePlan(args ...string) *gate {
	r.T.Helper()
	return r.GatePlan("gate", args...)
}

// gateSign signs g's entries (after edit, when set) plus extra under the
// provider's loaded binding with k.
func (r *run) gateSign(g *gate, k verdicttest.Key, edit func([]verdict.Instance), extra ...verdict.Instance) {
	r.T.Helper()
	r.GateSign(g, k, r.loaded(), edit, extra)
}

// entry returns a pointer to the entry of address (deposed "" for the
// current object) in ins.
func entry(ins []verdict.Instance, address, deposed string) *verdict.Instance {
	for i := range ins {
		if ins[i].Address == address && ins[i].Deposed == deposed {
			return &ins[i]
		}
	}
	return nil
}
