//go:build conformance

package verdict

import (
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
)

// TestEnvelopeDeleteKeySpoof: the verdict also holds a passing
// delete entry keyed kind identity {"id": "bobthecorp-other"}; an envelope
// edited to name that identity must not let the destroy RPC match it while
// the real entry's delete decision fails. fake_replace has no identity
// schema, so the request carries no identity and kind identity is refused.
func TestEnvelopeDeleteKeySpoof(t *testing.T) {
	k := newKey(t)
	r := newRun(t, replaceTF(false), gated(k))
	_, res := r.applyGated(k, pass)
	ok(t, res)
	g := r.gatePlan("-destroy")
	real := entry(g.Instances, "fake_replace.r", "")
	if real == nil || real.DeleteKey == "" {
		t.Fatalf("destroy entry %+v", real)
	}
	spoof := *real
	spoof.Address, spoof.PriorIdentityKind = "fake_replace.spoof", verdict.KindIdentity
	var err error
	if spoof.DeleteKey, err = verdict.Key(verdicttest.Leaf(t, g.Secret), "fake_replace", verdict.FormDelete, tftypes.Value{}, nil, []byte(`{"id":"bobthecorp-other"}`)); err != nil {
		t.Fatal(err)
	}
	g.Instances = append(g.Instances, spoof)
	r.gateSign(g, k, func(ins []verdict.Instance) {
		decide(ins, verdict.ResultPass, verdict.ResultFail)
		entry(ins, "fake_replace.spoof", "").DeleteDecisions[0].Result = verdict.ResultPass
	})
	before := r.State()
	r.envelope(`{"ctf": {"prior_identity_kind": "identity", "prior_identity": {"id": "bobthecorp-other"}}}`)
	res = r.TF("apply", "-no-color", "-input=false", g.File)
	r.envelope("")
	if res.Exit == 0 || strings.Contains(res.Stdout, "Apply complete") {
		t.Fatalf("an edited envelope matched another identity's passing delete entry\n%s%s", res.Stdout, res.Stderr)
	}
	if !strings.Contains(strings.Join(strings.Fields(res.Stderr), " "), "Envelope disagrees with prior state") {
		t.Fatalf("blocked without the envelope check:\n%s", res.Stderr)
	}
	if after := r.State(); !reflect.DeepEqual(resources(before), resources(after)) {
		t.Fatal("state changed")
	}
}
