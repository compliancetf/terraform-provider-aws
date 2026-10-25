//go:build record

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// TestRecordApply: a record build dumps each apply request's PlannedState
// (msgpack and type JSON) and the envelope header under
// COMPLIANCETF_RECORD_DIR, one name per instance; the envelope carries
// prior_identity_kind and nothing of upstream's private bytes.
func TestRecordApply(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("COMPLIANCETF_RECORD_DIR", dir)
	client, _, _ := startRoute(t, hook.Noop{})
	plan, err := client.PlanResourceChange(context.Background(), &tfplugin5.PlanResourceChange_Request{
		TypeName: "fake_thing", PriorState: thing(t, "p"), Config: thing(t, "cfg"),
		PriorIdentity: identityMsgpack(t, map[string]any{"account_id": "123456789012", "bucket": "bobthecorp-logs"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, planned := range []*tfplugin5.DynamicValue{plan.PlannedState, thing(t, "")} { // update, then the delete of the same prior
		if _, err := client.ApplyResourceChange(context.Background(), &tfplugin5.ApplyResourceChange_Request{
			TypeName: "fake_thing", PriorState: thing(t, "p"), PlannedState: planned, Config: thing(t, "cfg"), PlannedPrivate: plan.PlannedPrivate,
			PlannedIdentity: identityMsgpack(t, map[string]any{"account_id": "123456789012", "bucket": "bobthecorp-logs"}),
		}); err != nil {
			t.Fatal(err)
		}
	}
	msgs, _ := filepath.Glob(filepath.Join(dir, "apply", "fake_thing.*.msgpack"))
	if len(msgs) != 2 {
		t.Fatalf("apply dumps = %v, want one per instance request", msgs)
	}
	for i, m := range msgs {
		name := strings.TrimSuffix(filepath.Base(m), ".msgpack")
		b, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		tj, err := os.ReadFile(filepath.Join(dir, "apply", name+".type.json"))
		if err != nil {
			t.Fatal(err)
		}
		typ, err := tftypes.ParseJSONType(tj) //nolint:staticcheck // the recorded wire form
		if err != nil || !typ.Equal(thingType) {
			t.Errorf("%s: type %s (%v), want fake_thing's", name, tj, err)
		}
		if !bytes.Equal(b, plan.PlannedState.Msgpack) && !bytes.Equal(b, thing(t, "").Msgpack) {
			t.Errorf("%s: msgpack is not a request's PlannedState", name)
		}
		eb, err := os.ReadFile(filepath.Join(dir, "envelope", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var h hook.EnvelopeHeader
		if err := json.Unmarshal(eb, &h); err != nil || h.CTF.PriorIdentityKind != "identity" || len(h.CTF.PriorIdentity) == 0 {
			t.Errorf("%s: envelope %s (%v), want prior_identity_kind identity", name, eb, err)
		}
		if bytes.Contains(eb, []byte("upstream-planned-private")) {
			t.Errorf("%s: envelope dump carries upstream private bytes", name)
		}
		for _, f := range []string{m, filepath.Join(dir, "envelope", name+".json")} {
			if st, err := os.Stat(f); err != nil || st.Mode().Perm() != 0o600 {
				t.Errorf("file %d %s mode %v (%v), want 0600", i, f, st.Mode(), err)
			}
		}
	}
}

// TestRecordTypeName: a type name that is not a plain identifier is never a
// file name.
func TestRecordTypeName(t *testing.T) {
	dir := t.TempDir()
	req := &tfplugin5.ApplyResourceChange_Request{TypeName: "../fake_thing", PlannedState: &tfplugin5.DynamicValue{Msgpack: []byte{0xc0}}}
	if err := writeRecord(context.Background(), nil, dir, req, nil); err == nil {
		t.Fatal("wrote a record for ../fake_thing")
	}
}
