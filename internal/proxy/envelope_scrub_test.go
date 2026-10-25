package proxy

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/hook/hooktest"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
	"github.com/compliancetf/terraform-provider-aws/test/scrub/scrubtest"
)

// TestEnvelopeParseErrorsValueFree feeds apply a planned_private whose
// header carries marker text where a tamperer controls it (keys at each
// level, values, a duplicate key) and requires a block whose diagnostic and
// logs hold no marker, and a hook call that records only the
// block.
func TestEnvelopeParseErrorsValueFree(t *testing.T) {
	logs := scrubtest.CaptureLogs(t)
	m := scrubtest.Marker(90)
	for _, h := range []string{
		fmt.Sprintf(`{"v":1,"ctf":{"op":"update"},%q:1}`, m),
		fmt.Sprintf(`{"v":1,"ctf":{"op":"update","prior_identity_kind":"none",%q:true}}`, m),
		fmt.Sprintf(`{"v":%q,"ctf":{"op":"update"}}`, m),
		fmt.Sprintf(`{"v":1,"ctf":{"op":%q}}`, m),
		fmt.Sprintf(`{"v":1,"ctf":{"op":"update","prior_identity_kind":%q}}`, m),
		fmt.Sprintf(`{"v":1,"ctf":{"op":"update","control_versions_digest":{%q:1}}}`, m),
		fmt.Sprintf(`{"v":1,%q:1,%q:2,"ctf":{"op":"update"}}`, m, m),
		fmt.Sprintf(`{"v":1,"ctf":{"op":"update"}}%s`, m),
	} {
		rec := &hooktest.Recorder{}
		client, up, _ := startRoute(t, rec)
		got, err := client.ApplyResourceChange(context.Background(), &tfplugin5.ApplyResourceChange_Request{
			TypeName: "fake_thing", PriorState: thing(t, "p"), PlannedState: thing(t, "q"), Config: thing(t, "cfg"), PlannedPrivate: rawEnv(h, "pp"),
		})
		scrubtest.Must(t, "apply error", err)
		if !slices.Equal(summaries(got.Diagnostics), []string{"ERROR:Invalid compliance plan envelope"}) || slices.Contains(up.calls, "ApplyResourceChange") {
			t.Errorf("header %s: diagnostics %s, want only the invalid envelope block", scrubtest.Mask(h), scrubtest.Mask(fmt.Sprint(summaries(got.Diagnostics))))
		}
		// The hook sees only the block: no envelope byte.
		for _, r := range rec.Requests() {
			scrubtest.NoMarker(t, "hook request", fmt.Sprintf("%+v", *r))
			if r.Blocked != hook.BlockEnvelopeInvalid || r.Envelope != nil || r.Config != nil || r.Prior != nil || r.Planned != nil {
				t.Errorf("header %s: hook request %s, want only the invalid envelope block", scrubtest.Mask(h), scrubtest.Mask(fmt.Sprintf("%+v", *r)))
			}
		}
		for _, d := range got.Diagnostics {
			scrubtest.NoMarker(t, "diagnostic summary", d.Summary)
			scrubtest.NoMarker(t, "diagnostic detail", d.Detail)
		}
	}
	scrubtest.NoMarker(t, "logs", logs())
}
