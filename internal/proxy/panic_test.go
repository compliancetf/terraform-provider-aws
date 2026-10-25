package proxy

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/hook/hooktest"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// secretMarker stands in for a config value or secret a panic message may carry.
const secretMarker = "SECRET-MARKER-bobthecorp"

// panicSecretWants panics with the marker in Wants.
type panicSecretWants struct{ *hooktest.Recorder }

func (panicSecretWants) Wants(hook.Kind, string) bool { panic("wants: " + secretMarker) }

// secretErr is an error panic value; %v would print its message.
type secretErr struct{}

func (secretErr) Error() string { return "error: " + secretMarker }

// TestPanicValueNeverLeaks: whatever an evaluator panics with stays out of the
// log and out of every diagnostic; only the panic type and a fixed reason are
// logged.
func TestPanicValueNeverLeaks(t *testing.T) {
	var logs bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })

	boom := func() { panic("evaluate: " + secretMarker) }
	rec := &hooktest.Recorder{
		Respond:     func(*hook.Request) (*hook.Result, error) { boom(); return nil, nil },
		OnConfigure: func(*hook.ConfigureRequest) ([]hook.Diagnostic, error) { boom(); return nil, nil },
	}
	ctx := context.Background()
	applyReq := func() *tfplugin5.ApplyResourceChange_Request {
		return &tfplugin5.ApplyResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"), PlannedState: thing(t, "planned")}
	}
	var diags []*tfplugin5.Diagnostic

	client, _, _ := startRoute(t, rec)
	c, err := client.Configure(ctx, &tfplugin5.Configure_Request{Config: combinedConfig(t, "advisory")})
	if err != nil {
		t.Fatal(err)
	}
	diags = append(diags, c.Diagnostics...)
	a, err := client.ApplyResourceChange(ctx, applyReq())
	if err != nil {
		t.Fatal(err)
	}
	diags = append(diags, a.Diagnostics...)

	wclient, _, _ := startRoute(t, panicSecretWants{&hooktest.Recorder{}})
	w, err := wclient.ApplyResourceChange(ctx, applyReq())
	if err != nil {
		t.Fatal(err)
	}
	diags = append(diags, w.Diagnostics...)

	// Error-typed panic values (plain and wrapped) at apply_pre.
	for _, v := range []any{secretErr{}, fmt.Errorf("wrapped: %w", secretErr{})} {
		rec.Respond = func(*hook.Request) (*hook.Result, error) { panic(v) }
		e, err := client.ApplyResourceChange(ctx, applyReq())
		if err != nil {
			t.Fatal(err)
		}
		diags = append(diags, e.Diagnostics...)
	}

	if len(diags) == 0 || logs.Len() == 0 {
		t.Fatalf("diagnostics %v, log %q: want both non-empty", summaries(diags), logs.String())
	}
	for _, d := range diags {
		if strings.Contains(d.Summary, secretMarker) || strings.Contains(d.Detail, secretMarker) {
			t.Errorf("diagnostic leaks the panic value: %q / %q", d.Summary, d.Detail)
		}
	}
	out := logs.String()
	for _, typ := range []string{"(string)", "(proxy.secretErr)", "(*fmt.wrapError)"} {
		if !strings.Contains(out, "compliance evaluator panicked "+typ) {
			t.Errorf("log %q: want a line naming panic type %s", out, typ)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.Contains(line, secretMarker) {
			t.Errorf("log line leaks the panic value: %q", line)
		}
		if !strings.Contains(line, "compliance evaluator panicked (") {
			t.Errorf("log line %q: want only the panic type and fixed reason", line)
		}
	}
}
