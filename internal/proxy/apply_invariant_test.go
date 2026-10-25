//go:build ctftest

package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/hook/hooktest"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

// fakeResourceType is fake_thing as the test/fakeupstream binary declares it.
var fakeResourceType = tftypes.Object{AttributeTypes: map[string]tftypes.Type{
	"id": tftypes.String, "name": tftypes.String, "size": tftypes.Number, "crash": tftypes.Bool,
}}

func fakeThing(t *testing.T, id any, size any) *tfplugin5.DynamicValue {
	t.Helper()
	dv, err := tfprotov5.NewDynamicValue(fakeResourceType, tftypes.NewValue(fakeResourceType, map[string]tftypes.Value{
		"id":    tftypes.NewValue(tftypes.String, id),
		"name":  tftypes.NewValue(tftypes.String, "bobthecorp-thing"),
		"size":  tftypes.NewValue(tftypes.Number, size),
		"crash": tftypes.NewValue(tftypes.Bool, nil),
	}))
	if err != nil {
		t.Fatal(err)
	}
	return &tfplugin5.DynamicValue{Msgpack: dv.MsgPack}
}

// TestNewStateInvariant drives ApplyResourceChange through the proxy (served
// over bufconn) against the fake upstream binary, whose new_state msgpack is
// deliberately non-canonical, and requires new_state and private to be
// byte-equal to what the same upstream returns without the proxy.
func TestNewStateInvariant(t *testing.T) {
	upConn := launchFake(t)
	direct := tfplugin5.NewProviderClient(upConn)

	evaluators := map[string]func() hook.Evaluator{
		"noop": func() hook.Evaluator { return hook.Noop{} },
		"warning": func() hook.Evaluator {
			return &hooktest.Recorder{Respond: func(r *hook.Request) (*hook.Result, error) {
				return &hook.Result{Diagnostics: []hook.Diagnostic{{Severity: hook.SeverityWarning, Summary: string(r.Stage)}}}, nil
			}}
		},
		"error_after_apply": func() hook.Evaluator {
			return &hooktest.Recorder{Respond: func(r *hook.Request) (*hook.Result, error) {
				if r.Stage == hook.StageApplyPost {
					return &hook.Result{Diagnostics: []hook.Diagnostic{{Severity: hook.SeverityError, Summary: "denied"}}}, nil
				}
				return &hook.Result{}, nil
			}}
		},
		"failing_after_apply": func() hook.Evaluator {
			return &hooktest.Recorder{Respond: func(r *hook.Request) (*hook.Result, error) {
				if r.Stage == hook.StageApplyPost {
					return nil, errors.New("evaluator broke")
				}
				return &hook.Result{}, nil
			}}
		},
	}
	ops := map[string]*tfplugin5.DynamicValue{
		"create": nil,
		"update": fakeThing(t, "bobthecorp-thing", 1),
	}
	for evName, newEv := range evaluators {
		for opName, prior := range ops {
			t.Run(evName+"/"+opName, func(t *testing.T) {
				b := Backends{Evaluator: newEv(), Upstream: upConn, UpstreamSHA256: testUpstreamSHA}
				p := newServer5(b)
				proxied := tfplugin5.NewProviderClient(bufDial(t, func(s *grpc.Server) { registerIntercepts(s, p) }, serverOptions(b, p)...))
				ctx := context.Background()

				cfg := fakeThing(t, nil, 3)
				plan, err := proxied.PlanResourceChange(ctx, &tfplugin5.PlanResourceChange_Request{
					TypeName: "fake_thing", PriorState: orNull(t, prior), ProposedNewState: cfg, Config: cfg,
				})
				if err != nil {
					t.Fatal(err)
				}
				env, upstreamPrivate, err := Unwrap(plan.PlannedPrivate)
				if err != nil || env == nil {
					t.Fatalf("plan through the proxy returned no envelope (%v)", err)
				}
				apply := func(pp []byte) *tfplugin5.ApplyResourceChange_Request {
					return &tfplugin5.ApplyResourceChange_Request{
						TypeName: "fake_thing", PriorState: orNull(t, prior), PlannedState: plan.PlannedState, Config: cfg, PlannedPrivate: pp,
					}
				}
				want, err := direct.ApplyResourceChange(ctx, apply(upstreamPrivate))
				if err != nil {
					t.Fatal(err)
				}
				checkNonCanonical(t, want.GetNewState().GetMsgpack())
				got, err := proxied.ApplyResourceChange(ctx, apply(plan.PlannedPrivate))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.GetNewState().GetMsgpack(), want.GetNewState().GetMsgpack()) {
					t.Errorf("new_state.msgpack = %x, upstream returned %x", got.GetNewState().GetMsgpack(), want.GetNewState().GetMsgpack())
				}
				if !bytes.Equal(got.GetPrivate(), want.GetPrivate()) {
					t.Errorf("private = %q, upstream returned %q", got.GetPrivate(), want.GetPrivate())
				}
			})
		}
	}
}

// orNull is dv, or a null fake_thing when dv is nil (create).
func orNull(t *testing.T, dv *tfplugin5.DynamicValue) *tfplugin5.DynamicValue {
	t.Helper()
	if dv != nil {
		return dv
	}
	n, err := tfprotov5.NewDynamicValue(fakeResourceType, tftypes.NewValue(fakeResourceType, nil))
	if err != nil {
		t.Fatal(err)
	}
	return &tfplugin5.DynamicValue{Msgpack: n.MsgPack}
}

// launchFake builds test/fakeupstream (v5) and launches it the way main
// launches the real upstream.
func launchFake(t *testing.T) *grpc.ClientConn {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fakeupstream")
	cmd := exec.Command("go", "build", "-o", bin, "./v5")
	cmd.Dir = filepath.Join("..", "..", "test", "fakeupstream")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake upstream: %v: %s", err, out)
	}
	u, err := upstream.Launch(context.Background(), upstream.NewTestVerifiedBinary(bin), upstream.NewLogger(io.Discard, "hashicorp/aws"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(u.Close)
	return u.Conn
}

// checkNonCanonical fails unless b differs from its canonical re-encoding,
// so byte equality proves forwarding rather than re-encoding.
func checkNonCanonical(t *testing.T, b []byte) {
	t.Helper()
	v, err := (&tfprotov5.DynamicValue{MsgPack: b}).Unmarshal(fakeResourceType)
	if err != nil {
		t.Fatal(err)
	}
	dv, err := tfprotov5.NewDynamicValue(fakeResourceType, v)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dv.MsgPack, b) {
		t.Fatal("fake upstream new_state is canonical; the invariant test proves nothing")
	}
}
