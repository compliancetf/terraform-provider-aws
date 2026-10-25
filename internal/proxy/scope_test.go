package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/hook/hooktest"
	"github.com/compliancetf/terraform-provider-aws/internal/rawgrpc"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// TestVerdictGateScopeTable: the table names exactly the routed Provider
// methods, every intercepted method is allowlisted or ApplyResourceChange
// (so none skips the gate), no gated route streams client messages, and a
// method the table does not name is gated as rpc_unclassified.
func TestVerdictGateScopeTable(t *testing.T) {
	routes := tfplugin.V5()
	routed := map[string]bool{}
	for m, r := range routes {
		if !strings.HasPrefix(m, providerService) {
			continue
		}
		name := strings.TrimPrefix(m, providerService)
		routed[name] = true
		e, ok := rpcScope[name]
		switch {
		case !ok:
			t.Errorf("%s is routed but not classified in rpcScope", m)
		case r.Class == tfplugin.Intercept && e.gated() && name != "ApplyResourceChange":
			t.Errorf("%s is intercepted and gated: its typed handler would skip the gate", m)
		case e.gated() && r.ClientStream:
			t.Errorf("%s is gated and client-streaming", m)
		}
	}
	for name := range rpcScope {
		if !routed[name] {
			t.Errorf("rpcScope names %s, which is not routed", name)
		}
	}
	if e := scopeOf("/tfplugin5.Provider/FutureRPC"); e.token != "rpc_unclassified" {
		t.Errorf("unnamed method scope %+v", e)
	}
}

// TestVerdictGateScope checks the lifecycle verdict_gate_rpc_scope goldens'
// method classification: allowlisted ones are never gated, gated ones carry
// the golden's evidence token.
func TestVerdictGateScope(t *testing.T) {
	files, _ := filepath.Glob("../lifecycle/testdata/stages/verdict_gate_rpc_*.json")
	if len(files) < 10 {
		t.Fatalf("only %d goldens", len(files))
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var g struct {
			Method   string `json:"method"`
			Gated    bool   `json:"gated"`
			TypeName string `json:"type_name"`
		}
		if err := json.Unmarshal(raw, &g); err != nil {
			t.Fatal(err)
		}
		e := scopeOf(g.Method)
		if e.gated() != g.Gated || g.Gated && e.token != g.TypeName {
			t.Errorf("%s: %s scope %+v, golden gated %v token %q", filepath.Base(f), g.Method, e, g.Gated, g.TypeName)
		}
	}
}

// actionUpstream answers the gated passthroughs the gate tests use.
type actionUpstream struct {
	fakeUpstream5
}

func (a *actionUpstream) UpgradeResourceState(context.Context, *tfplugin5.UpgradeResourceState_Request) (*tfplugin5.UpgradeResourceState_Response, error) {
	a.record("UpgradeResourceState")
	return &tfplugin5.UpgradeResourceState_Response{}, nil
}

func (a *actionUpstream) InvokeAction(_ *tfplugin5.InvokeAction_Request, s grpc.ServerStreamingServer[tfplugin5.InvokeAction_Event]) error {
	a.record("InvokeAction")
	return s.Send(&tfplugin5.InvokeAction_Event{Type: &tfplugin5.InvokeAction_Event_Completed_{Completed: &tfplugin5.InvokeAction_Event_Completed{}}})
}

func (a *actionUpstream) ValidateDataSourceConfig(context.Context, *tfplugin5.ValidateDataSourceConfig_Request) (*tfplugin5.ValidateDataSourceConfig_Response, error) {
	a.record("ValidateDataSourceConfig")
	return &tfplugin5.ValidateDataSourceConfig_Response{}, nil
}

// TestVerdictGateRPC: a gated passthrough reaches the hook at stage rpc with
// its method, token and exact request bytes; refused, upstream never sees
// it; passed, it is forwarded. An allowlisted passthrough never reaches the
// gate.
func TestVerdictGateRPC(t *testing.T) {
	for _, deny := range []bool{true, false} {
		up := &actionUpstream{}
		rec := &hooktest.Recorder{Respond: func(r *hook.Request) (*hook.Result, error) {
			if deny && r.Stage == hook.StageRPC {
				return hooktest.Deny("Verdict required")(r)
			}
			return &hook.Result{}, nil
		}}
		client, _ := startProxy(t, up, Backends{Evaluator: rec})
		ctx := context.Background()
		upReq := &tfplugin5.UpgradeResourceState_Request{TypeName: "aws_s3_bucket", Version: 3}
		_, uerr := client.UpgradeResourceState(ctx, upReq)
		stream, err := client.InvokeAction(ctx, &tfplugin5.InvokeAction_Request{ActionType: "aws_lambda_invoke"})
		if err != nil {
			t.Fatal(err)
		}
		_, ierr := stream.Recv()
		if _, err := client.ValidateDataSourceConfig(ctx, &tfplugin5.ValidateDataSourceConfig_Request{TypeName: "aws_vpc"}); err != nil {
			t.Fatalf("allowlisted ValidateDataSourceConfig: %v", err)
		}
		var gate []*hook.Request
		for _, r := range rec.Requests() {
			if r.Stage == hook.StageRPC {
				gate = append(gate, r)
			}
		}
		want, _ := proto.Marshal(upReq)
		if len(gate) != 2 || gate[0].Method != providerService+"UpgradeResourceState" || gate[0].TypeName != "rpc_upgrade_resource_state" ||
			string(gate[0].RPCRequest) != string(want) || gate[1].Method != providerService+"InvokeAction" || gate[1].TypeName != "rpc_invoke_action" {
			t.Fatalf("deny=%v gate requests %+v", deny, gate)
		}
		up.mu.Lock()
		calls := strings.Join(up.calls, ",")
		up.mu.Unlock()
		if deny {
			for _, err := range []error{uerr, ierr} {
				if st := status.Convert(err); st.Code() != codes.FailedPrecondition || !strings.HasPrefix(st.Message(), "Verdict required: ") {
					t.Errorf("refused rpc: %v", err)
				}
			}
			if calls != "ValidateDataSourceConfig" {
				t.Errorf("upstream calls %q, want only the allowlisted one", calls)
			}
			continue
		}
		if uerr != nil || ierr != nil || calls != "UpgradeResourceState,InvokeAction,ValidateDataSourceConfig" {
			t.Errorf("passed rpcs: %v %v, upstream %q", uerr, ierr, calls)
		}
	}
}

// fakeStream is a server stream for a method, with scripted client frames.
type fakeStream struct {
	grpc.ServerStream
	ctx    context.Context
	frames [][]byte
}

type methodStream string

func (m methodStream) Method() string             { return string(m) }
func (methodStream) SetHeader(metadata.MD) error  { return nil }
func (methodStream) SendHeader(metadata.MD) error { return nil }
func (methodStream) SetTrailer(metadata.MD) error { return nil }
func (f *fakeStream) Context() context.Context    { return f.ctx }
func (f *fakeStream) RecvMsg(m any) error {
	if len(f.frames) == 0 {
		return io.EOF
	}
	m.(*rawgrpc.Frame).Bytes, f.frames = f.frames[0], f.frames[1:]
	return nil
}

// TestGatedForwarderUnclassified: a routed method the table does not name is
// gated, a client-streaming gated route is refused without the hook, and a
// passed call forwards only the frame the gate saw.
func TestGatedForwarderUnclassified(t *testing.T) {
	const future, futureStream = "/tfplugin5.Provider/FutureRPC", "/tfplugin5.Provider/FutureStream"
	routes := tfplugin.Routes{
		future:       {FullMethod: future, Class: tfplugin.Passthrough},
		futureStream: {FullMethod: futureStream, Class: tfplugin.Passthrough, ClientStream: true},
	}
	for _, deny := range []bool{true, false} {
		rec := &hooktest.Recorder{Respond: func(r *hook.Request) (*hook.Result, error) {
			if deny {
				return hooktest.Deny("Verdict required")(r)
			}
			return &hook.Result{}, nil
		}}
		s := newServer5(Backends{Evaluator: rec})
		var forwarded [][]byte
		fwd := func(_ any, ss grpc.ServerStream) error {
			for {
				f := &rawgrpc.Frame{}
				if err := ss.RecvMsg(f); err != nil {
					if errors.Is(err, io.EOF) {
						return nil
					}
					return err
				}
				forwarded = append(forwarded, f.Bytes)
			}
		}
		h := s.gatedForwarder(routes, fwd)
		ss := &fakeStream{ctx: grpc.NewContextWithServerTransportStream(context.Background(), methodStream(future)), frames: [][]byte{[]byte("one"), []byte("two")}}
		err := h(nil, ss)
		reqs := rec.Requests()
		if len(reqs) != 1 || reqs[0].TypeName != "rpc_unclassified" || string(reqs[0].RPCRequest) != "one" {
			t.Fatalf("deny=%v gate requests %+v", deny, reqs)
		}
		if deny && (status.Code(err) != codes.FailedPrecondition || forwarded != nil) {
			t.Errorf("refused: err %v forwarded %q", err, forwarded)
		}
		if !deny && (err != nil || len(forwarded) != 1 || string(forwarded[0]) != "one") {
			t.Errorf("passed: err %v forwarded %q (only the gated frame may reach upstream)", err, forwarded)
		}
		cs := &fakeStream{ctx: grpc.NewContextWithServerTransportStream(context.Background(), methodStream(futureStream))}
		if err := h(nil, cs); status.Code(err) != codes.FailedPrecondition || len(rec.Requests()) != 1 {
			t.Errorf("client-streaming gated route: %v", err)
		}
	}
}
