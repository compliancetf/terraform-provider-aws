package proxy

// scope.go is the verdict gate RPC scope: deny by
// default under verdict_required. Every tfplugin5.Provider method is named
// here as allowed or gated; a method missing from the table is gated.
// ApplyResourceChange is gated by the typed apply_pre hook (route5.go); every
// other gated method is a passthrough, sent to the hook at stage rpc before
// the forwarder opens the upstream stream. tfplugin5.Provisioner methods
// stay out of scope and pass through unchanged.

import (
	"io"
	"strings"

	"github.com/hashicorp/go-hclog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/rawgrpc"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// scopeEntry classifies a method: gated with its static evidence token
// (schema v1 resource.type), or allowed with token "".
type scopeEntry struct{ token string }

func (e scopeEntry) gated() bool { return e.token != "" }

var allow = scopeEntry{}

// rpcScope names every tfplugin5.Provider method of the pinned proto.
var rpcScope = map[string]scopeEntry{
	// Allowlisted: configure, plan, read, data source read (deferred
	// included), import, the validate and the schema RPCs.
	"Configure":                       allow,
	"PrepareProviderConfig":           allow, // validates the provider config
	"GetSchema":                       allow,
	"GetMetadata":                     allow,
	"GetResourceIdentitySchemas":      allow,
	"GetFunctions":                    allow,
	"ValidateResourceTypeConfig":      allow,
	"ValidateDataSourceConfig":        allow,
	"ValidateEphemeralResourceConfig": allow,
	"ValidateListResourceConfig":      allow,
	"ValidateActionConfig":            allow,
	"PlanResourceChange":              allow,
	"ReadResource":                    allow,
	"ReadDataSource":                  allow,
	"ImportResourceState":             allow,
	"OpenEphemeralResource":           allow, // evaluated as ephemeral controls
	"Stop":                            allow, // cancellation only; owner follow-up
	// Gated. UpgradeResourceState and UpgradeResourceIdentity are gated for
	// the before-Configure refusal; under verdict_required the lifecycle
	// passes them without a verdict.
	"ApplyResourceChange":     {"rpc_apply_resource_change"}, // typed apply_pre gate, never stage rpc
	"InvokeAction":            {"rpc_invoke_action"},
	"CallFunction":            {"rpc_call_function"},
	"UpgradeResourceState":    {"rpc_upgrade_resource_state"},
	"UpgradeResourceIdentity": {"rpc_upgrade_resource_identity"},
	"MoveResourceState":       {"rpc_move_resource_state"},
	"PlanAction":              {"rpc_plan_action"},
	"ListResource":            {"rpc_list_resource"},
	"GenerateResourceConfig":  {"rpc_generate_resource_config"},
	"RenewEphemeralResource":  {"rpc_renew_ephemeral_resource"},
	"CloseEphemeralResource":  {"rpc_close_ephemeral_resource"},
}

// scopeOf classifies a full method of the Provider service; a method the
// table does not name is gated as rpc_unclassified.
func scopeOf(method string) scopeEntry {
	if e, ok := rpcScope[strings.TrimPrefix(method, providerService)]; ok && strings.HasPrefix(method, providerService) {
		return e
	}
	return scopeEntry{"rpc_unclassified"}
}

// gatedForwarder wraps the passthrough forwarder: a gated Provider method
// reads its single request frame, passes the gate and only then reaches fwd,
// which replays that frame and nothing after it. Every other method (an
// allowed one, a provisioner method, one outside the pinned proto) goes to
// fwd unchanged.
func (s *server5) gatedForwarder(routes tfplugin.Routes, fwd grpc.StreamHandler) grpc.StreamHandler {
	return func(srv any, ss grpc.ServerStream) error {
		method, _ := grpc.MethodFromServerStream(ss)
		tapRPC(method)
		r, routed := routes[method]
		e := scopeOf(method)
		if !routed || r.Class != tfplugin.Passthrough || !strings.HasPrefix(method, providerService) || !e.gated() {
			return fwd(srv, ss)
		}
		if r.ClientStream { // none in v5; refused unconditionally
			return s.refuseRPC(method, "client_stream", "RPC refused", method+" streams client messages, which the compliance verdict gate cannot bind; it is refused.")
		}
		f := &rawgrpc.Frame{}
		if err := ss.RecvMsg(f); err != nil {
			return s.refuseRPC(method, "request_unreadable", "RPC refused", method+": the request could not be read for the compliance verdict gate.")
		}
		diags := s.evaluate(ss.Context(), &hook.Request{Stage: hook.StageRPC, Method: method, RPCRequest: f.Bytes}, e.token)
		if ss.Context().Err() != nil || s.stopCtx.Err() != nil {
			return s.refuseRPC(method, "cancelled", "Compliance evaluation cancelled", method+" was not forwarded.") //nolint:misspell // fixed diagnostic text
		}
		for _, d := range diags {
			if d.GetSeverity() == tfplugin5.Diagnostic_ERROR {
				return s.refuseRPC(method, "gate", d.GetSummary(), d.GetDetail())
			}
		}
		return fwd(srv, &replayStream{ServerStream: ss, first: f})
	}
}

// refuseRPC fails a gated RPC without opening upstream; the log names the
// method and a reason, never a value.
func (s *server5) refuseRPC(method, reason, summary, detail string) error {
	hclog.Default().Named("compliance").Warn("rpc blocked by the verdict gate", "method", method, "reason", reason)
	return status.Error(codes.FailedPrecondition, summary+": "+detail)
}

// replayStream hands the forwarder the frame the gate read, then io.EOF:
// the upstream send side closes and no later client frame is forwarded.
type replayStream struct {
	grpc.ServerStream
	first *rawgrpc.Frame
}

func (r *replayStream) RecvMsg(m any) error {
	if r.first == nil {
		return io.EOF
	}
	f, ok := m.(*rawgrpc.Frame)
	if !ok {
		return status.Error(codes.Internal, "verdict gate: unexpected message type")
	}
	*f, r.first = *r.first, nil
	return nil
}
