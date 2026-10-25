package proxy

import (
	"context"
	"path"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

// TestUpstreamExitIsDiagnostic: when the upstream process is gone, an
// intercepted RPC answers with the "upstream provider exited" error
// diagnostic, not a gRPC error Terraform shows
// as "Plugin did not respond". Stop has no diagnostics field and keeps the
// gRPC status.
func TestUpstreamExitIsDiagnostic(t *testing.T) {
	exited := func(method string, _ error) error {
		return &upstream.ExitedError{Upstream: "hashicorp/aws", Version: "6.0.0", Status: 2, RPC: path.Base(method)}
	}
	// fakeUpstream5 leaves ApplyResourceChange and ReadDataSource unimplemented,
	// so every forward of those fails and OnTransportErr reports the exit.
	c, _ := startProxy(t, &fakeUpstream5{}, Backends{OnTransportErr: exited})
	want := "hashicorp/aws 6.0.0 exited with status 2 during ApplyResourceChange. The request was not retried. Upstream output is in the Terraform log under \"upstream\"."

	apply, err := c.ApplyResourceChange(t.Context(), &tfplugin5.ApplyResourceChange_Request{TypeName: "fake_thing"})
	if err != nil {
		t.Fatalf("ApplyResourceChange: %v", err)
	}
	if d := apply.GetDiagnostics(); len(d) != 1 || d[0].GetSeverity() != tfplugin5.Diagnostic_ERROR || d[0].GetSummary() != upstream.ExitedSummary || d[0].GetDetail() != want {
		t.Fatalf("ApplyResourceChange diagnostics %v", d)
	}
	if apply.GetNewState() != nil {
		t.Fatalf("ApplyResourceChange new_state %v, want none", apply.GetNewState())
	}

	data, err := c.ReadDataSource(t.Context(), &tfplugin5.ReadDataSource_Request{TypeName: "fake_lookup"})
	if err != nil || len(data.GetDiagnostics()) != 1 || data.GetDiagnostics()[0].GetSummary() != upstream.ExitedSummary {
		t.Fatalf("ReadDataSource: %v, %v", data, err)
	}

	stop, _ := startProxy(t, &stopFails{}, Backends{OnTransportErr: exited})
	if _, err := stop.Stop(t.Context(), &tfplugin5.Stop_Request{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("Stop: %v, want Unavailable", err)
	}
}

type stopFails struct{ fakeUpstream5 }

func (*stopFails) Stop(_ context.Context, _ *tfplugin5.Stop_Request) (*tfplugin5.Stop_Response, error) {
	return nil, status.Error(codes.Unavailable, "gone")
}
