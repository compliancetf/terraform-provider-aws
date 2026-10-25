package proxy

import (
	"errors"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

// exitedDiagnostic turns an upstream exit on an intercepted RPC into a fresh
// response carrying only the "upstream provider exited" error diagnostic;
// Terraform would show a gRPC error as "Plugin did not respond". A response without a diagnostics field (Stop)
// and every other error pass through unchanged.
func exitedDiagnostic[Resp proto.Message](resp Resp, err error) (any, error) {
	var ex *upstream.ExitedError
	if !errors.As(err, &ex) {
		return resp, err
	}
	m := resp.ProtoReflect().New()
	fd := m.Descriptor().Fields().ByName("diagnostics")
	if fd == nil {
		return resp, err
	}
	d := &tfplugin5.Diagnostic{Severity: tfplugin5.Diagnostic_ERROR, Summary: upstream.ExitedSummary, Detail: ex.Detail()}
	m.Mutable(fd).List().Append(protoreflect.ValueOfMessage(d.ProtoReflect()))
	return m.Interface(), nil
}
