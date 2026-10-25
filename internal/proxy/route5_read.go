package proxy

// route5_read.go routes the read-side RPCs through the compliance hook. Read,
// ReadDataSource and ImportResourceState forward first and only append hook
// diagnostics; OpenEphemeralResource runs the hook on the request config and
// forwards only when that found no error. Every response field other than
// diagnostics passes untouched, and an ephemeral result, like renew and close
// payloads (passthrough), is never decoded or logged.

import (
	"context"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// ReadResource evaluates the refreshed state; an upstream error leaves no
// state to evaluate and is returned unchanged.
func (s *server5) ReadResource(ctx context.Context, req *tfplugin5.ReadResource_Request) (*tfplugin5.ReadResource_Response, error) {
	resp, err := s.up.ReadResource(ctx, req)
	if err != nil {
		return nil, s.upErr("ReadResource", err)
	}
	if hasErrorDiag(resp.Diagnostics) {
		return resp, nil
	}
	want, failed := s.wants(hook.StageRead, req.TypeName)
	if !want {
		return resp, nil
	}
	resp.Diagnostics = append(append(resp.Diagnostics, failed...), s.evaluate(ctx, &hook.Request{
		Stage:    hook.StageRead,
		Prior:    s.value(ctx, req.TypeName, req.CurrentState),
		New:      s.value(ctx, req.TypeName, resp.NewState),
		Identity: identityObject(resp.NewIdentity),
	}, req.TypeName)...)
	return resp, nil
}

// ReadDataSource evaluates the data source result; an upstream error is
// returned unchanged.
func (s *server5) ReadDataSource(ctx context.Context, req *tfplugin5.ReadDataSource_Request) (*tfplugin5.ReadDataSource_Response, error) {
	resp, err := s.up.ReadDataSource(ctx, req)
	if err != nil {
		return nil, s.upErr("ReadDataSource", err)
	}
	if hasErrorDiag(resp.Diagnostics) {
		return resp, nil
	}
	want, failed := s.wantsOf(hook.KindDataSource, hook.StageDataSource, req.TypeName)
	if !want {
		return resp, nil
	}
	resp.Diagnostics = append(append(resp.Diagnostics, failed...), s.evaluate(ctx, &hook.Request{
		Stage:  hook.StageDataSource,
		Kind:   hook.KindDataSource,
		Config: s.valueOf(ctx, hook.KindDataSource, req.TypeName, req.Config),
		New:    s.valueOf(ctx, hook.KindDataSource, req.TypeName, resp.State),
	}, req.TypeName)...)
	return resp, nil
}

// OpenEphemeralResource evaluates the request config only. An error
// diagnostic returns a response with diagnostics only, upstream not called.
// resp.Result is never read.
func (s *server5) OpenEphemeralResource(ctx context.Context, req *tfplugin5.OpenEphemeralResource_Request) (*tfplugin5.OpenEphemeralResource_Response, error) {
	want, diags := s.wantsOf(hook.KindEphemeral, hook.StageEphemeralOpen, req.TypeName)
	if want {
		diags = append(diags, s.evaluate(ctx, &hook.Request{
			Stage:  hook.StageEphemeralOpen,
			Kind:   hook.KindEphemeral,
			Config: s.valueOf(ctx, hook.KindEphemeral, req.TypeName, req.Config),
		}, req.TypeName)...)
		if hasErrorDiag(diags) {
			return &tfplugin5.OpenEphemeralResource_Response{Diagnostics: diags}, nil
		}
	}
	resp, err := s.up.OpenEphemeralResource(ctx, req)
	if err != nil {
		return nil, s.upErr("OpenEphemeralResource", err)
	}
	resp.Diagnostics = append(resp.Diagnostics, diags...)
	return resp, nil
}

// ImportResourceState evaluates each imported object, in upstream order,
// under its own type name; an upstream error is returned unchanged.
func (s *server5) ImportResourceState(ctx context.Context, req *tfplugin5.ImportResourceState_Request) (*tfplugin5.ImportResourceState_Response, error) {
	resp, err := s.up.ImportResourceState(ctx, req)
	if err != nil {
		return nil, s.upErr("ImportResourceState", err)
	}
	if hasErrorDiag(resp.Diagnostics) {
		return resp, nil
	}
	for _, r := range resp.ImportedResources {
		want, failed := s.wants(hook.StageImport, r.TypeName)
		if !want {
			continue
		}
		resp.Diagnostics = append(append(resp.Diagnostics, failed...), s.evaluate(ctx, &hook.Request{
			Stage:    hook.StageImport,
			Op:       hook.OpImport,
			New:      s.value(ctx, r.TypeName, r.State),
			Identity: identityObject(r.Identity),
		}, r.TypeName)...)
	}
	s.recordImported(ctx, resp)
	return resp, nil
}
