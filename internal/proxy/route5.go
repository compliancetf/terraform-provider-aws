package proxy

// route5.go routes the resource change RPCs through the compliance hook:
// validate runs the hook then forwards, plan forwards then runs the hook,
// apply runs apply_pre for every request (Wants is not consulted), forwards
// only when that found no error, then runs apply_post. Proxy diagnostics
// follow upstream diagnostics; new_state and private pass untouched.

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

func (s *server5) ValidateResourceTypeConfig(ctx context.Context, req *tfplugin5.ValidateResourceTypeConfig_Request) (*tfplugin5.ValidateResourceTypeConfig_Response, error) {
	want, diags := s.wants(hook.StageValidate, req.TypeName)
	if want {
		diags = append(diags, s.evaluate(ctx, &hook.Request{Stage: hook.StageValidate, Config: s.value(ctx, req.TypeName, req.Config)}, req.TypeName)...)
	}
	resp, err := s.up.ValidateResourceTypeConfig(ctx, req)
	if err != nil {
		return nil, s.upErr("ValidateResourceTypeConfig", err)
	}
	resp.Diagnostics = append(resp.Diagnostics, diags...)
	return resp, nil
}

// PlanResourceChange returns an upstream error unchanged: there is no planned
// value to evaluate. Otherwise it stamps the op and the prior identity and
// wraps planned_private in the compliance envelope, also when the evaluator
// wants nothing.
func (s *server5) PlanResourceChange(ctx context.Context, req *tfplugin5.PlanResourceChange_Request) (*tfplugin5.PlanResourceChange_Response, error) {
	carriedID, carriedKind, carried := carriedPrior(req)
	req.PriorPrivate = upstreamPrivate(req.PriorPrivate)
	resp, err := s.up.PlanResourceChange(ctx, req)
	if err != nil {
		return nil, s.upErr("PlanResourceChange", err)
	}
	if hasErrorDiag(resp.Diagnostics) {
		return resp, nil
	}
	op := planOp(req.PriorState, resp.PlannedState, len(resp.RequiresReplace))
	imported := s.planImported(ctx, op, req)
	if imported && op == hook.OpUpdate {
		op = hook.OpImport // a replace stays a replace
	}
	var digest string
	if want, failed := s.wants(hook.StagePlan, req.TypeName); want {
		identity := resp.PlannedIdentity
		if isNull(resp.PlannedState) {
			identity = req.PriorIdentity
		}
		var diags []*tfplugin5.Diagnostic
		var res *hook.Result
		diags, res = s.evaluateResult(ctx, &hook.Request{
			Stage:           hook.StagePlan,
			Op:              op,
			Config:          s.value(ctx, req.TypeName, req.Config),
			Prior:           s.value(ctx, req.TypeName, req.PriorState),
			Planned:         s.value(ctx, req.TypeName, resp.PlannedState),
			RequiresReplace: fromProtoPaths(resp.RequiresReplace),
			Deferred:        resp.Deferred != nil,
			Identity:        identityObject(identity),
		}, req.TypeName)
		if res != nil {
			digest = res.ControlVersionsDigest
		}
		resp.Diagnostics = append(append(resp.Diagnostics, failed...), diags...)
	}
	if op == "" {
		return resp, nil
	}
	h := hook.EnvelopeHeader{V: 1}
	h.CTF.Op, h.CTF.ControlVersionsDigest, h.CTF.Imported = op, digest, imported
	h.CTF.PriorIdentity, h.CTF.PriorIdentityKind, err = s.priorIdentity(ctx, req)
	if carried {
		h.CTF.Op, h.CTF.PriorIdentity, h.CTF.PriorIdentityKind = hook.OpReplace, carriedID, carriedKind
	}
	var pp []byte
	if err == nil {
		pp, err = Wrap(h, resp.PlannedPrivate)
	}
	if err != nil {
		resp.Diagnostics = append(resp.Diagnostics, &tfplugin5.Diagnostic{
			Severity: tfplugin5.Diagnostic_ERROR,
			Summary:  "Invalid compliance plan envelope",
			Detail:   fmt.Sprintf("The compliance envelope for %s cannot be written (%v). This is a provider bug; please report it.", req.TypeName, err),
		})
		return resp, nil
	}
	resp.PlannedPrivate = pp
	return resp, nil
}

// ApplyResourceChange unwraps planned_private, blocks on an unreadable or
// disagreeing envelope before the hook, then blocks on any error diagnostic
// at apply_pre. A blocked apply returns diagnostics only.
func (s *server5) ApplyResourceChange(ctx context.Context, req *tfplugin5.ApplyResourceChange_Request) (*tfplugin5.ApplyResourceChange_Response, error) {
	req.PlannedPrivate = editEnvelope(req.PlannedPrivate)
	env, upstreamPrivate, err := Unwrap(req.PlannedPrivate)
	if err != nil {
		return s.blockApply(ctx, req, hook.BlockEnvelopeInvalid, "", "Invalid compliance plan envelope",
			fmt.Sprintf("PlannedPrivate for %s carries a compliance envelope that cannot be read (%v). Re-run terraform plan.", req.TypeName, err)), nil
	}
	recordApply(ctx, s, req, env)
	if env != nil {
		if why := s.envelopeDisagrees(ctx, env, req); why != "" {
			detail := fmt.Sprintf("The compliance envelope for %s does not match the prior state of this apply; the change was not applied. Re-run terraform plan.", req.TypeName)
			if why == identityNotSent {
				detail = fmt.Sprintf("Terraform or OpenTofu did not send the identity of the %s object it destroys, so the compliance envelope cannot be confirmed; the change was not applied. Terraform 1.12 to 1.16.5 and OpenTofu (checked with 1.13) omit it on the destroy half of a replace: use Terraform 1.16.6 or later, or taint the object (terraform taint or tofu taint with its address) and apply again, since a tainted replace destroys it by resource id.", req.TypeName)
			}
			return s.blockApply(ctx, req, hook.BlockEnvelopeDisagrees, why, "Envelope disagrees with prior state", detail), nil
		}
		if env.CTF.PriorIdentityKind == "identity" && !isNull(req.PriorState) {
			env.CTF.PriorIdentity = keyIdentity(req.PlannedIdentity) // the request's identity, equal by envelopeDisagrees
		}
		req.PlannedPrivate = upstreamPrivate
	}
	op := applyOp(env, planOp(req.PriorState, req.PlannedState, 0))
	var identity map[string]any // evidence records no identity for a destroy
	if !isNull(req.PlannedState) {
		identity = identityObject(req.PlannedIdentity)
	}
	pre, preRes := s.evaluateResult(ctx, &hook.Request{
		Stage:    hook.StageApplyPre,
		Op:       op,
		Config:   s.value(ctx, req.TypeName, req.Config),
		Prior:    s.value(ctx, req.TypeName, req.PriorState),
		Planned:  s.value(ctx, req.TypeName, req.PlannedState),
		Envelope: env,
		Identity: identity,
	}, req.TypeName)
	if hasErrorDiag(pre) {
		return &tfplugin5.ApplyResourceChange_Response{Diagnostics: pre}, nil
	}
	resp, err := s.up.ApplyResourceChange(ctx, req)
	if err != nil {
		return nil, s.upErr("ApplyResourceChange", err)
	}
	tap := tapApply(req.TypeName, resp.GetNewState().GetMsgpack())
	defer func() { tap(resp.GetNewState().GetMsgpack()) }()
	resp.Diagnostics = append(resp.Diagnostics, pre...)
	if want, failed := s.wants(hook.StageApplyPost, req.TypeName); want {
		resp.Diagnostics = append(append(resp.Diagnostics, failed...), s.evaluate(ctx, &hook.Request{Stage: hook.StageApplyPost, Op: op,
			New: s.value(ctx, req.TypeName, resp.NewState), Identity: identityObject(resp.NewIdentity), Carry: carry(preRes)}, req.TypeName)...)
	}
	return resp, nil
}

// blockApply refuses an apply the proxy itself rejects; the log names the
// type and a reason, never a value. The hook records the block
// from the type and the request-shape op only: no value or envelope byte
// reaches it, and its diagnostics (a failed required evidence write) follow
// the block, which stands whatever the hook returns.
func (s *server5) blockApply(ctx context.Context, req *tfplugin5.ApplyResourceChange_Request, block, why, summary, detail string) *tfplugin5.ApplyResourceChange_Response {
	reason := block
	if why != "" {
		reason += ":" + why
	}
	hclog.Default().Named("compliance").Warn("apply blocked by the proxy", "type", req.TypeName, "reason", reason)
	rec := s.evaluate(ctx, &hook.Request{Stage: hook.StageApplyPre, Op: planOp(req.PriorState, req.PlannedState, 0), Blocked: block}, req.TypeName)
	return &tfplugin5.ApplyResourceChange_Response{Diagnostics: append([]*tfplugin5.Diagnostic{{Severity: tfplugin5.Diagnostic_ERROR, Summary: summary, Detail: detail}}, rec...)}
}

// evaluate calls the hook for an object of type typ (a resource unless
// req.Kind says otherwise) and applies the error and cancellation rules. The
// hook context ends with the request or at Stop.
func (s *server5) evaluate(ctx context.Context, req *hook.Request, typ string) []*tfplugin5.Diagnostic {
	diags, _ := s.evaluateResult(ctx, req, typ)
	return diags
}

// evaluateResult is evaluate that also returns the Result: nil when the
// evaluator failed, was stopped or returned none.
func (s *server5) evaluateResult(ctx context.Context, req *hook.Request, typ string) ([]*tfplugin5.Diagnostic, *hook.Result) {
	if req.Kind == "" {
		req.Kind = hook.KindResource
	}
	req.TypeName = typ
	if v := s.tfVersion.Load(); v != nil {
		req.TerraformVersion = *v
	}
	hctx, cancel := s.hookCtx(ctx)
	defer cancel()
	res, err := recovered(func() (*hook.Result, error) { return s.ev.Evaluate(hctx, req) })
	if req.Stage == hook.StageApplyPre && (hctx.Err() != nil || s.stopCtx.Err() != nil) {
		return []*tfplugin5.Diagnostic{{
			Severity: tfplugin5.Diagnostic_ERROR,
			Summary:  "Compliance evaluation cancelled", //nolint:misspell // fixed diagnostic text
			Detail:   fmt.Sprintf("Terraform stopped the provider before %s was evaluated; the change was not applied.", typ),
		}}, nil
	}
	if err != nil {
		return []*tfplugin5.Diagnostic{evalFailed(failSeverity(req.Stage), fmt.Sprintf("%s for %s", req.Stage, typ))}, nil
	}
	if res == nil {
		return nil, nil
	}
	return toProtoDiags(res.Diagnostics), res
}

// carry is the apply_pre Result.Carry handed to apply_post; nil without one.
func carry(res *hook.Result) any {
	if res == nil {
		return nil
	}
	return res.Carry
}

// hookCtx is ctx, also canceled when the proxy stop context is.
func (s *server5) hookCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	hctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.stopCtx, cancel)
	return hctx, func() { stop(); cancel() }
}

// failSeverity is the severity of an evaluator failure at stage: stages that
// run after upstream has acted only warn.
func failSeverity(stage hook.Stage) tfplugin5.Diagnostic_Severity {
	switch stage {
	case hook.StageApplyPost, hook.StageRead, hook.StageDataSource, hook.StageImport:
		return tfplugin5.Diagnostic_WARNING
	}
	return tfplugin5.Diagnostic_ERROR
}

// evalFailed names where evaluation failed; the error text is not shown, so
// no attribute value reaches the diagnostic.
func evalFailed(sev tfplugin5.Diagnostic_Severity, where string) *tfplugin5.Diagnostic {
	return &tfplugin5.Diagnostic{Severity: sev, Summary: "Compliance evaluation failed", Detail: where + ": evaluator error"}
}

// recovered runs an evaluator call; a panic becomes an error, so it follows
// the Go error rule instead of crashing the provider. Only the panic type is
// logged: the panic value and a stack trace (its argument words) may carry
// config values or secrets, so neither reaches the log or a diagnostic.
func recovered[T any](f func() (T, error)) (v T, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[ERROR] compliance evaluator panicked (%T)", r)
			err = errors.New("evaluator panicked")
		}
	}()
	return f()
}

// wants asks the evaluator about a resource type at stage.
func (s *server5) wants(stage hook.Stage, typ string) (bool, []*tfplugin5.Diagnostic) {
	return s.wantsOf(hook.KindResource, stage, typ)
}

// wantsOf asks the evaluator about a type of kind at stage. A panic counts as
// wanted, so the hook still runs, and also returns an evaluation failure at
// the stage severity, which the caller adds even when Evaluate then succeeds.
func (s *server5) wantsOf(kind hook.Kind, stage hook.Stage, typ string) (bool, []*tfplugin5.Diagnostic) {
	w, err := recovered(func() (bool, error) { return s.ev.Wants(kind, typ), nil })
	if err != nil {
		return true, []*tfplugin5.Diagnostic{evalFailed(failSeverity(stage), fmt.Sprintf("%s selection for %s", stage, typ))}
	}
	return w, nil
}

// value wraps dv, a resource of type typ, for the hook.
func (s *server5) value(ctx context.Context, typ string, dv *tfplugin5.DynamicValue) *hook.Value {
	return s.valueOf(ctx, hook.KindResource, typ, dv)
}

// valueOf wraps dv for the hook; the type of kind resolves on first Get. A
// schema fetch it needs ends with the request or at Stop.
func (s *server5) valueOf(ctx context.Context, kind hook.Kind, typ string, dv *tfplugin5.DynamicValue) *hook.Value {
	if dv == nil {
		return nil
	}
	return hook.NewValue(dv.Msgpack, dv.Json, func() (tftypes.Type, error) {
		fctx, cancel := s.hookCtx(ctx)
		defer cancel()
		pick, known := schemasOf[kind]
		if !known {
			return nil, fmt.Errorf("no schema table for kind %s", kind)
		}
		sch, ok, err := s.schemaOf(fctx, typ, pick)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("upstream has no schema for %s %s", kind, typ)
		}
		return sch.ValueType(), nil
	})
}

// schemaOf looks typ up in the cached upstream schema, fetching it if this
// process has not seen GetSchema (Terraform may skip it when upstream
// advertises get_provider_schema_optional).
func (s *server5) schemaOf(ctx context.Context, typ string, pick func(*tfplugin5.GetProviderSchema_Response) map[string]*tfplugin5.Schema) (*tfprotov5.Schema, bool, error) {
	resp := s.cachedSchema()
	if resp == nil {
		r, err := s.GetSchema(ctx, &tfplugin5.GetProviderSchema_Request{})
		if err != nil {
			return nil, false, err
		}
		if hasErrorDiag(r.Diagnostics) {
			return nil, false, errors.New("upstream GetSchema returned errors")
		}
		resp = r
	}
	in, ok := pick(resp)[typ]
	if !ok {
		return nil, false, nil
	}
	b, err := fromProtoBlock(in.GetBlock())
	if err != nil {
		return nil, false, err
	}
	return &tfprotov5.Schema{Version: in.Version, Block: b}, true, nil
}

// schemaSource is hook.SchemaSource over the upstream schema. A schema that
// cannot be fetched or parsed reads as absent.
// shortcut: converts per call; cache per type if the evaluator calls it per resource.
// A fetch made during Configure ends with that RPC; later fetches (the
// evaluator may keep the source) end at Stop.
type schemaSource struct {
	s     *server5
	ctx   context.Context // the Configure hook context
	ended chan struct{}   // closed when Configure returns
}

func (src schemaSource) get(typ string, pick func(*tfplugin5.GetProviderSchema_Response) map[string]*tfplugin5.Schema) (*tfprotov5.Schema, bool) {
	ctx := src.ctx
	select {
	case <-src.ended:
		ctx = src.s.stopCtx
	default:
	}
	sch, ok, err := src.s.schemaOf(ctx, typ, pick)
	return sch, ok && err == nil
}

func (src schemaSource) Resource(typ string) (*tfprotov5.Schema, bool) {
	return src.get(typ, schemasOf[hook.KindResource])
}

func (src schemaSource) DataSource(typ string) (*tfprotov5.Schema, bool) {
	return src.get(typ, schemasOf[hook.KindDataSource])
}

func (src schemaSource) EphemeralResource(typ string) (*tfprotov5.Schema, bool) {
	return src.get(typ, schemasOf[hook.KindEphemeral])
}

// schemasOf picks the schema table of each kind.
var schemasOf = map[hook.Kind]func(*tfplugin5.GetProviderSchema_Response) map[string]*tfplugin5.Schema{
	hook.KindResource:   (*tfplugin5.GetProviderSchema_Response).GetResourceSchemas,
	hook.KindDataSource: (*tfplugin5.GetProviderSchema_Response).GetDataSourceSchemas,
	hook.KindEphemeral:  (*tfplugin5.GetProviderSchema_Response).GetEphemeralResourceSchemas,
}

// fromProtoBlock keeps what value types and attribute rules need.
func fromProtoBlock(in *tfplugin5.Schema_Block) (*tfprotov5.SchemaBlock, error) {
	out := &tfprotov5.SchemaBlock{Version: in.GetVersion()}
	for _, a := range in.GetAttributes() {
		t, err := tftypes.ParseJSONType(a.Type) //nolint:staticcheck // the wire form of a schema type
		if err != nil {
			return nil, fmt.Errorf("attribute %s: %w", a.Name, err)
		}
		out.Attributes = append(out.Attributes, &tfprotov5.SchemaAttribute{
			Name: a.Name, Type: t, Required: a.Required, Optional: a.Optional, Computed: a.Computed, Sensitive: a.Sensitive,
		})
	}
	for _, nb := range in.GetBlockTypes() {
		b, err := fromProtoBlock(nb.Block)
		if err != nil {
			return nil, fmt.Errorf("block %s: %w", nb.TypeName, err)
		}
		out.BlockTypes = append(out.BlockTypes, &tfprotov5.SchemaNestedBlock{
			TypeName: nb.TypeName, Block: b, Nesting: tfprotov5.SchemaNestedBlockNestingMode(nb.Nesting), MinItems: nb.MinItems, MaxItems: nb.MaxItems,
		})
	}
	return out, nil
}

func fromProtoPaths(in []*tfplugin5.AttributePath) []*tftypes.AttributePath {
	var out []*tftypes.AttributePath
	for _, p := range in {
		path := tftypes.NewAttributePath()
		for _, st := range p.GetSteps() {
			switch sel := st.Selector.(type) {
			case *tfplugin5.AttributePath_Step_AttributeName:
				path = path.WithAttributeName(sel.AttributeName)
			case *tfplugin5.AttributePath_Step_ElementKeyString:
				path = path.WithElementKeyString(sel.ElementKeyString)
			case *tfplugin5.AttributePath_Step_ElementKeyInt:
				path = path.WithElementKeyInt(int(sel.ElementKeyInt))
			}
		}
		out = append(out, path)
	}
	return out
}

// toProtoPath stops at the first step the wire form cannot carry (a set
// element), so the attribute names the enclosing set.
func toProtoPath(in *tftypes.AttributePath) *tfplugin5.AttributePath {
	if in == nil {
		return nil
	}
	out := &tfplugin5.AttributePath{}
	for _, st := range in.Steps() {
		var sel *tfplugin5.AttributePath_Step
		switch v := st.(type) {
		case tftypes.AttributeName:
			sel = &tfplugin5.AttributePath_Step{Selector: &tfplugin5.AttributePath_Step_AttributeName{AttributeName: string(v)}}
		case tftypes.ElementKeyString:
			sel = &tfplugin5.AttributePath_Step{Selector: &tfplugin5.AttributePath_Step_ElementKeyString{ElementKeyString: string(v)}}
		case tftypes.ElementKeyInt:
			sel = &tfplugin5.AttributePath_Step{Selector: &tfplugin5.AttributePath_Step_ElementKeyInt{ElementKeyInt: int64(v)}}
		default:
			return out
		}
		out.Steps = append(out.Steps, sel)
	}
	return out
}

func toProtoDiags(in []hook.Diagnostic) []*tfplugin5.Diagnostic {
	var out []*tfplugin5.Diagnostic
	for _, d := range in {
		sev := tfplugin5.Diagnostic_ERROR
		if d.Severity == hook.SeverityWarning {
			sev = tfplugin5.Diagnostic_WARNING
		}
		out = append(out, &tfplugin5.Diagnostic{Severity: sev, Summary: d.Summary, Detail: d.Detail, Attribute: toProtoPath(d.Attribute)})
	}
	return out
}
