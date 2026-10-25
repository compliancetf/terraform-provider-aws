// Command fakeupstream is a fake upstream provider for proxy tests. It serves
// every RPC kind of the pinned protocol: resources fake_thing (with identity
// {id}), fake_named (with identity {name}, which differs from its id) and
// fake_replace, data source fake_lookup, ephemeral fake_secret, list
// resource fake_thing and action fake_poke (v6 adds state store fake_store,
// see v6/statestore.go and v5/nostatestore.go). ApplyResourceChange returns
// deliberately non-canonical msgpack, and crash = true on fake_thing,
// fake_replace, fake_lookup or fake_poke kills the process with a panic.
// A fake_thing or fake_replace whose name starts with "drift-" applies size
// one above the planned size and answers as a legacy (SDKv2) type system
// provider, so Terraform keeps the inconsistent result as hashicorp/aws's does.
//
// v6/provider_gen.go is generated from this file by v6/gen.sh; edit here and
// run `go generate ./v6`.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"os"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5/tf5server"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/vmihailenco/msgpack/v5"
)

func main() {
	err := tf5server.Serve("registry.terraform.io/bobthecorp/fake", func() tfprotov5.ProviderServer { return &provider{} })
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type obj = map[string]tftypes.Value

var (
	// id is Optional+Computed as on hashicorp/aws SDKv2 resources, so a deny
	// CEL control may read it (a Computed-only read is a load error).
	resourceSchema = schema(optComputed("id", tftypes.String), required("name", tftypes.String), optComputed("size", tftypes.Number), optional("crash", tftypes.Bool))
	lookupSchema   = schema(required("name", tftypes.String), computed("id", tftypes.String), optional("crash", tftypes.Bool))
	secretSchema   = schema(required("name", tftypes.String), &tfprotov5.SchemaAttribute{Name: "value", Type: tftypes.String, Computed: true, Sensitive: true})
	listSchema     = schema(optional("prefix", tftypes.String))
	pokeSchema     = schema(optional("target", tftypes.String), optional("crash", tftypes.Bool))
	identitySchema = &tfprotov5.ResourceIdentitySchema{IdentityAttributes: []*tfprotov5.ResourceIdentitySchemaAttribute{
		{Name: "id", Type: tftypes.String, RequiredForImport: true},
	}}
	namedIdentitySchema = &tfprotov5.ResourceIdentitySchema{IdentityAttributes: []*tfprotov5.ResourceIdentitySchemaAttribute{
		{Name: "name", Type: tftypes.String, RequiredForImport: true},
	}}
	// identitySchemas are the types with an identity and the attribute each
	// identity copies from the object.
	identitySchemas = map[string]*tfprotov5.ResourceIdentitySchema{"fake_thing": identitySchema, "fake_named": namedIdentitySchema}
	// providerSchema carries the hashicorp/aws attributes the proxy binds the
	// scope from (region, allowed_account_ids); the fake ignores them.
	providerSchema = schema(optional("region", tftypes.String), optional("allowed_account_ids", tftypes.Set{ElementType: tftypes.String}))
	resourceType   = resourceSchema.ValueType()
	caps           = &tfprotov5.ServerCapabilities{MoveResourceState: true, PlanDestroy: true, GenerateResourceConfig: true}
	// plannedPrivate is what PlanResourceChange returns; ApplyResourceChange
	// echoes the planned_private it receives as private.
	plannedPrivate = []byte(`{"fake":"planned"}`)
)

func schema(attrs ...*tfprotov5.SchemaAttribute) *tfprotov5.Schema {
	return &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{Attributes: attrs}}
}

func required(n string, t tftypes.Type) *tfprotov5.SchemaAttribute {
	return &tfprotov5.SchemaAttribute{Name: n, Type: t, Required: true}
}

func optional(n string, t tftypes.Type) *tfprotov5.SchemaAttribute {
	return &tfprotov5.SchemaAttribute{Name: n, Type: t, Optional: true}
}

func computed(n string, t tftypes.Type) *tfprotov5.SchemaAttribute {
	return &tfprotov5.SchemaAttribute{Name: n, Type: t, Computed: true}
}

func optComputed(n string, t tftypes.Type) *tfprotov5.SchemaAttribute {
	return &tfprotov5.SchemaAttribute{Name: n, Type: t, Optional: true, Computed: true}
}

// decode returns nil for a null or absent object.
func decode(dv *tfprotov5.DynamicValue, t tftypes.Type) (obj, error) {
	if dv == nil {
		return nil, nil
	}
	v, err := dv.Unmarshal(t)
	if err != nil || v.IsNull() {
		return nil, err
	}
	o := obj{}
	return o, v.As(&o)
}

func encode(t tftypes.Type, o obj) *tfprotov5.DynamicValue {
	v := tftypes.NewValue(t, nil)
	if o != nil {
		v = tftypes.NewValue(t, o)
	}
	dv, err := tfprotov5.NewDynamicValue(t, v)
	if err != nil {
		panic(err) // schema and values are built here; a mismatch is a bug in this file
	}
	return &dv
}

func fromRaw(raw *tfprotov5.RawState, t tftypes.Type) (*tfprotov5.DynamicValue, error) {
	if raw == nil {
		return nil, nil
	}
	v, err := raw.Unmarshal(t)
	if err != nil {
		return nil, err
	}
	dv, err := tfprotov5.NewDynamicValue(t, v)
	return &dv, err
}

func get[T any](o obj, k string) T {
	var v T
	if o[k].As(&v) != nil {
		var zero T
		return zero
	}
	return v
}

func crashIf(o obj) {
	if get[bool](o, "crash") {
		panic("fakeupstream: crash = true")
	}
}

func diags(err error) []*tfprotov5.Diagnostic {
	if err == nil {
		return nil
	}
	return []*tfprotov5.Diagnostic{{Severity: tfprotov5.DiagnosticSeverityError, Summary: "fakeupstream", Detail: err.Error()}}
}

func thing(id string) obj {
	return obj{
		"id":    tftypes.NewValue(tftypes.String, id),
		"name":  tftypes.NewValue(tftypes.String, id),
		"size":  tftypes.NewValue(tftypes.Number, 1),
		"crash": tftypes.NewValue(tftypes.Bool, nil),
	}
}

// identity returns the identity of a resource object: fake_thing {id},
// fake_named {name}; nil for a type without one.
func identity(typeName string, o obj) *tfprotov5.ResourceIdentityData {
	s := identitySchemas[typeName]
	if s == nil || o == nil {
		return nil
	}
	attr := s.IdentityAttributes[0].Name
	return &tfprotov5.ResourceIdentityData{IdentityData: encode(s.ValueType(), obj{attr: o[attr]})}
}

// nonCanonical encodes a flat object of primitives the way no canonical
// encoder does: keys in reverse order, integers as float64. Byte equality
// through the proxy then proves the proxy forwarded upstream's bytes.
func nonCanonical(o obj) ([]byte, error) {
	keys := slices.Sorted(maps.Keys(o))
	slices.Reverse(keys)
	var buf bytes.Buffer
	enc := msgpack.NewEncoder(&buf)
	err := enc.EncodeMapLen(len(keys))
	for _, k := range keys {
		v := o[k]
		err = errors.Join(err, enc.EncodeString(k))
		switch {
		case v.IsNull():
			err = errors.Join(err, enc.EncodeNil())
		case v.Type().Is(tftypes.String):
			err = errors.Join(err, enc.EncodeString(get[string](o, k)))
		case v.Type().Is(tftypes.Bool):
			err = errors.Join(err, enc.EncodeBool(get[bool](o, k)))
		case v.Type().Is(tftypes.Number):
			var f big.Float
			err = errors.Join(err, v.As(&f))
			// float64 only where it is exact, so the value Terraform decodes
			// still equals the planned one; otherwise the shortest decimal that
			// round-trips at the value's own (512-bit) precision.
			if x, acc := f.Float64(); acc == big.Exact {
				err = errors.Join(err, enc.EncodeFloat64(x))
			} else {
				err = errors.Join(err, enc.EncodeString(f.Text('g', -1)))
			}
		default:
			err = errors.Join(err, fmt.Errorf("nonCanonical: unsupported attribute %s", k))
		}
	}
	return buf.Bytes(), err
}

type provider struct{}

func (p *provider) GetMetadata(context.Context, *tfprotov5.GetMetadataRequest) (*tfprotov5.GetMetadataResponse, error) {
	return withStateStoreMetadata(&tfprotov5.GetMetadataResponse{
		ServerCapabilities: caps,
		Resources:          []tfprotov5.ResourceMetadata{{TypeName: "fake_thing"}, {TypeName: "fake_named"}, {TypeName: "fake_replace"}},
		DataSources:        []tfprotov5.DataSourceMetadata{{TypeName: "fake_lookup"}},
		EphemeralResources: []tfprotov5.EphemeralResourceMetadata{{TypeName: "fake_secret"}},
		ListResources:      []tfprotov5.ListResourceMetadata{{TypeName: "fake_thing"}},
		Actions:            []tfprotov5.ActionMetadata{{TypeName: "fake_poke"}},
	}), nil
}

func (p *provider) GetProviderSchema(context.Context, *tfprotov5.GetProviderSchemaRequest) (*tfprotov5.GetProviderSchemaResponse, error) {
	return withStateStoreSchema(&tfprotov5.GetProviderSchemaResponse{
		ServerCapabilities:       caps,
		Provider:                 providerSchema,
		ResourceSchemas:          map[string]*tfprotov5.Schema{"fake_thing": resourceSchema, "fake_named": resourceSchema, "fake_replace": resourceSchema},
		DataSourceSchemas:        map[string]*tfprotov5.Schema{"fake_lookup": lookupSchema},
		EphemeralResourceSchemas: map[string]*tfprotov5.Schema{"fake_secret": secretSchema},
		ListResourceSchemas:      map[string]*tfprotov5.Schema{"fake_thing": listSchema},
		ActionSchemas:            map[string]*tfprotov5.ActionSchema{"fake_poke": {Schema: pokeSchema}},
		Functions:                map[string]*tfprotov5.Function{},
	}), nil
}

func (p *provider) GetResourceIdentitySchemas(context.Context, *tfprotov5.GetResourceIdentitySchemasRequest) (*tfprotov5.GetResourceIdentitySchemasResponse, error) {
	return &tfprotov5.GetResourceIdentitySchemasResponse{IdentitySchemas: identitySchemas}, nil
}

func (p *provider) PrepareProviderConfig(_ context.Context, req *tfprotov5.PrepareProviderConfigRequest) (*tfprotov5.PrepareProviderConfigResponse, error) {
	return &tfprotov5.PrepareProviderConfigResponse{PreparedConfig: req.Config}, nil
}

func (p *provider) ConfigureProvider(context.Context, *tfprotov5.ConfigureProviderRequest) (*tfprotov5.ConfigureProviderResponse, error) {
	return &tfprotov5.ConfigureProviderResponse{}, nil
}

func (p *provider) StopProvider(context.Context, *tfprotov5.StopProviderRequest) (*tfprotov5.StopProviderResponse, error) {
	return &tfprotov5.StopProviderResponse{}, nil
}

func (p *provider) ValidateResourceTypeConfig(_ context.Context, req *tfprotov5.ValidateResourceTypeConfigRequest) (*tfprotov5.ValidateResourceTypeConfigResponse, error) {
	_, err := decode(req.Config, resourceType)
	return &tfprotov5.ValidateResourceTypeConfigResponse{Diagnostics: diags(err)}, nil
}

func (p *provider) UpgradeResourceState(_ context.Context, req *tfprotov5.UpgradeResourceStateRequest) (*tfprotov5.UpgradeResourceStateResponse, error) {
	dv, err := fromRaw(req.RawState, resourceType)
	return &tfprotov5.UpgradeResourceStateResponse{UpgradedState: dv, Diagnostics: diags(err)}, nil
}

func (p *provider) UpgradeResourceIdentity(_ context.Context, req *tfprotov5.UpgradeResourceIdentityRequest) (*tfprotov5.UpgradeResourceIdentityResponse, error) {
	s := identitySchemas[req.TypeName]
	if s == nil {
		return &tfprotov5.UpgradeResourceIdentityResponse{Diagnostics: diags(fmt.Errorf("%s has no identity", req.TypeName))}, nil
	}
	dv, err := fromRaw(req.RawIdentity, s.ValueType())
	return &tfprotov5.UpgradeResourceIdentityResponse{UpgradedIdentity: &tfprotov5.ResourceIdentityData{IdentityData: dv}, Diagnostics: diags(err)}, nil
}

// ReadResource reports the object unchanged: the fake has no backing store.
func (p *provider) ReadResource(_ context.Context, req *tfprotov5.ReadResourceRequest) (*tfprotov5.ReadResourceResponse, error) {
	o, err := decode(req.CurrentState, resourceType)
	return &tfprotov5.ReadResourceResponse{NewState: req.CurrentState, Private: req.Private, NewIdentity: identity(req.TypeName, o), Diagnostics: diags(err)}, nil
}

func (p *provider) PlanResourceChange(_ context.Context, req *tfprotov5.PlanResourceChangeRequest) (*tfprotov5.PlanResourceChangeResponse, error) {
	// Like hashicorp/aws (terraform-plugin-sdk v2): a non-JSON prior_private
	// is an error diagnostic.
	if len(req.PriorPrivate) > 0 {
		var m map[string]any
		if err := json.Unmarshal(req.PriorPrivate, &m); err != nil {
			return &tfprotov5.PlanResourceChangeResponse{Diagnostics: diags(err)}, nil
		}
	}
	prior, err1 := decode(req.PriorState, resourceType)
	o, err2 := decode(req.ProposedNewState, resourceType)
	if err := errors.Join(err1, err2); err != nil || o == nil {
		// A destroy plan echoes the prior identity, like hashicorp/aws (SDKv2);
		// Terraform before 1.16.6 sends it back as the destroy RPC's
		// planned_identity.
		return &tfprotov5.PlanResourceChangeResponse{PlannedState: req.ProposedNewState, PlannedIdentity: req.PriorIdentity, Diagnostics: diags(err)}, nil
	}
	resp := &tfprotov5.PlanResourceChangeResponse{PlannedPrivate: plannedPrivate, PlannedIdentity: identity(req.TypeName, prior)}
	if o["size"].IsNull() {
		o["size"] = tftypes.NewValue(tftypes.Number, 1)
	}
	if prior != nil && req.TypeName == "fake_replace" && !prior["name"].Equal(o["name"]) {
		resp.RequiresReplace = []*tftypes.AttributePath{tftypes.NewAttributePath().WithAttributeName("name")}
		prior = nil
	}
	if prior == nil {
		o["id"] = tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
	}
	resp.PlannedState = encode(resourceType, o)
	return resp, nil
}

func (p *provider) ApplyResourceChange(_ context.Context, req *tfprotov5.ApplyResourceChangeRequest) (*tfprotov5.ApplyResourceChangeResponse, error) {
	o, err := decode(req.PlannedState, resourceType)
	if err != nil || o == nil {
		return &tfprotov5.ApplyResourceChangeResponse{NewState: req.PlannedState, Diagnostics: diags(err)}, nil
	}
	crashIf(o)
	if !o["id"].IsKnown() {
		o["id"] = tftypes.NewValue(tftypes.String, "bobthecorp-"+get[string](o, "name"))
	}
	drift := strings.HasPrefix(get[string](o, "name"), "drift-")
	if drift {
		var size big.Float
		if err = o["size"].As(&size); err == nil {
			o["size"] = tftypes.NewValue(tftypes.Number, size.Add(&size, big.NewFloat(1)))
		}
	}
	b, err2 := nonCanonical(o)
	return &tfprotov5.ApplyResourceChangeResponse{
		NewState:                    &tfprotov5.DynamicValue{MsgPack: b},
		Private:                     req.PlannedPrivate,
		NewIdentity:                 identity(req.TypeName, o),
		Diagnostics:                 diags(errors.Join(err, err2)),
		UnsafeToUseLegacyTypeSystem: drift,
	}, nil
}

func (p *provider) ImportResourceState(_ context.Context, req *tfprotov5.ImportResourceStateRequest) (*tfprotov5.ImportResourceStateResponse, error) {
	id := req.ID
	if id == "" && req.Identity != nil {
		s := identitySchemas[req.TypeName]
		if s == nil {
			s = identitySchema
		}
		o, err := decode(req.Identity.IdentityData, s.ValueType())
		if err != nil {
			return &tfprotov5.ImportResourceStateResponse{Diagnostics: diags(err)}, nil
		}
		id = get[string](o, s.IdentityAttributes[0].Name) // shortcut: a fake_named imports with id = name
	}
	o := thing(id)
	return &tfprotov5.ImportResourceStateResponse{ImportedResources: []*tfprotov5.ImportedResource{
		{TypeName: req.TypeName, State: encode(resourceType, o), Identity: identity(req.TypeName, o)},
	}}, nil
}

func (p *provider) MoveResourceState(_ context.Context, req *tfprotov5.MoveResourceStateRequest) (*tfprotov5.MoveResourceStateResponse, error) {
	dv, err := fromRaw(req.SourceState, resourceType)
	return &tfprotov5.MoveResourceStateResponse{TargetState: dv, TargetPrivate: req.SourcePrivate, Diagnostics: diags(err)}, nil
}

func (p *provider) GenerateResourceConfig(_ context.Context, req *tfprotov5.GenerateResourceConfigRequest) (*tfprotov5.GenerateResourceConfigResponse, error) {
	o, err := decode(req.State, resourceType)
	if o != nil {
		o["id"] = tftypes.NewValue(tftypes.String, nil)
	}
	return &tfprotov5.GenerateResourceConfigResponse{Config: encode(resourceType, o), Diagnostics: diags(err)}, nil
}

func (p *provider) ValidateDataSourceConfig(_ context.Context, req *tfprotov5.ValidateDataSourceConfigRequest) (*tfprotov5.ValidateDataSourceConfigResponse, error) {
	_, err := decode(req.Config, lookupSchema.ValueType())
	return &tfprotov5.ValidateDataSourceConfigResponse{Diagnostics: diags(err)}, nil
}

func (p *provider) ReadDataSource(_ context.Context, req *tfprotov5.ReadDataSourceRequest) (*tfprotov5.ReadDataSourceResponse, error) {
	o, err := decode(req.Config, lookupSchema.ValueType())
	if err != nil || o == nil {
		return &tfprotov5.ReadDataSourceResponse{State: req.Config, Diagnostics: diags(err)}, nil
	}
	crashIf(o)
	o["id"] = tftypes.NewValue(tftypes.String, "lookup-"+get[string](o, "name"))
	return &tfprotov5.ReadDataSourceResponse{State: encode(lookupSchema.ValueType(), o)}, nil
}

func (p *provider) ValidateEphemeralResourceConfig(_ context.Context, req *tfprotov5.ValidateEphemeralResourceConfigRequest) (*tfprotov5.ValidateEphemeralResourceConfigResponse, error) {
	_, err := decode(req.Config, secretSchema.ValueType())
	return &tfprotov5.ValidateEphemeralResourceConfigResponse{Diagnostics: diags(err)}, nil
}

func (p *provider) OpenEphemeralResource(_ context.Context, req *tfprotov5.OpenEphemeralResourceRequest) (*tfprotov5.OpenEphemeralResourceResponse, error) {
	o, err := decode(req.Config, secretSchema.ValueType())
	if err != nil || o == nil {
		return &tfprotov5.OpenEphemeralResourceResponse{Result: req.Config, Diagnostics: diags(err)}, nil
	}
	o["value"] = tftypes.NewValue(tftypes.String, "bobthecorp-secret-"+get[string](o, "name"))
	return &tfprotov5.OpenEphemeralResourceResponse{Result: encode(secretSchema.ValueType(), o), Private: []byte("fake_secret")}, nil
}

func (p *provider) RenewEphemeralResource(_ context.Context, req *tfprotov5.RenewEphemeralResourceRequest) (*tfprotov5.RenewEphemeralResourceResponse, error) {
	return &tfprotov5.RenewEphemeralResourceResponse{Private: req.Private}, nil
}

func (p *provider) CloseEphemeralResource(context.Context, *tfprotov5.CloseEphemeralResourceRequest) (*tfprotov5.CloseEphemeralResourceResponse, error) {
	return &tfprotov5.CloseEphemeralResourceResponse{}, nil
}

func (p *provider) ValidateListResourceConfig(_ context.Context, req *tfprotov5.ValidateListResourceConfigRequest) (*tfprotov5.ValidateListResourceConfigResponse, error) {
	_, err := decode(req.Config, listSchema.ValueType())
	return &tfprotov5.ValidateListResourceConfigResponse{Diagnostics: diags(err)}, nil
}

// ListResource yields two fake_thing objects named <prefix>-1 and <prefix>-2.
func (p *provider) ListResource(_ context.Context, req *tfprotov5.ListResourceRequest) (*tfprotov5.ListResourceServerStream, error) {
	o, err := decode(req.Config, listSchema.ValueType())
	prefix := get[string](o, "prefix")
	if prefix == "" {
		prefix = "bobthecorp-thing"
	}
	return &tfprotov5.ListResourceServerStream{Results: func(yield func(tfprotov5.ListResourceResult) bool) {
		if err != nil {
			yield(tfprotov5.ListResourceResult{Diagnostics: diags(err)})
			return
		}
		for i := int64(1); i <= 2 && (req.Limit <= 0 || i <= req.Limit); i++ {
			t := thing(fmt.Sprintf("%s-%d", prefix, i))
			r := tfprotov5.ListResourceResult{DisplayName: get[string](t, "id"), Identity: identity("fake_thing", t)}
			if req.IncludeResource {
				r.Resource = encode(resourceType, t)
			}
			if !yield(r) {
				return
			}
		}
	}}, nil
}

func (p *provider) ValidateActionConfig(_ context.Context, req *tfprotov5.ValidateActionConfigRequest) (*tfprotov5.ValidateActionConfigResponse, error) {
	_, err := decode(req.Config, pokeSchema.ValueType())
	return &tfprotov5.ValidateActionConfigResponse{Diagnostics: diags(err)}, nil
}

func (p *provider) PlanAction(context.Context, *tfprotov5.PlanActionRequest) (*tfprotov5.PlanActionResponse, error) {
	return &tfprotov5.PlanActionResponse{}, nil
}

func (p *provider) InvokeAction(_ context.Context, req *tfprotov5.InvokeActionRequest) (*tfprotov5.InvokeActionServerStream, error) {
	o, err := decode(req.Config, pokeSchema.ValueType())
	crashIf(o)
	return &tfprotov5.InvokeActionServerStream{Events: slices.Values([]tfprotov5.InvokeActionEvent{
		{Type: tfprotov5.ProgressInvokeActionEventType{Message: "poking " + get[string](o, "target")}},
		{Type: tfprotov5.CompletedInvokeActionEventType{Diagnostics: diags(err)}},
	})}, nil
}

func (p *provider) GetFunctions(context.Context, *tfprotov5.GetFunctionsRequest) (*tfprotov5.GetFunctionsResponse, error) {
	return &tfprotov5.GetFunctionsResponse{Functions: map[string]*tfprotov5.Function{}}, nil
}

func (p *provider) CallFunction(_ context.Context, req *tfprotov5.CallFunctionRequest) (*tfprotov5.CallFunctionResponse, error) {
	return &tfprotov5.CallFunctionResponse{Error: &tfprotov5.FunctionError{Text: "fakeupstream has no function " + req.Name}}, nil
}
