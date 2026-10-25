package proxy

// server5.go serves the intercepted provider-level tfplugin5 RPCs on the
// generated proto messages: each handler mutates only the fields it owns and
// forwards the rest, so fields newer than the pinned proto survive as unknown
// fields.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

type server5 struct {
	up        tfplugin5.ProviderClient
	b         Backends
	ev        hook.Evaluator
	tfVersion atomic.Pointer[string]      // from Configure
	schema    atomic.Pointer[schemaEntry] // unioned, error-free
	fetch     singleflight.Group          // one upstream GetSchema per sha at a time
	stopCtx   context.Context             // canceled after upstream Stop
	stopProxy context.CancelFunc
	imported  importedSet // objects this process imported (imported.go)
}

func newServer5(b Backends) *server5 {
	ctx, cancel := context.WithCancel(context.Background())
	ev := b.Evaluator
	if ev == nil {
		ev = hook.Noop{}
	}
	return &server5{up: tfplugin5.NewProviderClient(b.Upstream), b: b, ev: ev, stopCtx: ctx, stopProxy: cancel}
}

// methods are the provider-level intercepts server5 serves.
func (s *server5) methods() []grpc.MethodDesc {
	return []grpc.MethodDesc{
		unary("GetSchema", s.GetSchema),
		unary("PrepareProviderConfig", s.PrepareProviderConfig),
		unary("Configure", s.Configure),
		unary("Stop", s.Stop),
		unary("ValidateResourceTypeConfig", s.ValidateResourceTypeConfig),
		unary("PlanResourceChange", s.PlanResourceChange),
		unary("ApplyResourceChange", s.ApplyResourceChange),
		unary("ReadResource", s.ReadResource),
		unary("ReadDataSource", s.ReadDataSource),
		unary("OpenEphemeralResource", s.OpenEphemeralResource),
		unary("ImportResourceState", s.ImportResourceState),
	}
}

func unary[Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](name string, f func(context.Context, PReq) (Resp, error)) grpc.MethodDesc {
	return grpc.MethodDesc{MethodName: name, Handler: func(srv any, ctx context.Context, dec func(any) error, ic grpc.UnaryServerInterceptor) (any, error) {
		req := PReq(new(Req))
		if err := dec(req); err != nil {
			return nil, err
		}
		h := func(ctx context.Context, r any) (any, error) {
			p, ok := r.(PReq)
			if !ok {
				return nil, status.Errorf(codes.Internal, "%s: request is %T", name, r)
			}
			resp, err := f(ctx, p)
			return exitedDiagnostic(resp, err)
		}
		if ic == nil {
			return h(ctx, req)
		}
		return ic(ctx, req, &grpc.UnaryServerInfo{Server: srv, FullMethod: providerService + name}, h)
	}}
}

// upErr maps a failed upstream call through Backends.OnTransportErr.
func (s *server5) upErr(method string, err error) error {
	if s.b.OnTransportErr == nil {
		return err
	}
	return s.b.OnTransportErr(providerService+method, err)
}

// schemaEntry is a GetSchema response cached for the verified upstream
// binary with sha256 sha.
type schemaEntry struct {
	sha  string
	resp *tfplugin5.GetProviderSchema_Response
}

// cachedSchema returns the cached GetSchema response if it was fetched from
// the binary Backends.UpstreamSHA256 names, else nil. The cache is in memory
// only: a binary swapped at the same path never reads another's schema. An
// empty sha names no binary and never hits.
func (s *server5) cachedSchema() *tfplugin5.GetProviderSchema_Response {
	if e := s.schema.Load(); e != nil && e.sha != "" && e.sha == s.b.UpstreamSHA256 {
		return e.resp
	}
	return nil
}

// GetSchema forwards, appends the compliance block to the provider schema and
// caches the result keyed on the upstream binary's verified sha256 (not
// cached when that is unknown).
// A response with error diagnostics is returned unchanged and not cached.
// Concurrent cache misses share one upstream call (the hashicorp/aws schema
// takes 0.3-1 s); a failed call is shared by its waiters only, and the next
// miss fetches again. A caller whose context ends stops waiting at once; the
// shared call runs on until it completes, schemaFetchTimeout passes or the
// proxy stops, so a hung upstream cannot hold the flight forever.
func (s *server5) GetSchema(ctx context.Context, req *tfplugin5.GetProviderSchema_Request) (*tfplugin5.GetProviderSchema_Response, error) {
	if c := s.cachedSchema(); c != nil {
		return c, nil
	}
	ch := s.fetch.DoChan(s.b.UpstreamSHA256, func() (any, error) {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), schemaFetchTimeout)
		defer cancel()
		defer context.AfterFunc(s.stopCtx, cancel)()
		return s.fetchSchema(fctx, req)
	})
	select {
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	case r := <-ch:
		if r.Err != nil {
			return nil, r.Err
		}
		resp, ok := r.Val.(*tfplugin5.GetProviderSchema_Response)
		if !ok {
			return nil, status.Errorf(codes.Internal, "GetSchema: shared fetch returned %T", r.Val)
		}
		return resp, nil
	}
}

// schemaFetchTimeout bounds a shared upstream GetSchema, which no single
// caller's deadline bounds (hashicorp/aws answers in about 1 s).
var schemaFetchTimeout = 2 * time.Minute

// fetchSchema is GetSchema's upstream call, run once per flight.
func (s *server5) fetchSchema(ctx context.Context, req *tfplugin5.GetProviderSchema_Request) (*tfplugin5.GetProviderSchema_Response, error) {
	if c := s.cachedSchema(); c != nil { // a flight that ended after our miss
		return c, nil
	}
	resp, err := s.up.GetSchema(ctx, req)
	if err != nil {
		return nil, s.upErr("GetSchema", err)
	}
	if hasErrorDiag(resp.Diagnostics) {
		return resp, nil
	}
	if resp.Provider == nil {
		resp.Provider = &tfplugin5.Schema{}
	}
	if resp.Provider.Block == nil {
		resp.Provider.Block = &tfplugin5.Schema_Block{}
	}
	resp.Provider.Block.BlockTypes = append(resp.Provider.Block.BlockTypes, complianceBlock5)
	if s.b.UpstreamSHA256 != "" {
		s.schema.Store(&schemaEntry{sha: s.b.UpstreamSHA256, resp: resp})
	}
	return resp, nil
}

// PrepareProviderConfig forwards the config without the compliance block and
// returns the original config as prepared_config, so Configure receives the
// block.
func (s *server5) PrepareProviderConfig(ctx context.Context, req *tfplugin5.PrepareProviderConfig_Request) (*tfplugin5.PrepareProviderConfig_Response, error) {
	orig := req.Config
	_, _, stripped, err := splitCompliance(orig)
	if err != nil {
		return &tfplugin5.PrepareProviderConfig_Response{Diagnostics: []*tfplugin5.Diagnostic{invalidConfig(err)}}, nil
	}
	req.Config = stripped
	resp, err := s.up.PrepareProviderConfig(ctx, req)
	if err != nil {
		return nil, s.upErr("PrepareProviderConfig", err)
	}
	resp.PreparedConfig = orig
	return resp, nil
}

// Configure hands the compliance block to Evaluator.Configure and forwards
// the config without it unless that returned an error diagnostic. Proxy
// diagnostics follow upstream diagnostics.
func (s *server5) Configure(ctx context.Context, req *tfplugin5.Configure_Request) (*tfplugin5.Configure_Response, error) {
	comp, region, stripped, err := splitCompliance(req.Config)
	if err != nil {
		return &tfplugin5.Configure_Response{Diagnostics: []*tfplugin5.Diagnostic{invalidConfig(err)}}, nil
	}
	tfv := req.TerraformVersion
	s.tfVersion.Store(&tfv)
	hctx, cancel := s.hookCtx(ctx)
	defer cancel()
	ended := make(chan struct{})
	hd, herr := recovered(func() ([]hook.Diagnostic, error) {
		defer close(ended)
		return s.ev.Configure(hctx, &hook.ConfigureRequest{TerraformVersion: req.TerraformVersion, Compliance: comp, Schemas: schemaSource{s, hctx, ended},
			Region: region.s, RegionKnown: region.known, RegionNull: region.null, SharedConfigSet: region.sharedSet, Profile: region.profile,
			AccountID: region.account, AccountKnown: region.accountKnown, SkipAccountID: region.skipAccount})
	})
	diags := toProtoDiags(hd)
	if hook.IsNoop(s.ev) {
		diags = append(diags, &tfplugin5.Diagnostic{Severity: tfplugin5.Diagnostic_WARNING, Summary: noControlsSummary, Detail: fmt.Sprintf(noControlsDetail, s.b.UpstreamName)})
	}
	if herr != nil {
		diags = append(diags, evalFailed(tfplugin5.Diagnostic_ERROR, "configure for provider"))
	}
	if hasErrorDiag(diags) {
		return &tfplugin5.Configure_Response{Diagnostics: diags}, nil
	}
	req.Config = stripped
	resp, err := s.up.Configure(ctx, req)
	if err != nil {
		return nil, s.upErr("Configure", err)
	}
	resp.Diagnostics = append(resp.Diagnostics, diags...)
	return resp, nil
}

// Stop forwards to upstream first, then cancels the proxy stop context.
func (s *server5) Stop(ctx context.Context, req *tfplugin5.Stop_Request) (*tfplugin5.Stop_Response, error) {
	resp, err := s.up.Stop(ctx, req)
	s.stopProxy()
	if err != nil {
		return nil, s.upErr("Stop", err)
	}
	return resp, nil
}

func hasErrorDiag(diags []*tfplugin5.Diagnostic) bool {
	for _, d := range diags {
		if d.GetSeverity() == tfplugin5.Diagnostic_ERROR {
			return true
		}
	}
	return false
}

func invalidConfig(err error) *tfplugin5.Diagnostic {
	return &tfplugin5.Diagnostic{Severity: tfplugin5.Diagnostic_ERROR, Summary: "Invalid compliance configuration", Detail: err.Error()}
}

// complianceBlock5 is ComplianceBlockSchema as a proto nested block.
var complianceBlock5 = func() *tfplugin5.Schema_NestedBlock {
	in := ComplianceBlockSchema()
	block := &tfplugin5.Schema_Block{}
	for _, a := range in.Block.Attributes {
		typ, err := a.Type.MarshalJSON() //nolint:staticcheck // the wire form of a schema type
		if err != nil {
			panic(fmt.Sprintf("compliance attribute %s: %v", a.Name, err))
		}
		block.Attributes = append(block.Attributes, &tfplugin5.Schema_Attribute{Name: a.Name, Type: typ, Description: a.Description, Optional: a.Optional})
	}
	return &tfplugin5.Schema_NestedBlock{TypeName: in.TypeName, Nesting: tfplugin5.Schema_NestedBlock_SINGLE, Block: block}
}()

// configRegion is the region attribute of the upstream provider config;
// known is false when it is absent, null, unknown or not a string, null is
// true when it is absent or null. sharedSet is true when
// shared_config_files or shared_credentials_files is not null, or profile
// is not null and not a known non-empty string; profile is the profile when
// it is one. account is the one id of allowed_account_ids,
// accountKnown false unless that set is wholly known with exactly one
// element; skipAccount is true unless skip_requesting_account_id is null,
// absent or known false.
type configRegion struct {
	s, profile, account                               string
	known, null, sharedSet, accountKnown, skipAccount bool
}

// splitCompliance parses the compliance block of a msgpack provider config
// and returns it, the region and the config without the block. It needs no
// upstream schema: the config is a msgpack map, and every other entry is
// copied byte for byte.
func splitCompliance(cfg *tfplugin5.DynamicValue) (tftypes.Value, configRegion, *tfplugin5.DynamicValue, error) {
	region := configRegion{null: true}
	null := tftypes.NewValue(ComplianceBlockType(), nil)
	if cfg == nil || (len(cfg.Msgpack) == 0 && len(cfg.Json) == 0) {
		return null, region, cfg, nil
	}
	if len(cfg.Msgpack) == 0 {
		return null, region, nil, errors.New("provider config is JSON-encoded; only msgpack is supported")
	}
	r := bytes.NewReader(cfg.Msgpack)
	dec := msgpack.NewDecoder(r)
	n, err := dec.DecodeMapLen()
	if err != nil {
		return null, region, nil, fmt.Errorf("provider config is not a msgpack map: %w", err)
	}
	var kept [][]byte
	var comp msgpack.RawMessage
	for range n {
		key, err := dec.DecodeRaw()
		if err != nil {
			return null, region, nil, fmt.Errorf("read provider config key: %w", err)
		}
		var name string
		if err := msgpack.Unmarshal(key, &name); err != nil {
			return null, region, nil, fmt.Errorf("read provider config key: %w", err)
		}
		val, err := dec.DecodeRaw()
		if err != nil {
			return null, region, nil, fmt.Errorf("read provider config %s: %w", name, err)
		}
		switch name {
		case "region":
			kept := region
			region = decodeRegion(val)
			region.sharedSet, region.profile = kept.sharedSet, kept.profile
			region.account, region.accountKnown, region.skipAccount = kept.account, kept.accountKnown, kept.skipAccount
		case "allowed_account_ids":
			region.account, region.accountKnown = decodeAccount(val)
		case "skip_requesting_account_id":
			region.skipAccount = !isNil(val) && !knownFalse(val)
		case "profile":
			if p := decodeRegion(val); p.known && p.s != "" {
				region.profile = p.s
			} else {
				region.sharedSet = region.sharedSet || !p.null
			}
		case "shared_config_files", "shared_credentials_files":
			region.sharedSet = region.sharedSet || !isNil(val)
		}
		if name == "compliance" {
			comp = val
			continue
		}
		kept = append(kept, key, val)
	}
	if r.Len() > 0 {
		return null, region, nil, errors.New("trailing bytes after provider config")
	}

	cv := null
	if comp != nil {
		if cv, err = (&tfprotov5.DynamicValue{MsgPack: comp}).Unmarshal(ComplianceBlockType()); err != nil {
			return null, region, nil, fmt.Errorf("compliance block: %w", err)
		}
	}

	var out bytes.Buffer
	enc := msgpack.NewEncoder(&out)
	if err := enc.EncodeMapLen(len(kept) / 2); err != nil {
		return null, region, nil, err
	}
	for _, b := range kept {
		out.Write(b)
	}
	stripped := proto.CloneOf(cfg)
	stripped.Msgpack = out.Bytes()
	return cv, region, stripped, nil
}

// decodeRegion reads one msgpack config value as a known string; anything
// else (null, unknown, another type) is not known, and only null is null.
func decodeRegion(raw []byte) configRegion {
	if isNil(raw) {
		return configRegion{null: true}
	}
	v, err := (&tfprotov5.DynamicValue{MsgPack: raw}).Unmarshal(tftypes.String)
	var s string
	if err != nil || !v.IsKnown() || v.IsNull() || v.As(&s) != nil {
		return configRegion{}
	}
	return configRegion{s: s, known: true}
}

// decodeAccount reads allowed_account_ids as its one element; any other
// value (null, unknown, an unknown element, zero or several ids, another
// type) is not known.
func decodeAccount(raw []byte) (string, bool) {
	v, err := (&tfprotov5.DynamicValue{MsgPack: raw}).Unmarshal(tftypes.Set{ElementType: tftypes.String})
	var ids []tftypes.Value
	if err != nil || !v.IsFullyKnown() || v.IsNull() || v.As(&ids) != nil || len(ids) != 1 {
		return "", false
	}
	var s string
	if ids[0].IsNull() || ids[0].As(&s) != nil {
		return "", false
	}
	return s, true
}

// knownFalse reports whether raw is the known bool false.
func knownFalse(raw []byte) bool {
	v, err := (&tfprotov5.DynamicValue{MsgPack: raw}).Unmarshal(tftypes.Bool)
	var b bool
	return err == nil && v.IsKnown() && !v.IsNull() && v.As(&b) == nil && !b
}

// isNil reports whether raw is the msgpack nil, a null config value.
func isNil(raw []byte) bool { return len(raw) == 1 && raw[0] == 0xc0 }

// The Configure warning of a build serving hook.Noop.
const (
	noControlsSummary = "No compliance controls enforced"
	noControlsDetail  = "compliance.tf: no compliance controls are enforced in this build. Resources are planned and applied as %s would, without compliance checks."
)
