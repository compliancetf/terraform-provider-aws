package proxy

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/hook/hooktest"
	"github.com/compliancetf/terraform-provider-aws/internal/rawgrpc"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// unknownField is field 99 (varint 7): no tfplugin5 message declares it, so
// it stands for a field newer than the pinned proto.
var unknownField = protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 7)

func withUnknown[M proto.Message](m M) M {
	m.ProtoReflect().SetUnknown(unknownField)
	return m
}

// fakeUpstream5 records the provider-level calls the proxy forwards.
type fakeUpstream5 struct {
	tfplugin5.UnimplementedProviderServer
	mu        sync.Mutex
	calls     []string
	prepare   *tfplugin5.PrepareProviderConfig_Request
	configure *tfplugin5.Configure_Request
	schema    *tfplugin5.GetProviderSchema_Response
	onStop    func()
}

func (f *fakeUpstream5) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
}

func (f *fakeUpstream5) GetSchema(context.Context, *tfplugin5.GetProviderSchema_Request) (*tfplugin5.GetProviderSchema_Response, error) {
	f.record("GetSchema")
	return f.schema, nil
}

func (f *fakeUpstream5) PrepareProviderConfig(_ context.Context, req *tfplugin5.PrepareProviderConfig_Request) (*tfplugin5.PrepareProviderConfig_Response, error) {
	f.record("PrepareProviderConfig")
	f.prepare = req
	return withUnknown(&tfplugin5.PrepareProviderConfig_Response{PreparedConfig: req.Config}), nil
}

func (f *fakeUpstream5) Configure(_ context.Context, req *tfplugin5.Configure_Request) (*tfplugin5.Configure_Response, error) {
	f.record("Configure")
	f.configure = req
	return withUnknown(&tfplugin5.Configure_Response{Diagnostics: []*tfplugin5.Diagnostic{{Severity: tfplugin5.Diagnostic_WARNING, Summary: "upstream"}}}), nil
}

func (f *fakeUpstream5) Stop(context.Context, *tfplugin5.Stop_Request) (*tfplugin5.Stop_Response, error) {
	f.record("Stop")
	if f.onStop != nil {
		f.onStop()
	}
	return &tfplugin5.Stop_Response{}, nil
}

// terraformCallSizes are the per-call limits Terraform core sets on its
// provider plugin clients.
var terraformCallSizes = grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(math.MaxInt32), grpc.MaxCallSendMsgSize(math.MaxInt32))

// bufDial serves register over bufconn with opts and dials it the way
// Terraform core dials a provider.
func bufDial(t *testing.T, register func(*grpc.Server), opts ...grpc.ServerOption) *grpc.ClientConn {
	t.Helper()
	return bufDialWith(t, register, opts, terraformCallSizes)
}

func bufDialWith(t *testing.T, register func(*grpc.Server), opts []grpc.ServerOption, dial grpc.DialOption) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	s := grpc.NewServer(opts...)
	register(s)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()), dial)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// testUpstreamSHA stands for the verified sha256 of the fake upstream.
var testUpstreamSHA = strings.Repeat("0", 64)

// startProxy serves the proxy's intercepts in front of up and returns a
// client on the proxy and the server5 behind it.
func startProxy(t *testing.T, up tfplugin5.ProviderServer, b Backends) (tfplugin5.ProviderClient, *server5) {
	t.Helper()
	// The upstream conn carries the limits upstream.Launch dials with.
	b.Upstream = bufDialWith(t, func(s *grpc.Server) { tfplugin5.RegisterProviderServer(s, up) }, nil, rawgrpc.CallSizes())
	if b.UpstreamSHA256 == "" {
		b.UpstreamSHA256 = testUpstreamSHA // as main passes the verified sha
	}
	p := newServer5(b)
	conn := bufDial(t, func(s *grpc.Server) { registerIntercepts(s, p) }, serverOptions(b, p)...)
	return tfplugin5.NewProviderClient(conn), p
}

var upstreamProviderSchema = &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{
	Attributes: []*tfprotov5.SchemaAttribute{{Name: "region", Type: tftypes.String, Optional: true}},
}}

// combinedConfig is a provider config as Terraform sends it: the upstream
// attributes plus the compliance block.
func combinedConfig(t *testing.T, mode string) *tfplugin5.DynamicValue {
	t.Helper()
	compType := ComplianceBlockType().(tftypes.Object)
	comp := map[string]tftypes.Value{}
	for name, typ := range compType.AttributeTypes {
		comp[name] = tftypes.NewValue(typ, nil)
	}
	comp["enforcement_mode"] = tftypes.NewValue(tftypes.String, mode)
	typ := CombinedProviderType(upstreamProviderSchema)
	dv, err := tfprotov5.NewDynamicValue(typ, tftypes.NewValue(typ, map[string]tftypes.Value{
		"region":     tftypes.NewValue(tftypes.String, "eu-west-1"),
		"compliance": tftypes.NewValue(compType, comp),
	}))
	if err != nil {
		t.Fatal(err)
	}
	return &tfplugin5.DynamicValue{Msgpack: dv.MsgPack}
}

func upstreamConfig(t *testing.T) []byte {
	t.Helper()
	typ := UpstreamProviderType(upstreamProviderSchema)
	dv, err := tfprotov5.NewDynamicValue(typ, tftypes.NewValue(typ, map[string]tftypes.Value{
		"region": tftypes.NewValue(tftypes.String, "eu-west-1"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	return dv.MsgPack
}

func TestProviderRPCGetSchemaUnion(t *testing.T) {
	upSchema := withUnknown(&tfplugin5.GetProviderSchema_Response{
		Provider: &tfplugin5.Schema{Block: &tfplugin5.Schema_Block{
			Attributes: []*tfplugin5.Schema_Attribute{{Name: "region", Type: []byte(`"string"`), Optional: true}},
			BlockTypes: []*tfplugin5.Schema_NestedBlock{{TypeName: "assume_role", Nesting: tfplugin5.Schema_NestedBlock_LIST, Block: &tfplugin5.Schema_Block{}}},
		}},
		ResourceSchemas:          map[string]*tfplugin5.Schema{"fake_thing": {Version: 1}},
		EphemeralResourceSchemas: map[string]*tfplugin5.Schema{"fake_secret": {}},
		ListResourceSchemas:      map[string]*tfplugin5.Schema{"fake_thing": {}},
		ActionSchemas:            map[string]*tfplugin5.ActionSchema{"fake_poke": {}},
		ServerCapabilities:       &tfplugin5.ServerCapabilities{PlanDestroy: true, GetProviderSchemaOptional: true},
	})
	up := &fakeUpstream5{schema: upSchema}
	client, _ := startProxy(t, up, Backends{})

	for range 2 {
		got, err := client.GetSchema(context.Background(), &tfplugin5.GetProviderSchema_Request{})
		if err != nil {
			t.Fatal(err)
		}
		blocks := got.Provider.Block.BlockTypes
		if n := len(blocks); n != 2 || blocks[1].TypeName != "compliance" || blocks[1].Nesting != tfplugin5.Schema_NestedBlock_SINGLE {
			t.Fatalf("provider block types = %v, want assume_role then compliance", blocks)
		}
		if len(blocks[1].Block.Attributes) != len(ComplianceBlockSchema().Block.Attributes) {
			t.Errorf("compliance block has %d attributes, want %d", len(blocks[1].Block.Attributes), len(ComplianceBlockSchema().Block.Attributes))
		}
		if !bytes.Equal(got.ProtoReflect().GetUnknown(), unknownField) {
			t.Errorf("unknown field lost: %x", got.ProtoReflect().GetUnknown())
		}
		// Without the compliance block the response is the upstream's,
		// including capabilities, identity, ephemeral, list and action types.
		got.Provider.Block.BlockTypes = blocks[:1]
		if !proto.Equal(got, upSchema) {
			t.Errorf("response minus compliance = %v, want upstream %v", got, upSchema)
		}
	}
	if len(up.calls) != 1 {
		t.Errorf("upstream calls = %v, want one GetSchema (cached)", up.calls)
	}
}

// TestProviderRPCGetSchemaCacheKeyedOnSHA: an upstream relaunched from the
// same path with a different verified binary must not get the schema cached
// for the first one.
func TestProviderRPCGetSchemaCacheKeyedOnSHA(t *testing.T) {
	schemaWith := func(typ string) *tfplugin5.GetProviderSchema_Response {
		return &tfplugin5.GetProviderSchema_Response{ResourceSchemas: map[string]*tfplugin5.Schema{typ: {Block: &tfplugin5.Schema_Block{}}}}
	}
	upA := &fakeUpstream5{schema: schemaWith("fake_a")}
	client, p := startProxy(t, upA, Backends{UpstreamSHA256: strings.Repeat("a", 64)})
	if _, err := client.GetSchema(context.Background(), &tfplugin5.GetProviderSchema_Request{}); err != nil {
		t.Fatal(err)
	}

	// Same path, swapped binary: a new conn and a new verified sha.
	upB := &fakeUpstream5{schema: schemaWith("fake_b")}
	p.up = tfplugin5.NewProviderClient(bufDialWith(t, func(s *grpc.Server) { tfplugin5.RegisterProviderServer(s, upB) }, nil, rawgrpc.CallSizes()))
	p.b.UpstreamSHA256 = strings.Repeat("b", 64)

	got, err := client.GetSchema(context.Background(), &tfplugin5.GetProviderSchema_Request{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.ResourceSchemas["fake_b"]; !ok {
		t.Fatalf("schema after the swap = %v, want the second binary's fake_b", got.ResourceSchemas)
	}
	if _, ok, err := p.schemaOf(context.Background(), "fake_a", schemasOf[hook.KindResource]); err != nil || ok {
		t.Fatalf("schemaOf(fake_a) after the swap = %v, %v; want absent", ok, err)
	}

	// An unknown sha names no binary: nothing is served from or stored in
	// the cache.
	p.b.UpstreamSHA256 = ""
	for range 2 {
		if _, err := client.GetSchema(context.Background(), &tfplugin5.GetProviderSchema_Request{}); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(upB.calls); n != 3 {
		t.Fatalf("upstream B GetSchema calls = %d, want 3 (empty sha is never cached)", n)
	}
}

// TestProviderRPCGetSchemaLarge forwards a 16 MiB GetSchema response, four
// times gRPC's 4 MiB default; the real hashicorp/aws schema is over that
// default too.
func TestProviderRPCGetSchemaLarge(t *testing.T) {
	desc := strings.Repeat("x", 16<<20)
	up := &fakeUpstream5{schema: &tfplugin5.GetProviderSchema_Response{
		Provider:        &tfplugin5.Schema{Block: &tfplugin5.Schema_Block{}},
		ResourceSchemas: map[string]*tfplugin5.Schema{"fake_thing": {Block: &tfplugin5.Schema_Block{Description: desc}}},
	}}
	client, _ := startProxy(t, up, Backends{})
	got, err := client.GetSchema(context.Background(), &tfplugin5.GetProviderSchema_Request{})
	if err != nil {
		t.Fatal(err)
	}
	if got.ResourceSchemas["fake_thing"].GetBlock().GetDescription() != desc {
		t.Fatal("16 MiB resource schema description not forwarded intact")
	}
}

func TestProviderRPCGetSchemaErrorNotCached(t *testing.T) {
	up := &fakeUpstream5{schema: &tfplugin5.GetProviderSchema_Response{Diagnostics: []*tfplugin5.Diagnostic{{Severity: tfplugin5.Diagnostic_ERROR, Summary: "boom"}}}}
	client, _ := startProxy(t, up, Backends{})
	for range 2 {
		got, err := client.GetSchema(context.Background(), &tfplugin5.GetProviderSchema_Request{})
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(got, up.schema) {
			t.Errorf("got %v, want the upstream error response unchanged", got)
		}
	}
	if len(up.calls) != 2 {
		t.Errorf("upstream calls = %v, want two GetSchema (errors are not cached)", up.calls)
	}
}

func TestProviderRPCPrepareStrips(t *testing.T) {
	up := &fakeUpstream5{}
	client, _ := startProxy(t, up, Backends{})
	cfg := combinedConfig(t, "advisory")

	got, err := client.PrepareProviderConfig(context.Background(), withUnknown(&tfplugin5.PrepareProviderConfig_Request{Config: cfg}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(up.prepare.Config.Msgpack, upstreamConfig(t)) {
		t.Errorf("upstream config = %x, want the config without compliance %x", up.prepare.Config.Msgpack, upstreamConfig(t))
	}
	if !bytes.Equal(up.prepare.ProtoReflect().GetUnknown(), unknownField) {
		t.Error("request unknown field did not reach upstream")
	}
	if !proto.Equal(got.PreparedConfig, cfg) {
		t.Error("prepared_config is not the original config")
	}
	if !bytes.Equal(got.ProtoReflect().GetUnknown(), unknownField) {
		t.Error("response unknown field lost")
	}
}

func TestProviderRPCConfigure(t *testing.T) {
	up := &fakeUpstream5{}
	var seen string
	client, _ := startProxy(t, up, Backends{Evaluator: &hooktest.Recorder{OnConfigure: func(r *hook.ConfigureRequest) ([]hook.Diagnostic, error) {
		var f map[string]tftypes.Value
		if err := r.Compliance.As(&f); err == nil {
			_ = f["enforcement_mode"].As(&seen)
		}
		return []hook.Diagnostic{{Severity: hook.SeverityWarning, Summary: "proxy"}}, nil
	}}})
	caps := &tfplugin5.ClientCapabilities{DeferralAllowed: true}

	got, err := client.Configure(context.Background(), withUnknown(&tfplugin5.Configure_Request{TerraformVersion: "1.14.0", Config: combinedConfig(t, "advisory"), ClientCapabilities: caps}))
	if err != nil {
		t.Fatal(err)
	}
	if seen != "advisory" {
		t.Fatalf("compliance enforcement_mode = %q, want advisory", seen)
	}
	if !bytes.Equal(up.configure.Config.Msgpack, upstreamConfig(t)) {
		t.Error("upstream config still carries compliance")
	}
	if up.configure.TerraformVersion != "1.14.0" || !proto.Equal(up.configure.ClientCapabilities, caps) || !bytes.Equal(up.configure.ProtoReflect().GetUnknown(), unknownField) {
		t.Errorf("upstream request = %v, want version, capabilities and unknown field unchanged", up.configure)
	}
	if len(got.Diagnostics) != 2 || got.Diagnostics[0].Summary != "upstream" || got.Diagnostics[1].Summary != "proxy" {
		t.Errorf("diagnostics = %v, want upstream then proxy", got.Diagnostics)
	}
	if !bytes.Equal(got.ProtoReflect().GetUnknown(), unknownField) {
		t.Error("response unknown field lost")
	}
}

func TestProviderRPCConfigureNotForwarded(t *testing.T) {
	blocking := &hooktest.Recorder{OnConfigure: func(*hook.ConfigureRequest) ([]hook.Diagnostic, error) {
		return []hook.Diagnostic{{Severity: hook.SeverityError, Summary: "bad bundle"}}, nil
	}}
	failing := &hooktest.Recorder{OnConfigure: func(*hook.ConfigureRequest) ([]hook.Diagnostic, error) { return nil, errors.New("x") }}
	// "compliance" holds an integer where the block's object belongs.
	badConfig := &tfplugin5.DynamicValue{Msgpack: []byte{0x81, 0xaa, 'c', 'o', 'm', 'p', 'l', 'i', 'a', 'n', 'c', 'e', 0x05}}
	for name, tc := range map[string]struct {
		b    Backends
		cfg  func(*testing.T) *tfplugin5.DynamicValue
		want string
	}{
		"hook diag":   {Backends{Evaluator: blocking}, func(t *testing.T) *tfplugin5.DynamicValue { return combinedConfig(t, "hard_fail") }, "bad bundle"},
		"hook error":  {Backends{Evaluator: failing}, func(t *testing.T) *tfplugin5.DynamicValue { return combinedConfig(t, "hard_fail") }, "Compliance evaluation failed"},
		"parse error": {Backends{}, func(*testing.T) *tfplugin5.DynamicValue { return badConfig }, "Invalid compliance configuration"},
	} {
		t.Run(name, func(t *testing.T) {
			up := &fakeUpstream5{}
			client, _ := startProxy(t, up, tc.b)
			got, err := client.Configure(context.Background(), &tfplugin5.Configure_Request{Config: tc.cfg(t)})
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Diagnostics) != 1 || got.Diagnostics[0].Severity != tfplugin5.Diagnostic_ERROR || got.Diagnostics[0].Summary != tc.want {
				t.Errorf("diagnostics = %v, want one error %q", got.Diagnostics, tc.want)
			}
			if len(up.calls) != 0 {
				t.Errorf("upstream calls = %v, want none", up.calls)
			}
		})
	}
}

func TestProviderRPCStopOrder(t *testing.T) {
	up := &fakeUpstream5{}
	client, p := startProxy(t, up, Backends{})
	ctxErrAtUpstream := context.Canceled
	up.onStop = func() { ctxErrAtUpstream = p.stopCtx.Err() }

	if _, err := client.Stop(context.Background(), &tfplugin5.Stop_Request{}); err != nil {
		t.Fatal(err)
	}
	if ctxErrAtUpstream != nil {
		t.Errorf("stop context was canceled before upstream Stop: %v", ctxErrAtUpstream)
	}
	if p.stopCtx.Err() == nil {
		t.Error("stop context not canceled after Stop")
	}
}

// TestProviderRPCConfigureNoopWarns: a build serving hook.Noop tells the user
// at Configure that it enforces nothing, after upstream's diags.
func TestProviderRPCConfigureNoopWarns(t *testing.T) {
	up := &fakeUpstream5{}
	client, _ := startProxy(t, up, Backends{})
	got, err := client.Configure(context.Background(), &tfplugin5.Configure_Request{Config: combinedConfig(t, "hard_fail")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Diagnostics) != 2 || got.Diagnostics[0].Summary != "upstream" {
		t.Fatalf("diagnostics = %v, want upstream then the no-op warning", got.Diagnostics)
	}
	if d := got.Diagnostics[1]; d.Severity != tfplugin5.Diagnostic_WARNING || d.Summary != noControlsSummary || !strings.Contains(d.Detail, "compliance.tf") {
		t.Errorf("no-op diagnostic = %v, want warning %q naming compliance.tf", d, noControlsSummary)
	}
}

// TestProviderRPCConfigureRegion: Configure hands the
// upstream provider config region to the evaluator; a null or unknown region
// is not known, only a null one is null, a known non-empty profile is
// handed as Profile, and any other non-null profile or a
// non-null shared_config_files or shared_credentials_files (unknown
// included) sets SharedConfigSet.
func TestProviderRPCConfigureRegion(t *testing.T) {
	list := tftypes.List{ElementType: tftypes.String}
	typ := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"region": tftypes.String, "profile": tftypes.String, "shared_config_files": list,
		"shared_credentials_files": list, "compliance": ComplianceBlockType(),
	}}
	files := tftypes.NewValue(list, []tftypes.Value{tftypes.NewValue(tftypes.String, "f")})
	for _, c := range []struct {
		name                    string
		region, profile         any
		configFiles, credsFiles tftypes.Value
		want, profileOut        string
		known, null, sharedSet  bool
	}{
		{name: "known", region: "cn-north-1", want: "cn-north-1", known: true},
		{name: "null", null: true},
		{name: "unknown", region: tftypes.UnknownValue},
		{name: "profile", profile: "p", null: true, profileOut: "p"},
		{name: "profile unknown", profile: tftypes.UnknownValue, null: true, sharedSet: true},
		{name: "profile empty", profile: "", null: true, sharedSet: true},
		{name: "profile with files", profile: "p", configFiles: files, null: true, sharedSet: true, profileOut: "p"},
		{name: "config files", configFiles: files, null: true, sharedSet: true},
		{name: "credentials files", credsFiles: files, null: true, sharedSet: true},
		{name: "files unknown", credsFiles: tftypes.NewValue(list, tftypes.UnknownValue), null: true, sharedSet: true},
		{name: "known with profile", region: "eu-west-1", profile: "p", want: "eu-west-1", known: true, profileOut: "p"},
	} {
		var got *hook.ConfigureRequest
		client, _ := startProxy(t, &fakeUpstream5{}, Backends{Evaluator: &hooktest.Recorder{OnConfigure: func(r *hook.ConfigureRequest) ([]hook.Diagnostic, error) {
			got = r
			return nil, nil
		}}})
		orNull := func(v tftypes.Value) tftypes.Value {
			if v.Type() == nil {
				return tftypes.NewValue(list, nil)
			}
			return v
		}
		dv, err := tfprotov5.NewDynamicValue(typ, tftypes.NewValue(typ, map[string]tftypes.Value{
			"region":                   tftypes.NewValue(tftypes.String, c.region),
			"profile":                  tftypes.NewValue(tftypes.String, c.profile),
			"shared_config_files":      orNull(c.configFiles),
			"shared_credentials_files": orNull(c.credsFiles),
			"compliance":               tftypes.NewValue(ComplianceBlockType(), nil),
		}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Configure(context.Background(), &tfplugin5.Configure_Request{Config: &tfplugin5.DynamicValue{Msgpack: dv.MsgPack}}); err != nil {
			t.Fatal(err)
		}
		if got == nil || got.Region != c.want || got.RegionKnown != c.known || got.RegionNull != c.null || got.SharedConfigSet != c.sharedSet || got.Profile != c.profileOut {
			t.Errorf("%s: evaluator saw %+v, want %q known %v null %v shared %v profile %q", c.name, got, c.want, c.known, c.null, c.sharedSet, c.profileOut)
		}
	}
}

// TestDecodeRegion: only a known string is a region; a known
// empty string is known here and becomes an unknown partition in lifecycle.
func TestDecodeRegion(t *testing.T) {
	enc := func(v tftypes.Value) []byte {
		dv, err := tfprotov5.NewDynamicValue(v.Type(), v)
		if err != nil {
			t.Fatal(err)
		}
		return dv.MsgPack
	}
	for _, c := range []struct {
		name string
		raw  []byte
		want configRegion
	}{
		{"string", enc(tftypes.NewValue(tftypes.String, "us-gov-west-1")), configRegion{s: "us-gov-west-1", known: true}},
		{"empty", enc(tftypes.NewValue(tftypes.String, "")), configRegion{s: "", known: true}},
		{"null", enc(tftypes.NewValue(tftypes.String, nil)), configRegion{null: true}},
		{"unknown", enc(tftypes.NewValue(tftypes.String, tftypes.UnknownValue)), configRegion{}},
		{"number", enc(tftypes.NewValue(tftypes.Number, 1)), configRegion{}},
		{"bool", enc(tftypes.NewValue(tftypes.Bool, true)), configRegion{}},
		{"list", enc(tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{tftypes.NewValue(tftypes.String, "cn-north-1")})), configRegion{}},
		{"garbage", []byte{0xc1}, configRegion{}},
	} {
		if got := decodeRegion(c.raw); got != c.want {
			t.Errorf("%s: decodeRegion = %+v, want %+v", c.name, got, c.want)
		}
	}
}

// TestProviderRPCConfigureAccount: Configure hands the one id of
// the upstream config allowed_account_ids to the evaluator; an absent, null,
// empty, unknown or partly unknown set, or one with several ids, is not
// known. skip_requesting_account_id other than null or known false sets
// SkipAccountID. The region binding is unchanged by either attribute.
func TestProviderRPCConfigureAccount(t *testing.T) {
	set := tftypes.Set{ElementType: tftypes.String}
	str := func(v any) tftypes.Value { return tftypes.NewValue(tftypes.String, v) }
	ids := func(v ...tftypes.Value) tftypes.Value { return tftypes.NewValue(set, v) }
	for _, c := range []struct {
		name        string
		attrs       map[string]tftypes.Value
		want        string
		known, skip bool
	}{
		{name: "absent", attrs: map[string]tftypes.Value{}},
		{name: "null", attrs: map[string]tftypes.Value{"allowed_account_ids": tftypes.NewValue(set, nil)}},
		{name: "empty", attrs: map[string]tftypes.Value{"allowed_account_ids": ids()}},
		{name: "one", attrs: map[string]tftypes.Value{"allowed_account_ids": ids(str("111111111111"))}, want: "111111111111", known: true},
		{name: "many", attrs: map[string]tftypes.Value{"allowed_account_ids": ids(str("111111111111"), str("222222222222"))}},
		{name: "unknown at plan", attrs: map[string]tftypes.Value{"allowed_account_ids": tftypes.NewValue(set, tftypes.UnknownValue)}},
		{name: "element unknown", attrs: map[string]tftypes.Value{"allowed_account_ids": ids(str(tftypes.UnknownValue))}},
		{name: "skip true", attrs: map[string]tftypes.Value{"allowed_account_ids": ids(str("111111111111")), "skip_requesting_account_id": tftypes.NewValue(tftypes.Bool, true)},
			want: "111111111111", known: true, skip: true},
		{name: "null element", attrs: map[string]tftypes.Value{"allowed_account_ids": ids(str(nil))}},
		{name: "declared, skip false", attrs: map[string]tftypes.Value{"allowed_account_ids": ids(str("111111111111")), "skip_requesting_account_id": tftypes.NewValue(tftypes.Bool, false)},
			want: "111111111111", known: true},
		{name: "declared, skip unknown", attrs: map[string]tftypes.Value{"allowed_account_ids": ids(str("111111111111")), "skip_requesting_account_id": tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)},
			want: "111111111111", known: true, skip: true},
		{name: "skip unknown", attrs: map[string]tftypes.Value{"skip_requesting_account_id": tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue)}, skip: true},
		{name: "skip false", attrs: map[string]tftypes.Value{"skip_requesting_account_id": tftypes.NewValue(tftypes.Bool, false)}},
		{name: "skip null", attrs: map[string]tftypes.Value{"skip_requesting_account_id": tftypes.NewValue(tftypes.Bool, nil)}},
	} {
		types := map[string]tftypes.Type{"region": tftypes.String, "compliance": ComplianceBlockType()}
		vals := map[string]tftypes.Value{"region": str("eu-west-1"), "compliance": tftypes.NewValue(ComplianceBlockType(), nil)}
		for k, v := range c.attrs {
			types[k], vals[k] = v.Type(), v
		}
		typ := tftypes.Object{AttributeTypes: types}
		dv, err := tfprotov5.NewDynamicValue(typ, tftypes.NewValue(typ, vals))
		if err != nil {
			t.Fatal(err)
		}
		var got *hook.ConfigureRequest
		client, _ := startProxy(t, &fakeUpstream5{}, Backends{Evaluator: &hooktest.Recorder{OnConfigure: func(r *hook.ConfigureRequest) ([]hook.Diagnostic, error) {
			got = r
			return nil, nil
		}}})
		if _, err := client.Configure(context.Background(), &tfplugin5.Configure_Request{Config: &tfplugin5.DynamicValue{Msgpack: dv.MsgPack}}); err != nil {
			t.Fatal(err)
		}
		if got == nil || got.AccountID != c.want || got.AccountKnown != c.known || got.SkipAccountID != c.skip || got.Region != "eu-west-1" || !got.RegionKnown {
			t.Errorf("%s: evaluator saw %+v, want account %q known %v skip %v", c.name, got, c.want, c.known, c.skip)
		}
	}
}
