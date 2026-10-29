package proxy_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/compliancetf/terraform-provider-aws/internal/rawgrpc"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin6"
)

// v6Plugin hands the test the fake's gRPC connection, as the proxy does.
type v6Plugin struct{ plugin.NetRPCUnsupportedPlugin }

func (v6Plugin) GRPCServer(*plugin.GRPCBroker, *grpc.Server) error { return nil }

func (v6Plugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return c, nil
}

// v6Proxy builds and launches test/fakeupstream/v6, puts the raw forwarder
// with the pinned v6 route table in front of it and returns a connection to
// the forwarder.
func v6Proxy(t *testing.T) *grpc.ClientConn {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fake6")
	if runtime.GOOS == "windows" {
		bin += ".exe" // exec finds a binary on Windows only by its extension
	}
	build := exec.Command("go", "build", "-o", bin, "./v6")
	build.Dir = filepath.Join("..", "..", "test", "fakeupstream")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake v6 upstream: %v\n%s", err, out)
	}
	c := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: plugin.HandshakeConfig{
			MagicCookieKey:   "TF_PLUGIN_MAGIC_COOKIE",
			MagicCookieValue: "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2",
		},
		VersionedPlugins: map[int]plugin.PluginSet{6: {"provider": v6Plugin{}}},
		Cmd:              exec.Command(bin),
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
		Logger:           hclog.New(&hclog.LoggerOptions{Name: "fake6", Level: hclog.Warn}),
	})
	t.Cleanup(c.Kill)
	rpc, err := c.Client()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := rpc.Dispense("provider")
	if err != nil {
		t.Fatal(err)
	}
	upstream := raw.(*grpc.ClientConn)

	srv := grpc.NewServer(grpc.ForceServerCodecV2(rawgrpc.Codec{}), grpc.UnknownServiceHandler(rawgrpc.Forwarder(upstream, tfplugin.V6(), nil)))
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// call6 sends each JSON request of method on one stream and returns every
// response.
func call6(conn *grpc.ClientConn, method string, reqs ...string) ([]*dynamicpb.Message, error) {
	md := tfplugin6.File_tfplugin6_proto.Services().ByName("Provider").Methods().ByName(protoreflect.Name(method))
	if md == nil {
		return nil, fmt.Errorf("no method %s in tfplugin6.Provider", method)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: md.IsStreamingServer(), ClientStreams: md.IsStreamingClient()}, "/tfplugin6.Provider/"+method)
	if err != nil {
		return nil, err
	}
	for _, r := range reqs {
		m := dynamicpb.NewMessage(md.Input())
		if err := protojson.Unmarshal([]byte(r), m); err != nil {
			return nil, fmt.Errorf("request %s: %w", r, err)
		}
		if err := s.SendMsg(m); err != nil {
			return nil, err
		}
	}
	if err := s.CloseSend(); err != nil {
		return nil, err
	}
	var out []*dynamicpb.Message
	for {
		m := dynamicpb.NewMessage(md.Output())
		err := s.RecvMsg(m)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, m)
		if !md.IsStreamingServer() {
			return out, nil
		}
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// dv is a DynamicValue JSON carrying js as its JSON encoding.
func dv(js string) string { return fmt.Sprintf(`{"json":%q}`, b64([]byte(js))) }

// writeChunks6 splits b into 64-byte WriteStateBytes chunks; meta rides on
// the first.
func writeChunks6(id string, b []byte) []string {
	var out []string
	for start := 0; start < len(b); start += 64 {
		end := min(start+64, len(b))
		meta := ``
		if start == 0 {
			meta = `"meta":{"type_name":"fake_store","state_id":"` + id + `"},`
		}
		out = append(out, fmt.Sprintf(`{%s"bytes":%q,"total_length":%d,"range":{"start":%d,"end":%d}}`,
			meta, b64(b[start:end]), len(b), start, end))
	}
	return out
}

type rpc6 struct {
	reqs []string
	want string // substring of the space-free protojson of the responses
}

// rpcs6 has one request per tfplugin6.Provider method of the fake upstream.
func rpcs6() map[string]rpc6 {
	var (
		empty      = dv(`{}`)
		thingCfg   = dv(`{"id":null,"name":"a","size":null,"crash":null}`)
		thingState = dv(`{"id":"bobthecorp-a","name":"a","size":1,"crash":null}`)
		lookupCfg  = dv(`{"name":"a","id":null,"crash":null}`)
		secretCfg  = dv(`{"name":"a","value":null}`)
		listCfg    = dv(`{"prefix":"bobthecorp-x"}`)
		pokeCfg    = dv(`{"target":"a","crash":null}`)
		rawThing   = fmt.Sprintf(`{"json":%q}`, b64([]byte(`{"id":"x","name":"x","size":1,"crash":null}`)))
		priv       = b64([]byte("p"))
		st         = `{"type_name":"fake_store","state_id":"default"}`
	)
	return map[string]rpc6{
		"GetMetadata":                     {[]string{`{}`}, `"stateStores":[{"typeName":"fake_store"}]`},
		"GetProviderSchema":               {[]string{`{}`}, `"stateStoreSchemas":{"fake_store":`},
		"GetResourceIdentitySchemas":      {[]string{`{}`}, `"fake_thing"`},
		"ValidateProviderConfig":          {[]string{`{"config":` + empty + `}`}, ``},
		"ValidateResourceConfig":          {[]string{`{"type_name":"fake_thing","config":` + thingCfg + `}`}, ``},
		"ValidateDataResourceConfig":      {[]string{`{"type_name":"fake_lookup","config":` + lookupCfg + `}`}, ``},
		"ValidateEphemeralResourceConfig": {[]string{`{"type_name":"fake_secret","config":` + secretCfg + `}`}, ``},
		"ValidateListResourceConfig":      {[]string{`{"type_name":"fake_thing","config":` + listCfg + `}`}, ``},
		"ValidateActionConfig":            {[]string{`{"action_type":"fake_poke","config":` + pokeCfg + `}`}, ``},
		"ConfigureProvider":               {[]string{`{"config":` + empty + `}`}, ``},
		"UpgradeResourceState":            {[]string{`{"type_name":"fake_thing","raw_state":` + rawThing + `}`}, `"upgradedState"`},
		"UpgradeResourceIdentity": {[]string{
			`{"type_name":"fake_thing","raw_identity":{"json":"` + b64([]byte(`{"id":"x"}`)) + `"}}`}, `"identityData"`},
		"ReadResource":       {[]string{`{"type_name":"fake_thing","current_state":` + thingState + `}`}, `"newIdentity"`},
		"PlanResourceChange": {[]string{`{"type_name":"fake_thing","proposed_new_state":` + thingCfg + `,"config":` + thingCfg + `}`}, `"plannedPrivate"`},
		"ApplyResourceChange": {[]string{
			`{"type_name":"fake_thing","planned_state":` + thingState + `,"config":` + thingCfg + `,"planned_private":"` + priv + `"}`}, `"private":"` + priv + `"`},
		"ImportResourceState": {[]string{`{"type_name":"fake_thing","id":"bobthecorp-a"}`}, `"identity"`},
		"MoveResourceState": {[]string{
			`{"source_type_name":"fake_thing","target_type_name":"fake_thing","source_state":` + rawThing + `}`}, `"targetState"`},
		"ReadDataSource":         {[]string{`{"type_name":"fake_lookup","config":` + lookupCfg + `}`}, `"state"`},
		"GenerateResourceConfig": {[]string{`{"type_name":"fake_thing","state":` + thingState + `}`}, `"config"`},
		"OpenEphemeralResource":  {[]string{`{"type_name":"fake_secret","config":` + secretCfg + `}`}, `"result"`},
		"RenewEphemeralResource": {[]string{`{"type_name":"fake_secret","private":"` + priv + `"}`}, `"private"`},
		"CloseEphemeralResource": {[]string{`{"type_name":"fake_secret","private":"` + priv + `"}`}, ``},
		"ListResource": {[]string{
			`{"type_name":"fake_thing","config":` + listCfg + `,"include_resource_object":true}`}, `"displayName":"bobthecorp-x-2"`},
		"GetFunctions":             {[]string{`{}`}, ``},
		"CallFunction":             {[]string{`{"name":"nope"}`}, `"error"`},
		"PlanAction":               {[]string{`{"action_type":"fake_poke","config":` + pokeCfg + `}`}, ``},
		"InvokeAction":             {[]string{`{"action_type":"fake_poke","config":` + pokeCfg + `}`}, `"completed"`},
		"StopProvider":             {[]string{`{}`}, ``},
		"ValidateStateStoreConfig": {[]string{`{"type_name":"fake_store","config":` + empty + `}`}, ``},
		"ConfigureStateStore":      {[]string{`{"type_name":"fake_store","config":` + empty + `}`}, `"chunkSize":"64"`},
		"WriteStateBytes":          {writeChunks6("default", bytes.Repeat([]byte("s"), 10)), ``},
		"ReadStateBytes":           {[]string{st}, `"bytes":"c3Nzc3Nzc3Nzcw=="`},
		"GetStates":                {[]string{`{"type_name":"fake_store"}`}, `"stateIds":["default"]`},
		"LockState":                {[]string{st}, `"lockId":"lock-default"`},
		"UnlockState":              {[]string{st}, ``},
		"DeleteState":              {[]string{st}, ``},
	}
}

// v6Order runs the state store methods after WriteStateBytes so the reads
// see written state, and DeleteState last.
var v6Order = []string{"WriteStateBytes", "ReadStateBytes", "GetStates", "LockState", "UnlockState", "DeleteState"}

func compact6(t *testing.T, ms []*dynamicpb.Message) string {
	t.Helper()
	var sb strings.Builder
	for _, m := range ms {
		b, err := protojson.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		sb.Write(b)
	}
	return strings.ReplaceAll(sb.String(), " ", "")
}

// TestV6Passthrough forwards every method of the pinned v6 route table raw to
// the fake v6 upstream binary: unary, server-stream ReadStateBytes and
// ListResource, client-stream WriteStateBytes.
func TestV6Passthrough(t *testing.T) {
	conn := v6Proxy(t)
	routes := tfplugin.V6()
	table := rpcs6()
	if len(routes) != len(table) {
		t.Errorf("v6 route table has %d methods, rpcs6 has %d", len(routes), len(table))
	}
	var methods []string
	for full, r := range routes {
		if r.Class != tfplugin.Passthrough {
			t.Errorf("%s: class %s, want passthrough", full, r.Class)
		}
		name := strings.TrimPrefix(full, "/tfplugin6.Provider/")
		if _, ok := table[name]; !ok {
			t.Errorf("%s: no request in rpcs6", full)
			continue
		}
		if !slices.Contains(v6Order, name) {
			methods = append(methods, name)
		}
	}
	methods = append(methods, v6Order...)

	for _, name := range methods {
		c := table[name]
		resps, err := call6(conn, name, c.reqs...)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got := compact6(t, resps)
		if !routes["/tfplugin6.Provider/"+name].ServerStream && len(resps) != 1 {
			t.Errorf("%s: %d responses, want 1", name, len(resps))
		}
		if strings.Contains(got, `"severity":"ERROR"`) {
			t.Errorf("%s: error diagnostic: %s", name, got)
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: response %s lacks %s", name, got, c.want)
		}
	}
}

// TestV6StateBytesRoundTrip: a multi-chunk client-stream write and the
// server-stream read of it cross the forwarder unchanged.
func TestV6StateBytesRoundTrip(t *testing.T) {
	conn := v6Proxy(t)
	state := bytes.Repeat([]byte("bobthecorp"), 15)
	if _, err := call6(conn, "WriteStateBytes", writeChunks6("s1", state)...); err != nil {
		t.Fatal(err)
	}
	resps, err := call6(conn, "ReadStateBytes", `{"type_name":"fake_store","state_id":"s1"}`)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	for _, r := range resps {
		got = append(got, r.Get(r.Descriptor().Fields().ByName("bytes")).Bytes()...)
	}
	if len(resps) != 3 || !bytes.Equal(got, state) {
		t.Errorf("read %d chunks %q, want 3 chunks %q", len(resps), got, state)
	}
}

// TestV6UnknownMethod: a method absent from the pinned v6 proto returns
// Unimplemented.
func TestV6UnknownMethod(t *testing.T) {
	conn := v6Proxy(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := conn.Invoke(ctx, "/tfplugin6.Provider/FutureRPC", &rawgrpc.Frame{}, &rawgrpc.Frame{}, grpc.ForceCodecV2(rawgrpc.Codec{}))
	if status.Code(err) != codes.Unimplemented || !strings.Contains(err.Error(), "not in the pinned protocol") {
		t.Errorf("err %v, want Unimplemented: not in the pinned protocol", err)
	}
}
