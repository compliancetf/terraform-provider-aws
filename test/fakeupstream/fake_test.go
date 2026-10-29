package fakeupstream_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	// Register the tfplugin5 and tfplugin6 descriptors the fakes serve.
	_ "github.com/hashicorp/terraform-plugin-go/tfprotov5/tf5server"
	_ "github.com/hashicorp/terraform-plugin-go/tfprotov6/tf6server"
)

var bins = map[int]string{}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "fakeupstream")
	if err != nil {
		panic(err)
	}
	for _, v := range []int{5, 6} {
		bins[v] = filepath.Join(dir, fmt.Sprintf("fake%d", v))
		if runtime.GOOS == "windows" {
			bins[v] += ".exe" // exec finds a binary on Windows only by its extension
		}
		if out, err := exec.Command("go", "build", "-o", bins[v], fmt.Sprintf("./v%d", v)).CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build v%d: %v\n%s", v, err, out)
			os.Exit(1)
		}
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// rawPlugin hands the test the plugin's gRPC connection, as the proxy does.
type rawPlugin struct{ plugin.NetRPCUnsupportedPlugin }

func (rawPlugin) GRPCServer(*plugin.GRPCBroker, *grpc.Server) error { return nil }

func (rawPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return c, nil
}

func launch(t *testing.T, v int) (*grpc.ClientConn, *plugin.Client) {
	t.Helper()
	c := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: plugin.HandshakeConfig{
			MagicCookieKey:   "TF_PLUGIN_MAGIC_COOKIE",
			MagicCookieValue: "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2",
		},
		VersionedPlugins: map[int]plugin.PluginSet{v: {"provider": rawPlugin{}}},
		Cmd:              exec.Command(bins[v]),
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
		Logger:           hclog.New(&hclog.LoggerOptions{Name: "fake", Level: hclog.Warn}),
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
	return raw.(*grpc.ClientConn), c
}

func service(t *testing.T, v int) protoreflect.ServiceDescriptor {
	t.Helper()
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(fmt.Sprintf("tfplugin%d.Provider", v)))
	if err != nil {
		t.Fatal(err)
	}
	return d.(protoreflect.ServiceDescriptor)
}

// call sends each JSON request on one stream and returns every response.
func call(conn *grpc.ClientConn, md protoreflect.MethodDescriptor, reqs ...string) ([]*dynamicpb.Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	desc := &grpc.StreamDesc{ServerStreams: md.IsStreamingServer(), ClientStreams: md.IsStreamingClient()}
	s, err := conn.NewStream(ctx, desc, fmt.Sprintf("/%s/%s", md.Parent().FullName(), md.Name()))
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

// mp is a DynamicValue JSON with the msgpack encoding of o.
func mp(o map[string]any) string {
	b, err := msgpack.Marshal(o)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf(`{"msgpack":%q}`, b64(b))
}

type rpc struct {
	reqs []string
	want string // substring of the space-free protojson of the responses
}

var (
	empty      = mp(map[string]any{})
	thingCfg   = mp(map[string]any{"id": nil, "name": "a", "size": nil, "crash": nil})
	thingState = mp(map[string]any{"id": "bobthecorp-a", "name": "a", "size": 1, "crash": nil})
	thingCrash = mp(map[string]any{"id": "bobthecorp-a", "name": "a", "size": 1, "crash": true})
	lookupCfg  = mp(map[string]any{"name": "a", "id": nil, "crash": nil})
	secretCfg  = mp(map[string]any{"name": "a", "value": nil})
	listCfg    = mp(map[string]any{"prefix": "bobthecorp-x"})
	pokeCfg    = mp(map[string]any{"target": "a", "crash": nil})
	pokeCrash  = mp(map[string]any{"target": "a", "crash": true})
	rawThing   = fmt.Sprintf(`{"json":%q}`, b64([]byte(`{"id":"x","name":"x","size":1,"crash":null}`)))
	priv       = b64([]byte("p"))
)

// rpcs has one request per method of the protocol-v service; a method missing
// here fails TestServesEveryRPC, so a protocol bump cannot skip the fake.
func rpcs(v int) map[string]rpc {
	r := map[string]rpc{
		"GetMetadata":                {[]string{`{}`}, `"typeName":"fake_poke"`},
		"GetResourceIdentitySchemas": {[]string{`{}`}, `"fake_thing"`},
		"ValidateEphemeralResourceConfig": {[]string{
			`{"type_name":"fake_secret","config":` + secretCfg + `}`}, ``},
		"UpgradeResourceState": {[]string{`{"type_name":"fake_thing","raw_state":` + rawThing + `}`}, `"upgradedState"`},
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
		"ValidateListResourceConfig": {[]string{`{"type_name":"fake_thing","config":` + listCfg + `}`}, ``},
		"GetFunctions":               {[]string{`{}`}, ``},
		"CallFunction":               {[]string{`{"name":"nope"}`}, `"error"`},
		"ValidateActionConfig":       {[]string{`{"action_type":"fake_poke","config":` + pokeCfg + `}`}, ``},
		"PlanAction":                 {[]string{`{"action_type":"fake_poke","config":` + pokeCfg + `}`}, ``},
		"InvokeAction":               {[]string{`{"action_type":"fake_poke","config":` + pokeCfg + `}`}, `"completed"`},
	}
	// Methods whose names differ between protocol 5 and 6.
	names := map[string][2]string{
		"schema":    {"GetSchema", "GetProviderSchema"},
		"validate":  {"PrepareProviderConfig", "ValidateProviderConfig"},
		"resource":  {"ValidateResourceTypeConfig", "ValidateResourceConfig"},
		"data":      {"ValidateDataSourceConfig", "ValidateDataResourceConfig"},
		"configure": {"Configure", "ConfigureProvider"},
		"stop":      {"Stop", "StopProvider"},
	}
	n := func(k string) string { return names[k][v-5] }
	r[n("schema")] = rpc{[]string{`{}`}, `"fake_replace"`}
	r[n("validate")] = rpc{[]string{`{"config":` + empty + `}`}, ``}
	r[n("resource")] = rpc{[]string{`{"type_name":"fake_thing","config":` + thingCfg + `}`}, ``}
	r[n("data")] = rpc{[]string{`{"type_name":"fake_lookup","config":` + lookupCfg + `}`}, ``}
	r[n("configure")] = rpc{[]string{`{"config":` + empty + `}`}, ``}
	r[n("stop")] = rpc{[]string{`{}`}, ``}
	if v == 6 {
		st := `{"type_name":"fake_store","state_id":"default"}`
		r["ValidateStateStoreConfig"] = rpc{[]string{`{"type_name":"fake_store","config":` + empty + `}`}, ``}
		r["ConfigureStateStore"] = rpc{[]string{`{"type_name":"fake_store","config":` + empty + `}`}, `"chunkSize":"64"`}
		r["WriteStateBytes"] = rpc{writeChunks("default", bytes.Repeat([]byte("s"), 10)), ``}
		r["ReadStateBytes"] = rpc{[]string{st}, ``}
		r["GetStates"] = rpc{[]string{`{"type_name":"fake_store"}`}, ``}
		r["LockState"] = rpc{[]string{st}, `"lockId":"lock-default"`}
		r["UnlockState"] = rpc{[]string{st}, ``}
		r["DeleteState"] = rpc{[]string{st}, ``}
	}
	return r
}

// writeChunks splits b into 64-byte WriteStateBytes chunks; meta rides on the first.
func writeChunks(id string, b []byte) []string {
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

func compact(t *testing.T, ms []*dynamicpb.Message) string {
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

func TestServesEveryRPC(t *testing.T) {
	for _, v := range []int{5, 6} {
		t.Run(fmt.Sprintf("v%d", v), func(t *testing.T) {
			conn, _ := launch(t, v)
			table := rpcs(v)
			methods := service(t, v).Methods()
			if methods.Len() != len(table) {
				t.Errorf("service has %d methods, table has %d", methods.Len(), len(table))
			}
			for i := range methods.Len() {
				md := methods.Get(i)
				c, ok := table[string(md.Name())]
				if !ok {
					t.Errorf("%s: no request in rpcs(%d)", md.Name(), v)
					continue
				}
				resps, err := call(conn, md, c.reqs...)
				if err != nil {
					t.Errorf("%s: %v", md.Name(), err)
					continue
				}
				got := compact(t, resps)
				if !md.IsStreamingServer() && len(resps) != 1 {
					t.Errorf("%s: %d responses", md.Name(), len(resps))
				}
				if strings.Contains(got, `"severity":"ERROR"`) {
					t.Errorf("%s: error diagnostic: %s", md.Name(), got)
				}
				if !strings.Contains(got, c.want) {
					t.Errorf("%s: response %s lacks %s", md.Name(), got, c.want)
				}
			}
		})
	}
}

func field(m protoreflect.Message, names ...string) protoreflect.Value {
	var v protoreflect.Value
	for _, n := range names {
		fd := m.Descriptor().Fields().ByName(protoreflect.Name(n))
		v = m.Get(fd)
		if fd.Message() != nil {
			m = v.Message()
		}
	}
	return v
}

// TestNonCanonicalNewState: keys in reverse order, integer size as float64.
func TestNonCanonicalNewState(t *testing.T) {
	for _, v := range []int{5, 6} {
		conn, _ := launch(t, v)
		md := service(t, v).Methods().ByName("ApplyResourceChange")
		resps, err := call(conn, md, rpcs(v)["ApplyResourceChange"].reqs...)
		if err != nil {
			t.Fatal(err)
		}
		b := field(resps[0], "new_state", "msgpack").Bytes()
		wantPrefix := []byte{0x84, 0xa4, 's', 'i', 'z', 'e', 0xcb}
		if !bytes.HasPrefix(b, wantPrefix) {
			t.Errorf("v%d: new_state % x does not start with % x", v, b, wantPrefix)
		}
		var got map[string]any
		if err := msgpack.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"size": 1.0, "name": "a", "id": "bobthecorp-a", "crash": nil}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("v%d: new_state %v, want %v", v, got, want)
		}
	}
}

// TestCrash: crash = true kills the process on an intercepted RPC (apply)
// and on a passthrough one (InvokeAction).
func TestCrash(t *testing.T) {
	cases := map[string]string{
		"ApplyResourceChange": `{"type_name":"fake_thing","planned_state":` + thingCrash + `,"config":` + thingCrash + `}`,
		"InvokeAction":        `{"action_type":"fake_poke","config":` + pokeCrash + `}`,
	}
	for _, v := range []int{5, 6} {
		for method, req := range cases {
			conn, client := launch(t, v)
			_, err := call(conn, service(t, v).Methods().ByName(protoreflect.Name(method)), req)
			if status.Code(err) != codes.Unavailable {
				t.Errorf("v%d %s: err %v, want Unavailable", v, method, err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for !client.Exited() && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if !client.Exited() {
				t.Errorf("v%d %s: process still running", v, method)
			}
		}
	}
}

// TestStateStoreRoundTrip: client-stream write then server-stream read, chunked.
func TestStateStoreRoundTrip(t *testing.T) {
	conn, _ := launch(t, 6)
	methods := service(t, 6).Methods()
	state := bytes.Repeat([]byte("bobthecorp"), 15)
	if _, err := call(conn, methods.ByName("WriteStateBytes"), writeChunks("s1", state)...); err != nil {
		t.Fatal(err)
	}
	resps, err := call(conn, methods.ByName("ReadStateBytes"), `{"type_name":"fake_store","state_id":"s1"}`)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	for _, r := range resps {
		got = append(got, field(r, "bytes").Bytes()...)
	}
	if len(resps) != 3 || !bytes.Equal(got, state) {
		t.Errorf("read %d chunks %q, want 3 chunks %q", len(resps), got, state)
	}
}

func TestV6GeneratedInSync(t *testing.T) {
	want, err := exec.Command("sh", "v6/gen.sh").Output()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("v6/provider_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("v6/provider_gen.go is stale: run go generate ./v6")
	}
}

// TestStateStoreAdvertised: Terraform only accepts a state_store block whose
// type the provider lists, so v6 advertises fake_store in GetMetadata and
// GetProviderSchema. v5 has no state stores and must not mention it.
func TestStateStoreAdvertised(t *testing.T) {
	want := map[string]string{
		"GetMetadata":       `"stateStores":[{"typeName":"fake_store"}]`,
		"GetProviderSchema": `"stateStoreSchemas":{"fake_store":`,
	}
	for _, v := range []int{5, 6} {
		conn, _ := launch(t, v)
		for method, sub := range want {
			if v == 5 && method == "GetProviderSchema" {
				method = "GetSchema"
			}
			resps, err := call(conn, service(t, v).Methods().ByName(protoreflect.Name(method)), `{}`)
			if err != nil {
				t.Fatal(err)
			}
			got := compact(t, resps)
			if v == 6 && !strings.Contains(got, sub) {
				t.Errorf("v6 %s: response lacks %s", method, sub)
			}
			if v == 5 && strings.Contains(got, "fake_store") {
				t.Errorf("v5 %s: response mentions fake_store", method)
			}
		}
	}
}
