//go:build conformance

package conformance

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// capPin is one upstream's entry in testdata/capabilities.json.
type capPin struct {
	Protocol           int             `json:"protocol"`
	ProtocolVersion    string          `json:"protocol_version"`
	ServerCapabilities map[string]bool `json:"server_capabilities"`
}

// TestCapabilities: the proxy advertises the upstream's protocol and
// server_capabilities, and both equal the pin. The protocol minor is the
// version line of the tfplugin5.proto each side is compiled from (the wire
// carries only the major). The check needs no Terraform binary, so it runs
// once per -tf cell with the same result.
func TestCapabilities(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "capabilities.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pins map[string]capPin
	if err := strictUnmarshal(b, &pins); err != nil {
		t.Fatalf("capabilities.json: %v", err)
	}
	pin, ok := pins["fakeupstream/v5"]
	if !ok {
		t.Fatal("capabilities.json: no fakeupstream/v5 entry")
	}

	fakeDir, err := exec.Command("go", "-C", filepath.Join("..", "fakeupstream"), "list", "-m", "-f", "{{.Dir}}", "github.com/hashicorp/terraform-plugin-go").Output()
	if err != nil {
		t.Fatalf("go list terraform-plugin-go for the fake upstream: %v", err)
	}
	minors := map[string]string{
		"upstream": protoVersion(t, filepath.Join(strings.TrimSpace(string(fakeDir)), "tfprotov5", "internal", "tfplugin5", "tfplugin5.proto")),
		"proxy":    protoVersion(t, filepath.Join("..", "..", "internal", "tfplugin", "proto", "tfplugin5.proto")),
	}
	for side, v := range minors {
		if v != pin.ProtocolVersion {
			t.Errorf("%s tfplugin5.proto is protocol %s, pin %s", side, v, pin.ProtocolVersion)
		}
	}

	upstream := filepath.Join(binDir, "fakeupstream")
	for side, bin := range map[string]string{"upstream": upstream, "proxy": filepath.Join(binDir, "terraform-provider-aws")} {
		conn, proto := dialProvider(t, bin)
		if proto != pin.Protocol {
			t.Errorf("%s negotiated protocol %d, pin %d", side, proto, pin.Protocol)
		}
		c := tfplugin5.NewProviderClient(conn)
		schema, err := c.GetSchema(t.Context(), &tfplugin5.GetProviderSchema_Request{})
		if err != nil {
			t.Fatalf("%s GetSchema: %v", side, err)
		}
		meta, err := c.GetMetadata(t.Context(), &tfplugin5.GetMetadata_Request{})
		if err != nil {
			t.Fatalf("%s GetMetadata: %v", side, err)
		}
		for rpc, caps := range map[string]*tfplugin5.ServerCapabilities{"GetSchema": schema.GetServerCapabilities(), "GetMetadata": meta.GetServerCapabilities()} {
			if got := capMap(t, caps); !reflect.DeepEqual(got, pin.ServerCapabilities) {
				t.Errorf("%s %s server_capabilities %v, pin %v", side, rpc, got, pin.ServerCapabilities)
			}
		}
	}
}

var protoVersionRE = regexp.MustCompile(`(?m)^// Terraform Plugin RPC protocol version (\d+\.\d+)$`)

func protoVersion(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := protoVersionRE.FindSubmatch(b)
	if m == nil {
		t.Fatalf("%s: no protocol version line", path)
	}
	return string(m[1])
}

// capMap renders every ServerCapabilities field, unset ones as false, so a
// capability added to the proto shows up as a pin mismatch.
func capMap(t *testing.T, c *tfplugin5.ServerCapabilities) map[string]bool {
	t.Helper()
	if c == nil {
		c = &tfplugin5.ServerCapabilities{}
	}
	b, err := protojson.MarshalOptions{EmitUnpopulated: true, UseProtoNames: true}.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]bool
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// dialProvider starts bin as Terraform would (go-plugin handshake, the same
// environment the scenarios get) and returns its gRPC conn and the protocol
// it negotiated. The process is killed when the test ends.
func dialProvider(t *testing.T, bin string) (*grpc.ClientConn, int) {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Env = childEnv("", "", "")
	c := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: plugin.HandshakeConfig{
			MagicCookieKey:   "TF_PLUGIN_MAGIC_COOKIE",
			MagicCookieValue: "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2",
		},
		VersionedPlugins: map[int]plugin.PluginSet{5: {"provider": rawPlugin{}}, 6: {"provider": rawPlugin{}}},
		Cmd:              cmd,
		SkipHostEnv:      true,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
		Logger:           hclog.NewNullLogger(),
	})
	t.Cleanup(c.Kill)
	rpc, err := c.Client()
	if err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	raw, err := rpc.Dispense("provider")
	if err != nil {
		t.Fatalf("dispense %s: %v", bin, err)
	}
	conn, ok := raw.(*grpc.ClientConn)
	if !ok {
		t.Fatalf("dispensed %T", raw)
	}
	return conn, c.NegotiatedVersion()
}

// rawPlugin dispenses the go-plugin conn itself.
type rawPlugin struct{ plugin.NetRPCUnsupportedPlugin }

func (rawPlugin) GRPCServer(*plugin.GRPCBroker, *grpc.Server) error { return nil }

func (rawPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, conn *grpc.ClientConn) (any, error) {
	return conn, nil
}
