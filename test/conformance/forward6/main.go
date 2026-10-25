//go:build conformance

// Command forward6 is a conformance-only protocol 6 provider: it serves the
// proxy's raw forwarder (internal/rawgrpc) with the pinned tfplugin6 route
// table in front of the upstream binary FORWARD6_UPSTREAM, as
// internal/proxy/passthrough6_test.go does in process. The released proxy
// serves protocol 5 only (v6 intercepted handlers are deferred), so this is
// how real Terraform reaches the v6 passthrough, state store RPCs included.
// With FORWARD6_CALLS set it appends one line per forwarded call to that
// file: the full method, a tab and the gRPC status code. A failed append
// fails the call with a "forward6: ERR" status, which Terraform logs.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/compliancetf/terraform-provider-aws/internal/rawgrpc"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin"
)

var handshake = plugin.HandshakeConfig{
	ProtocolVersion:  6,
	MagicCookieKey:   "TF_PLUGIN_MAGIC_COOKIE",
	MagicCookieValue: "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2",
}

// connPlugin dispenses the upstream's raw gRPC conn and registers nothing on
// the served side, so every tfplugin6 method reaches the forwarder.
type connPlugin struct{ plugin.NetRPCUnsupportedPlugin }

func (connPlugin) GRPCServer(*plugin.GRPCBroker, *grpc.Server) error { return nil }

func (connPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return c, nil
}

func main() {
	c := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  handshake,
		VersionedPlugins: map[int]plugin.PluginSet{6: {"provider": connPlugin{}}},
		Cmd:              exec.Command(os.Getenv("FORWARD6_UPSTREAM")), //nolint:gosec // conformance-only, path set by the test
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
		Logger:           hclog.New(&hclog.LoggerOptions{Name: "forward6-upstream", Level: hclog.Warn}),
		GRPCDialOptions:  []grpc.DialOption{rawgrpc.CallSizes()},
	})
	fail := func(format string, args ...any) {
		c.Kill()
		log.Fatalf("forward6: "+format, args...)
	}
	rpc, err := c.Client()
	if err != nil {
		fail("start upstream: %s", err)
	}
	raw, err := rpc.Dispense("provider")
	if err != nil {
		fail("dispense upstream: %s", err)
	}
	conn, ok := raw.(*grpc.ClientConn)
	if !ok {
		fail("dispensed %T", raw)
	}
	defer c.Kill()
	fwd := rawgrpc.Forwarder(conn, tfplugin.V6(), nil)
	calls := os.Getenv("FORWARD6_CALLS")
	handler := func(srv any, ss grpc.ServerStream) error {
		err := fwd(srv, ss)
		if calls != "" {
			method, _ := grpc.MethodFromServerStream(ss)
			if rerr := record(calls, fmt.Sprintf("%s\t%s\n", method, status.Code(err))); rerr != nil {
				return status.Errorf(codes.Internal, "forward6: ERR record call %s: %s", method, rerr)
			}
		}
		return err
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig:  handshake,
		VersionedPlugins: map[int]plugin.PluginSet{6: {"provider": connPlugin{}}},
		GRPCServer: func(opts []grpc.ServerOption) *grpc.Server {
			return grpc.NewServer(append(opts,
				grpc.ForceServerCodecV2(rawgrpc.Codec{}),
				grpc.UnknownServiceHandler(handler),
				grpc.MaxRecvMsgSize(rawgrpc.MaxMsgSize),
				grpc.MaxSendMsgSize(rawgrpc.MaxMsgSize),
			)...)
		},
	})
}

// record appends line to path.
func record(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(line)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
