package proxy

// serve.go serves the provider over go-plugin on a raw gRPC server. Methods
// the route table classes passthrough go to upstream as undecoded bytes,
// intercepted methods go to their handlers, and a method absent from the
// pinned proto returns Unimplemented.

import (
	"context"
	"errors"
	"io"
	"log"
	"strings"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/rawgrpc"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin"
)

const providerService = "/tfplugin5.Provider/"

// Backends are the conns the served methods reach.
type Backends struct {
	// Upstream serves every passthrough method.
	Upstream *grpc.ClientConn
	// UpstreamName is the upstream named in diagnostics (Source.Name).
	UpstreamName string
	// UpstreamSHA256 is the verified sha256 of the binary behind Upstream;
	// the GetSchema cache is keyed on it.
	UpstreamSHA256 string
	// OnTransportErr maps an Unavailable error from Upstream (upstream.TransportErr).
	OnTransportErr func(method string, err error) error
	// Evaluator is called at Configure and at each hook stage. Nil: hook.Noop.
	Evaluator hook.Evaluator
}

// Serve runs the go-plugin server with protocol 5 until Terraform ends it.
// Debug and reattach mode (TF_REATTACH_PROVIDERS) are not offered.
func Serve(b Backends) {
	p := newServer5(b)
	if hook.IsNoop(p.ev) {
		log.Println("[WARN] compliance.tf: this build has no compliance evaluator; no compliance control is enforced")
	}
	defer func() {
		if c, ok := p.ev.(io.Closer); ok {
			if err := c.Close(); err != nil {
				log.Printf("[ERROR] close compliance evaluator: %s", err)
			}
		}
	}()
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: plugin.HandshakeConfig{
			ProtocolVersion:  5,
			MagicCookieKey:   "TF_PLUGIN_MAGIC_COOKIE",
			MagicCookieValue: "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2",
		},
		VersionedPlugins: map[int]plugin.PluginSet{5: {"provider": providerPlugin{p: p}}},
		GRPCServer: func(opts []grpc.ServerOption) *grpc.Server {
			return grpc.NewServer(append(opts, serverOptions(b, p)...)...)
		},
	})
}

func serverOptions(b Backends, p *server5) []grpc.ServerOption {
	routes := tfplugin.V5()
	return []grpc.ServerOption{
		grpc.ForceServerCodecV2(rawgrpc.Codec{}),
		grpc.UnknownServiceHandler(p.gatedForwarder(routes, rawgrpc.Forwarder(b.Upstream, routes, b.OnTransportErr))),
		grpc.MaxRecvMsgSize(rawgrpc.MaxMsgSize),
		grpc.MaxSendMsgSize(rawgrpc.MaxMsgSize),
	}
}

// registerIntercepts registers the intercepted tfplugin5.Provider methods, so
// only they bypass the unknown-service forwarder. p serves them on proto
// messages.
func registerIntercepts(s *grpc.Server, p *server5) {
	s.RegisterService(&grpc.ServiceDesc{ServiceName: strings.Trim(providerService, "/"), HandlerType: (*any)(nil), Methods: p.methods()}, nil)
}

type providerPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	p *server5
}

func (p providerPlugin) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	registerIntercepts(s, p.p)
	return nil
}

func (providerPlugin) GRPCClient(context.Context, *plugin.GRPCBroker, *grpc.ClientConn) (any, error) {
	return nil, errors.New("proxy: providerPlugin is server-only")
}
