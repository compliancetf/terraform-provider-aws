package rawgrpc_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/compliancetf/terraform-provider-aws/internal/rawgrpc"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

const (
	unaryM     = "/tfplugin5.Provider/GetMetadata"
	serverM    = "/tfplugin5.Provider/ListResource"
	clientM    = "/tfplugin6.Provider/WriteStateBytes"
	bidiM      = "/test.Bidi/Chat" // no bidi RPC in the pinned protos
	interceptM = "/tfplugin5.Provider/PlanResourceChange"
	schemaM    = "/tfplugin5.Provider/GetSchema"
	absentM    = "/tfplugin5.Provider/FutureRPC"
)

// testRoutes is the pinned v5 and v6 tables plus one bidi method.
func testRoutes() tfplugin.Routes {
	r := tfplugin.V5()
	for m, v := range tfplugin.V6() {
		r[m] = v
	}
	r[bidiM] = tfplugin.Route{FullMethod: bidiM, ClientStream: true, ServerStream: true, Class: tfplugin.Passthrough}
	return r
}

// fakeUpstream echoes frames by stream kind and records what it saw.
type fakeUpstream struct {
	routes   tfplugin.Routes
	mu       sync.Mutex
	calls    []string
	received [][]byte
	md       metadata.MD
	canceled chan struct{}
}

func (u *fakeUpstream) handle(_ any, ss grpc.ServerStream) error {
	method, _ := grpc.MethodFromServerStream(ss)
	md, _ := metadata.FromIncomingContext(ss.Context())
	u.mu.Lock()
	u.calls = append(u.calls, method)
	u.md = md
	u.mu.Unlock()

	if len(md.Get("x-trailers-only")) > 0 {
		ss.SetTrailer(metadata.Pairs("x-up-trailer", "t"))
		return status.Error(codes.NotFound, "trailers only")
	}
	if err := ss.SendHeader(metadata.Pairs("x-up-header", "h", "x-echo", strings.Join(md.Get("x-req"), ","))); err != nil {
		return err
	}
	ss.SetTrailer(metadata.Pairs("x-up-trailer", "t"))
	switch {
	case len(md.Get("x-block")) > 0:
		<-ss.Context().Done()
		close(u.canceled)
		return ss.Context().Err()
	case len(md.Get("x-unavail")) > 0:
		return status.Error(codes.Unavailable, "upstream gone")
	case len(md.Get("x-fail")) > 0:
		st, _ := status.New(codes.FailedPrecondition, "boom").WithDetails(&errdetails.ErrorInfo{Reason: "bobthecorp"})
		return st.Err()
	}

	r := u.routes[method]
	var all []byte
	for {
		f := &rawgrpc.Frame{}
		err := ss.RecvMsg(f)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		u.mu.Lock()
		u.received = append(u.received, f.Bytes)
		u.mu.Unlock()
		switch {
		case r.ClientStream && r.ServerStream:
			if err := ss.SendMsg(f); err != nil {
				return err
			}
		case r.ServerStream:
			for range 3 {
				if err := ss.SendMsg(f); err != nil {
					return err
				}
			}
		case r.ClientStream:
			all = append(all, f.Bytes...)
		default:
			return ss.SendMsg(f)
		}
	}
	if r.ClientStream && !r.ServerStream {
		return ss.SendMsg(&rawgrpc.Frame{Bytes: all})
	}
	return nil
}

func (u *fakeUpstream) callCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.calls)
}

func serve(t *testing.T, s *grpc.Server) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

type harness struct {
	up       *fakeUpstream
	proxy    *grpc.ClientConn
	mappedMu sync.Mutex
	mapped   []string
}

// newHarness starts the fake upstream and a proxy server that registers a
// typed GetSchema handler and forwards everything else.
func newHarness(t *testing.T, mapErr func(string, error) error) *harness {
	t.Helper()
	h := &harness{up: &fakeUpstream{routes: testRoutes(), canceled: make(chan struct{})}}
	upConn := serve(t, grpc.NewServer(grpc.ForceServerCodecV2(rawgrpc.Codec{}), grpc.UnknownServiceHandler(h.up.handle)))
	onErr := func(m string, err error) error {
		h.mappedMu.Lock()
		h.mapped = append(h.mapped, m)
		h.mappedMu.Unlock()
		return mapErr(m, err)
	}
	ps := grpc.NewServer(grpc.ForceServerCodecV2(rawgrpc.Codec{}), grpc.UnknownServiceHandler(rawgrpc.Forwarder(upConn, testRoutes(), onErr)))
	ps.RegisterService(&grpc.ServiceDesc{
		ServiceName: "tfplugin5.Provider",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "GetSchema", Handler: func(_ any, _ context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
			if err := dec(new(tfplugin5.GetProviderSchema_Request)); err != nil {
				return nil, err
			}
			return &tfplugin5.GetProviderSchema_Response{ServerCapabilities: &tfplugin5.ServerCapabilities{PlanDestroy: true}}, nil
		}}},
	}, struct{}{})
	h.proxy = serve(t, ps)
	return h
}

func ctxT(t *testing.T, kv ...string) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return metadata.AppendToOutgoingContext(ctx, kv...)
}

func rawStream(t *testing.T, ctx context.Context, conn *grpc.ClientConn, method string) grpc.ClientStream {
	t.Helper()
	cs, err := conn.NewStream(ctx, &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, method, grpc.ForceCodecV2(rawgrpc.Codec{}))
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// call sends reqs, half-closes and collects every response frame.
func call(t *testing.T, ctx context.Context, conn *grpc.ClientConn, method string, reqs ...[]byte) (grpc.ClientStream, [][]byte, error) {
	t.Helper()
	cs := rawStream(t, ctx, conn, method)
	for _, r := range reqs {
		if err := cs.SendMsg(&rawgrpc.Frame{Bytes: r}); err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	}
	if err := cs.CloseSend(); err != nil {
		t.Fatal(err)
	}
	var got [][]byte
	for {
		f := &rawgrpc.Frame{}
		err := cs.RecvMsg(f)
		if errors.Is(err, io.EOF) {
			return cs, got, nil
		}
		if err != nil {
			return cs, got, err
		}
		got = append(got, f.Bytes)
	}
}

// withUnknownField is a valid message carrying field 999, absent from every
// pinned message.
func withUnknownField(tag string) []byte {
	b := protowire.AppendTag(nil, 999, protowire.BytesType)
	return protowire.AppendString(b, tag)
}

func noMap(_ string, err error) error { return err }

func TestForwardStreamKinds(t *testing.T) {
	h := newHarness(t, noMap)
	a, b := withUnknownField("a"), withUnknownField("b")
	cases := []struct {
		method string
		reqs   [][]byte
		want   [][]byte
	}{
		{unaryM, [][]byte{a}, [][]byte{a}},
		{serverM, [][]byte{a}, [][]byte{a, a, a}},
		{clientM, [][]byte{a, b}, [][]byte{append(slices.Clone(a), b...)}},
		{bidiM, [][]byte{a, b}, [][]byte{a, b}},
	}
	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			cs, got, err := call(t, ctxT(t, "x-req", "r1"), h.proxy, c.method, c.reqs...)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.EqualFunc(got, c.want, bytes.Equal) {
				t.Errorf("responses = %x, want %x", got, c.want)
			}
			hdr, _ := cs.Header()
			if hdr.Get("x-up-header")[0] != "h" || hdr.Get("x-echo")[0] != "r1" {
				t.Errorf("header = %v", hdr)
			}
			if tr := cs.Trailer(); len(tr.Get("x-up-trailer")) != 1 {
				t.Errorf("trailer = %v", tr)
			}
		})
	}
	h.up.mu.Lock()
	defer h.up.mu.Unlock()
	if !bytes.Equal(h.up.received[0], a) {
		t.Errorf("upstream received %x, want %x (unknown field lost)", h.up.received[0], a)
	}
	if v := h.up.md.Get("x-req"); len(v) != 1 || v[0] != "r1" {
		t.Errorf("upstream metadata x-req = %v", v)
	}
}

func TestForwardHeaderBeforeFirstMessage(t *testing.T) {
	h := newHarness(t, noMap)
	cs := rawStream(t, ctxT(t), h.proxy, clientM)
	if err := cs.SendMsg(&rawgrpc.Frame{Bytes: []byte{}}); err != nil {
		t.Fatal(err)
	}
	// Upstream sends headers before reading; the client stream is still open.
	hdr, err := cs.Header()
	if err != nil || len(hdr.Get("x-up-header")) != 1 {
		t.Fatalf("header before half-close = %v, %v", hdr, err)
	}
	_ = cs.CloseSend()
}

func TestForwardStatusAndDetails(t *testing.T) {
	h := newHarness(t, noMap)
	cs, _, err := call(t, ctxT(t, "x-fail", "1"), h.proxy, unaryM, []byte{})
	st := status.Convert(err)
	if st.Code() != codes.FailedPrecondition || st.Message() != "boom" {
		t.Fatalf("status = %v", st)
	}
	if d := st.Details(); len(d) != 1 || d[0].(*errdetails.ErrorInfo).GetReason() != "bobthecorp" {
		t.Errorf("details = %v", d)
	}
	if hdr, _ := cs.Header(); len(hdr.Get("x-up-header")) != 1 {
		t.Errorf("header on error = %v", hdr)
	}
	if tr := cs.Trailer(); len(tr.Get("x-up-trailer")) != 1 {
		t.Errorf("trailer on error = %v", tr)
	}
}

// A trailers-only upstream response stays trailers-only: no empty header
// frame is invented downstream.
func TestForwardTrailersOnly(t *testing.T) {
	h := newHarness(t, noMap)
	cs, _, err := call(t, ctxT(t, "x-trailers-only", "1"), h.proxy, unaryM, []byte{})
	if st := status.Convert(err); st.Code() != codes.NotFound || st.Message() != "trailers only" {
		t.Fatalf("status = %v", st)
	}
	if hdr, _ := cs.Header(); hdr != nil {
		t.Errorf("header = %v, want none (trailers-only)", hdr)
	}
	if tr := cs.Trailer(); len(tr.Get("x-up-trailer")) != 1 {
		t.Errorf("trailer = %v", tr)
	}
}

// grpc- keys belong to each hop; a client's grpc-accept-encoding must not
// let upstream pick a compressor the proxy cannot decode.
func TestForwardDropsProtocolMetadata(t *testing.T) {
	h := newHarness(t, noMap)
	if _, _, err := call(t, ctxT(t, "grpc-accept-encoding", "bobthecorp-zip", "x-req", "r"), h.proxy, unaryM, []byte{}); err != nil {
		t.Fatal(err)
	}
	h.up.mu.Lock()
	defer h.up.mu.Unlock()
	if slices.Contains(h.up.md.Get("grpc-accept-encoding"), "bobthecorp-zip") {
		t.Errorf("upstream saw client grpc-accept-encoding: %v", h.up.md)
	}
}

func TestForwardNotInPinnedProto(t *testing.T) {
	h := newHarness(t, noMap)
	_, _, err := call(t, ctxT(t), h.proxy, absentM, []byte{})
	st := status.Convert(err)
	want := "tfplugin method " + absentM + " is not in the pinned protocol of this provider release"
	if st.Code() != codes.Unimplemented || st.Message() != want {
		t.Errorf("status = %v, want Unimplemented %q", st, want)
	}
	_, _, err = call(t, ctxT(t), h.proxy, interceptM, []byte{})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("intercept-class method without handler: %v, want Unimplemented", err)
	}
	if n := h.up.callCount(); n != 0 {
		t.Errorf("upstream saw %d calls, want 0", n)
	}
}

// A typed handler on tfplugin5.Provider serves its method; other methods of
// the same service still reach the forwarder. The client uses the default
// proto codec and generated messages.
func TestForwardRegisteredServiceSplit(t *testing.T) {
	h := newHarness(t, noMap)
	c := tfplugin5.NewProviderClient(h.proxy)
	resp, err := c.GetSchema(ctxT(t), &tfplugin5.GetProviderSchema_Request{})
	if err != nil || !resp.GetServerCapabilities().GetPlanDestroy() {
		t.Fatalf("GetSchema = %v, %v", resp, err)
	}
	if n := h.up.callCount(); n != 0 {
		t.Fatalf("typed GetSchema reached upstream (%d calls)", n)
	}
	if _, err := c.GetMetadata(ctxT(t), &tfplugin5.GetMetadata_Request{}); err != nil {
		t.Fatalf("GetMetadata = %v", err)
	}
	h.up.mu.Lock()
	defer h.up.mu.Unlock()
	if h.up.calls[0] != unaryM {
		t.Errorf("upstream calls = %v", h.up.calls)
	}
}

func TestForwardCancelPropagates(t *testing.T) {
	h := newHarness(t, noMap)
	ctx, cancel := context.WithCancel(metadata.AppendToOutgoingContext(context.Background(), "x-block", "1"))
	cs := rawStream(t, ctx, h.proxy, serverM)
	if _, err := cs.Header(); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-h.up.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream context not canceled")
	}
}

func TestForwardTransportErrorMapping(t *testing.T) {
	h := newHarness(t, func(m string, _ error) error { return status.Error(codes.Unavailable, "crashed in "+m) })
	_, _, err := call(t, ctxT(t, "x-unavail", "1"), h.proxy, unaryM, []byte{})
	if st := status.Convert(err); st.Code() != codes.Unavailable || st.Message() != "crashed in "+unaryM {
		t.Errorf("mapped status = %v", st)
	}

	h = newHarness(t, func(string, error) error { return nil })
	_, _, err = call(t, ctxT(t, "x-unavail", "1"), h.proxy, unaryM, []byte{})
	if st := status.Convert(err); st.Code() != codes.Unavailable || st.Message() != "upstream gone" {
		t.Errorf("nil mapping must keep the original, got %v", st)
	}
	h.mappedMu.Lock()
	defer h.mappedMu.Unlock()
	if len(h.mapped) != 1 {
		t.Errorf("onTransportErr calls = %v", h.mapped)
	}
}

// brokerPlugin captures the go-plugin broker of the server it registers on.
type brokerPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	broker chan *plugin.GRPCBroker
}

func (p *brokerPlugin) GRPCServer(b *plugin.GRPCBroker, _ *grpc.Server) error {
	p.broker <- b
	return nil
}

func (p *brokerPlugin) GRPCClient(context.Context, *plugin.GRPCBroker, *grpc.ClientConn) (any, error) {
	return nil, nil
}

func connInfo(id uint32) []byte {
	b := protowire.AppendTag(nil, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(id))
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, "tcp")
	b = protowire.AppendTag(b, 3, protowire.BytesType)
	return protowire.AppendString(b, "127.0.0.1:1")
}

// go-plugin's health and broker services run on the same server as the
// forced codec and the unknown-service forwarder.
func TestForwardGoPluginServices(t *testing.T) {
	h := newHarness(t, noMap)
	bp := &brokerPlugin{broker: make(chan *plugin.GRPCBroker, 1)}
	// plugin.Serve in test mode gives the server a logger, so its stdio
	// copiers end cleanly when CloseCh stops it.
	ctx, cancel := context.WithCancel(context.Background())
	reattach := make(chan *plugin.ReattachConfig, 1)
	closed := make(chan struct{})
	go plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: plugin.HandshakeConfig{ProtocolVersion: 5, MagicCookieKey: "BOBTHECORP_TEST", MagicCookieValue: "x"},
		Plugins:         plugin.PluginSet{"provider": bp},
		GRPCServer: func(opts []grpc.ServerOption) *grpc.Server {
			upConn := h.proxy // any conn; only go-plugin services are called
			return grpc.NewServer(append(opts, grpc.ForceServerCodecV2(rawgrpc.Codec{}), grpc.UnknownServiceHandler(rawgrpc.Forwarder(upConn, testRoutes(), noMap)))...)
		},
		Logger: hclog.NewNullLogger(),
		Test:   &plugin.ServeTestConfig{Context: ctx, ReattachConfigCh: reattach, CloseCh: closed},
	})
	t.Cleanup(func() { cancel(); <-closed })
	var addr net.Addr
	select {
	case rc := <-reattach:
		addr = rc.Addr
	case <-time.After(10 * time.Second):
		t.Fatal("plugin.Serve sent no reattach config")
	}
	conn, err := grpc.NewClient("passthrough:///plugin",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, addr.Network(), addr.String())
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	hr, err := grpc_health_v1.NewHealthClient(conn).Check(ctxT(t), &grpc_health_v1.HealthCheckRequest{Service: plugin.GRPCServiceName})
	if err != nil || hr.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("health = %v, %v", hr, err)
	}

	broker := <-bp.broker
	cs := rawStream(t, ctxT(t), conn, "/plugin.GRPCBroker/StartStream")
	if err := cs.SendMsg(&rawgrpc.Frame{Bytes: connInfo(7)}); err != nil {
		t.Fatal(err)
	}
	dialed, err := broker.Dial(7) // server decoded the client's ConnInfo
	if err != nil {
		t.Fatalf("broker did not receive ConnInfo: %v", err)
	}
	_ = dialed.Close()
	ln, err := broker.Accept(8) // server sends ConnInfo{8} to the client
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f := &rawgrpc.Frame{}
	if err := cs.RecvMsg(f); err != nil {
		t.Fatal(err)
	}
	num, typ, n := protowire.ConsumeTag(f.Bytes)
	id, _ := protowire.ConsumeVarint(f.Bytes[n:])
	if num != 1 || typ != protowire.VarintType || id != 8 {
		t.Errorf("broker ConnInfo from server = %x", f.Bytes)
	}
}

func TestCodecFallsBackToProto(t *testing.T) {
	c := rawgrpc.Codec{}
	in := &tfplugin5.GetProviderSchema_Request{}
	data, err := c.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	out := &tfplugin5.GetProviderSchema_Request{}
	if err := c.Unmarshal(data, out); err != nil || !proto.Equal(in, out) {
		t.Fatalf("proto round trip: %v", err)
	}
	if c.Name() != "proto" {
		t.Errorf("Name = %q, want proto", c.Name())
	}
}
