//go:build ctftest

package proxy_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/compliancetf/terraform-provider-aws/internal/proxy"
	"github.com/compliancetf/terraform-provider-aws/internal/rawgrpc"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin"
	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

var (
	buildOnce sync.Once
	binDir    string
	buildErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		_ = os.RemoveAll(binDir)
	}
	os.Exit(code)
}

// buildBinaries builds the provider binary and the fake v5 upstream once.
func buildBinaries(t *testing.T) (provider, fake string) {
	t.Helper()
	buildOnce.Do(func() {
		if binDir, buildErr = os.MkdirTemp("", "passthrough-test"); buildErr != nil {
			return
		}
		for _, b := range []struct{ dir, pkg, out string }{
			{filepath.Join("..", ".."), ".", "provider"},
			{filepath.Join("..", "..", "test", "fakeupstream"), "./v5", "fakeupstream"},
		} {
			cmd := exec.Command("go", "build", "-tags", "ctftest", "-o", filepath.Join(binDir, b.out), b.pkg)
			cmd.Dir = b.dir
			if out, err := cmd.CombinedOutput(); err != nil {
				buildErr = errors.New(err.Error() + ": " + string(out))
				return
			}
		}
	})
	if buildErr != nil {
		t.Fatalf("build: %v", buildErr)
	}
	return filepath.Join(binDir, "provider"), filepath.Join(binDir, "fakeupstream")
}

// launch starts bin through upstream.Launch, the path main uses. The provider
// child is a ctftest build, so its Discover returns childUpstream unpinned.
func launch(t *testing.T, bin, childUpstream string) *grpc.ClientConn {
	t.Helper()
	t.Setenv(upstream.TestUpstreamPathEnv, childUpstream)
	u, err := upstream.Launch(context.Background(), upstream.NewTestVerifiedBinary(bin), upstream.NewLogger(io.Discard, "hashicorp/aws"))
	if err != nil {
		t.Fatalf("Launch %s: %v", bin, err)
	}
	t.Cleanup(u.Close)
	return u.Conn
}

// result is everything a raw call returns that the proxy must not change.
type result struct {
	frames [][]byte
	code   codes.Code
	msg    string
}

// call sends req as the one request frame on method and collects every
// response frame and the final status.
func call(t *testing.T, conn *grpc.ClientConn, r tfplugin.Route, req []byte) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := conn.NewStream(ctx, &grpc.StreamDesc{ClientStreams: r.ClientStream, ServerStreams: r.ServerStream}, r.FullMethod, grpc.ForceCodecV2(rawgrpc.Codec{}))
	if err != nil {
		st := status.Convert(err)
		return result{code: st.Code(), msg: st.Message()}
	}
	if err := cs.SendMsg(&rawgrpc.Frame{Bytes: req}); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("%s: send: %v", r.FullMethod, err)
	}
	if err := cs.CloseSend(); err != nil {
		t.Fatalf("%s: close send: %v", r.FullMethod, err)
	}
	var res result
	for {
		f := &rawgrpc.Frame{}
		if err := cs.RecvMsg(f); err != nil {
			if !errors.Is(err, io.EOF) {
				st := status.Convert(err)
				res.code, res.msg = st.Code(), st.Message()
			}
			return res
		}
		res.frames = append(res.frames, f.Bytes)
	}
}

func passthroughV5() []tfplugin.Route {
	var routes []tfplugin.Route
	for _, r := range tfplugin.V5() {
		if r.Class == tfplugin.Passthrough {
			routes = append(routes, r)
		}
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].FullMethod < routes[j].FullMethod })
	return routes
}

// TestPassthroughAllMethods calls every passthrough method of the v5 route
// table through the provider binary and directly on the fake upstream, and
// requires the same frames and status from both. The provider is never
// configured, so a method the verdict gate scope gates is refused
// before upstream instead, except CallFunction.
func TestPassthroughAllMethods(t *testing.T) {
	provider, fake := buildBinaries(t)
	direct := launch(t, fake, "")
	proxied := launch(t, provider, fake)

	routes := passthroughV5()
	if len(routes) == 0 {
		t.Fatal("route table has no passthrough methods")
	}
	for _, r := range routes {
		t.Run(strings.TrimPrefix(r.FullMethod, "/tfplugin5."), func(t *testing.T) {
			want := call(t, direct, r, nil)
			got := call(t, proxied, r, nil)
			if proxy.VerdictGated(r.FullMethod) && r.FullMethod != "/tfplugin5.Provider/CallFunction" {
				want = result{code: codes.FailedPrecondition, msg: "Compliance not configured: " + r.FullMethod +
					" was called before the provider was configured; under compliance.tf it is refused until configuration loads."}
			}
			if got.code != want.code || got.msg != want.msg {
				t.Fatalf("status = %v %q, upstream returns %v %q", got.code, got.msg, want.code, want.msg)
			}
			if len(got.frames) != len(want.frames) {
				t.Fatalf("%d frames, upstream returns %d", len(got.frames), len(want.frames))
			}
			// Only the identity schemas response is a map (random entry order);
			// every other frame stays byte-equal, repeated-field order included.
			unordered := r.FullMethod == "/tfplugin5.Provider/GetResourceIdentitySchemas"
			for i := range want.frames {
				if !bytes.Equal(got.frames[i], want.frames[i]) && !(unordered && sameFields(got.frames[i], want.frames[i])) {
					t.Errorf("frame %d = %x, upstream returns %x", i, got.frames[i], want.frames[i])
				}
			}
		})
	}
}

// sameFields reports whether a and b hold the same top-level protobuf
// fields in any order: upstream encodes a map field (two identity schemas)
// in random entry order, so two calls differ in order only.
func sameFields(a, b []byte) bool {
	split := func(m []byte) ([]string, bool) {
		var out []string
		for len(m) > 0 {
			_, _, n := protowire.ConsumeField(m)
			if n < 0 {
				return nil, false
			}
			out = append(out, string(m[:n]))
			m = m[n:]
		}
		sort.Strings(out)
		return out, true
	}
	fa, ok1 := split(a)
	fb, ok2 := split(b)
	return ok1 && ok2 && slices.Equal(fa, fb)
}

// TestUnknownMethodUnimplemented: a method absent from the pinned proto gets
// the proxy's own Unimplemented, not an upstream answer.
func TestUnknownMethodUnimplemented(t *testing.T) {
	provider, fake := buildBinaries(t)
	proxied := launch(t, provider, fake)

	for _, m := range []string{"/tfplugin5.Provider/NoSuchMethod", "/tfplugin99.Provider/GetSchema"} {
		got := call(t, proxied, tfplugin.Route{FullMethod: m}, nil)
		if got.code != codes.Unimplemented || !strings.Contains(got.msg, "not in the pinned protocol") {
			t.Errorf("%s: status = %v %q, want Unimplemented from the proxy", m, got.code, got.msg)
		}
	}
}

// TestInterceptGetSchema: GetSchema is served by the proxy (it carries the
// compliance block) and keeps the upstream's ephemeral, list and action types.
func TestInterceptGetSchema(t *testing.T) {
	provider, fake := buildBinaries(t)
	proxied := launch(t, provider, fake)

	got := call(t, proxied, tfplugin.V5()["/tfplugin5.Provider/GetSchema"], nil)
	if got.code != codes.OK || len(got.frames) != 1 {
		t.Fatalf("GetSchema = %v %q, %d frames; want OK", got.code, got.msg, len(got.frames))
	}
	for _, want := range []string{"compliance", "fake_secret", "fake_poke"} {
		if !bytes.Contains(got.frames[0], []byte(want)) {
			t.Errorf("GetSchema response lacks %s", want)
		}
	}
}

// TestPassthroughLargeMessage sends a CallFunction request over gRPC's 4 MiB
// default; the fake echoes the function name, so the response is as large.
func TestPassthroughLargeMessage(t *testing.T) {
	provider, fake := buildBinaries(t)
	proxied := launch(t, provider, fake)

	name := bytes.Repeat([]byte("x"), 5<<20)
	req := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), name) // CallFunction.Request.name
	got := call(t, proxied, tfplugin.V5()["/tfplugin5.Provider/CallFunction"], req)
	if got.code != codes.OK || len(got.frames) != 1 || !bytes.Contains(got.frames[0], name) {
		t.Fatalf("CallFunction = %v %q, %d frames; want OK echoing the 5 MiB name", got.code, got.msg, len(got.frames))
	}
}
