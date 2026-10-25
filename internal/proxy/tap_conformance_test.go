//go:build conformance

package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// TestInvariantTap: a conformance build writes one line per forwarded apply
// with the sha256 of upstream's and of the returned new_state msgpack.
func TestInvariantTap(t *testing.T) {
	tap := filepath.Join(t.TempDir(), "tap.jsonl")
	t.Setenv("COMPLIANCETF_CONFORMANCE_TAP", tap)
	client, up, _ := startRoute(t, hook.Noop{})
	for range 2 {
		if _, err := client.ApplyResourceChange(context.Background(), &tfplugin5.ApplyResourceChange_Request{TypeName: "fake_thing", PriorState: thing(t, "prior"), PlannedState: thing(t, "planned"), Config: thing(t, "cfg")}); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(tap)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(up.apply.NewState.Msgpack)
	want := map[string]string{"rpc": "ApplyResourceChange", "type": "fake_thing", "upstream_sha256": hex.EncodeToString(sum[:]), "returned_sha256": hex.EncodeToString(sum[:])}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("tap has %d lines, want 2:\n%s", len(lines), b)
	}
	for _, l := range lines {
		var got map[string]string
		if err := json.Unmarshal([]byte(l), &got); err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) {
			t.Errorf("tap line %s, want %v", l, want)
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("tap %s = %q, want %q", k, got[k], v)
			}
		}
	}
}

// TestTapGetMetadata: a GetMetadata call from Core, and only that method,
// writes {"rpc":"GetMetadata"} to the tap and is still forwarded.
func TestTapGetMetadata(t *testing.T) {
	tap := filepath.Join(t.TempDir(), "tap.jsonl")
	t.Setenv("COMPLIANCETF_CONFORMANCE_TAP", tap)
	forwarded := 0
	h := newServer5(Backends{Evaluator: hook.Noop{}}).gatedForwarder(tfplugin.V5(), func(any, grpc.ServerStream) error { forwarded++; return nil })
	for _, m := range []string{"GetProviderSchema", "GetSchema", "GetMetadata", "GetResourceIdentitySchemas"} {
		ss := &fakeStream{ctx: grpc.NewContextWithServerTransportStream(context.Background(), methodStream(providerService+m))}
		if err := h(nil, ss); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
	}
	b, err := os.ReadFile(tap)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "{\"rpc\":\"GetMetadata\"}\n" || forwarded != 4 {
		t.Fatalf("tap %q, forwarded %d; want one GetMetadata line and 4 forwarded", b, forwarded)
	}
}

// TestTapWriteFailure: a tap that cannot be written leaves its error in
// <tap>.failed, which the conformance runner fails on.
func TestTapWriteFailure(t *testing.T) {
	tap := t.TempDir() // a directory: opening it for append fails
	t.Setenv("COMPLIANCETF_CONFORMANCE_TAP", tap)
	tapRPC(providerService + "GetMetadata")
	b, err := os.ReadFile(tap + ".failed")
	if err != nil || len(b) == 0 {
		t.Fatalf("no failure record: %q, %v", b, err)
	}
}
