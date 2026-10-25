package proxy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

func fakeSchema() *tfplugin5.GetProviderSchema_Response {
	return &tfplugin5.GetProviderSchema_Response{
		Provider:        &tfplugin5.Schema{Block: &tfplugin5.Schema_Block{}},
		ResourceSchemas: map[string]*tfplugin5.Schema{"fake_thing": {Version: 1}},
	}
}

// getSchema runs GetSchema through a fresh proxy process over dir and returns
// the response and the upstream calls.
func getSchema(t *testing.T, dir string, up *fakeUpstream5) (*tfplugin5.GetProviderSchema_Response, []string) {
	t.Helper()
	client, _ := startProxy(t, up, Backends{SchemaCacheDir: dir})
	got, err := client.GetSchema(context.Background(), &tfplugin5.GetProviderSchema_Request{})
	if err != nil {
		t.Fatal(err)
	}
	return got, up.calls
}

// TestSchemaFileSkipsUpstreamInLaterProcesses: the first process asks the
// upstream and writes the file; the next serves the same response from it.
func TestSchemaFileSkipsUpstreamInLaterProcesses(t *testing.T) {
	dir := t.TempDir()
	first, calls := getSchema(t, dir, &fakeUpstream5{schema: fakeSchema()})
	if len(calls) != 1 {
		t.Fatalf("first process: upstream calls %v, want one GetSchema", calls)
	}
	second, calls := getSchema(t, dir, &fakeUpstream5{schema: fakeSchema()})
	if len(calls) != 0 {
		t.Fatalf("second process: upstream calls %v, want none", calls)
	}
	if !proto.Equal(first, second) {
		t.Fatalf("cached response %v differs from upstream %v", second, first)
	}
}

func TestSchemaFileIgnoredWhenDamaged(t *testing.T) {
	for name, damage := range map[string]func(b []byte) []byte{
		"truncated": func(b []byte) []byte { return b[:len(b)-1] },
		"flipped":   func(b []byte) []byte { b[len(b)-1] ^= 1; return b },
		"empty":     func([]byte) []byte { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			getSchema(t, dir, &fakeUpstream5{schema: fakeSchema()})
			p := filepath.Join(dir, schemaFileName)
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, damage(b), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, calls := getSchema(t, dir, &fakeUpstream5{schema: fakeSchema()}); len(calls) != 1 {
				t.Fatalf("damaged file served: upstream calls %v", calls)
			}
		})
	}
}

func TestSchemaFileNotWrittenForErrors(t *testing.T) {
	dir := t.TempDir()
	bad := fakeSchema()
	bad.Diagnostics = []*tfplugin5.Diagnostic{{Severity: tfplugin5.Diagnostic_ERROR, Summary: "broken"}}
	getSchema(t, dir, &fakeUpstream5{schema: bad})
	if _, err := os.Stat(filepath.Join(dir, schemaFileName)); !os.IsNotExist(err) {
		t.Fatalf("error response cached: %v", err)
	}
}
