package tfplugin_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin6"
)

var update = flag.Bool("update", false, "rewrite testdata/rpcs*.golden from the route table")

// interceptedV5 is the "Intercepted RPC routing (protocol 5)" table of the
// proxy design. Every other method of the pinned proto is passthrough.
var interceptedV5 = []string{
	"/tfplugin5.Provider/ApplyResourceChange",
	"/tfplugin5.Provider/Configure",
	"/tfplugin5.Provider/GetSchema",
	"/tfplugin5.Provider/ImportResourceState",
	"/tfplugin5.Provider/OpenEphemeralResource",
	"/tfplugin5.Provider/PlanResourceChange",
	"/tfplugin5.Provider/PrepareProviderConfig",
	"/tfplugin5.Provider/ReadDataSource",
	"/tfplugin5.Provider/ReadResource",
	"/tfplugin5.Provider/Stop",
	"/tfplugin5.Provider/ValidateResourceTypeConfig",
}

// render prints one "<full method> <kind> <class>" line per route, sorted.
func render(routes tfplugin.Routes) string {
	lines := make([]string, 0, len(routes))
	for _, r := range routes {
		kind := "unary"
		switch {
		case r.ClientStream && r.ServerStream:
			kind = "bidi_stream"
		case r.ClientStream:
			kind = "client_stream"
		case r.ServerStream:
			kind = "server_stream"
		}
		lines = append(lines, fmt.Sprintf("%s %s %s\n", r.FullMethod, kind, r.Class))
	}
	slices.Sort(lines)
	return strings.Join(lines, "")
}

func loadClasses(t *testing.T) map[string]tfplugin.Class {
	t.Helper()
	data, err := os.ReadFile("classes.json")
	if err != nil {
		t.Fatal(err)
	}
	classes, err := tfplugin.ParseClasses(data)
	if err != nil {
		t.Fatal(err)
	}
	return classes
}

func TestRoutesGolden(t *testing.T) {
	classes := loadClasses(t)
	for _, tc := range []struct {
		name   string
		routes tfplugin.Routes
		file   protoreflect.FileDescriptor
	}{
		{"rpcs5", tfplugin.V5(), tfplugin5.File_tfplugin5_proto},
		{"rpcs6", tfplugin.V6(), tfplugin6.File_tfplugin6_proto},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := render(tc.routes)
			path := filepath.Join("testdata", tc.name+".golden")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("route table differs from %s:\n got:\n%s\nwant:\n%s", path, got, want)
			}

			fresh, err := tfplugin.Build(tc.file, classes)
			if err != nil {
				t.Fatal(err)
			}
			if render(fresh) != got {
				t.Errorf("routes_gen.go is stale against the descriptor and classes.json; run go generate ./internal/tfplugin")
			}
		})
	}
}

func TestInterceptedRoutes(t *testing.T) {
	var got []string
	for m, r := range tfplugin.V5() {
		if r.Class == tfplugin.Intercept {
			got = append(got, m)
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, interceptedV5) {
		t.Errorf("intercepted v5 methods = %v, want %v", got, interceptedV5)
	}
	for m, r := range tfplugin.V6() {
		if r.Class != tfplugin.Passthrough {
			t.Errorf("v6 method %s has class %s; v6 intercepts are deferred, want passthrough", m, r.Class)
		}
	}
}

func TestBuildRejectsIncompleteClasses(t *testing.T) {
	classes := loadClasses(t)

	missing := maps.Clone(classes)
	delete(missing, "/tfplugin5.Provider/GetMetadata")
	if _, err := tfplugin.Build(tfplugin5.File_tfplugin5_proto, missing); err == nil ||
		!strings.Contains(err.Error(), "/tfplugin5.Provider/GetMetadata") {
		t.Errorf("Build with an unclassified method: err = %v, want error naming the method", err)
	}

	stale := maps.Clone(classes)
	stale["/tfplugin5.Provider/NoSuchMethod"] = tfplugin.Passthrough
	if _, err := tfplugin.Build(tfplugin5.File_tfplugin5_proto, stale); err == nil ||
		!strings.Contains(err.Error(), "/tfplugin5.Provider/NoSuchMethod") {
		t.Errorf("Build with a class for a method absent from the proto: err = %v, want error naming it", err)
	}

	if _, err := tfplugin.ParseClasses([]byte(`{"/tfplugin5.Provider/GetSchema": "forward"}`)); err == nil {
		t.Error("ParseClasses accepted class \"forward\"; want only intercept or passthrough")
	}
}

// TestProtoSources checks the vendored protos against the sha256 recorded by
// make proto, so a hand edit of a vendored proto fails.
func TestProtoSources(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("proto", "SOURCES.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sources map[string]struct {
		Module  string `json:"module"`
		Version string `json:"version"`
		Path    string `json:"path"`
		SHA256  string `json:"sha256"`
	}
	if err := json.Unmarshal(data, &sources); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tfplugin5.proto", "tfplugin6.proto"} {
		src, ok := sources[name]
		if !ok {
			t.Errorf("SOURCES.json has no entry for %s", name)
			continue
		}
		body, err := os.ReadFile(filepath.Join("proto", name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != src.SHA256 {
			t.Errorf("%s sha256 = %s, SOURCES.json records %s (%s@%s %s); run make proto", name, got, src.SHA256, src.Module, src.Version, src.Path)
		}
	}
}
