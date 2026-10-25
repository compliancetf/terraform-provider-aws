package engine_test

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/pkg/engine"
	"github.com/compliancetf/terraform-provider-aws/pkg/engine/enginetest"
)

// TestVectors runs the cross-check vectors through the public API: the
// facade must give the outcome the provider's exception path recorded.
func TestVectors(t *testing.T) {
	f, err := enginetest.Load("testdata/selector_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) < 150 {
		t.Fatalf("%d vectors", len(f.Vectors))
	}
	for i := range f.Vectors {
		v := &f.Vectors[i]
		t.Run(v.Name, func(t *testing.T) {
			sel, err := engine.CompileSelector(v.Selector)
			if v.CompileError != "" {
				if err == nil || err.Error() != v.CompileError {
					t.Fatalf("compile: %v, want %q", err, v.CompileError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			in, err := f.Input(v)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			out := sel.Eval(ctx, in)
			if out.State != v.Want.State || out.Err != v.Want.Err || !slices.Equal(out.UnknownPaths, v.Want.UnknownPaths) {
				t.Fatalf("got %+v, want %+v", out, *v.Want)
			}
		})
	}
}

// TestNoSchema: a type without a schema never applies.
func TestNoSchema(t *testing.T) {
	sel, err := engine.CompileSelector("true")
	if err != nil {
		t.Fatal(err)
	}
	if out := sel.Eval(t.Context(), &engine.Input{Type: "aws_s3_bucket"}); out.State != engine.NotEvaluable || out.Err != engine.ErrNoSuchAttribute {
		t.Fatalf("got %+v", out)
	}
}

// forbidden are packages the facade and enginetest must not link: plugin servers, the
// protocol copy, and provider runtime and policy state.
var forbidden = regexp.MustCompile(`/tfprotov[56]/tf[56]server$|/internal/tfplugin[56]?(/|$)|/internal/(proxy|rawgrpc|upstream|wrapper|hook|lifecycle|exceptions|profile|fetch|evidence|verdict|baseline|breakglass)(/|$)|^google\.golang\.org/grpc$|/go-plugin$`)

func TestDeps(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", ".", "./enginetest")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for _, pkg := range strings.Fields(string(out)) {
		if forbidden.MatchString(pkg) {
			t.Errorf("pkg/engine links %s", pkg)
		}
	}
}
