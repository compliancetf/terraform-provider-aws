package hook

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// notEvaluator lists the internal packages, relative to internal/, that hold
// no evaluator code: the gRPC proxy layers and build or test tooling. The
// evaluator calls back into proxy only synchronously (schema lookups), on the
// RPC goroutine. Every other internal package is evaluator code.
var notEvaluator = []string{"proxy", "rawgrpc", "upstream", "tfplugin", "testutil", "bundlegen"}

// asyncCalls names calls that run a function in another goroutine: the
// cel-go async API, time.AfterFunc and context.AfterFunc, and errgroup-style
// Group.Go and Group.TryGo.
var asyncCalls = map[string]bool{
	"ConcurrentEval": true, "AsyncBinding": true, "SingletonAsyncBinding": true,
	"AfterFunc": true, "Go": true, "TryGo": true,
}

// TestEvaluatorStartsNoGoroutines: the proxy recovers an
// evaluator panic only on the RPC goroutine; a panic in a goroutine the
// evaluator starts escapes that recover, crashes the provider and prints the
// panic value to stderr. So evaluator code starts none. A future goroutine
// there must recover, turn the panic into a value-free evaluation error (the
// policy of proxy.recovered and TestPanicValueNeverLeaks), and be listed here
// with that recovery under test.
func TestEvaluatorStartsNoGoroutines(t *testing.T) {
	fset := token.NewFileSet()
	files := 0
	scan := func(path string) error {
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.GoStmt:
				t.Errorf("%s: evaluator code starts a goroutine; a panic in it escapes the proxy recover", fset.Position(n.Pos()))
			case *ast.SelectorExpr:
				if asyncCalls[n.Sel.Name] {
					t.Errorf("%s: %s runs code in another goroutine; a panic there escapes the proxy recover", fset.Position(n.Pos()), n.Sel.Name)
				}
			}
			return true
		})
		return nil
	}

	root := ".."
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			for _, p := range notEvaluator {
				if rel == p {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		return scan(path)
	})
	if err != nil {
		t.Fatal(err)
	}

	// The wrapper's evaluator constructors (release and conformance builds)
	// are under internal/wrapper, so the walk scanned them.
	mains, _ := filepath.Glob(filepath.Join(root, "wrapper", "evaluator*.go"))
	if len(mains) < 2 {
		t.Fatalf("found %d evaluator*.go files in internal/wrapper, want 2", len(mains))
	}
	if files < 20 {
		t.Fatalf("scanned only %d evaluator source files; the walk root is wrong", files)
	}
}
