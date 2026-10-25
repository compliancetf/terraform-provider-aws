//go:build ctftest

package embedded

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle/bundletest"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

const releaseIAM = "../../testdata/bundles/release-iam"

// TestReleaseIAMCatalog is the IAM action catalog oracle: the release-iam
// bundle, built and signed by cmd/ctfbundle, lists
// iam-actions.json (built by cmd/iamcatalog from the pinned service
// reference snapshot) in its signed manifest, and its IAM controls compile
// and evaluate against that catalog. The same bundle re-signed without the
// file is rejected iam_catalog_missing (the check Configure runs before it
// records the bundle); with the file changed it fails the manifest digest.
func TestReleaseIAMCatalog(t *testing.T) {
	archive := readFile(t, releaseIAM+".tar.gz")
	src := readFile(t, releaseIAM+"/iam-actions.json")
	b, err := bundle.ReadArchive(archive, testVerify)
	if err != nil {
		t.Fatalf("release-iam.tar.gz: %v (go generate ./testdata/generate.go)", err)
	}
	listed := false
	for _, f := range b.Manifest.Files {
		listed = listed || f.Path == bundle.IAMActionsFile && f.SHA256 == hexSum(src) && f.Size == int64(len(src))
	}
	if !listed || b.IAMCatalog == nil || b.IAMCatalog.Digest() != "sha256:"+hexSum(src) {
		t.Fatal("the signed manifest does not list the release iam-actions.json")
	}

	// Versioning: the catalog records the snapshot digest and retrieved
	// date of the committed pin.
	var cat struct{ Retrieved, Snapshot string }
	if err := json.Unmarshal(src, &cat); err != nil {
		t.Fatal(err)
	}
	pin := readFile(t, "../../testdata/iam/service-reference-"+cat.Retrieved+".sha256")
	if cat.Snapshot != "sha256:"+hexSum(pin) {
		t.Fatalf("catalog snapshot %s does not match the pinned service-reference-%s.sha256", cat.Snapshot, cat.Retrieved)
	}

	t.Run("controls evaluate", func(t *testing.T) {
		cs, cc := releaseCompiler(t, b)
		if err := celeng.CheckCatalogs(cs.All(), cs.IAMCatalog); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			typ, id, action string
			state           engine.State
			class           engine.ErrClass
		}{
			{"aws_iam_policy", "iam_policy_no_full_access_to_kms", "kms:Decrypt", engine.Pass, ""},
			{"aws_iam_policy", "iam_policy_no_full_access_to_kms", "kms:*", engine.Fail, ""},
			{"aws_iam_policy", "iam_policy_no_full_access_to_kms", "kms:BobthecorpNoSuchAction", engine.NotEvaluable, engine.ErrUnresolved},
			{"aws_iam_role_policy", "iam_policy_inline_no_blocked_kms_actions", "kms:Encrypt", engine.Pass, ""},
			{"aws_iam_role_policy", "iam_policy_inline_no_blocked_kms_actions", "kms:Decrypt", engine.Fail, ""},
		} {
			out := evalPolicy(t, cc, cs, tc.typ, tc.id, tc.action)
			if out.State != tc.state || out.Err != tc.class {
				t.Errorf("%s %s: %s/%s, want %s/%s", tc.id, tc.action, out.State, out.Err, tc.state, tc.class)
			}
		}
	})

	t.Run("without the file", func(t *testing.T) {
		without, err := bundletest.WithoutFile(archive, bundle.IAMActionsFile, testkeys.Bundle())
		if err != nil {
			t.Fatal(err)
		}
		nb, err := bundle.ReadArchive(without, testVerify)
		if err != nil {
			t.Fatal(err)
		}
		if nb.IAMCatalog != nil || len(nb.Controls) != len(b.Controls) {
			t.Fatal("re-signed bundle must keep every control and drop only the catalog")
		}
		cs, _ := releaseCompiler(t, nb)
		var d *celeng.LoadDiag
		if err := celeng.CheckCatalogs(cs.All(), cs.IAMCatalog); !errors.As(err, &d) || d.Code != "iam_catalog_missing" {
			t.Fatalf("got %v, want iam_catalog_missing", err)
		}
	})

	t.Run("changed file", func(t *testing.T) {
		changed, err := bundletest.Rewrite(archive, func(name string, body []byte) ([]byte, bool, error) {
			if name != bundle.IAMActionsFile {
				return body, true, nil
			}
			out := bytes.Replace(body, []byte(`"cancelkeydeletion"`), []byte(`"cancelkeydeletioo"`), 1) // same size
			if bytes.Equal(out, body) {
				t.Fatal("kms cancelkeydeletion not in the catalog")
			}
			return out, true, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bundle.ReadArchive(changed, testVerify); err == nil || !strings.Contains(err.Error(), "iam-actions.json: digest mismatch") {
			t.Fatalf("got %v, want iam-actions.json digest mismatch", err)
		}
	})
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func releaseCompiler(t *testing.T, b *bundle.Bundle) (*bundle.ControlSet, *celeng.Compiler) {
	t.Helper()
	cs, _, err := bundle.NewControlSet("bobthecorp", time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), trust.NoRevocations(), b)
	if err != nil {
		t.Fatal(err)
	}
	return cs, celeng.NewCompilerFor(awsSchemas(t), cs, cs.ContentDigest(nil))
}

// evalPolicy evaluates control id of typ on a create whose policy allows
// action on every resource, as evalBoth binds it.
func evalPolicy(t *testing.T, cc *celeng.Compiler, cs *bundle.ControlSet, typ, id, action string) engine.Outcome {
	t.Helper()
	for _, c := range cs.For(typ, bundle.OnCreate) {
		if c.ID != id {
			continue
		}
		sc, ok := awsSchemas(t).Resource(typ)
		if !ok {
			t.Fatalf("%s missing from aws-subset.json", typ)
		}
		p, err := cc.Compile(&c, sc.ValueType())
		if err != nil {
			t.Fatal(err)
		}
		policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"` + action + `","Resource":"*"}]}`
		v := tv(sc.ValueType(), obj{"policy": policy})
		// A generous deadline: this checks verdicts, not the per-resource budget.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return p.Eval(ctx, &engine.Activation{Resource: v, Config: v, Op: engine.OpCreate})
	}
	t.Fatalf("control %s on %s not loaded", id, typ)
	return engine.Outcome{}
}
