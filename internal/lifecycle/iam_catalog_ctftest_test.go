//go:build ctftest

package lifecycle

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle/bundletest"
	"github.com/compliancetf/terraform-provider-aws/internal/bundlegen"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// TestConfigureIAMCatalog: Configure compiles the iam.* controls of
// an air-gap bundle against the iam-actions.json of its signed manifest, so
// they evaluate. The same bundle re-signed without the file fails Configure
// iam_catalog_missing and leaves no bundle version in the trust state.
func TestConfigureIAMCatalog(t *testing.T) {
	archive, err := os.ReadFile("../../testdata/bundles/release-iam.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := bundlegen.LoadSchemas("../../testdata/schemas/aws-subset.json")
	if err != nil {
		t.Fatal(err)
	}
	configure := func(t *testing.T, archive []byte) (*Lifecycle, string, error) {
		t.Helper()
		dir := t.TempDir()
		for _, k := range []string{"COMPLIANCETF_ENFORCEMENT_MODE", "COMPLIANCETF_GOVERNED", "COMPLIANCETF_TOKEN",
			"COMPLIANCETF_PROFILE_PATH", "COMPLIANCETF_FLOOR_PATH", "COMPLIANCETF_ENVIRONMENT", "COMPLIANCETF_WORKSPACE",
			"COMPLIANCETF_EXCEPTIONS_FILE", "COMPLIANCETF_MIN_BUNDLE_VERSION", "COMPLIANCETF_MIN_PROFILE_VERSION"} {
			t.Setenv(k, "")
		}
		t.Setenv("COMPLIANCETF_BREAK_GLASS", "")
		os.Unsetenv("COMPLIANCETF_BREAK_GLASS") //nolint:errcheck,usetesting // any value fails Configure; t.Setenv restores it
		t.Setenv("COMPLIANCETF_OFFLINE", "true")
		t.Setenv("COMPLIANCETF_ORG_ID", "bobthecorp")
		state := filepath.Join(dir, "state")
		t.Setenv("COMPLIANCETF_STATE_DIR", state)
		t.Setenv("COMPLIANCETF_CACHE_DIR", filepath.Join(dir, "cache"))
		t.Setenv("COMPLIANCETF_EVIDENCE_DIR", filepath.Join(dir, "evidence"))
		path := filepath.Join(dir, "release-iam.tar.gz")
		writeFile(t, path, archive)
		t.Setenv("COMPLIANCETF_BUNDLE_PATH", path)
		l := New(Options{ProviderVersion: "6.40.0", Now: func() time.Time { return configureNow }})
		t.Cleanup(func() { _ = l.Close() }) //nolint:errcheck // test cleanup
		_, err := l.Configure(context.Background(), tftypes.NewValue(BlockType(), nil), "1.14.0", schemas)
		return l, state, err
	}

	t.Run("catalog in the manifest", func(t *testing.T) {
		l, _, err := configure(t, archive)
		if err != nil {
			t.Fatal(err)
		}
		cfg := l.Configured()
		// the compiler keys its memo by the content digest, not the bundle digests.
		cov, _ := exceptions.NewCoverability(cfg.Controls.Coverable(), cfg.Table.Exceptions)
		if want := cfg.Controls.ContentDigest(cov.Kinds()); cfg.Content != want {
			t.Fatalf("Configured.Content %q, want the content digest %q", cfg.Content, want)
		}
		sc, _ := schemas.Resource("aws_iam_policy")
		for _, c := range cfg.Controls.For("aws_iam_policy", bundle.OnCreate) {
			if c.ID != "iam_policy_no_full_access_to_kms" {
				continue
			}
			p, err := l.compilerFor(cfg).Compile(&c, sc.ValueType())
			if err != nil {
				t.Fatal(err)
			}
			v := withPolicy(t, sc.ValueType(), `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"*"}]}`)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if out := p.Eval(ctx, &engine.Activation{Resource: v, Config: v, Op: engine.OpCreate}); out.State != engine.Fail {
				t.Fatalf("kms:* evaluated %s/%s, want fail", out.State, out.Err)
			}
			return
		}
		t.Fatal("iam_policy_no_full_access_to_kms not loaded")
	})

	t.Run("catalog missing", func(t *testing.T) {
		without, err := bundletest.WithoutFile(archive, bundle.IAMActionsFile, testkeys.Bundle())
		if err != nil {
			t.Fatal(err)
		}
		_, state, err := configure(t, without)
		if err == nil || !strings.Contains(err.Error(), "iam_catalog_missing") {
			t.Fatalf("Configure: %v, want iam_catalog_missing", err)
		}
		s, err := trust.LoadState(state)
		if err != nil {
			t.Fatal(err)
		}
		if v, ok := s.Bundles["bobthecorp-release-iam"]; ok {
			t.Fatalf("rejected bundle recorded at v%d", v)
		}
	})
}

// withPolicy is a value of typ with only policy set.
func withPolicy(t *testing.T, typ tftypes.Type, policy string) tftypes.Value {
	t.Helper()
	obj, ok := typ.(tftypes.Object)
	if !ok {
		t.Fatalf("%s is not an object", typ)
	}
	m := map[string]tftypes.Value{}
	for k, at := range obj.AttributeTypes {
		m[k] = tftypes.NewValue(at, nil)
	}
	m["policy"] = tftypes.NewValue(tftypes.String, policy)
	return tftypes.NewValue(typ, m)
}
