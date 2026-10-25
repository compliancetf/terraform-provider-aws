//go:build ctftest

package lifecycle

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle/bundletest"
	"github.com/compliancetf/terraform-provider-aws/internal/bundlegen"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// TestConfigureLoadsEveryKind: a signed
// bundle holding a data_source or an ephemeral control configures and is
// recorded as accepted, as the resource-only bundle does; a graph control
// (with its graph.json) too, since apply enforces it through the verdict.
func TestConfigureLoadsEveryKind(t *testing.T) {
	archive, err := os.ReadFile("../../testdata/bundles/release-iam.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := bundlegen.LoadSchemas("../../testdata/schemas/aws-subset.json")
	if err != nil {
		t.Fatal(err)
	}
	configure := func(t *testing.T, archive []byte) (string, error) {
		t.Helper()
		dir := t.TempDir()
		for _, k := range []string{"COMPLIANCETF_ENFORCEMENT_MODE", "COMPLIANCETF_GOVERNED", "COMPLIANCETF_TOKEN",
			"COMPLIANCETF_PROFILE_PATH", "COMPLIANCETF_FLOOR_PATH", "COMPLIANCETF_ENVIRONMENT", "COMPLIANCETF_WORKSPACE",
			"COMPLIANCETF_EXCEPTIONS_FILE", "COMPLIANCETF_MIN_BUNDLE_VERSION", "COMPLIANCETF_MIN_PROFILE_VERSION",
			"COMPLIANCETF_DATA_SOURCES"} {
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
		path := filepath.Join(dir, "bundle.tar.gz")
		writeFile(t, path, archive)
		t.Setenv("COMPLIANCETF_BUNDLE_PATH", path)
		l := New(Options{ProviderVersion: "6.40.0", Now: func() time.Time { return configureNow }})
		t.Cleanup(func() { _ = l.Close() }) //nolint:errcheck // test cleanup
		_, err := l.Configure(context.Background(), tftypes.NewValue(BlockType(), nil), "1.14.0", schemas)
		return state, err
	}

	t.Run("resource only", func(t *testing.T) {
		if _, err := configure(t, archive); err != nil {
			t.Fatal(err)
		}
	})

	controlsOf := func(archive []byte) []byte {
		var controls []byte
		if _, err := bundletest.Rewrite(archive, func(name string, body []byte) ([]byte, bool, error) {
			if name == bundle.ControlsFile {
				controls = body
			}
			return body, true, nil
		}); err != nil {
			t.Fatal(err)
		}
		return controls
	}
	graphArchive, err := os.ReadFile("../../testdata/bundles/swap-graph/a.tar.gz") // binds a graph.json
	if err != nil {
		t.Fatal(err)
	}
	for kind, extra := range map[string]string{
		"data_source": `{"id": "ami_most_recent", "version": "1.0.0", "kind": "data_source", "resource_type": "aws_ami",
			"reads": ["most_recent"], "presence_mode": "configured", "expr": "config.most_recent == true",
			"action": "deny", "severity": "high", "message": "m"}`,
		"ephemeral": `{"id": "secret_id_set", "version": "1.0.0", "kind": "ephemeral", "resource_type": "aws_secretsmanager_secret_version",
			"reads": ["secret_id"], "expr": "config.secret_id != ''", "action": "deny", "severity": "high", "message": "m"}`,
		"graph": `{"id": "s3_bucket_public_access_block_present", "version": "1.0.0", "kind": "graph", "resource_type": "aws_s3_bucket",
			"graph": {"rule": "companion_present", "companion_type": "aws_s3_bucket_public_access_block", "link_attr": "bucket",
			"target_attrs": ["id", "bucket"]}, "action": "deny", "severity": "high", "message": "m"}`,
	} {
		t.Run(kind, func(t *testing.T) {
			base := archive
			if kind == "graph" {
				base = graphArchive
			}
			controls := controlsOf(base)
			i := bytes.LastIndexByte(controls, ']')
			body := append(append(append([]byte{}, controls[:i]...), ","+extra...), controls[i:]...)
			signed, err := bundletest.WithFile(base, bundle.ControlsFile, body, testkeys.Bundle())
			if err != nil {
				t.Fatal(err)
			}
			state, err := configure(t, signed)
			if err != nil {
				t.Fatalf("Configure with a %s control: %v", kind, err)
			}
			st, err := trust.LoadState(state)
			if err != nil {
				t.Fatal(err)
			}
			id := "bobthecorp-release-iam"
			if kind == "graph" {
				id = "bobthecorp-swap-graph"
			}
			if _, ok := st.Bundles[id]; !ok {
				t.Fatal("accepted bundle not recorded")
			}
		})
	}
}
