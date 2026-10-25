package bundlegen

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// TestPruneSchema: the pruned schema keeps the content types and every type
// name, is canonical (golden, idempotent), loads through LoadSchemas and
// gives the same schema_compat_digest as the full schema.
func TestPruneSchema(t *testing.T) {
	cs, err := LoadControls(filepath.Join(inputs, "authored.json"))
	if err != nil {
		t.Fatal(err)
	}
	// A type the schema lacks is left out, for schemadiff to report.
	gone := cs[0]
	gone.ResourceType = "aws_gone"
	cs = append(cs, gone)

	full := filepath.Join("testdata", "prune", "full.json")
	raw, err := ReadRegular(full)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PruneSchema(raw, cs)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "prune", "pruned.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if want, err := os.ReadFile(golden); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("pruned schema differs from %s (err %v; -update to rewrite):\n%s", golden, err, got)
	}
	if again, err := PruneSchema(got, cs); err != nil || !bytes.Equal(again, got) {
		t.Fatalf("prune is not idempotent (err %v):\n%s", err, again)
	}

	var doc struct {
		ProviderSchemas map[string]prunedProvider `json:"provider_schemas"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	p := doc.ProviderSchemas[upstreamProvider]
	if len(doc.ProviderSchemas) != 1 || len(p.Resources) != 3 || len(p.DataSources) != 0 || len(p.Ephemeral) != 0 {
		t.Errorf("kept %d providers, types %v %v %v", len(doc.ProviderSchemas), p.Resources, p.DataSources, p.Ephemeral)
	}
	for key, want := range map[string][]string{
		"resource_schemas":           {"aws_db_instance", "aws_iam_policy", "aws_instance", "aws_s3_bucket_versioning"},
		"data_source_schemas":        {"aws_caller_identity"},
		"ephemeral_resource_schemas": {"aws_secretsmanager_random_password"},
	} {
		if !slices.Equal(p.TypeNames[key], want) {
			t.Errorf("type_names %s = %v, want %v", key, p.TypeNames[key], want)
		}
	}

	pf := filepath.Join(t.TempDir(), "pruned.json")
	if err := WriteFileAtomic(pf, got); err != nil {
		t.Fatal(err)
	}
	pruned, err := LoadSchemas(pf)
	if err != nil {
		t.Fatal(err)
	}
	fullS, err := LoadSchemas(full)
	if err != nil {
		t.Fatal(err)
	}
	cs = cs[:len(cs)-1]
	a, err := SchemaCompatDigest(cs, pruned)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := SchemaCompatDigest(cs, fullS); err != nil || a != b {
		t.Errorf("schema_compat_digest pruned %s, full %s (err %v)", a, b, err)
	}
}

func TestPruneSchemaErrors(t *testing.T) {
	c := bundle.Control{ID: "x", Kind: bundle.KindResource, ResourceType: "aws_x"}
	for name, raw := range map[string]string{
		"no aws provider": `{"provider_schemas": {}}`,
		"trailing data":   `{"provider_schemas": {}} {}`,
		"bad types":       `{"provider_schemas": {"registry.terraform.io/hashicorp/aws": {"resource_schemas": []}}}`,
	} {
		var e *Error
		if _, err := PruneSchema([]byte(raw), []bundle.Control{c}); !errors.As(err, &e) || e.Code != "E_INPUT" {
			t.Errorf("%s: err %v, want E_INPUT", name, err)
		}
	}
	bad := c
	bad.Kind = "nope"
	var e *Error
	if _, err := PruneSchema([]byte(`{"provider_schemas": {"registry.terraform.io/hashicorp/aws": {}}}`), []bundle.Control{bad}); !errors.As(err, &e) || e.Code != "E_SCHEMA_TYPE" {
		t.Errorf("unknown kind: err %v, want E_SCHEMA_TYPE", err)
	}
}

// TestWriteFileAtomic: a symlink at the path is replaced, not followed, and
// the result is a regular 0644 file.
func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "out.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(link, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("symlink target overwritten: %q", b)
	}
	fi, err := os.Lstat(link)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
		t.Fatalf("out.json mode %v (err %v), want regular 0644", fi.Mode(), err)
	}
	if b, _ := os.ReadFile(link); string(b) != "new" {
		t.Errorf("out.json = %q", b)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 {
		t.Errorf("temp file left behind: %v", ents)
	}
	if err := WriteFileAtomic(filepath.Join(dir, "missing", "f"), nil); err == nil {
		t.Error("write into a missing directory succeeded")
	}
}

// TestPruneSchemaGraph: a graph control keeps its target and
// companion resource types, for schemadiff to check both; one without
// graph fails E_SCHEMA_TYPE.
func TestPruneSchemaGraph(t *testing.T) {
	raw, err := ReadRegular(filepath.Join("testdata", "prune", "full.json"))
	if err != nil {
		t.Fatal(err)
	}
	g := bundle.Control{ID: "g", Kind: bundle.KindGraph, ResourceType: "aws_db_instance",
		Graph: &bundle.Graph{CompanionType: "aws_s3_bucket_versioning"}}
	got, err := PruneSchema(raw, []bundle.Control{g})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ProviderSchemas map[string]prunedProvider `json:"provider_schemas"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	p := doc.ProviderSchemas[upstreamProvider]
	if len(p.Resources) != 2 || p.Resources["aws_db_instance"] == nil || p.Resources["aws_s3_bucket_versioning"] == nil {
		t.Errorf("kept resources %v, want the target and companion types", p.Resources)
	}
	g.Graph = nil
	var e *Error
	if _, err := PruneSchema(raw, []bundle.Control{g}); !errors.As(err, &e) || e.Code != "E_SCHEMA_TYPE" {
		t.Errorf("graph without graph: err %v, want E_SCHEMA_TYPE", err)
	}
}
