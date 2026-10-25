package bundlegen

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// TestReleasesOlder: releases run from the floor to the pin, ascending,
// exact x.y.z of one major; Older returns those below the pin.
func TestReleasesOlder(t *testing.T) {
	rel := func(floor string, rs ...string) Releases {
		return Releases{Format: ReleasesFormat, Floor: floor, Releases: rs}
	}
	for _, c := range []struct {
		r     Releases
		pin   string
		older []string
	}{
		{rel("6.67.0", "6.67.0"), "6.67.0", []string{}},
		{rel("6.67.0", "6.67.0", "6.68.0", "6.68.1", "6.70.0"), "6.70.0", []string{"6.67.0", "6.68.0", "6.68.1"}},
		{rel("6.9.0", "6.9.0", "6.10.0"), "6.10.0", []string{"6.9.0"}}, // numeric, not string, order
	} {
		got, err := c.r.Older(c.pin)
		if err != nil || !slices.Equal(got, c.older) {
			t.Errorf("%+v.Older(%s) = %q, %v; want %q", c.r, c.pin, got, err, c.older)
		}
	}
	for name, c := range map[string]struct {
		r    Releases
		pin  string
		code string
	}{
		"bad pin":          {rel("6.67.0", "6.67.0"), "6.67", "E_UPSTREAM_PIN"},
		"no floor":         {rel("", "6.67.0"), "6.67.0", "E_RELEASE_FLOOR"},
		"prerelease floor": {rel("6.67.0-beta.1", "6.67.0-beta.1", "6.67.0"), "6.67.0", "E_RELEASE_FLOOR"},
		"v floor":          {rel("v6.67.0", "v6.67.0"), "6.67.0", "E_RELEASE_FLOOR"},
		"floor above pin":  {rel("6.68.0", "6.68.0"), "6.67.0", "E_RELEASE_FLOOR"},
		"other major":      {rel("5.100.0", "5.100.0", "6.67.0"), "6.67.0", "E_RELEASE_FLOOR"},
		"no releases":      {rel("6.67.0"), "6.67.0", "E_RELEASE_FLOOR"},
		"first not floor":  {rel("6.66.0", "6.67.0"), "6.67.0", "E_RELEASE_FLOOR"},
		"below floor":      {rel("6.66.0", "6.65.0", "6.66.0", "6.67.0"), "6.67.0", "E_RELEASE_FLOOR"},
		"last not pin":     {rel("6.66.0", "6.66.0", "6.68.0"), "6.67.0", "E_RELEASE_FLOOR"},
		"unsorted":         {rel("6.66.0", "6.66.0", "6.68.0", "6.67.0"), "6.67.0", "E_RELEASE_FLOOR"},
		"duplicate":        {rel("6.66.0", "6.66.0", "6.66.0", "6.67.0"), "6.67.0", "E_RELEASE_FLOOR"},
		"bad release":      {rel("6.66.0", "6.66.0", "6.66", "6.67.0"), "6.67.0", "E_RELEASE_FLOOR"},
	} {
		if got, err := c.r.Older(c.pin); errCode(err) != c.code || got != nil {
			t.Errorf("%s: Older = %q, %v; want %s", name, got, err, c.code)
		}
	}
}

// TestLoadReleases: format and keys are checked; an unknown key fails.
func TestLoadReleases(t *testing.T) {
	dir := t.TempDir()
	for body, ok := range map[string]bool{
		`{"format": "compliancetf.releases/v1", "floor": "6.67.0", "releases": ["6.67.0"]}`:                    true,
		`{"format": "compliancetf.releases/v2", "floor": "6.67.0", "releases": ["6.67.0"]}`:                    false,
		`{"format": "compliancetf.releases/v1", "flor": "6.67.0", "releases": ["6.67.0"]}`:                     false,
		`{"format": "compliancetf.releases/v1", "floor": "6.67.0", "releases": ["6.67.0"], "extra": 1}`:        false,
		`{"format": "compliancetf.releases/v1", "floor": "6.67.0", "releases": ["6.67.0"]} {"floor": "6.0.0"}`: false,
	} {
		p := filepath.Join(dir, "releases.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadReleases(p); (err == nil) != ok {
			t.Errorf("LoadReleases(%s) err = %v, want ok %v", body, err, ok)
		}
	}
}

// TestRepoReleases: the repo releases.json fits pins.json, and
// testdata/schemas/aws holds the schema of each supported release below the
// pin and nothing else (a release below the floor is pruned with it).
func TestRepoReleases(t *testing.T) {
	r, err := LoadReleases("../../releases.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../pins.json")
	if err != nil {
		t.Fatal(err)
	}
	var pins struct{ Version string }
	if err := json.Unmarshal(data, &pins); err != nil {
		t.Fatal(err)
	}
	older, err := r.Older(pins.Version)
	if err != nil {
		t.Fatal(err)
	}
	const dir = "../../testdata/schemas/aws"
	if _, err := LoadSupportedSchemas(dir, older); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, e := range ents {
		if v, ok := strings.CutSuffix(e.Name(), ".json"); !ok || !slices.Contains(older, v) {
			t.Errorf("%s/%s is not the schema of a supported release below the pin %s: remove it", dir, e.Name(), pins.Version)
		}
	}
}

// withAttr returns a copy of s whose type typ has attribute name changed by
// edit (nil: removed).
func withAttr(t *testing.T, s Schemas, typ, name string, edit func(*tfprotov5.SchemaAttribute)) Schemas {
	t.Helper()
	resp := *s.ProviderSchema()
	resp.ResourceSchemas = maps.Clone(resp.ResourceSchemas)
	sc := *resp.ResourceSchemas[typ]
	b := *sc.Block
	b.Attributes = nil
	found := false
	for _, a := range sc.Block.Attributes {
		if a.Name != name {
			b.Attributes = append(b.Attributes, a)
			continue
		}
		found = true
		if edit != nil {
			x := *a
			edit(&x)
			b.Attributes = append(b.Attributes, &x)
		}
	}
	if !found {
		t.Fatalf("%s.%s not in the schema", typ, name)
	}
	sc.Block = &b
	resp.ResourceSchemas[typ] = &sc
	return Schemas{&resp}
}

// TestGenerateSupported: with floor 6.66.0 the build.json ranges start at
// the floor and the controls must hold on the 6.66.0 schema too: a missing
// schema, a read gone, retyped or turned Computed only in 6.66.0 fails
// E_SUPPORTED_SCHEMA naming the control, the read and the version.
func TestGenerateSupported(t *testing.T) {
	in := loadInputs(t, inputs, true)
	pinned := generate(t, in)
	var c *bundle.Control
	cs, err := bundle.ParseControls(pinned["all/controls.json"])
	if err != nil {
		t.Fatal(err)
	}
	for i := range cs {
		sc, _ := in.Schemas.Lookup(cs[i].Kind, cs[i].ResourceType)
		if cs[i].Kind == bundle.KindResource && cs[i].PresenceMode != bundle.PresenceConfigured &&
			len(cs[i].Reads) > 0 && !strings.Contains(cs[i].Reads[0], ".") && !ReadComputed(sc, cs[i].Reads[0]) {
			c = &cs[i]
			break
		}
	}
	if c == nil {
		t.Fatal("no effective resource control with a top-level non-Computed read in the fixture")
	}
	read := c.Reads[0]

	opts := testOpts
	opts.Releases = Releases{Format: ReleasesFormat, Floor: "6.66.0", Releases: []string{"6.66.0", "6.67.0"}}
	if out, err := Generate(in, opts); errCode(err) != "E_SUPPORTED_SCHEMA" || out != nil || !strings.Contains(err.Error(), "6.66.0") {
		t.Errorf("no 6.66.0 schema: err = %v, want E_SUPPORTED_SCHEMA", err)
	}

	in.SupportedSchemas = map[string]Schemas{"6.66.0": in.Schemas}
	out, err := Generate(in, opts)
	if err != nil {
		t.Fatal(err)
	}
	var b build
	if err := json.Unmarshal(out.Files["all/build.json"], &b); err != nil {
		t.Fatal(err)
	}
	if b.Provider.VersionRange != ">= 6.66.0, < 7.0.0" || b.Upstream.VersionRange != b.Provider.VersionRange {
		t.Errorf("ranges %q, %q; want >= 6.66.0, < 7.0.0", b.Provider.VersionRange, b.Upstream.VersionRange)
	}

	for name, s := range map[string]Schemas{
		"gone":     withAttr(t, in.Schemas, c.ResourceType, read, nil),
		"computed": withAttr(t, in.Schemas, c.ResourceType, read, func(a *tfprotov5.SchemaAttribute) { a.Optional, a.Computed = true, true }),
		"retyped": withAttr(t, in.Schemas, c.ResourceType, read, func(a *tfprotov5.SchemaAttribute) {
			if a.Type.Is(tftypes.Number) {
				a.Type = tftypes.String
			} else {
				a.Type = tftypes.Number
			}
		}),
	} {
		in.SupportedSchemas = map[string]Schemas{"6.66.0": s}
		out, err := Generate(in, opts)
		want := []string{"hashicorp/aws 6.66.0", c.ID, c.ResourceType + "." + read}
		if errCode(err) != "E_SUPPORTED_SCHEMA" || out != nil || !containsAll(err.Error(), want) {
			t.Errorf("%s in 6.66.0: err = %v, want E_SUPPORTED_SCHEMA naming %q", name, err, want)
		}
	}
}

// TestReadSignature: a list or set step on the way to a read is part of its
// signature, so an object turned list of objects differs.
func TestReadSignature(t *testing.T) {
	leaf := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"enabled": tftypes.Bool}}
	obj := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"settings": leaf}}
	list := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"settings": tftypes.List{ElementType: leaf}}}
	a, b := readSignature(obj, "settings.enabled"), readSignature(list, "settings.enabled")
	if a == "" || b == "" || a == b {
		t.Errorf("signatures %q, %q: want both set and different", a, b)
	}
	if got := readSignature(obj, "settings.missing"); got != "" {
		t.Errorf("missing read signature %q, want empty", got)
	}
}

func containsAll(s string, subs []string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}
