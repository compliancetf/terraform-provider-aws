package wrapper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

type inputs struct {
	wrapper, pins []byte
	anchors       [][]byte
	cis           []byte
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// awsInputs are the aws wrapper's real inputs: testdata/aws.wrapper.json, the
// committed pins.json and HashiCorp key, and the CIS archive of this build.
func awsInputs(t *testing.T) inputs {
	return inputs{
		wrapper: read(t, "testdata/aws.wrapper.json"),
		pins:    read(t, "../../pins.json"),
		anchors: [][]byte{read(t, "../../keys/hashicorp-security.asc")},
		cis:     read(t, cisPath),
	}
}

func (in inputs) load() (Config, error) { return Load(in.wrapper, in.pins, in.anchors, in.cis) }

// edited is aws.wrapper.json with edit applied, in canonical form.
func edited(t *testing.T, edit func(*file)) []byte {
	t.Helper()
	var f file
	if err := json.Unmarshal(read(t, "testdata/aws.wrapper.json"), &f); err != nil {
		t.Fatal(err)
	}
	edit(&f)
	b, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func TestLoadAWS(t *testing.T) {
	in := awsInputs(t)
	cfg, err := in.load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Address.String() != "registry.compliance.tf/compliancetf/aws" || cfg.Upstream.String() != "registry.terraform.io/hashicorp/aws" {
		t.Errorf("address %s, upstream %s", cfg.Address, cfg.Upstream)
	}
	if cfg.Protocol != 5 || cfg.ResourcePrefix != "aws_" {
		t.Errorf("protocol %d, prefix %q", cfg.Protocol, cfg.ResourcePrefix)
	}
	if !bytes.Equal(cfg.UpstreamPins, in.pins) || !bytes.Equal(cfg.CISBundle, in.cis) || len(cfg.TrustAnchors) != 1 || !bytes.Equal(cfg.TrustAnchors[0], in.anchors[0]) {
		t.Fatal("Config does not carry the inputs")
	}
	in.pins[0], in.cis[0], in.anchors[0][0] = 'x', 'x', 'x'
	if cfg.UpstreamPins[0] == 'x' || cfg.CISBundle[0] == 'x' || cfg.TrustAnchors[0][0] == 'x' {
		t.Error("Config aliases the caller's slices")
	}
}

// otherKey is an armored public key that is not the HashiCorp release key.
func otherKey(t *testing.T) []byte {
	t.Helper()
	e, err := openpgp.NewEntity("bobthecorp test", "", "test@bobthecorp.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestLoadErrors(t *testing.T) {
	base := read(t, "testdata/aws.wrapper.json")
	azurerm := func(f *file) {
		f.Address, f.Upstream = "registry.compliance.tf/compliancetf/azurerm", "registry.terraform.io/hashicorp/azurerm"
		f.ResourcePrefix, f.CatalogProvider, f.CISBundleID = "azurerm_", "azure", "cis-azure"
	}
	cases := []struct {
		name string
		edit func(t *testing.T, in *inputs)
		want string // exact error text, or a prefix ending in "*"
	}{
		// The Load error rows, exact text.
		{"protocol 6", func(t *testing.T, in *inputs) { in.wrapper = edited(t, func(f *file) { f.Protocol = 6 }) },
			"wrapper: protocol 6 is not supported by this SDK; upstream registry.terraform.io/hashicorp/aws must advertise 5.0"},
		{"address host", func(t *testing.T, in *inputs) {
			in.wrapper = edited(t, func(f *file) { f.Address = "registry.terraform.io/compliancetf/aws" })
		}, "wrapper: address registry.terraform.io/compliancetf/aws is not under registry.compliance.tf"},
		{"type mismatch", func(t *testing.T, in *inputs) {
			in.wrapper = edited(t, func(f *file) { f.Address = "registry.compliance.tf/compliancetf/google" })
		}, "wrapper: address type google does not match upstream type aws"},
		{"pins upstream", func(t *testing.T, in *inputs) { in.wrapper = edited(t, azurerm) },
			"wrapper: pins.json is for registry.terraform.io/hashicorp/aws, wrapper.json says registry.terraform.io/hashicorp/azurerm"},

		// wrapper.json shape.
		{"empty wrapper.json", func(_ *testing.T, in *inputs) { in.wrapper = nil }, "wrapper: wrapper.json is 0 bytes, want 1 to 65536"},
		{"oversize wrapper.json", func(_ *testing.T, in *inputs) {
			in.wrapper = append(bytes.Clone(base), bytes.Repeat([]byte(" "), MaxWrapperJSONBytes)...)
		}, "wrapper: wrapper.json is *"},
		{"unknown field", func(_ *testing.T, in *inputs) {
			in.wrapper = bytes.Replace(base, []byte(`  "format"`), []byte(`  "extra": 1,`+"\n"+`  "format"`), 1)
		}, `wrapper: wrapper.json: json: unknown field "extra"`},
		{"duplicate member", func(_ *testing.T, in *inputs) {
			in.wrapper = bytes.Replace(base, []byte(`  "protocol": 5,`), []byte(`  "protocol": 6,`+"\n"+`  "protocol": 5,`), 1)
		}, "wrapper: wrapper.json is not in canonical form"},
		{"reformatted", func(_ *testing.T, in *inputs) { in.wrapper = bytes.ReplaceAll(base, []byte("  "), []byte("\t")) },
			"wrapper: wrapper.json is not in canonical form"},
		{"trailing data", func(_ *testing.T, in *inputs) { in.wrapper = append(bytes.Clone(base), "{}\n"...) },
			"wrapper: wrapper.json is not in canonical form"},
		{"missing field", func(_ *testing.T, in *inputs) {
			in.wrapper = bytes.Replace(base, []byte(`  "verdict_kms": "aws_kms"`+"\n"), nil, 1)
			in.wrapper = bytes.Replace(in.wrapper, []byte(`"catalog_provider": "aws",`), []byte(`"catalog_provider": "aws"`), 1)
		}, "wrapper: wrapper.json is not in canonical form"},
		{"protocol float", func(_ *testing.T, in *inputs) {
			in.wrapper = bytes.Replace(base, []byte(`"protocol": 5,`), []byte(`"protocol": 5.0,`), 1)
		}, "wrapper: wrapper.json: *"},
		{"format", func(t *testing.T, in *inputs) {
			in.wrapper = edited(t, func(f *file) { f.Format = "compliancetf.wrapper/v2" })
		},
			`wrapper: format "compliancetf.wrapper/v2", want "compliancetf.wrapper/v1"`},
		{"protocol 4", func(t *testing.T, in *inputs) { in.wrapper = edited(t, func(f *file) { f.Protocol = 4 }) },
			"wrapper: protocol 4 is not supported by this SDK; upstream registry.terraform.io/hashicorp/aws must advertise 5.0"},
		{"short address", func(t *testing.T, in *inputs) {
			in.wrapper = edited(t, func(f *file) { f.Address = "compliancetf/aws" })
		},
			`wrapper: address "compliancetf/aws" is not a canonical hostname/namespace/type provider address`},
		{"uppercase address", func(t *testing.T, in *inputs) {
			in.wrapper = edited(t, func(f *file) { f.Address = "registry.compliance.tf/CompliancetF/aws" })
		}, `wrapper: address "registry.compliance.tf/CompliancetF/aws" is not a canonical hostname/namespace/type provider address`},
		{"short upstream", func(t *testing.T, in *inputs) { in.wrapper = edited(t, func(f *file) { f.Upstream = "hashicorp/aws" }) },
			`wrapper: upstream "hashicorp/aws" is not a canonical hostname/namespace/type provider address`},
		{"address namespace", func(t *testing.T, in *inputs) {
			in.wrapper = edited(t, func(f *file) { f.Address = "registry.compliance.tf/bobthecorp/aws" })
		}, "wrapper: address registry.compliance.tf/bobthecorp/aws is not in namespace compliancetf"},
		{"upstream namespace", func(t *testing.T, in *inputs) {
			in.wrapper = edited(t, func(f *file) { f.Upstream = "registry.terraform.io/bobthecorp/aws" })
		}, "wrapper: upstream registry.terraform.io/bobthecorp/aws is not under registry.terraform.io/hashicorp"},
		{"upstream host", func(t *testing.T, in *inputs) {
			in.wrapper = edited(t, func(f *file) { f.Upstream = "registry.opentofu.org/hashicorp/aws" })
		}, "wrapper: upstream registry.opentofu.org/hashicorp/aws is not under registry.terraform.io/hashicorp"},
		{"resource_prefix", func(t *testing.T, in *inputs) { in.wrapper = edited(t, func(f *file) { f.ResourcePrefix = "a" }) },
			`wrapper: resource_prefix "a", want "aws_"`},
		{"unknown upstream type", func(t *testing.T, in *inputs) {
			in.wrapper = edited(t, func(f *file) {
				f.Address, f.Upstream, f.ResourcePrefix = "registry.compliance.tf/compliancetf/null", "registry.terraform.io/hashicorp/null", "null_"
			})
		}, "wrapper: upstream type null has no catalog provider"},
		{"catalog_provider", func(t *testing.T, in *inputs) { in.wrapper = edited(t, func(f *file) { f.CatalogProvider = "gcp" }) },
			`wrapper: catalog_provider "gcp", want "aws" for upstream type aws`},
		{"cis_bundle_id", func(t *testing.T, in *inputs) { in.wrapper = edited(t, func(f *file) { f.CISBundleID = "soc2" }) },
			"wrapper: cis_bundle_id \"soc2\" does not match ^cis-[a-z0-9]+$"},
		{"cis_framework", func(t *testing.T, in *inputs) { in.wrapper = edited(t, func(f *file) { f.CISFramework = "" }) },
			"wrapper: cis_framework \"\" does not match ^cis_[a-z0-9_]+$"},
		{"verdict_kms", func(t *testing.T, in *inputs) { in.wrapper = edited(t, func(f *file) { f.VerdictKMS = "vault" }) },
			`wrapper: verdict_kms "vault" is not a known KMS type`},

		// pins.json.
		{"empty pins", func(_ *testing.T, in *inputs) { in.pins = nil }, "wrapper: pins.json is 0 bytes, want 1 to 1048576"},
		{"oversize pins", func(_ *testing.T, in *inputs) { in.pins = bytes.Repeat([]byte(" "), MaxPinsBytes+1) },
			"wrapper: pins.json is 1048577 bytes, want 1 to 1048576"},
		{"pins not canonical", func(_ *testing.T, in *inputs) { in.pins = append(in.pins, '\n') }, "wrapper: pins: not in canonical form"},
		{"pins not JSON", func(_ *testing.T, in *inputs) { in.pins = []byte("x") },
			"wrapper: pins.json: invalid character 'x' looking for beginning of value"},
		{"pins names of another type", func(t *testing.T, in *inputs) {
			// Upstream matches an azurerm wrapper.json, but the zip and binary
			// names are still aws: names derive from Config.Upstream.
			in.wrapper = edited(t, azurerm)
			var p upstream.Pins
			if err := json.Unmarshal(in.pins, &p); err != nil {
				t.Fatal(err)
			}
			p.Upstream = "registry.terraform.io/hashicorp/azurerm"
			b, err := upstream.MarshalPins(&p)
			if err != nil {
				t.Fatal(err)
			}
			in.pins = b
		}, "wrapper: pins: platform *"},

		// trust anchors.
		{"no anchor", func(_ *testing.T, in *inputs) { in.anchors = nil }, "wrapper: 0 trust anchors, want exactly 1"},
		{"two anchors", func(_ *testing.T, in *inputs) { in.anchors = append(in.anchors, in.anchors[0]) }, "wrapper: 2 trust anchors, want exactly 1"},
		{"empty anchor", func(_ *testing.T, in *inputs) { in.anchors = [][]byte{nil} }, "wrapper: trust anchor is 0 bytes, want 1 to 65536"},
		{"oversize anchor", func(_ *testing.T, in *inputs) { in.anchors = [][]byte{bytes.Repeat([]byte("A"), MaxAnchorBytes+1)} },
			"wrapper: trust anchor is 65537 bytes, want 1 to 65536"},
		{"garbage anchor", func(_ *testing.T, in *inputs) { in.anchors = [][]byte{[]byte("not a key")} }, "wrapper: trust anchor: reading key: *"},
		{"other anchor", func(t *testing.T, in *inputs) { in.anchors = [][]byte{otherKey(t)} }, "wrapper: trust anchor: key fingerprint * is not the pinned *"},

		// CIS bundle.
		{"empty bundle", func(_ *testing.T, in *inputs) { in.cis = nil }, sigErr(t, nil)},
		{"cis_framework not in bundle", func(t *testing.T, in *inputs) {
			in.wrapper = edited(t, func(f *file) { f.CISFramework = "cis_v700" })
		}, "wrapper: no CIS bundle control has a framework_ref for wrapper.json cis_framework"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := awsInputs(t)
			tc.edit(t, &in)
			cfg, err := in.load()
			checkErr(t, cfg, err, tc.want)
			if strings.HasPrefix(tc.name, "protocol") && err != nil && strings.Contains(err.Error(), "is not supported") && !errors.Is(err, ErrProtocolUnsupported) {
				t.Error("protocol error does not match ErrProtocolUnsupported")
			}
		})
	}
}

// sigErr is the error bundle.ReadArchive itself returns for archive, which
// Load must return unchanged.
func sigErr(t *testing.T, archive []byte) string {
	t.Helper()
	_, err := bundle.ReadArchive(archive, func(env []byte, payloadType string) (trust.Verified, error) {
		return trust.Verify(env, payloadType, trust.NoRevocations())
	})
	if err == nil {
		t.Fatal("archive verifies")
	}
	return err.Error()
}

func checkErr(t *testing.T, cfg Config, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("Load succeeded, want %q", want)
	}
	if p, ok := strings.CutSuffix(want, "*"); ok {
		if !matchGlob(err.Error(), want) {
			t.Fatalf("error %q, want %q", err, p+"*")
		}
	} else if err.Error() != want {
		t.Fatalf("error %q\nwant  %q", err, want)
	}
	if cfg.Protocol != 0 || cfg.UpstreamPins != nil || cfg.CISBundle != nil || cfg.TrustAnchors != nil {
		t.Error("Load returned a non-zero Config with an error")
	}
}

// matchGlob matches s against pattern, where each "*" stands for any text.
func matchGlob(s, pattern string) bool {
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, p := range parts[1:] {
		i := strings.Index(s, p)
		if i < 0 {
			return false
		}
		s = s[i+len(p):]
	}
	return true
}

func TestCheckPrefix(t *testing.T) {
	graph := func(companion string) bundle.Control {
		return bundle.Control{ID: "g", ResourceType: "aws_s3_bucket", Graph: &bundle.Graph{CompanionType: companion}}
	}
	cases := []struct {
		name     string
		controls []bundle.Control
		want     string
	}{
		{"inside", []bundle.Control{{ID: "r", ResourceType: "aws_s3_bucket"}, graph("aws_s3_bucket_policy")}, ""},
		{"resource outside", []bundle.Control{{ID: "r", ResourceType: "google_storage_bucket"}},
			"wrapper: CIS bundle control r targets google_storage_bucket, outside resource_prefix aws_"},
		{"bare prefix", []bundle.Control{{ID: "r", ResourceType: "aws_"}}, "wrapper: CIS bundle control r targets aws_, outside resource_prefix aws_"},
		{"companion outside", []bundle.Control{graph("azurerm_storage_account")},
			"wrapper: CIS bundle control g targets azurerm_storage_account, outside resource_prefix aws_"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkPrefix(tc.controls, "aws_")
			if got := fmt.Sprint(err); (err == nil) != (tc.want == "") || (err != nil && got != tc.want) {
				t.Fatalf("checkPrefix: %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCheckFramework(t *testing.T) {
	ctl := func(refs ...string) bundle.Control { return bundle.Control{ID: "c", FrameworkRefs: refs} }
	cases := []struct {
		name     string
		controls []bundle.Control
		ok       bool
	}{
		{"none", []bundle.Control{ctl(), ctl("cis_aws:2.1.1")}, false},
		{"lookalikes", []bundle.Control{ctl("cis_v6000:3", "cis_v600", "xcis_v600:3")}, false},
		{"one", []bundle.Control{ctl("cis_aws:2.1.1"), ctl("cis_aws:2.1.2", "cis_v600:3")}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkFramework(tc.controls, "cis_v600")
			if (err == nil) != tc.ok {
				t.Fatalf("checkFramework: %v, want ok %v", err, tc.ok)
			}
			if err != nil && strings.Contains(err.Error(), "cis_v") {
				t.Errorf("error %q carries a framework value", err)
			}
		})
	}
}
