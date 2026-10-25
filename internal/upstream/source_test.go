package upstream

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	tfaddr "github.com/hashicorp/terraform-registry-address"
)

const awsAddress = "registry.terraform.io/hashicorp/aws"

func mustSource(t testing.TB, s string) Source {
	t.Helper()
	src, err := ParseSource(s)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// pinsFor is a valid pins document for src at version 6.40.0.
func pinsFor(t testing.TB, src Source) *Pins {
	t.Helper()
	h := strings.Repeat("a", 64)
	return &Pins{
		Format: PinsFormat, Upstream: src.String(), Version: "6.40.0", Protocol: PinsProtocol,
		SigningKeyFingerprint: HashiCorpFingerprint, SHA256SumsSHA256: h,
		Platforms: map[string]PlatformPin{
			"linux_amd64":   {Zip: src.ZipName("6.40.0", "linux", "amd64"), ZipSHA256: h, Binary: src.BinaryName("6.40.0", "linux", 5), BinarySHA256: h},
			"windows_amd64": {Zip: src.ZipName("6.40.0", "windows", "amd64"), ZipSHA256: h, Binary: src.BinaryName("6.40.0", "windows", 5), BinarySHA256: h},
		},
	}
}

// TestSourceNames: every upstream-specific name derives from the type, and
// the aws row is the original aws literal set unchanged.
func TestSourceNames(t *testing.T) {
	cases := []struct {
		addr, name, zip, bin, winBin, sums, url, dir string
	}{
		{awsAddress, "hashicorp/aws",
			"terraform-provider-aws_6.40.0_linux_amd64.zip", "terraform-provider-aws_v6.40.0_x5", "terraform-provider-aws_v6.40.0_x5.exe",
			"terraform-provider-aws_6.40.0_SHA256SUMS", "https://releases.hashicorp.com/terraform-provider-aws",
			filepath.Join("registry.terraform.io", "hashicorp", "aws")},
		{"registry.terraform.io/hashicorp/azurerm", "hashicorp/azurerm",
			"terraform-provider-azurerm_6.40.0_linux_amd64.zip", "terraform-provider-azurerm_v6.40.0_x5", "terraform-provider-azurerm_v6.40.0_x5.exe",
			"terraform-provider-azurerm_6.40.0_SHA256SUMS", "https://releases.hashicorp.com/terraform-provider-azurerm",
			filepath.Join("registry.terraform.io", "hashicorp", "azurerm")},
		{"registry.terraform.io/hashicorp/google", "hashicorp/google",
			"terraform-provider-google_6.40.0_linux_amd64.zip", "terraform-provider-google_v6.40.0_x5", "terraform-provider-google_v6.40.0_x5.exe",
			"terraform-provider-google_6.40.0_SHA256SUMS", "https://releases.hashicorp.com/terraform-provider-google",
			filepath.Join("registry.terraform.io", "hashicorp", "google")},
	}
	for _, c := range cases {
		s := mustSource(t, c.addr)
		got := []string{s.String(), s.Name(), s.ZipName("6.40.0", "linux", "amd64"), s.BinaryName("6.40.0", "linux", 5),
			s.BinaryName("6.40.0", "windows", 5), s.SumsName("6.40.0"), s.ReleasesURL(), s.RegistryDir()}
		want := []string{c.addr, c.name, c.zip, c.bin, c.winBin, c.sums, c.url, c.dir}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s: name %d = %q, want %q", c.addr, i, got[i], want[i])
			}
		}
		if s.Address().String() != c.addr {
			t.Errorf("%s: Address = %s", c.addr, s.Address())
		}
	}
}

func TestSourceRejects(t *testing.T) {
	for _, s := range []string{
		"hashicorp/aws",                         // short form
		"registry.opentofu.org/hashicorp/aws",   // other registry
		"registry.terraform.io/bobthecorp/aws",  // other namespace
		"registry.terraform.io/hashicorp/aws-x", // derived names must stay plain
		"Registry.terraform.io/hashicorp/aws",   // not canonical
		"registry.terraform.io/hashicorp/aws/x", // extra segment
		"",
	} {
		if _, err := ParseSource(s); err == nil {
			t.Errorf("ParseSource(%q) accepted", s)
		}
	}
	if _, err := NewSource(tfaddr.NewProvider(tfaddr.DefaultProviderRegistryHost, "bobthecorp", "aws")); err == nil {
		t.Error("NewSource accepted namespace bobthecorp")
	}
}

// TestParsePinsBySource: pins parse only against their own source, and a zero
// source fails closed.
func TestParsePinsBySource(t *testing.T) {
	srcs := []Source{mustSource(t, awsAddress), mustSource(t, "registry.terraform.io/hashicorp/azurerm"), mustSource(t, "registry.terraform.io/hashicorp/google")}
	for _, src := range srcs {
		data, err := MarshalPins(pinsFor(t, src))
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParsePins(data, src, HashiCorpFingerprint)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if p.Source() != src {
			t.Errorf("%s: Source = %v", src, p.Source())
		}
		for _, other := range srcs {
			if other != src {
				if _, err := ParsePins(data, other, HashiCorpFingerprint); err == nil {
					t.Errorf("%s pins accepted as %s", src, other)
				}
			}
		}
		if _, err := ParsePins(data, Source{}, HashiCorpFingerprint); err == nil || !strings.Contains(err.Error(), "no upstream source") {
			t.Errorf("%s pins with zero source: %v", src, err)
		}
		// Upstream matches but the names are another type's.
		wrong := pinsFor(t, src)
		wrong.Platforms = pinsFor(t, srcs[(indexOf(srcs, src)+1)%len(srcs)]).Platforms
		if data, err = MarshalPins(wrong); err != nil {
			t.Fatal(err)
		}
		if _, err := ParsePins(data, src, HashiCorpFingerprint); err == nil {
			t.Errorf("%s pins with another type's names accepted", src)
		}
	}
}

func indexOf(srcs []Source, s Source) int {
	for i, x := range srcs {
		if x == s {
			return i
		}
	}
	return -1
}

// TestDiscoverPathBySource: the exact pinned Terraform path and the packed
// mirror zip path derive from the source (azurerm and google rows).
func TestDiscoverPathBySource(t *testing.T) {
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	for _, typ := range []string{"azurerm", "google"} {
		t.Run(typ, func(t *testing.T) {
			src := mustSource(t, "registry.terraform.io/hashicorp/"+typ)
			r := newReleaseFor(t, src)
			dir := t.TempDir()
			writeBin(t, filepath.Join(dir, "registry.terraform.io", "hashicorp", typ, testVersion, testOSArch,
				"terraform-provider-"+typ+"_v"+testVersion+"_x5"+exe), r.bin)
			// an aws-path copy must not be found
			writeBin(t, filepath.Join(dir, "registry.terraform.io", "hashicorp", "aws", testVersion, testOSArch, r.pins.Platforms[testOSArch].Binary), []byte("aws"))
			s := newSource(t, r, nil)
			s.dirs = []string{dir}
			vb, err := s.find(context.Background())
			wantCopy(t, s, vb, err, r.bin)

			pin := r.pins.Platforms[testOSArch]
			want := filepath.Join(dir, "registry.terraform.io", "hashicorp", typ, "terraform-provider-"+typ+"_"+testVersion+"_"+testOSArch+".zip")
			if got := packedZipPath(dir, src, pin); got != want {
				t.Errorf("packedZipPath = %q, want %q", got, want)
			}
		})
	}
}

// TestDownloadBySource: the release URL and SHA256SUMS name derive from the
// source.
func TestDownloadBySource(t *testing.T) {
	src := mustSource(t, "registry.terraform.io/hashicorp/google")
	d, err := newDownloader(src, [][]byte{[]byte("anchor")})
	if err != nil {
		t.Fatal(err)
	}
	if d.base != "https://releases.hashicorp.com/terraform-provider-google" {
		t.Errorf("base = %q", d.base)
	}
	r := newReleaseFor(t, src)
	if _, ok := r.files["/terraform-provider-google/"+testVersion+"/terraform-provider-google_"+testVersion+"_SHA256SUMS"]; !ok {
		t.Fatal("fixture does not serve the google SHA256SUMS")
	}
	path, err := r.download(t, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFile(path, r.pins, testOSArch); err != nil {
		t.Fatal(err)
	}
}
