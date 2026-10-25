package main

import (
	"os"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

const goodCaps = `{
  "format": "compliancetf.release-capabilities/v1",
  "capabilities": [
    "bundle_signature_verification"
  ]
}
`

func validPins(t *testing.T) []byte {
	t.Helper()
	h := strings.Repeat("a", 64)
	src, err := upstream.ParseSource(upstreamAddress)
	if err != nil {
		t.Fatal(err)
	}
	b, err := upstream.MarshalPins(&upstream.Pins{
		Format: upstream.PinsFormat, Upstream: src.String(), Version: "6.40.0", Protocol: upstream.PinsProtocol,
		SigningKeyFingerprint: upstream.HashiCorpFingerprint, SHA256SumsSHA256: h,
		Platforms: map[string]upstream.PlatformPin{
			"linux_amd64": {Zip: src.ZipName("6.40.0", "linux", "amd64"), ZipSHA256: h, Binary: src.BinaryName("6.40.0", "linux", 5), BinarySHA256: h},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCheckAcceptsPinnedRelease(t *testing.T) {
	if err := check(validPins(t), []byte(goodCaps), "v6.40.0", false); err != nil {
		t.Fatalf("valid release metadata rejected: %v", err)
	}
}

func TestCommittedCapabilities(t *testing.T) {
	b, err := os.ReadFile("../../capabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := check(validPins(t), b, "v6.40.0", false); err != nil {
		t.Fatalf("committed capabilities.json rejected: %v", err)
	}
}

// TestCapabilitiesNotClaimedBeforeWiring: the provider does not verify bundle
// signatures yet (the v2 trust path is not wired into Configure), so the
// release must not claim it. Wiring it flips this test and the file.
func TestCapabilitiesNotClaimedBeforeWiring(t *testing.T) {
	b, err := os.ReadFile("../../capabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "bundle_signature_verification") {
		t.Fatal("capabilities.json claims bundle_signature_verification, which the provider does not perform yet")
	}
	if err := check(validPins(t), []byte(`{"format": "compliancetf.release-capabilities/v1", "capabilities": []}`), "v6.40.0", false); err != nil {
		t.Fatalf("empty capability set rejected: %v", err)
	}
}

func TestCheckRejects(t *testing.T) {
	placeholder := `{
  "format": "compliancetf.upstream-pins/v1",
  "upstream": "registry.terraform.io/hashicorp/aws",
  "version": "",
  "protocol": 5,
  "signing_key_fingerprint": "",
  "sha256sums_sha256": "",
  "platforms": null
}
`
	pins := string(validPins(t))
	cases := map[string][2]string{
		"placeholder pins":     {placeholder, goodCaps},
		"empty pins":           {"", goodCaps},
		"unknown capability":   {pins, strings.Replace(goodCaps, `"bundle_signature_verification"`, `"other"`, 1)},
		"null capabilities":    {pins, `{"format": "compliancetf.release-capabilities/v1", "capabilities": null}`},
		"absent capabilities":  {pins, `{"format": "compliancetf.release-capabilities/v1"}`},
		"wrong caps format":    {pins, strings.Replace(goodCaps, "/v1", "/v2", 1)},
		"unknown caps field":   {pins, strings.Replace(goodCaps, `"format"`, `"extra": 1, "format"`, 1)},
		"duplicate capability": {pins, strings.Replace(goodCaps, `"bundle_signature_verification"`, `"bundle_signature_verification", "bundle_signature_verification"`, 1)},
		"trailing caps data":   {pins, goodCaps + "{}"},
		"empty caps":           {pins, ""},
	}
	for name, c := range cases {
		if err := check([]byte(c[0]), []byte(c[1]), "v6.40.0", false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckVersion(t *testing.T) {
	cases := map[string]bool{
		"6.67.0":                       true,
		"v6.67.0":                      true,
		"6.67.0-beta.1":                true,
		"v6.67.0-beta.1":               true,
		"6.67.0-compliancetf.2":        true,
		"v6.67.0-compliancetf.0":       true,
		"6.67.0-ctf.1":                 false,
		"6.66.0":                       false,
		"2.0.0":                        false,
		"6.67.0-rc.1":                  false,
		"v2.0.0":                       false,
		"":                             false,
		"vv6.67.0":                     false,
		"6.67.0-beta":                  false,
		"6.67.0-beta.01":               false,
		"6.67.0-beta.1.2":              false,
		"6.67.0+build":                 false,
		"6.67.01":                      false,
		"6x67x0":                       false,
		"6.67.0.1":                     false,
		"6.67.0-compliancetf.1-beta.1": false,
	}
	for v, ok := range cases {
		if err := checkVersion(v, "6.67.0"); (err == nil) != ok {
			t.Errorf("%q: ok=%v, err=%v", v, ok, err)
		}
	}
}

func TestCheckVersionAgainstPins(t *testing.T) {
	pins, caps := validPins(t), []byte(goodCaps)
	if err := check(pins, caps, "v6.41.0", false); err == nil {
		t.Error("tag that differs from pins.json version accepted")
	}
	if err := check(pins, caps, "", false); err == nil {
		t.Error("empty release version accepted")
	}
	if err := check(pins, caps, "", true); err != nil {
		t.Errorf("snapshot without a version rejected: %v", err)
	}
	if err := check(pins, caps, "v0.0.0", true); err != nil {
		t.Errorf("snapshot with a mismatched tag rejected: %v", err)
	}
}
