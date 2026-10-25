package upstream

import (
	"strings"
	"testing"
)

func validPins(t testing.TB) *Pins { return pinsFor(t, mustSource(t, awsAddress)) }

func TestParsePinsRoundTrip(t *testing.T) {
	data, err := MarshalPins(validPins(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePins(data, mustSource(t, awsAddress), HashiCorpFingerprint); err != nil {
		t.Fatalf("valid pins rejected: %v", err)
	}
}

func TestParsePinsRejects(t *testing.T) {
	canon := func(mut func(*Pins)) string {
		p := validPins(t)
		mut(p)
		b, err := MarshalPins(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	good := canon(func(*Pins) {})
	cases := map[string]string{
		"fingerprint mismatch": canon(func(p *Pins) { p.SigningKeyFingerprint = strings.Repeat("B", 40) }),
		"empty platforms":      canon(func(p *Pins) { p.Platforms = map[string]PlatformPin{} }),
		"zip name mismatch": canon(func(p *Pins) {
			pl := p.Platforms["linux_amd64"]
			pl.Zip = "evil.zip"
			p.Platforms["linux_amd64"] = pl
		}),
		"binary name mismatch": canon(func(p *Pins) {
			pl := p.Platforms["windows_amd64"]
			pl.Binary = "terraform-provider-aws_v6.40.0_x5"
			p.Platforms["windows_amd64"] = pl
		}),
		"uppercase sha256": canon(func(p *Pins) { p.SHA256SumsSHA256 = strings.Repeat("A", 64) }),
		"wrong protocol":   canon(func(p *Pins) { p.Protocol = 6 }),
		"other upstream":   canon(func(p *Pins) { p.Upstream = "registry.terraform.io/hashicorp/google" }),
		"loose version":    canon(func(p *Pins) { p.Version = "6.x" }),
		"unknown field":    strings.Replace(good, `"format"`, `"extra": 1,`+"\n  "+`"format"`, 1),
		"duplicate member": strings.Replace(good, `  "version": "6.40.0",`, `  "version": "6.39.0",`+"\n"+`  "version": "6.40.0",`, 1),
		"not canonical":    strings.TrimSuffix(good, "\n"),
		"trailing data":    good + "{}",
	}
	for name, data := range cases {
		if _, err := ParsePins([]byte(data), mustSource(t, awsAddress), HashiCorpFingerprint); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
