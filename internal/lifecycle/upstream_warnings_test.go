package lifecycle

import (
	"slices"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// TestUpstreamWarnings: a bundle whose signed upstream range or
// source does not admit the running upstream gets one value-free warning;
// an unknown upstream version is one warning for the run; a dev upstream
// version is never lenient, on any build.
func TestUpstreamWarnings(t *testing.T) {
	mk := func(id, src, r string) *bundle.Bundle {
		m := &bundle.Manifest{BundleID: id, BundleVersion: 1}
		m.Upstream.Source, m.Upstream.VersionRange = src, r
		return &bundle.Bundle{Manifest: m}
	}
	in := mk("cis-aws", "hashicorp/aws", ">= 6.0.0, < 7.0.0")
	out := mk("soc2-aws", "hashicorp/aws", ">= 7.0.0")
	other := mk("bobthecorp-custom", "hashicorp/google", ">= 6.0.0")
	for _, c := range []struct {
		u    string
		b    []*bundle.Bundle
		want []string
	}{
		{"6.40.0", []*bundle.Bundle{in}, nil},
		{"6.40.0", []*bundle.Bundle{in, out}, []string{"upstream hashicorp/aws 6.40.0 is outside the upstream version range of bundle soc2-aws v1"}},
		{"6.40.0", []*bundle.Bundle{other}, []string{"upstream hashicorp/aws 6.40.0 is outside the upstream version range of bundle bobthecorp-custom v1"}},
		{"dev", []*bundle.Bundle{in}, []string{"upstream hashicorp/aws dev is outside the upstream version range of bundle cis-aws v1"}},
		{"", []*bundle.Bundle{in, out}, []string{"upstream hashicorp/aws version is unknown: bundle upstream version ranges were not checked"}},
		{" ", nil, []string{"upstream hashicorp/aws version is unknown: bundle upstream version ranges were not checked"}},
	} {
		if got := upstreamWarnings("hashicorp/aws", c.u, c.b); !slices.Equal(got, c.want) {
			t.Errorf("upstreamWarnings(%q) = %q, want %q", c.u, got, c.want)
		}
	}
}
