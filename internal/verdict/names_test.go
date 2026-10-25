package verdict

import (
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// TestCheckContextEmptyNameFailsClosed: an empty WrapperName or UpstreamName
// never matches, even a signed provider_versions member named "".
func TestCheckContextEmptyNameFailsClosed(t *testing.T) {
	now := time.Date(2026, 10, 18, 11, 0, 0, 0, time.UTC)
	doc := &Document{OrgID: "bobthecorp", ProfileDigest: "sha256:p", BundleDigest: "sha256:b", ContentDigest: "sha256:c",
		IssuedAt: "2026-10-18T10:00:00Z", ExpiresAt: "2026-10-18T12:00:00Z",
		ProviderVersions: map[string]string{"compliancetf/aws": "2.0.0", "hashicorp/aws": "6.14.1", "": "2.0.0"}}
	in := Input{Profile: &profile.Profile{OrgID: "bobthecorp", Digest: "sha256:p"}, BundleDigest: "sha256:b", ContentDigest: "sha256:c",
		WrapperName: "compliancetf/aws", WrapperVersion: "2.0.0", UpstreamName: "hashicorp/aws", UpstreamVersion: "6.14.1", Now: now}
	if err := checkContext(doc, in); err != nil {
		t.Fatalf("named input: %v", err)
	}
	wrapperless := in
	wrapperless.WrapperName = ""
	upstreamless := in
	upstreamless.UpstreamName = ""
	upstreamDoc := *doc
	upstreamDoc.ProviderVersions = map[string]string{"compliancetf/aws": "2.0.0", "": "6.14.1"}
	for name, c := range map[string]struct {
		doc *Document
		in  Input
	}{"wrapper": {doc, wrapperless}, "upstream": {&upstreamDoc, upstreamless}} {
		err := checkContext(c.doc, c.in)
		if err == nil || !strings.Contains(err.Error(), "Verdict issued for none") {
			t.Errorf("empty %s name: err = %v, want a re-run error naming none", name, err)
		}
	}
}
