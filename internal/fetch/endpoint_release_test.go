//go:build !ctftest

package fetch

import "testing"

// TestReleaseEndpoint: a release build talks only to the compiled service
// over the system roots.
func TestReleaseEndpoint(t *testing.T) {
	base, roots := endpoint()
	if base != "https://bundles.compliance.tf" || roots != nil {
		t.Fatalf("endpoint %q roots %v", base, roots)
	}
	c, err := New(Config{CacheDir: t.TempDir()})
	if err != nil || c.base.Host != "bundles.compliance.tf" {
		t.Fatal(c, err)
	}
	fc, err := NewFloorClient(FloorConfig{})
	if err != nil || fc.base.Host != "bundles.compliance.tf" || fc.hc.Transport.(floorPinned).host != "bundles.compliance.tf" {
		t.Fatal(fc, err)
	}
}
