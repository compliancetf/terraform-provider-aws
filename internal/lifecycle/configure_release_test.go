//go:build !ctftest

package lifecycle

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// TestConfigureReleaseFailsClosed: the release keyring has no bundle key yet
// (owner), so the test-signed embedded CIS bundle does not verify and every
// Configure fails instead of running without controls. The ctftest goldens
// (TestConfigure) cover the rest.
func TestConfigureReleaseFailsClosed(t *testing.T) {
	kr, err := trust.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range kr.Keys() {
		if k.Purpose == trust.PurposeBundle {
			t.Skip("release keyring has a bundle key")
		}
	}
	t.Setenv("COMPLIANCETF_STATE_DIR", t.TempDir())
	t.Setenv("COMPLIANCETF_CACHE_DIR", t.TempDir())
	l := New(Options{ProviderVersion: "2.0.0"})
	if _, err := l.Configure(context.Background(), tftypes.NewValue(BlockType(), nil), "1.14.0", nil); err == nil || l.Configured() != nil {
		t.Fatalf("release Configure without a bundle key: err %v", err)
	}
}
