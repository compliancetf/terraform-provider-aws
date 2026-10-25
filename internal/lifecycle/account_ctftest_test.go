//go:build ctftest

package lifecycle

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/test/scrub/scrubtest"
)

// TestHookConfigureOwnAccount: Hook.Configure binds the declared
// allowed_account_ids id as provider.account_id in the Configure snapshot;
// skip_requesting_account_id or a malformed id leave it unknown, and a
// malformed id never reaches the binding, a diagnostic or a log.
func TestHookConfigureOwnAccount(t *testing.T) {
	marked := scrubtest.Marker(1)
	for _, c := range []struct {
		name  string
		req   hook.ConfigureRequest
		want  string
		known bool
	}{
		{"declared", hook.ConfigureRequest{AccountID: "111111111111", AccountKnown: true}, "111111111111", true},
		{"skip requesting account id", hook.ConfigureRequest{AccountID: "111111111111", AccountKnown: true, SkipAccountID: true}, "", false},
		{"malformed", hook.ConfigureRequest{AccountID: marked, AccountKnown: true}, "", false},
		{"not declared", hook.ConfigureRequest{}, "", false},
	} {
		offlineEnv(t)
		logs := scrubtest.CaptureLogs(t)
		l := New(Options{ProviderVersion: "6.40.0"})
		t.Cleanup(func() { _ = l.Close() }) //nolint:errcheck // test cleanup
		req := c.req
		req.TerraformVersion, req.Compliance = "1.14.0", tftypes.NewValue(BlockType(), nil)
		req.Region, req.RegionKnown = "us-east-1", true
		diags, err := Hook{Lifecycle: l}.Configure(context.Background(), &req)
		if err != nil || l.Configured() == nil {
			t.Fatalf("%s: Configure: %v %v", c.name, err, diags)
		}
		if p := l.Configured().Provider; p.AccountID != c.want || p.AccountKnown != c.known || p.Region != "us-east-1" || !p.RegionKnown {
			t.Errorf("%s: provider binding %s, want account %q known %v", c.name, scrubtest.Mask(fmt.Sprintf("%+v", p)), c.want, c.known)
		}
		scrubtest.NoMarker(t, c.name+" binding", fmt.Sprintf("%+v", l.Configured().Provider))
		scrubtest.NoMarker(t, c.name+" diagnostics", fmt.Sprintf("%+v", diags))
		scrubtest.NoMarker(t, c.name+" log", logs())
	}
}
