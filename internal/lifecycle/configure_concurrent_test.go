//go:build ctftest

package lifecycle

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/fetch"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// TestConfigureConcurrentRaise: another process raises the
// accepted version of a bundle this run loaded, between the load and the
// final trust state save. Configure re-checks every loaded bundle against
// the merged state that save returns and fails closed; without the raise
// the same run succeeds.
func TestConfigureConcurrentRaise(t *testing.T) {
	for _, tc := range []struct {
		name  string
		raise trust.State
		want  string
	}{
		{name: "none"},
		{name: "fetched bundle", raise: trust.State{Bundles: map[string]int64{"bobthecorp-swap-graph": 2}},
			want: "bundle bobthecorp-swap-graph v1 is below the minimum v2 accepted by a concurrent run"},
		{name: "embedded bundle", raise: trust.State{Bundles: map[string]int64{"cis-aws": 3}},
			want: "bundle cis-aws v2 is below the minimum v3 accepted by a concurrent run"},
		{name: "profile", raise: trust.State{Profiles: map[string]int64{"bobthecorp": 8}},
			want: "org profile v7 is below the minimum v8 accepted by a concurrent run"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile("../../testdata/bundles/swap-graph/a.tar.gz")
			if err != nil {
				t.Fatal(err)
			}
			// The service raises the state while it serves the bundle: after
			// Configure loaded the state, before its final save.
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/orgs/bobthecorp/bundles/bobthecorp-swap-graph" {
					http.Error(w, "unavailable", http.StatusServiceUnavailable)
					return
				}
				if tc.raise.Bundles != nil || tc.raise.Profiles != nil {
					if _, err := trust.UpdateState(os.Getenv("COMPLIANCETF_STATE_DIR"), tc.raise); err != nil {
						t.Error(err)
					}
				}
				w.Header().Set("Content-Type", "application/gzip")
				w.Write(raw) //nolint:errcheck,gosec // test server
			}))
			t.Cleanup(srv.Close)
			t.Cleanup(fetch.SetTestEndpoint(srv.URL, srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs))
			c := configureCase{Block: map[string]string{"org_id": "bobthecorp"}, Env: map[string]string{"COMPLIANCETF_TOKEN": "t"},
				Floor: json.RawMessage(`{}`), Profiles: map[string]json.RawMessage{"env": json.RawMessage(
					`{"floor_mode": "airgap", "governed": true, "profile_version": 7, "bundles": [{"bundle_id": "bobthecorp-swap-graph", "min_version": 1}]}`)}}
			_, _, err = runConfigure(t, c)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("configure: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("configure error %v, want %q", err, tc.want)
			}
		})
	}
}
