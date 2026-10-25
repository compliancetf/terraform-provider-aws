//go:build ctftest

package fetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// Fake AWS credentials: none of them may reach the floor request.
var fakeAWS = map[string]string{
	"AWS_ACCESS_KEY_ID":                  "AKIABOBTHECORPFAKE01",
	"AWS_SECRET_ACCESS_KEY":              "bobthecorp-fake-secret-access-key",
	"AWS_SESSION_TOKEN":                  "bobthecorp-fake-session-token",
	"AWS_PROFILE":                        "bobthecorp-fake-profile",
	"AWS_REGION":                         "eu-west-1",
	"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://127.0.0.1:1/creds",
	"AWS_WEB_IDENTITY_TOKEN_FILE":        "/nonexistent/bobthecorp-token",
}

func setFakeAWS(t *testing.T) {
	t.Helper()
	for k, v := range fakeAWS {
		t.Setenv(k, v)
	}
}

func floorEnv(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "trust", "testdata", "floor", name+".dsse.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type floorServer struct {
	*server
	mu   sync.Mutex
	reqs []*http.Request
	code int
	body []byte
}

// newFloorServer serves body with code and records every request.
func newFloorServer(t *testing.T, body []byte) *floorServer {
	t.Helper()
	fs := &floorServer{code: http.StatusOK, body: body}
	fs.server = newServer(t, func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		fs.reqs = append(fs.reqs, r.Clone(context.Background()))
		code, b := fs.code, fs.body
		fs.mu.Unlock()
		if code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b) //nolint:errcheck // test server
	})
	return fs
}

func (fs *floorServer) set(code int, body []byte) {
	fs.mu.Lock()
	fs.code, fs.body = code, body
	fs.mu.Unlock()
}

func floorIn(t *testing.T, mode string, at time.Time) trust.FloorInput {
	t.Helper()
	s, err := trust.LoadState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return trust.FloorInput{OrgID: org, Mode: mode, ProviderVersion: "2.0.0", Now: at, Revs: noRevs, State: s}
}

func newFloorClient(t *testing.T, cfg FloorConfig) *FloorClient {
	t.Helper()
	c, err := NewFloorClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func unavailable(mode string) string {
	return "Org floor for bobthecorp unavailable: governed runs need a signed floor statement (floor_mode " + mode + ")."
}

// TestFloorClientNoCredentials: with AWS credentials in the environment the
// floor request carries exactly the bearer token, no SigV4 Authorization, no
// X-Amz-* header and no AWS secret anywhere, on the pinned path and query.
func TestFloorClientNoCredentials(t *testing.T) {
	setFakeAWS(t)
	fs := newFloorServer(t, floorEnv(t, "good"))
	c := newFloorClient(t, FloorConfig{Token: "tok"})
	f, delta, err := c.Floor(context.Background(), floorIn(t, trust.FloorOnline, floorNow), "")
	if err != nil || f.Epoch != 7 || delta.Floors[org].Epoch != 7 {
		t.Fatal(f, err)
	}
	if len(fs.reqs) != 1 {
		t.Fatalf("%d requests", len(fs.reqs))
	}
	r := fs.reqs[0]
	if r.Method != http.MethodGet || r.URL.Path != "/v1/orgs/bobthecorp/floor" || r.URL.RawQuery != "keyring="+url.QueryEscape(trust.KeyringDigest()) {
		t.Fatalf("request %s %s", r.Method, r.URL)
	}
	if got := r.Header.Values("Authorization"); len(got) != 1 || got[0] != "Bearer tok" {
		t.Fatalf("Authorization %q", got)
	}
	for name, vals := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-amz") {
			t.Fatalf("header %s sent", name)
		}
		for _, v := range vals {
			for k, secret := range fakeAWS {
				if strings.Contains(v, secret) {
					t.Fatalf("header %s carries %s", name, k)
				}
			}
		}
	}
	for name := range r.Header {
		switch name {
		case "Authorization", "Accept", "User-Agent":
		default:
			t.Fatalf("unexpected header %s", name)
		}
	}
}

// TestFloorClientRedirectRefused: a same-host or cross-host redirect is
// refused and its target never reached; the run fails closed.
func TestFloorClientRedirectRefused(t *testing.T) {
	setFakeAWS(t)
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("cross-host redirect target reached")
	}))
	defer other.Close()
	for _, target := range []string{"/v1/orgs/bobthecorp/floor?hop=1", other.URL + "/v1/orgs/bobthecorp/floor"} {
		hops := 0
		newServer(t, func(w http.ResponseWriter, r *http.Request) {
			hops++
			http.Redirect(w, r, target, http.StatusFound)
		})
		c := newFloorClient(t, FloorConfig{Token: "tok"})
		_, _, err := c.Floor(context.Background(), floorIn(t, trust.FloorOnline, floorNow), "")
		if err == nil || !strings.Contains(err.Error(), unavailable("online")) || !strings.Contains(err.Error(), "refused by the floor transport policy") {
			t.Fatalf("redirect to %s: %v", target, err)
		}
		if hops != 1 {
			t.Fatalf("redirect to %s followed: %d hops", target, hops)
		}
	}
}

// TestFloorClientPinned: the floor transport refuses any request that is not
// the exact pinned GET, before any I/O; the other server is never hit.
func TestFloorClientPinned(t *testing.T) {
	setFakeAWS(t)
	fs := newFloorServer(t, floorEnv(t, "good"))
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("non-pinned host reached")
	}))
	defer other.Close()
	c := newFloorClient(t, FloorConfig{Token: "tok"})
	path := "/v1/orgs/bobthecorp/floor"
	query := "keyring=" + url.QueryEscape(trust.KeyringDigest())
	ok := func() *http.Request {
		ctx := context.WithValue(context.Background(), floorPathKey{}, path)
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, fs.URL+path+"?"+query, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer tok")
		r.Header.Set("Accept", "application/json")
		r.Header.Set("User-Agent", floorUserAgent)
		return r
	}
	cases := map[string]func(r *http.Request) *http.Request{
		"other host": func(r *http.Request) *http.Request {
			u, _ := url.Parse(other.URL)
			r.URL.Host = u.Host
			return r
		},
		"http scheme":   func(r *http.Request) *http.Request { r.URL.Scheme = "http"; return r },
		"userinfo":      func(r *http.Request) *http.Request { r.URL.User = url.User("x"); return r },
		"Host header":   func(r *http.Request) *http.Request { r.Host = "evil.example"; return r },
		"other path":    func(r *http.Request) *http.Request { r.URL.Path = "/v1/orgs/bobthecorp/profile"; return r },
		"other org":     func(r *http.Request) *http.Request { r.URL.Path = "/v1/orgs/alicecorp/floor"; return r },
		"no path value": func(r *http.Request) *http.Request { return r.WithContext(context.Background()) },
		"extra query":   func(r *http.Request) *http.Request { r.URL.RawQuery += "&x=1"; return r },
		"fragment":      func(r *http.Request) *http.Request { r.URL.Fragment = "x"; return r },
		"POST":          func(r *http.Request) *http.Request { r.Method = http.MethodPost; return r },
		"body":          func(r *http.Request) *http.Request { r.ContentLength = 1; return r },
		"X-Amz header":  func(r *http.Request) *http.Request { r.Header.Set("X-Amz-Security-Token", "t"); return r },
		"SigV4 auth": func(r *http.Request) *http.Request {
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIABOBTHECORPFAKE01")
			return r
		},
		"wrong bearer":  func(r *http.Request) *http.Request { r.Header.Set("Authorization", "Bearer other"); return r },
		"two bearers":   func(r *http.Request) *http.Request { r.Header.Add("Authorization", "Bearer tok"); return r },
		"cookie":        func(r *http.Request) *http.Request { r.Header.Set("Cookie", "a=b"); return r },
		"other accept":  func(r *http.Request) *http.Request { r.Header.Set("Accept", "*/*"); return r },
		"other agent":   func(r *http.Request) *http.Request { r.Header.Set("User-Agent", "aws-sdk-go-v2"); return r },
		"accept gzip":   func(r *http.Request) *http.Request { r.Header.Set("Accept-Encoding", "gzip"); return r },
		"session token": func(r *http.Request) *http.Request { r.Header.Set("X-Session", fakeAWS["AWS_SESSION_TOKEN"]); return r },
	}
	for name, mutate := range cases {
		resp, err := c.hc.Transport.RoundTrip(mutate(ok()))
		if err == nil {
			resp.Body.Close() //nolint:errcheck,gosec // test
			t.Errorf("%s: not refused", name)
		}
	}
	if len(fs.reqs) != 0 {
		t.Fatalf("pinned server hit %d times by refused requests", len(fs.reqs))
	}
	resp, err := c.hc.Transport.RoundTrip(ok())
	if err != nil {
		t.Fatal("the pinned request itself:", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // test
}

// TestFloorClientNoAWSDeps: the fetch package links no AWS SDK, so no
// credential chain can be reached from the floor client.
func TestFloorClientNoAWSDeps(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-tags", "ctftest", ".").Output()
	if err != nil {
		t.Skip("go list unavailable:", err)
	}
	for _, p := range strings.Fields(string(out)) {
		if strings.Contains(p, "github.com/aws/") {
			t.Fatalf("fetch depends on %s", p)
		}
	}
}

// TestFloorCacheReverify: the in-process cache is re-verified on every read;
// a tampered or expired cached floor is never returned, and the cache never
// serves a run that must not go online.
func TestFloorCacheReverify(t *testing.T) {
	fs := newFloorServer(t, floorEnv(t, "good"))
	c := newFloorClient(t, FloorConfig{Token: "tok"})
	dir := t.TempDir()
	s, err := trust.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	in := trust.FloorInput{OrgID: org, Mode: trust.FloorOnline, ProviderVersion: "2.0.0", Now: floorNow, Revs: noRevs, State: s}
	_, delta, err := c.Floor(context.Background(), in, "")
	if err != nil {
		t.Fatal(err)
	}
	// After its own delta is stored, the cached statement still verifies
	// (equal epoch) and needs no second request.
	if in.State, err = trust.UpdateState(dir, delta); err != nil {
		t.Fatal(err)
	}
	if f, _, err := c.Floor(context.Background(), in, ""); err != nil || f.Epoch != 7 || len(fs.reqs) != 1 {
		t.Fatalf("cached read: %v, %d requests", err, len(fs.reqs))
	}

	// Tampered cache: never returned; refetched, and with the service down
	// the run fails closed.
	c.mu.Lock()
	b := c.cache[org]
	b[len(b)/2] ^= 0x01
	c.mu.Unlock()
	fs.set(http.StatusServiceUnavailable, nil)
	if _, _, err := c.Floor(context.Background(), in, ""); err == nil || !strings.Contains(err.Error(), unavailable("online")) {
		t.Fatalf("tampered cache: %v", err)
	}
	if len(fs.reqs) != 2 {
		t.Fatalf("tampered cache not refetched: %d requests", len(fs.reqs))
	}

	// Expired cache: rejected on read, refetched; the refetched copy is the
	// same expired statement, so the run fails with the expiry error.
	fs.set(http.StatusOK, floorEnv(t, "good"))
	if _, _, err := c.Floor(context.Background(), in, ""); err != nil {
		t.Fatal(err)
	}
	late := in
	late.Now = time.Date(2026, 10, 7, 0, 0, 1, 0, time.UTC)
	if _, _, err := c.Floor(context.Background(), late, ""); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired cache: %v", err)
	}
	if len(fs.reqs) != 4 {
		t.Fatalf("expired cache not refetched: %d requests", len(fs.reqs))
	}

	// Offline with a warm cache: no floor, no request.
	if _, _, err := c.Floor(context.Background(), in, ""); err != nil {
		t.Fatal(err)
	}
	n := len(fs.reqs)
	c.cfg.Offline = true
	if _, _, err := c.Floor(context.Background(), in, ""); err == nil || !strings.Contains(err.Error(), unavailable("online")) {
		t.Fatalf("offline warm cache: %v", err)
	}
	if len(fs.reqs) != n {
		t.Fatal("offline run reached the service")
	}
}

// TestFloorModeExplicit: floor_mode is taken as given, never inferred from a
// fetch outcome. Air-gap never touches the network; an online failure never
// falls back to COMPLIANCETF_FLOOR_PATH, so a governed run fails Configure.
func TestFloorModeExplicit(t *testing.T) {
	good := floorEnv(t, "good")
	dir := t.TempDir()
	file := filepath.Join(dir, "floor.dsse.json")
	if err := os.WriteFile(file, good, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "mounted.dsse.json")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}

	fs := newFloorServer(t, good)
	c := newFloorClient(t, FloorConfig{Token: "tok", EnvPath: file})
	for _, p := range []string{"", link} { // env path, then the profile's pinned path
		if f, _, err := c.Floor(context.Background(), floorIn(t, trust.FloorAirgap, floorNow), p); err != nil || f.Epoch != 7 {
			t.Fatalf("airgap %q: %v", p, err)
		}
	}
	if len(fs.reqs) != 0 {
		t.Fatal("airgap mode reached the service")
	}
	c.cfg.EnvPath = ""
	if _, _, err := c.Floor(context.Background(), floorIn(t, trust.FloorAirgap, floorNow), ""); err == nil || !strings.Contains(err.Error(), unavailable("airgap")) {
		t.Fatalf("airgap without a file: %v", err)
	}
	c.cfg.EnvPath = dir // a directory is not a floor file
	if _, _, err := c.Floor(context.Background(), floorIn(t, trust.FloorAirgap, floorNow), ""); err == nil || !strings.Contains(err.Error(), unavailable("airgap")) {
		t.Fatalf("airgap directory: %v", err)
	}

	// Online, service down, valid COMPLIANCETF_FLOOR_PATH and profile path:
	// both ignored, fail closed.
	fs.set(http.StatusBadGateway, nil)
	c = newFloorClient(t, FloorConfig{Token: "tok", EnvPath: file})
	_, _, err := c.Floor(context.Background(), floorIn(t, trust.FloorOnline, floorNow), link)
	if err == nil || err.Error() != unavailable("online")+" Reason: HTTP 502." {
		t.Fatalf("online failure with a floor file: %v", err)
	}
	for _, offline := range []FloorConfig{{EnvPath: file}, {Token: "tok", Offline: true, EnvPath: file}} {
		c = newFloorClient(t, offline)
		if _, _, err := c.Floor(context.Background(), floorIn(t, trust.FloorOnline, floorNow), ""); err == nil || !strings.Contains(err.Error(), unavailable("online")) {
			t.Fatalf("online %+v: %v", offline, err)
		}
	}

	// No mode is never a mode.
	for _, m := range []string{"", "auto", "Online"} {
		if _, _, err := c.Floor(context.Background(), floorIn(t, m, floorNow), file); err == nil || !strings.Contains(err.Error(), "want online or airgap") {
			t.Fatalf("mode %q: %v", m, err)
		}
	}
}

// TestFloorClientPendingKeepsHighWater: an online floor whose revocation
// bundle is withheld fails closed but returns the pending (generation,
// epoch) delta, so the caller can persist it and an older floor stays
// refused.
func TestFloorClientPendingKeepsHighWater(t *testing.T) {
	newFloorServer(t, floorEnv(t, "revoked-epoch-missing"))
	c := newFloorClient(t, FloorConfig{Token: "tok"})
	f, delta, err := c.Floor(context.Background(), floorIn(t, trust.FloorOnline, floorNow), "")
	if !errors.Is(err, trust.ErrFloorRevocationPending) || f != nil {
		t.Fatalf("pending: %v %v", f, err)
	}
	if m := delta.Floors[org]; m.Epoch == 0 || m.Generation != 2 {
		t.Fatalf("pending delta %+v: want generation 2 and its epoch", delta)
	}
}
