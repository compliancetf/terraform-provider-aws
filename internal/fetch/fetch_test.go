//go:build ctftest

package fetch

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

const (
	org      = "bobthecorp"
	bundleID = "bobthecorp-soc2"
)

var (
	// goodHex is the hex of bundle.Bundle.Digest of good.tar.gz.
	goodHex    = mustDigestHex()
	goodDigest = "sha256:" + goodHex
	now        = time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	noRevs     = trust.NoRevocations()
)

func fixture(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type server struct {
	*httptest.Server
	hits    atomic.Int32
	inm     atomic.Value // last If-None-Match
	auth    atomic.Value // last Authorization
	handler func(w http.ResponseWriter, r *http.Request)
}

// newServer starts a TLS server and points the client endpoint at it.
func newServer(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *server {
	t.Helper()
	s := &server{handler: h}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.inm.Store(r.Header.Get("If-None-Match"))
		s.auth.Store(r.Header.Get("Authorization"))
		s.handler(w, r)
	}))
	t.Cleanup(s.Close)
	testBase, testRoots = s.URL, s.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	t.Cleanup(func() { testBase, testRoots = "", nil })
	return s
}

func mustDigestHex() string {
	raw, err := os.ReadFile("../../testdata/bundles/bobthecorp-soc2-sim/good.tar.gz")
	if err != nil {
		panic(err)
	}
	b, err := bundle.ReadArchive(raw, func(env []byte, pt string) (trust.Verified, error) {
		return trust.Verify(env, pt, trust.NoRevocations())
	})
	if err != nil {
		panic(err)
	}
	return strings.TrimPrefix(b.Digest, "sha256:")
}

func serveGood(t *testing.T) func(http.ResponseWriter, *http.Request) {
	good := fixture(t, "bundles/bobthecorp-soc2-sim/good.tar.gz")
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/orgs/bobthecorp/bundles/bobthecorp-soc2" || r.URL.Query().Get("min_version") != "10" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("If-None-Match") == `"`+goodDigest+`"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(good) //nolint:errcheck // test server
	}
}

func newClient(t *testing.T, token string, offline bool) (*Client, string) {
	t.Helper()
	dir := t.TempDir()
	c, err := New(Config{Token: token, CacheDir: dir, Offline: offline, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return c, dir
}

func fetchGood(t *testing.T, c *Client) ([]string, error) {
	t.Helper()
	b, warns, err := c.Bundle(context.Background(), org, bundleID, 10, 6, noRevs)
	if err == nil && (b.Digest != goodDigest || b.Manifest.BundleVersion != 12) {
		t.Fatalf("got %s v%d", b.Digest, b.Manifest.BundleVersion)
	}
	return warns, err
}

func TestBundle200Then304(t *testing.T) {
	s := newServer(t, serveGood(t))
	c, dir := newClient(t, "tok", false)
	if _, err := fetchGood(t, c); err != nil {
		t.Fatal(err)
	}
	if s.auth.Load() != "Bearer tok" || s.inm.Load() != "" {
		t.Fatal("headers", s.auth.Load(), s.inm.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, "bundles", "sha256-"+goodHex+".tar.gz")); err != nil {
		t.Fatal(err)
	}
	if warns, err := fetchGood(t, c); err != nil || len(warns) != 0 || s.inm.Load() != `"`+goodDigest+`"` {
		t.Fatal(warns, err, s.inm.Load())
	}
}

func TestBundleUnsolicited304AndRedirect(t *testing.T) {
	newServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotModified) })
	c, _ := newClient(t, "tok", false)
	if _, err := fetchGood(t, c); err == nil || !strings.Contains(err.Error(), "304") {
		t.Fatal(err)
	}
	good := serveGood(t) // a same-host redirect is followed
	newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("hop") == "" {
			http.Redirect(w, r, r.URL.Path+"?min_version=10&hop=1", http.StatusFound)
			return
		}
		good(w, r)
	})
	c, _ = newClient(t, "tok", false) // trusts the new server
	if _, err := fetchGood(t, c); err != nil {
		t.Fatal(err)
	}
}

func TestBundleCrossHostRedirect(t *testing.T) {
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("cross-host target reached")
	}))
	defer other.Close()
	newServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.RequestURI(), http.StatusFound)
	})
	c, dir := newClient(t, "tok", false)
	seedCache(t, dir) // a refusal never falls back
	if _, err := fetchGood(t, c); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatal(err)
	}
}

// TestBundleErrorsValueFree: a hostile or intercepted service must not get
// its redirect target, headers or the token reflected into diagnostics.
func TestBundleErrorsValueFree(t *testing.T) {
	const marker = "BOBTHECORP-MARKER-1"
	good := fixture(t, "bundles/bobthecorp-soc2-sim/good.tar.gz")
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer other.Close()
	for name, h := range map[string]func(http.ResponseWriter, *http.Request){
		"cross-host redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/"+marker+"?q="+marker, http.StatusFound)
		},
		"same-host redirect loop": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/"+marker+"?q="+marker, http.StatusFound)
		},
		"content type": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/"+marker)
			w.Write(good) //nolint:errcheck // test server
		},
		"content encoding": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/gzip")
			w.Header().Set("Content-Encoding", marker)
			w.Write(good) //nolint:errcheck // test server
		},
	} {
		newServer(t, h)
		c, _ := newClient(t, marker, false)
		if _, err := fetchGood(t, c); err == nil || strings.Contains(err.Error(), marker) {
			t.Errorf("%s: error %v", name, err)
		}
	}
	newServer(t, serveGood(t))
	testRoots = x509.NewCertPool()
	c, _ := newClient(t, marker, false)
	if _, err := fetchGood(t, c); !errors.Is(err, errCertificate) || strings.Contains(err.Error(), "min_version") {
		t.Errorf("untrusted cert: error %v", err)
	}
}

func TestBundleUntrustedCert(t *testing.T) {
	newServer(t, serveGood(t))
	testRoots = x509.NewCertPool() // the server certificate is not trusted
	c, dir := newClient(t, "tok", false)
	seedCache(t, dir) // an impersonated service never falls back
	if _, err := fetchGood(t, c); !errors.Is(err, errCertificate) {
		t.Fatal(err)
	}
}

func TestBundleCanceled(t *testing.T) {
	flushed := make(chan struct{}, 1)
	newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write([]byte{0x1f}) //nolint:errcheck // test server
		w.(http.Flusher).Flush()
		flushed <- struct{}{}
		<-r.Context().Done()
	})
	c, dir := newClient(t, "tok", false)
	seedCache(t, dir) // cancellation never falls back, before or during the body
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := c.Bundle(ctx, org, bundleID, 10, 6, noRevs); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	go func() { <-flushed; cancel() }()
	if _, _, err := c.Bundle(ctx, org, bundleID, 10, 6, noRevs); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// A caller deadline is a timeout: it falls back.
	ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if b, warns, err := c.Bundle(ctx, org, bundleID, 10, 6, noRevs); err != nil || b == nil || len(warns) != 1 {
		t.Fatal(warns, err)
	}
}

// TestReadBodyAfterDeadline: a body that ends cleanly once the request
// deadline has passed may have been cut short by the client's own close
// (TLS close_notify goes out before the socket closes), so it is a timeout,
// never a complete body. This was the TestBundleCanceled flake.
func TestReadBodyAfterDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://bundles.bobthecorp.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{
		Header:  http.Header{"Content-Type": {"application/gzip"}},
		Body:    io.NopCloser(bytes.NewReader([]byte{0x1f})), // ends with io.EOF
		Request: req,
	}
	b, err := readBody(resp, "application/gzip", 10)
	var tr *transient
	if !errors.As(err, &tr) || b != nil {
		t.Fatalf("readBody = %x, %v; want a transient timeout and no body", b, err)
	}
}

func TestBundleBad200(t *testing.T) {
	good := fixture(t, "bundles/bobthecorp-soc2-sim/good.tar.gz")
	for name, tc := range map[string]struct {
		ctype, enc string
		body       []byte
	}{
		"oversize":     {"application/gzip", "", bytes.Repeat([]byte{0}, maxBundleBytes+1)},
		"tampered":     {"application/gzip", "", fixture(t, "bundles/bobthecorp-soc2-sim/tamper-digest.tar.gz")},
		"content-type": {"text/html", "", good},
		"encoded":      {"application/gzip", "gzip", good},
	} {
		t.Run(name, func(t *testing.T) {
			newServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.ctype)
				if tc.enc != "" {
					w.Header().Set("Content-Encoding", tc.enc)
				}
				w.Write(tc.body) //nolint:errcheck // test server
			})
			c, dir := newClient(t, "tok", false)
			seedCache(t, dir) // a bad 200 never falls back
			if _, err := fetchGood(t, c); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestBundleStatus(t *testing.T) {
	for code, fallback := range map[int]bool{503: true, 429: true, 401: false, 403: false, 404: false} {
		newServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
		c, dir := newClient(t, "tok", false)
		seedCache(t, dir)
		warns, err := fetchGood(t, c)
		if fallback != (err == nil) {
			t.Fatalf("%d: fallback %v, err %v", code, fallback, err)
		}
		if fallback && (len(warns) != 1 || !strings.HasPrefix(warns[0], "Bundle service unreachable: using cached bobthecorp-soc2 v12 ("+goodDigest+").")) {
			t.Fatalf("%d: warnings %q", code, warns)
		}
	}
}

func TestBundleTimeout(t *testing.T) {
	old := timeout
	timeout = 200 * time.Millisecond
	t.Cleanup(func() { timeout = old })
	stall := func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
	slowBody := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write([]byte{0x1f}) //nolint:errcheck // test server
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}
	for _, h := range []http.HandlerFunc{stall, slowBody} {
		newServer(t, h)
		c, dir := newClient(t, "tok", false)
		if _, err := fetchGood(t, c); err == nil {
			t.Fatal("no cache: want error")
		}
		seedCache(t, dir)
		if warns, err := fetchGood(t, c); err != nil || len(warns) != 1 || !strings.Contains(warns[0], "Bundle service unreachable") {
			t.Fatal(warns, err)
		}
	}
}

func TestBundleOffline(t *testing.T) {
	s := newServer(t, serveGood(t))
	c, dir := newClient(t, "tok", true)
	if _, err := fetchGood(t, c); err == nil {
		t.Fatal("empty cache offline: want error")
	}
	seedCache(t, dir)
	if warns, err := fetchGood(t, c); err != nil || len(warns) != 1 || !strings.Contains(warns[0], "COMPLIANCETF_OFFLINE") {
		t.Fatal(warns, err)
	}
	if _, _, err := c.Bundle(context.Background(), org, bundleID, 13, 6, noRevs); err == nil {
		t.Fatal("cached v12 below min 13 accepted")
	}
	c, dir = newClient(t, "", false) // no token: cache only as well
	seedCache(t, dir)
	if warns, err := fetchGood(t, c); err != nil || len(warns) != 1 || !strings.Contains(warns[0], "COMPLIANCETF_TOKEN") {
		t.Fatal(warns, err)
	}
	if s.hits.Load() != 0 {
		t.Fatalf("made %d requests", s.hits.Load())
	}
}

func TestCacheIgnoresMisnamedAndLinks(t *testing.T) {
	newServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) })
	c, dir := newClient(t, "tok", false)
	good := fixture(t, "bundles/bobthecorp-soc2-sim/good.tar.gz")
	put(t, filepath.Join(dir, "bundles"), "sha256-"+strings.Repeat("0", 64)+".tar.gz", good)
	put(t, dir, "x", good)
	if err := os.Symlink(filepath.Join(dir, "x"), filepath.Join(dir, "bundles", "sha256-"+goodHex+".tar.gz")); err != nil {
		t.Fatal(err)
	}
	if _, err := fetchGood(t, c); err == nil {
		t.Fatal("misnamed or symlinked cache entry used")
	}
}

func TestInvalidIDs(t *testing.T) {
	s := newServer(t, serveGood(t))
	c, _ := newClient(t, "tok", false)
	for _, ids := range [][2]string{{"../x", bundleID}, {org, "a/b"}, {"Bob", bundleID}, {org, ""}} {
		if _, _, err := c.Bundle(context.Background(), ids[0], ids[1], 0, 6, noRevs); err == nil {
			t.Fatalf("%q accepted", ids)
		}
	}
	// Bundle ids come from the signed profile, which only requires them
	// non-empty: an invalid one is rejected without echoing it.
	if _, _, err := c.Bundle(context.Background(), org, "BOBTHECORP-MARKER-2", 0, 6, noRevs); err == nil || strings.Contains(err.Error(), "MARKER") {
		t.Errorf("invalid bundle id: error %v", err)
	}
	if s.hits.Load() != 0 {
		t.Fatal("request made for an invalid id")
	}
}

func put(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func seedCache(t *testing.T, dir string) {
	t.Helper()
	put(t, filepath.Join(dir, "bundles"), "sha256-"+goodHex+".tar.gz", fixture(t, "bundles/bobthecorp-soc2-sim/good.tar.gz"))
}

// Bundle tags its result with where it came from: the service or the cache
// (a 304 or a fallback).
func TestBundleSource(t *testing.T) {
	newServer(t, serveGood(t))
	c, dir := newClient(t, "tok", false)
	for _, want := range []string{bundle.SourceFetched, bundle.SourceCache} { // 200, then 304
		b, _, err := c.Bundle(context.Background(), org, bundleID, 10, 6, noRevs)
		if err != nil || b.Source != want {
			t.Fatalf("source %v, %v; want %s", b, err, want)
		}
	}
	c, _ = newClient(t, "tok", true)
	c.cfg.CacheDir = dir // offline over the cache just written
	if b, _, err := c.Bundle(context.Background(), org, bundleID, 10, 6, noRevs); err != nil || b.Source != bundle.SourceCache {
		t.Fatalf("offline source %v, %v; want cache", b, err)
	}
}

// CachedTrust reports one reason per file named like an archive that it
// did not use; other names are not cache archives and are not counted.
func TestCachedTrustSkipReasons(t *testing.T) {
	dir := t.TempDir()
	bdir := filepath.Join(dir, "bundles")
	good := fixture(t, "bundles/bobthecorp-soc2-sim/good.tar.gz")
	put(t, bdir, "sha256-"+goodHex+".tar.gz", good)                 // used
	put(t, bdir, "sha256-"+strings.Repeat("0", 64)+".tar.gz", good) // digest_mismatch
	put(t, bdir, "sha256-"+strings.Repeat("1", 64)+".tar.gz", []byte("not an archive"))
	put(t, bdir, "notes.txt", good)
	if err := os.Symlink(filepath.Join(bdir, "notes.txt"), filepath.Join(bdir, "sha256-"+strings.Repeat("2", 64)+".tar.gz")); err != nil {
		t.Fatal(err)
	}
	big, err := os.Create(filepath.Join(bdir, "sha256-"+strings.Repeat("3", 64)+".tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(big.Truncate(maxBundleBytes+1), big.Close()); err != nil { // sparse, over the cap
		t.Fatal(err)
	}
	_, ms, _, skipped, err := CachedTrust(dir, noRevs)
	slices.Sort(skipped)
	want := []string{SkipDigestMismatch, SkipNotRegular, SkipUnreadable, SkipUnverified}
	if err != nil || len(ms) != 1 || !slices.Equal(skipped, want) {
		t.Fatalf("CachedTrust: %d manifests, skipped %v, %v; want 1, %v", len(ms), skipped, err, want)
	}

	for i := range maxCacheFiles + 1 - 4 { // 4 regular archive names above
		put(t, bdir, fmt.Sprintf("sha256-%064x.tar.gz", i+16), nil)
	}
	_, ms, warns, skipped, err := CachedTrust(dir, noRevs)
	over := slices.DeleteFunc(slices.Clone(skipped), func(s string) bool { return s != SkipOverLimit })
	if err != nil || len(ms) != 0 || len(warns) != 1 || len(over) != maxCacheFiles+1 {
		t.Fatalf("over the limit: %d manifests, %d over_limit, warns %v, %v", len(ms), len(over), warns, err)
	}
}
