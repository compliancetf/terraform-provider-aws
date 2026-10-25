// Package fetch is the bundle service client over pinned HTTPS with a
// digest-named cache and offline fallback, used only at ConfigureProvider. The
// cache is never a trust input: every cached artifact is verified on load.
package fetch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// baseURL is the compiled bundle service; only ctftest builds override it.
const baseURL = "https://bundles.compliance.tf"

const (
	maxBundleBytes = 8 << 20 // bundle archive compressed limit
	maxRedirects   = 3
)

// timeout bounds a whole request: connect, redirects and body. Tests lower it.
var timeout = 15 * time.Second

// idRE is the org and bundle id charset of the profile and bundle packages;
// ids are checked before any URL or cache path is built.
var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// errRefused marks a transport policy violation (host, scheme, redirects);
// it never falls back to the cache.
var errRefused = errors.New("refused by the fetch policy")

// errCertificate is a server certificate that did not verify: the service
// may be impersonated, so it never falls back to the cache either.
var errCertificate = errors.New("bundle service certificate verification failed")

// Config of a Client: COMPLIANCETF_TOKEN, COMPLIANCETF_CACHE_DIR ("" means
// os.UserCacheDir()/compliancetf), COMPLIANCETF_OFFLINE=true.
type Config struct {
	Token    string
	CacheDir string
	Offline  bool
	Now      func() time.Time
}

// Client fetches from the compiled bundle service.
type Client struct {
	cfg  Config
	base *url.URL
	hc   *http.Client
}

// New builds a client with its own transport: TLS >= 1.2, HTTPS_PROXY
// honored, no transparent decompression, every hop pinned to the compiled
// host, at most maxRedirects same-host redirects, no cookie jar.
func New(cfg Config) (*Client, error) {
	if cfg.CacheDir == "" {
		d, err := os.UserCacheDir()
		if err != nil {
			return nil, fmt.Errorf("cache dir: %w", err)
		}
		cfg.CacheDir = filepath.Join(d, "compliancetf")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	raw, roots := endpoint()
	base, err := url.Parse(raw)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil {
		return nil, fmt.Errorf("bundle service URL %q: want https://host", raw)
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: timeout,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
	}
	hc := &http.Client{
		Transport: pinned{tr, base.Host},
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return fmt.Errorf("%w: more than %d redirects", errRefused, maxRedirects)
			}
			return nil
		},
	}
	return &Client{cfg: cfg, base: base, hc: hc}, nil
}

// pinned refuses any hop, the first included, not https to the compiled host.
type pinned struct {
	rt   http.RoundTripper
	host string
}

func (p pinned) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.User != nil || r.URL.Host != p.host {
		return nil, fmt.Errorf("%w: request to a host other than the bundle service", errRefused)
	}
	return p.rt.RoundTrip(r)
}

// transient is a failure that may fall back to the cache: the service was not
// reached or is overloaded. Everything else is a hard error.
type transient struct{ reason string }

func (t *transient) Error() string { return t.reason }

// get returns a 200 or 304 response (body open), a *transient, or a hard error.
func (c *Client) get(ctx context.Context, path, query string, hdr http.Header) (*http.Response, error) {
	u := *c.base
	u.Path, u.RawQuery = path, query
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header = hdr
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	resp, err := c.hc.Do(req)
	if err != nil {
		// Fixed reasons only: a *url.Error quotes the (redirect) URL.
		switch {
		case errors.Is(ctx.Err(), context.Canceled):
			return nil, ctx.Err()
		case errors.Is(err, errRefused):
			return nil, fmt.Errorf("bundle service request %w", errRefused)
		case tlsAuthFailure(err):
			return nil, errCertificate
		}
		var ue *url.Error
		if errors.As(err, &ue) && ue.Timeout() {
			return nil, &transient{"timeout"}
		}
		return nil, &transient{"connection failed"}
	}
	switch code := resp.StatusCode; {
	case code == http.StatusOK || code == http.StatusNotModified:
		return resp, nil
	case code >= 500 || code == http.StatusTooManyRequests:
		resp.Body.Close() //nolint:errcheck,gosec // read-only
		return nil, &transient{"HTTP " + strconv.Itoa(code)}
	default:
		resp.Body.Close() //nolint:errcheck,gosec // read-only
		return nil, fmt.Errorf("bundle service answered HTTP %d for %s", code, path)
	}
}

// tlsAuthFailure reports a server certificate that did not verify: the
// service may be impersonated, so the cache must not hide it.
func tlsAuthFailure(err error) bool {
	var (
		cv *tls.CertificateVerificationError
		ua x509.UnknownAuthorityError
		he x509.HostnameError
		ci x509.CertificateInvalidError
	)
	return errors.As(err, &cv) || errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci)
}

// readBody checks the media type and encoding of a 200 and reads at most max
// bytes. A failed read (a timeout included) is transient unless the caller
// canceled. A read that overlaps an expired deadline is a timeout even when
// it ended cleanly: the client's own close may have ended the body early.
func readBody(resp *http.Response, wantType string, maxBytes int64) ([]byte, error) {
	defer resp.Body.Close() //nolint:errcheck // read-only
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mt != wantType {
		return nil, fmt.Errorf("content type is not %s", wantType) // header values are never echoed
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && ce != "identity" {
		return nil, errors.New("unexpected content encoding")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxBytes)
	}
	switch cerr := resp.Request.Context().Err(); {
	case errors.Is(cerr, context.Canceled):
		return nil, cerr
	case cerr != nil:
		return nil, &transient{"timeout"}
	case err != nil:
		return nil, &transient{"body read failed"}
	}
	return b, nil
}

// RejectedError is a service bundle whose archive verified but that failed
// an acceptance check (floor, profile minimum, org, expiry). Manifest is
// authenticated: callers may keep its minimums, never its controls.
type RejectedError struct {
	Manifest *bundle.Manifest
	Err      error
}

func (e *RejectedError) Error() string { return e.Err.Error() }
func (e *RejectedError) Unwrap() error { return e.Err }

// Bundle returns the newest acceptable bundle bundleID for org at or above
// minVersion, the caller's effective minimum. A 200 must verify and pass
// every check, then it replaces older cached copies. When the service is not
// reached (or offline, or no token) the best cached copy that verifies and
// passes the same checks is used with a warning; none is an error.
//
// Manifest minimums: minVersion is raised to the highest min_bundle_version
// of any cached manifest of bundleID for org or public (empty org_id) that
// verifies now (expired or not); a bundle whose min_profile_version is above profileVersion (the run's
// selected org profile, 0 for none) is not accepted.
func (c *Client) Bundle(ctx context.Context, org, bundleID string, minVersion, profileVersion int64, revs trust.Revocations) (*bundle.Bundle, []string, error) {
	if !idRE.MatchString(org) || !idRE.MatchString(bundleID) {
		return nil, nil, fmt.Errorf("org or bundle id: want %s", idRE) // the bundle id comes from the signed profile
	}
	verify := func(env []byte, pt string) (trust.Verified, error) { return trust.Verify(env, pt, revs) }
	now := c.cfg.Now()
	accept := func(b *bundle.Bundle) (string, error) {
		m := b.Manifest
		if m.BundleID != bundleID {
			return "", fmt.Errorf("got another bundle, want %q", bundleID)
		}
		if m.BundleVersion < minVersion {
			return "", fmt.Errorf("bundle %s v%d is below the floor v%d", bundleID, m.BundleVersion, minVersion)
		}
		if m.MinProfileVersion > profileVersion {
			return "", fmt.Errorf("bundle %s v%d needs org profile v%d or later, run has v%d", bundleID, m.BundleVersion, m.MinProfileVersion, profileVersion)
		}
		return b.Check(org, now, revs)
	}
	dir := filepath.Join(c.cfg.CacheDir, "bundles")
	cached, cwarns, _ := loadCachedBundles(c.cfg.CacheDir, dir, bundleID, verify) // skips: CachedTrust reports them
	for _, cb := range cached {
		if m := cb.b.Manifest; m.OrgID == "" || m.OrgID == org {
			minVersion = max(minVersion, m.MinBundleVersion)
		}
	}
	best, bestWarn := pickBest(cached, accept)

	// fallback uses the cache; lead names why, reason is the sanitized
	// transport failure (never a body, header or URL).
	fallback := func(lead, reason string) (*bundle.Bundle, []string, error) {
		if reason != "" {
			reason = " Reason: " + reason + "."
		}
		if best == nil {
			return nil, nil, fmt.Errorf("%sno usable cached %s at or above v%d.%s", lead, bundleID, minVersion, reason)
		}
		w := fmt.Sprintf("%susing cached %s v%d (%s).%s", lead, bundleID, best.Manifest.BundleVersion, best.Digest, reason)
		return best, append(append([]string{w}, bestWarn...), cwarns...), nil
	}
	switch {
	case c.cfg.Offline:
		return fallback("COMPLIANCETF_OFFLINE is set: ", "")
	case c.cfg.Token == "":
		return fallback("COMPLIANCETF_TOKEN is not set: ", "")
	}

	hdr := http.Header{}
	if best != nil {
		hdr.Set("If-None-Match", `"`+best.Digest+`"`)
	}
	resp, err := c.get(ctx, "/v1/orgs/"+org+"/bundles/"+bundleID,
		"min_version="+strconv.FormatInt(minVersion, 10), hdr)
	var tr *transient
	if errors.As(err, &tr) {
		return fallback("Bundle service unreachable: ", tr.reason)
	}
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode == http.StatusNotModified {
		resp.Body.Close() //nolint:errcheck,gosec // read-only
		if best == nil {
			return nil, nil, fmt.Errorf("bundle %s: HTTP 304 without a cached copy offered", bundleID)
		}
		return best, bestWarn, nil
	}
	raw, err := readBody(resp, "application/gzip", maxBundleBytes)
	if errors.As(err, &tr) {
		return fallback("Bundle service unreachable: ", tr.reason)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("bundle %s from the service: %w", bundleID, err)
	}
	b, err := bundle.ReadArchive(raw, verify)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle %s from the service: %w", bundleID, err)
	}
	warn, err := accept(b)
	if err != nil {
		err = fmt.Errorf("bundle %s from the service: %w", bundleID, err)
		if b.Manifest.BundleID == bundleID {
			err = &RejectedError{Manifest: b.Manifest, Err: err}
		}
		return nil, nil, err
	}
	var warns []string
	if warn != "" {
		warns = append(warns, warn)
	}
	b.Source = bundle.SourceFetched
	if err := storeBundle(c.cfg.CacheDir, dir, b, raw, cached); err != nil {
		warns = append(warns, fmt.Sprintf("Bundle cache not updated: %v.", err))
	}
	return b, warns, nil
}
