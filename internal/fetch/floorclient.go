package fetch

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

const (
	maxFloorBytes  = 64 << 10
	floorUserAgent = "compliancetf-floor/1"
)

// floorPathKey carries the expected request path from Floor to floorPinned.
type floorPathKey struct{}

// FloorConfig of a FloorClient: COMPLIANCETF_TOKEN, COMPLIANCETF_OFFLINE,
// COMPLIANCETF_FLOOR_PATH. It has no URL, TLS or proxy setting: the endpoint
// is compiled (endpoint()).
type FloorConfig struct {
	Token   string
	Offline bool
	EnvPath string
}

// FloorClient obtains the floor statement in the profile's floor_mode. It
// has its own transport, no AWS SDK or credential chain, and sends only the
// bundle-service bearer token. Online statements are cached in process only
// and re-verified on every read.
type FloorClient struct {
	cfg   FloorConfig
	base  *url.URL
	hc    *http.Client
	mu    sync.Mutex
	cache map[string][]byte // org -> envelope of the last accepted online statement
}

// NewFloorClient builds the dedicated floor client: a new transport (TLS >=
// 1.2, HTTPS_PROXY honored, no decompression), no cookie jar, every redirect
// refused, every request checked by floorPinned.
func NewFloorClient(cfg FloorConfig) (*FloorClient, error) {
	raw, roots := endpoint()
	base, err := url.Parse(raw)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil ||
		strings.Trim(base.Path, "/") != "" || base.RawQuery != "" || base.Fragment != "" {
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
		Transport: floorPinned{tr, base.Host, cfg.Token},
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("%w: redirect", errRefused)
		},
	}
	return &FloorClient{cfg: cfg, base: base, hc: hc, cache: map[string][]byte{}}, nil
}

// floorPinned refuses, before any I/O, every request that is not the exact
// floor GET Floor builds: pinned host, path and query, and only the bearer
// token, Accept and User-Agent headers with their exact values.
type floorPinned struct {
	rt    http.RoundTripper
	host  string
	token string
}

func (p floorPinned) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := p.check(r); err != nil {
		return nil, fmt.Errorf("%w: %s", errRefused, err)
	}
	return p.rt.RoundTrip(r)
}

func (p floorPinned) check(r *http.Request) error {
	u := r.URL
	want, ok0 := r.Context().Value(floorPathKey{}).(string)
	org, ok := strings.CutPrefix(want, "/v1/orgs/")
	org, ok2 := strings.CutSuffix(org, "/floor")
	switch {
	case !ok0:
		return errors.New("no expected floor path")
	case r.Method != http.MethodGet || r.Body != nil && r.Body != http.NoBody || r.ContentLength != 0 || len(r.TransferEncoding) != 0:
		return errors.New("not a bodyless GET")
	case u.Scheme != "https" || u.User != nil || u.Host != p.host || r.Host != "" && r.Host != p.host:
		return errors.New("not the bundle service")
	case u.Opaque != "" || u.Fragment != "" || u.RawPath != "" || !ok || !ok2 || !idRE.MatchString(org) || u.Path != want:
		return errors.New("not the floor path")
	case u.RawQuery != "keyring="+url.QueryEscape(trust.KeyringDigest()):
		return errors.New("not the floor query")
	}
	exact := map[string]string{"Authorization": "Bearer " + p.token, "Accept": "application/json", "User-Agent": floorUserAgent}
	for name, vals := range r.Header {
		if v, ok := exact[name]; !ok || len(vals) != 1 || vals[0] != v {
			return fmt.Errorf("header %s not allowed", name)
		}
	}
	if len(r.Header) != len(exact) {
		return errors.New("missing header")
	}
	return nil
}

// Floor returns the verified floor statement for in.OrgID in in.Mode (the
// signed profile's floor_mode, never inferred) and the state delta to persist.
// profileAirgapPath is the profile's floor_airgap_path. Any failure to obtain
// a floor is the governed "unavailable" error with a fixed reason; floors
// that fail verification return trust.VerifyFloor's error; a pending
// revocation epoch also returns its (generation, epoch) delta to persist.
func (c *FloorClient) Floor(ctx context.Context, in trust.FloorInput, profileAirgapPath string) (*trust.Floor, trust.State, error) {
	org := in.OrgID
	if !idRE.MatchString(org) {
		return nil, trust.State{}, fmt.Errorf("org %q: want %s", org, idRE)
	}
	unavailable := func(reason string) (*trust.Floor, trust.State, error) {
		return nil, trust.State{}, fmt.Errorf("Org floor for %s unavailable: governed runs need a signed floor statement (floor_mode %s). Reason: %s.", org, in.Mode, reason) //nolint:staticcheck // spec text
	}
	switch in.Mode {
	case trust.FloorAirgap:
		env, reason := readFloorFile(profileAirgapPath, c.cfg.EnvPath)
		if reason != "" {
			return unavailable(reason)
		}
		return trust.VerifyFloor(env, in)
	case trust.FloorOnline:
	default:
		return nil, trust.State{}, fmt.Errorf("floor_mode %q: want online or airgap", in.Mode)
	}

	switch {
	case c.cfg.Offline:
		return unavailable("COMPLIANCETF_OFFLINE is set")
	case c.cfg.Token == "":
		return unavailable("COMPLIANCETF_TOKEN is not set")
	}
	c.mu.Lock()
	cached := bytes.Clone(c.cache[org])
	c.mu.Unlock()
	if cached != nil {
		if f, delta, err := trust.VerifyFloor(cached, in); err == nil {
			return f, delta, nil
		}
		c.mu.Lock()
		if bytes.Equal(c.cache[org], cached) {
			delete(c.cache, org)
		}
		c.mu.Unlock()
	}

	env, reason, err := c.fetch(ctx, org)
	if err != nil {
		return nil, trust.State{}, err
	}
	if reason != "" {
		return unavailable(reason)
	}
	f, delta, err := trust.VerifyFloor(env, in)
	if errors.Is(err, trust.ErrFloorRevocationPending) {
		return nil, delta, err // high-water only; never cached as accepted
	}
	if err != nil {
		// On ErrFloorRevocationPending delta holds the high-water the caller
		// must persist; on any other error it is empty.
		return nil, delta, err
	}
	c.mu.Lock()
	c.cache[org] = env
	c.mu.Unlock()
	return f, delta, nil
}

// fetch GETs the floor statement. It returns the body, or a fixed reason
// (never error text, body, header or URL), or the caller's cancellation.
func (c *FloorClient) fetch(ctx context.Context, org string) ([]byte, string, error) {
	path := "/v1/orgs/" + org + "/floor"
	u := *c.base
	u.Path, u.RawQuery = path, "keyring="+url.QueryEscape(trust.KeyringDigest())
	req, err := http.NewRequestWithContext(context.WithValue(ctx, floorPathKey{}, path), http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "invalid request", nil
	}
	req.Header = http.Header{
		"Authorization": {"Bearer " + c.cfg.Token},
		"Accept":        {"application/json"},
		"User-Agent":    {floorUserAgent},
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		var ue *url.Error
		switch {
		case errors.Is(ctx.Err(), context.Canceled):
			return nil, "", ctx.Err()
		case errors.Is(err, errRefused):
			return nil, "refused by the floor transport policy", nil
		case tlsAuthFailure(err):
			return nil, "certificate verification failed", nil
		case errors.As(err, &ue) && ue.Timeout():
			return nil, "timeout", nil
		}
		return nil, "connection failed", nil
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close() //nolint:errcheck,gosec // read-only
		return nil, "HTTP " + strconv.Itoa(resp.StatusCode), nil
	}
	b, err := readBody(resp, "application/json", maxFloorBytes)
	var tr *transient
	switch {
	case errors.Is(err, context.Canceled):
		return nil, "", err
	case errors.As(err, &tr):
		return nil, "body read failed", nil
	case err != nil:
		return nil, "invalid response", nil
	}
	return b, "", nil
}

// readFloorFile reads the air-gap floor file: the profile's pinned path, else
// COMPLIANCETF_FLOOR_PATH. Symlinks are followed (mounted secrets); the
// signature, not the file type, is the trust boundary.
func readFloorFile(profilePath, envPath string) ([]byte, string) {
	path := profilePath
	if path == "" {
		path = envPath
	}
	if path == "" {
		return nil, "floor file not set"
	}
	f, err := os.Open(path) //nolint:gosec // operator- or profile-named path, verified by signature
	if err != nil {
		return nil, "floor file unreadable"
	}
	defer f.Close() //nolint:errcheck // read-only
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, "floor file is not a regular file"
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFloorBytes+1))
	switch {
	case err != nil:
		return nil, "floor file unreadable"
	case len(b) > maxFloorBytes:
		return nil, "floor file too large"
	}
	return b, ""
}
