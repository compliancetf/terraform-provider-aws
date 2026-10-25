// Command pinupstream writes the repo root pins.json for one hashicorp/aws
// version (go run ./tools/pinupstream -version 6.40.0): it verifies the
// detached signature of SHA256SUMS against -key (primary fingerprint must be
// upstream.HashiCorpFingerprint), checks every platform zip against the signed
// sums and hashes the binary inside. Nothing is written unless all checks pass.
//
// Key: fetch https://www.hashicorp.com/.well-known/pgp-key.txt at every pin
// bump, match its fingerprint against HashiCorp's security page and the
// constant, commit it as keys/hashicorp-security.asc. A
// rotation changes key file and constant in one protected-path PR. A static
// key misses revocations; the owner tracks HashiCorp security advisories.
package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

const defaultBase = "https://releases.hashicorp.com/terraform-provider-aws"

// Size caps; vars so tests can lower them.
var (
	maxSumsBytes   int64 = 1 << 20
	maxSigBytes    int64 = 64 << 10
	maxZipBytes          = upstream.MaxZipBytes
	maxBinaryBytes       = upstream.MaxBinaryBytes
)

const (
	smallTimeout = 30 * time.Second
	zipTimeout   = 10 * time.Minute
)

// awsUpstream is the upstream this tool pins.
// shortcut: aws only and names below still spell terraform-provider-aws; an
// -upstream flag would derive every name from it.
var awsUpstream = mustSource("registry.terraform.io/hashicorp/aws")

func mustSource(s string) upstream.Source {
	src, err := upstream.ParseSource(s)
	if err != nil {
		panic(err)
	}
	return src
}

var sumsLineRe = regexp.MustCompile(`^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$`)

type config struct {
	version, keyPath, base, out string
	expectFingerprint           string
	allowLoopbackHTTP           bool // test only; not reachable from flags
}

func main() {
	cfg := config{expectFingerprint: upstream.HashiCorpFingerprint}
	flag.StringVar(&cfg.version, "version", "", "exact hashicorp/aws version, x.y.z (required)")
	flag.StringVar(&cfg.keyPath, "key", "keys/hashicorp-security.asc", "armored HashiCorp release public key")
	flag.StringVar(&cfg.base, "base", defaultBase, "release base URL (https only)")
	flag.StringVar(&cfg.out, "out", "pins.json", "output path")
	flag.Parse()
	if err := run(context.Background(), cfg); err != nil {
		fmt.Fprintln(os.Stderr, "pinupstream:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config) error {
	if !upstream.ValidVersion(cfg.version) {
		return fmt.Errorf("-version %q is not x.y.z", cfg.version)
	}
	if err := checkBase(cfg.base, cfg.allowLoopbackHTTP); err != nil {
		return err
	}
	keyData, err := os.ReadFile(cfg.keyPath)
	if err != nil {
		return fmt.Errorf("reading key: %w", err)
	}
	entity, err := upstream.LoadKey(keyData, cfg.expectFingerprint)
	if err != nil {
		return err
	}
	client := newClient()
	prefix := strings.TrimSuffix(cfg.base, "/") + "/" + cfg.version + "/"
	sumsURL := prefix + "terraform-provider-aws_" + cfg.version + "_SHA256SUMS"
	sums, err := fetch(ctx, client, sumsURL, maxSumsBytes)
	if err != nil {
		return err
	}
	sig, err := fetch(ctx, client, sumsURL+".sig", maxSigBytes)
	if err != nil {
		return err
	}
	if err := upstream.VerifySumsSignature(entity, sums, sig, time.Now(), false); err != nil {
		return err
	}
	zips, err := parseSums(sums, cfg.version)
	if err != nil {
		return err
	}
	sumsHash := sha256.Sum256(sums)
	pins := &upstream.Pins{
		Format:                upstream.PinsFormat,
		Upstream:              awsUpstream.String(),
		Version:               cfg.version,
		Protocol:              upstream.PinsProtocol,
		SigningKeyFingerprint: upstream.Fingerprint(entity),
		SHA256SumsSHA256:      hex.EncodeToString(sumsHash[:]),
		Platforms:             map[string]upstream.PlatformPin{},
	}
	dir := filepath.Dir(cfg.out)
	for _, z := range zips {
		pin, err := pinZip(ctx, client, prefix, dir, cfg.version, z)
		if err != nil {
			return fmt.Errorf("%s: %w", z.name, err)
		}
		pins.Platforms[z.goos+"_"+z.goarch] = pin
	}
	data, err := upstream.MarshalPins(pins)
	if err != nil {
		return err
	}
	if _, err := upstream.ParsePins(data, awsUpstream, cfg.expectFingerprint); err != nil {
		return err
	}
	return writeAtomic(cfg.out, data)
}

// checkBase allows https, or plain http to a loopback IP when the test option is set.
func checkBase(base string, allowLoopbackHTTP bool) error {
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("-base: %w", err)
	}
	if u.Scheme == "https" && u.Host != "" {
		return nil
	}
	if u.Scheme == "http" && allowLoopbackHTTP {
		if ip := net.ParseIP(u.Hostname()); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("-base %q must be https", base)
}

func newClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, ResponseHeaderTimeout: smallTimeout},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != via[0].URL.Scheme || req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("redirect to %s://%s refused", req.URL.Scheme, req.URL.Host)
			}
			return nil
		},
	}
}

func get(ctx context.Context, client *http.Client, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		cleanup(resp.Body.Close)
		return nil, fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	return resp, nil
}

func fetch(ctx context.Context, client *http.Client, u string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, smallTimeout)
	defer cancel()
	resp, err := get(ctx, client, u)
	if err != nil {
		return nil, err
	}
	defer cleanup(resp.Body.Close)
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("GET %s: larger than %d bytes", u, limit)
	}
	return b, nil
}

type zipRef struct {
	name, sha256, goos, goarch string
}

// parseSums accepts only platform zips and the manifest; anything else fails.
func parseSums(sums []byte, version string) ([]zipRef, error) {
	s := string(sums)
	if !strings.HasSuffix(s, "\n") || strings.ContainsRune(s, '\r') {
		return nil, errors.New("SHA256SUMS: must be LF-terminated lines")
	}
	zipRe := regexp.MustCompile(`^terraform-provider-aws_` + regexp.QuoteMeta(version) + `_([a-z0-9]+)_([a-z0-9]+)\.zip$`)
	manifest := "terraform-provider-aws_" + version + "_manifest.json"
	seen := map[string]bool{}
	var zips []zipRef
	for _, line := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		m := sumsLineRe.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("SHA256SUMS: bad line %q", line)
		}
		name := m[2]
		if seen[name] {
			return nil, fmt.Errorf("SHA256SUMS: duplicate %s", name)
		}
		seen[name] = true
		if name == manifest {
			continue
		}
		zm := zipRe.FindStringSubmatch(name)
		if zm == nil {
			return nil, fmt.Errorf("SHA256SUMS: unexpected file %s", name)
		}
		zips = append(zips, zipRef{name: name, sha256: m[1], goos: zm[1], goarch: zm[2]})
	}
	if len(zips) == 0 {
		return nil, errors.New("SHA256SUMS: no platform zips")
	}
	return zips, nil
}

// pinZip downloads one zip to a temp file next to the output, checks it
// against the signed sums, then hashes the provider binary from the same fd.
func pinZip(ctx context.Context, client *http.Client, prefix, dir, version string, z zipRef) (upstream.PlatformPin, error) {
	var pin upstream.PlatformPin
	ctx, cancel := context.WithTimeout(ctx, zipTimeout)
	defer cancel()
	f, err := os.CreateTemp(dir, ".pinupstream-*")
	if err != nil {
		return pin, err
	}
	defer cleanup(f.Close, func() error { return os.Remove(f.Name()) })

	resp, err := get(ctx, client, prefix+z.name)
	if err != nil {
		return pin, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxZipBytes+1))
	cleanup(resp.Body.Close)
	if err != nil {
		return pin, err
	}
	if n > maxZipBytes {
		return pin, fmt.Errorf("larger than %d bytes; raise upstream.MaxZipBytes with this pin", maxZipBytes)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != z.sha256 {
		return pin, fmt.Errorf("sha256 %s does not match signed SHA256SUMS %s", got, z.sha256)
	}
	if st, err := f.Stat(); err != nil || st.Size() != n {
		return pin, errors.New("temp file size changed")
	}
	zr, err := zip.NewReader(f, n)
	if err != nil {
		return pin, err
	}
	bin, err := upstream.FindBinary(zr, awsUpstream.BinaryName(version, z.goos, upstream.PinsProtocol))
	if err != nil {
		return pin, err
	}
	rc, err := bin.Open()
	if err != nil {
		return pin, err
	}
	defer cleanup(rc.Close)
	bh := sha256.New()
	bn, err := io.Copy(bh, io.LimitReader(rc, maxBinaryBytes+1))
	if err != nil {
		return pin, err
	}
	if bn > maxBinaryBytes {
		return pin, fmt.Errorf("binary larger than %d bytes", maxBinaryBytes)
	}
	return upstream.PlatformPin{
		Zip:          z.name,
		ZipSHA256:    z.sha256,
		Binary:       bin.Name,
		BinarySHA256: hex.EncodeToString(bh.Sum(nil)),
	}, nil
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".pinupstream-*")
	if err != nil {
		return err
	}
	defer cleanup(f.Close, func() error { return os.Remove(f.Name()) })
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil { // best effort where directories cannot be opened
		defer cleanup(d.Close)
		if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, errors.ErrUnsupported) {
			return err
		}
	}
	return nil
}

// cleanup runs best-effort close/remove steps in order and reports any error
// other than an already closed handle or an already removed file.
func cleanup(fns ...func() error) {
	for _, fn := range fns {
		if err := fn(); err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stderr, "pinupstream: cleanup:", err)
		}
	}
}
