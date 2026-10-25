package upstream

// download.go fetches the pinned upstream release, verifies the signed
// SHA256SUMS chain against the configured trust anchor and the pins, and
// publishes the extracted binary into the content-addressed cache. No unsigned
// or TOFU path.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// MaxZipBytes caps a release zip, downloaded or read from a packed mirror,
// before its sha256 is known. tools/pinupstream refuses to pin a larger zip,
// so a pinned zip always fits and a larger mirror file is rejected unread.
// The 6.67.0 zips are 150-180 MiB.
const MaxZipBytes int64 = 384 << 20

const (
	maxSumsBytes int64 = 1 << 20
	maxSigBytes  int64 = 64 << 10
	smallTimeout       = 30 * time.Second
	zipTimeout         = 10 * time.Minute
)

// mirrorReadTimeout bounds reading one local candidate (mirror, plugin cache,
// own cache); a var so tests can lower it.
var mirrorReadTimeout = zipTimeout

// downloader fetches from base with client and trusts only key.
type downloader struct {
	base        string
	client      *http.Client
	key         []byte
	fingerprint string
}

// newDownloader trusts the one anchor, which download checks against the
// compiled HashiCorpFingerprint.
func newDownloader(src Source, anchors [][]byte) (downloader, error) {
	if len(anchors) != 1 {
		return downloader{}, fmt.Errorf("HashiCorp release key: %d trust anchors, want exactly 1", len(anchors))
	}
	key := anchors[0]
	client := &http.Client{
		Transport:     &http.Transport{Proxy: http.ProxyFromEnvironment, ResponseHeaderTimeout: smallTimeout},
		CheckRedirect: checkRedirect,
	}
	return downloader{base: src.ReleasesURL(), client: client, key: key, fingerprint: HashiCorpFingerprint}, nil
}

// checkRedirect allows at most 5 redirects, each on https to the same host:port
// without userinfo.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host || req.URL.User != nil {
		return fmt.Errorf("redirect to %s://%s refused", req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// cachePath is the content-addressed cache name for a binary sha256.
func cachePath(dir, sha string) string {
	name := "sha256-" + sha
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(dir, name)
}

// download returns the cache path of the verified binary for osArch.
func (d downloader) download(ctx context.Context, p *Pins, osArch, cacheDir string) (string, error) {
	pin, ok := p.Platforms[osArch]
	if !ok {
		return "", fmt.Errorf("no pin for %s", osArch)
	}
	if d.key == nil {
		return "", errors.New("HashiCorp release key not embedded")
	}
	key, err := LoadKey(d.key, d.fingerprint)
	if err != nil {
		return "", err
	}
	if err := privateDir(cacheDir); err != nil {
		return "", err
	}
	prefix := d.base + "/" + p.Version + "/"
	sumsURL := prefix + p.src.SumsName(p.Version)
	sums, err := d.fetch(ctx, sumsURL, maxSumsBytes)
	if err != nil {
		return "", err
	}
	sig, err := d.fetch(ctx, sumsURL+".sig", maxSigBytes)
	if err != nil {
		return "", err
	}
	if err := VerifySumsSignature(key, sums, sig, time.Now(), true); err != nil {
		return "", err
	}
	if got := sha256.Sum256(sums); hex.EncodeToString(got[:]) != p.SHA256SumsSHA256 {
		return "", errors.New("SHA256SUMS sha256 does not match the pin")
	}

	ctx, cancel := context.WithTimeout(ctx, zipTimeout)
	defer cancel()
	zf, err := os.CreateTemp(cacheDir, ".download-*")
	if err != nil {
		return "", err
	}
	defer removeTemp(zf)
	resp, err := d.get(ctx, prefix+pin.Zip)
	if err != nil {
		return "", err
	}
	n, got, err := copyHashed(zf, resp.Body, MaxZipBytes)
	_ = resp.Body.Close()
	if err != nil {
		return "", err
	}
	return installZip(zf, n, got, p, osArch, cacheDir)
}

// installZip extracts the pinned binary from zf, a private copy of n bytes
// whose sha256 got was taken while it was written, into the cache. The zip is
// parsed only once got equals the signed pin.
func installZip(zf *os.File, n int64, got string, p *Pins, osArch, cacheDir string) (string, error) {
	pin := p.Platforms[osArch]
	if got != pin.ZipSHA256 {
		return "", fmt.Errorf("zip sha256 %s does not match the pin %s", got, pin.ZipSHA256)
	}
	zr, err := zip.NewReader(zf, n)
	if err != nil {
		return "", err
	}
	entry, err := FindBinary(zr, pin.Binary)
	if err != nil {
		return "", err
	}
	return extract(entry, p, osArch, cacheDir)
}

// extract writes entry to a temp file, checks its hash, and renames it onto
// the cache name. The cache name is never opened for writing.
func extract(entry *zip.File, p *Pins, osArch, cacheDir string) (string, error) {
	want := p.Platforms[osArch].BinarySHA256
	// archive/zip fails a read past the declared size, so this caps the output.
	if entry.UncompressedSize64 > uint64(MaxBinaryBytes) {
		return "", fmt.Errorf("zip entry %q is larger than %d bytes", entry.Name, MaxBinaryBytes)
	}
	rc, err := entry.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	bf, err := os.CreateTemp(cacheDir, ".download-*")
	if err != nil {
		return "", err
	}
	defer removeTemp(bf)
	_, got, err := copyHashed(bf, rc, MaxBinaryBytes)
	if err != nil {
		return "", err
	}
	if got != want {
		return "", &NotVerifiedError{Upstream: p.src.Name(), Path: entry.Name, Got: got, Want: want, Version: p.Version, OSArch: osArch}
	}
	if err := bf.Chmod(0o700); err != nil {
		return "", err
	}
	if err := bf.Sync(); err != nil {
		return "", err
	}
	if err := bf.Close(); err != nil {
		return "", err
	}
	final := cachePath(cacheDir, want)
	if err := publish(bf.Name(), final, p, osArch); err != nil {
		return "", err
	}
	if d, err := os.Open(cacheDir); err == nil { // best effort durability
		_ = d.Sync()
		_ = d.Close()
	}
	return final, nil
}

// publish renames tmp onto final. When that fails (destination in use on
// Windows, a concurrent writer) an existing final is kept only if it matches;
// a mismatched one is removed and the rename retried once.
func publish(tmp, final string, p *Pins, osArch string) error {
	err := os.Rename(tmp, final)
	if err == nil {
		return nil
	}
	if verifyFile(final, p, osArch) == nil {
		return nil
	}
	if rerr := os.Remove(final); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		return fmt.Errorf("publishing %q: %w", final, err)
	}
	return os.Rename(tmp, final)
}

// copyHashed copies at most limit bytes from r to w and returns the count and sha256.
func copyHashed(w io.Writer, r io.Reader, limit int64) (int64, string, error) {
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(r, limit+1))
	if err != nil {
		return n, "", err
	}
	if n > limit {
		return n, "", fmt.Errorf("larger than %d bytes", limit)
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// maxBlockedReads bounds the copyWithin reads in flight, abandoned ones
// included, so hung candidates cannot pile up goroutines and fds.
const maxBlockedReads = 4

// readSlots holds one token per copyWithin read in flight.
var readSlots = make(chan struct{}, maxBlockedReads)

// beforeCopyWait runs after the read starts and before copyWithin waits on
// it; tests use it to make the copy and the deadline both ready.
var beforeCopyWait = func() {}

// copyWithin is copyBytes, given up when ctx ends or mirrorReadTimeout passes.
// A read of a regular file cannot be interrupted, so a hung read (a stuck FUSE
// or network mirror) is abandoned: the caller's deferred Close of r and w takes
// effect once the syscall returns, and any later write to w fails. An abandoned
// read keeps its slot until it returns; with every slot taken a new read fails
// at once. A ctx that is already done returns ctx.Err() before a slot is
// taken; one that ends during the read returns ctx.Err() unless the copy has
// finished by then.
func copyWithin(ctx context.Context, w io.Writer, r io.Reader, limit int64) (int64, string, error) {
	if err := ctx.Err(); err != nil {
		return 0, "", err
	}
	select {
	case readSlots <- struct{}{}:
	default:
		return 0, "", fmt.Errorf("%d earlier reads are still blocked", maxBlockedReads)
	}
	copyFn, timeout := copyBytes, mirrorReadTimeout
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type result struct {
		n   int64
		sum string
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-readSlots }()
		n, sum, err := copyFn(w, r, limit)
		done <- result{n, sum, err}
	}()
	beforeCopyWait()
	select {
	case res := <-done:
		return res.n, res.sum, res.err
	case <-rctx.Done():
	}
	// select picks at random when both are ready. A copy that has finished by
	// the deadline wins, even when ctx itself was canceled.
	select {
	case res := <-done:
		return res.n, res.sum, res.err
	default:
	}
	if err := ctx.Err(); err != nil {
		return 0, "", err
	}
	return 0, "", fmt.Errorf("read did not finish within %s: %w", timeout, rctx.Err())
}

// closeFile closes a read-only f; a close error cannot lose data.
func closeFile(f *os.File) {
	if err := f.Close(); err != nil {
		log.Printf("[upstream] closing %q: %v", f.Name(), err)
	}
}

// removeTemp closes then removes f (Windows cannot remove open files). After
// a successful rename the remove finds nothing.
func removeTemp(f *os.File) {
	_ = f.Close()
	if err := os.Remove(f.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("[upstream] removing %q: %v", f.Name(), err)
	}
}

func (d downloader) get(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	return resp, nil
}

func (d downloader) fetch(ctx context.Context, u string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, smallTimeout)
	defer cancel()
	resp, err := d.get(ctx, u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, _, err := copyHashed(&buf, resp.Body, limit); err != nil {
		return nil, fmt.Errorf("GET %s: %w", u, err)
	}
	return buf.Bytes(), nil
}
