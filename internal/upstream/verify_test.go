package upstream

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const testVersion = "6.40.0"

var testOSArch = runtime.GOOS + "_" + runtime.GOARCH

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// newKey generates a signing key at test time; no key material is committed.
func newKey(t *testing.T, cfg *packet.Config) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity("bobthecorp test", "", "release@bobthecorp.example", cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func armoredPublic(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	return buf.Bytes()
}

func fingerprint(e *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))
}

func detachSign(t *testing.T, e *openpgp.Entity, msg []byte, cfg *packet.Config) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := openpgp.DetachSign(&buf, e, bytes.NewReader(msg), cfg); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		fh := &zip.FileHeader{Name: name, Method: zip.Deflate}
		fh.SetMode(0o755)
		w, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// release is a signed fake releases.hashicorp.com tree plus matching pins.
type release struct {
	key    *openpgp.Entity
	bin    []byte
	pins   *Pins
	files  map[string][]byte // URL path -> body
	prefix string            // URL path prefix of the version dir
	path   string            // URL path of the release base
}

func newRelease(t *testing.T) *release { return newReleaseFor(t, mustSource(t, awsAddress)) }

func newReleaseFor(t *testing.T, src Source) *release {
	t.Helper()
	goos, goarch, _ := strings.Cut(testOSArch, "_")
	key := newKey(t, nil)
	bin := []byte("#!/bin/sh\necho bobthecorp fake upstream\n")
	binName := src.BinaryName(testVersion, goos, PinsProtocol)
	zipName := src.ZipName(testVersion, goos, goarch)
	z := makeZip(t, map[string]string{binName: string(bin), "LICENSE.txt": "MPL"})
	sums := []byte(hexSum(z) + "  " + zipName + "\n")
	path := strings.TrimPrefix(src.ReleasesURL(), releasesHost)
	prefix := path + "/" + testVersion + "/"
	sumsName := src.SumsName(testVersion)
	return &release{
		key: key,
		bin: bin,
		pins: &Pins{
			Format: PinsFormat, Upstream: src.String(), Version: testVersion, Protocol: PinsProtocol,
			SigningKeyFingerprint: fingerprint(key),
			SHA256SumsSHA256:      hexSum(sums),
			Platforms: map[string]PlatformPin{testOSArch: {
				Zip: zipName, ZipSHA256: hexSum(z), Binary: binName, BinarySHA256: hexSum(bin),
			}},
			src: src,
		},
		files: map[string][]byte{
			prefix + sumsName:          sums,
			prefix + sumsName + ".sig": detachSign(t, key, sums, nil),
			prefix + zipName:           z,
		},
		prefix: prefix,
		path:   path,
	}
}

func (r *release) serve(t *testing.T) (base string, client *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, ok := r.files[req.URL.Path]
		if !ok {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	client = srv.Client()
	client.CheckRedirect = checkRedirect
	return srv.URL + r.path, client
}

func (r *release) download(t *testing.T, cacheDir string) (string, error) {
	t.Helper()
	base, client := r.serve(t)
	d := downloader{base: base, client: client, key: armoredPublic(t, r.key), fingerprint: fingerprint(r.key)}
	return d.download(context.Background(), r.pins, testOSArch, cacheDir)
}

func writeBin(t *testing.T, path string, body []byte) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyFile(t *testing.T) {
	r := newRelease(t)
	dir := t.TempDir()

	good := writeBin(t, filepath.Join(dir, "good"), r.bin)
	if err := verifyFile(good, r.pins, testOSArch); err != nil {
		t.Fatalf("matching binary: %v", err)
	}

	bad := writeBin(t, filepath.Join(dir, "bad"), []byte("tampered"))
	err := verifyFile(bad, r.pins, testOSArch)
	var nv *NotVerifiedError
	if !errors.As(err, &nv) {
		t.Fatalf("mismatch: want *NotVerifiedError, got %v", err)
	}
	want := bad + ": sha256 " + hexSum([]byte("tampered")) + " does not match the pinned hashicorp/aws " + testVersion + " " + testOSArch + " checksum " + hexSum(r.bin) + "."
	if nv.Detail() != want || !strings.HasPrefix(nv.Error(), "Upstream provider not verified: ") {
		t.Fatalf("detail = %q", nv.Detail())
	}

	if err := verifyFile(dir, r.pins, testOSArch); err == nil || errors.As(err, &nv) {
		t.Fatalf("directory: want non-regular error, got %v", err)
	}
	if err := verifyFile(filepath.Join(dir, "missing"), r.pins, testOSArch); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: want ErrNotExist, got %v", err)
	}
	if err := verifyFile(good, r.pins, "plan9_mips"); err == nil {
		t.Fatal("unpinned os_arch must fail")
	}
}

func TestVerifiedBinaryZeroValueRefused(t *testing.T) {
	if _, err := Launch(context.Background(), VerifiedBinary{}, nil); err == nil {
		t.Fatal("Launch of a zero VerifiedBinary must fail")
	}
}

func TestDownloadHappyPath(t *testing.T) {
	r := newRelease(t)
	cache := filepath.Join(t.TempDir(), "cache")
	path, err := r.download(t, cache)
	if err != nil {
		t.Fatal(err)
	}
	if path != cachePath(cache, hexSum(r.bin)) {
		t.Fatalf("path = %s, want content-addressed name", path)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, r.bin) {
		t.Fatal("cached bytes differ")
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o700 {
			t.Fatalf("mode %v, want 0700", st.Mode().Perm())
		}
		if st, _ := os.Stat(cache); st.Mode().Perm() != 0o700 {
			t.Fatalf("cache dir mode %v, want 0700", st.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(cache)
	if len(entries) != 1 {
		t.Fatalf("cache holds %d entries, want only the binary (temps removed)", len(entries))
	}
}

func TestDownloadFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, r *release)
		want   string
	}{
		{"unsigned sums", func(_ *testing.T, r *release) {
			delete(r.files, r.prefix+"terraform-provider-aws_"+testVersion+"_SHA256SUMS.sig")
		}, "status 404"},
		{"bad signature", func(t *testing.T, r *release) {
			r.files[r.prefix+"terraform-provider-aws_"+testVersion+"_SHA256SUMS.sig"] = detachSign(t, r.key, []byte("other"), nil)
		}, "signature"},
		{"wrong key", func(t *testing.T, r *release) {
			sums := r.files[r.prefix+"terraform-provider-aws_"+testVersion+"_SHA256SUMS"]
			r.files[r.prefix+"terraform-provider-aws_"+testVersion+"_SHA256SUMS.sig"] = detachSign(t, newKey(t, nil), sums, nil)
		}, "signature"},
		{"sums mismatch", func(_ *testing.T, r *release) {
			r.pins.SHA256SumsSHA256 = hexSum([]byte("x"))
		}, "SHA256SUMS sha256"},
		{"zip mismatch", func(_ *testing.T, r *release) {
			pin := r.pins.Platforms[testOSArch]
			pin.ZipSHA256 = hexSum([]byte("x"))
			r.pins.Platforms[testOSArch] = pin
		}, "zip sha256"},
		{"binary mismatch", func(_ *testing.T, r *release) {
			pin := r.pins.Platforms[testOSArch]
			pin.BinarySHA256 = hexSum([]byte("x"))
			r.pins.Platforms[testOSArch] = pin
		}, "does not match the pinned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelease(t)
			tc.mutate(t, r)
			cache := filepath.Join(t.TempDir(), "cache")
			_, err := r.download(t, cache)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
			entries, _ := os.ReadDir(cache)
			if len(entries) != 0 {
				t.Fatalf("cache holds %d entries after failure", len(entries))
			}
		})
	}
}

func TestDownloadRejectsKeyWithOtherFingerprint(t *testing.T) {
	r := newRelease(t)
	base, client := r.serve(t)
	d := downloader{base: base, client: client, key: armoredPublic(t, r.key), fingerprint: HashiCorpFingerprint}
	if _, err := d.download(context.Background(), r.pins, testOSArch, t.TempDir()); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("err = %v", err)
	}
	d.key = nil // key file not embedded yet
	if _, err := d.download(context.Background(), r.pins, testOSArch, t.TempDir()); err == nil {
		t.Fatal("missing key must fail closed")
	}
}

func TestSignatureExpiryPolicy(t *testing.T) {
	past := time.Now().Add(-48 * time.Hour)
	cfg := &packet.Config{Time: func() time.Time { return past }, KeyLifetimeSecs: 3600}
	key := newKey(t, cfg)
	sums := []byte("sums\n")
	sig := detachSign(t, key, sums, cfg)

	if err := VerifySumsSignature(key, sums, sig, time.Now(), false); err == nil {
		t.Fatal("wall-clock check must reject a key that has since expired")
	}
	if err := VerifySumsSignature(key, sums, sig, time.Now(), true); err != nil {
		t.Fatalf("signing-time check must accept a key valid when it signed: %v", err)
	}

	future := time.Now().Add(time.Hour)
	fcfg := &packet.Config{Time: func() time.Time { return future }}
	fkey := newKey(t, fcfg)
	if err := VerifySumsSignature(fkey, sums, detachSign(t, fkey, sums, fcfg), time.Now(), true); err == nil {
		t.Fatal("signature from the future must fail")
	}
}

func TestPublishRenameFailure(t *testing.T) {
	r := newRelease(t)
	dir := t.TempDir()
	final := cachePath(dir, hexSum(r.bin))
	missingTmp := filepath.Join(dir, "gone") // rename of a missing temp always fails

	writeBin(t, final, r.bin)
	if err := publish(missingTmp, final, r.pins, testOSArch); err != nil {
		t.Fatalf("matching destination must be kept: %v", err)
	}

	writeBin(t, final, []byte("tampered"))
	if err := publish(missingTmp, final, r.pins, testOSArch); err == nil {
		t.Fatal("mismatched destination must not be accepted")
	}
	if _, err := os.Stat(final); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("mismatched destination must be removed, stat err = %v", err)
	}
}

func TestCheckRedirect(t *testing.T) {
	mk := func(raw string) *http.Request {
		req, _ := http.NewRequest(http.MethodGet, raw, http.NoBody)
		return req
	}
	via := []*http.Request{mk("https://releases.hashicorp.com/a")}
	if err := checkRedirect(mk("https://releases.hashicorp.com/b"), via); err != nil {
		t.Fatalf("same host: %v", err)
	}
	for _, bad := range []string{"http://releases.hashicorp.com/b", "https://evil.example/b", "https://releases.hashicorp.com:8443/b", "https://u:p@releases.hashicorp.com/b"} {
		if err := checkRedirect(mk(bad), via); err == nil {
			t.Errorf("%s: redirect allowed", bad)
		}
	}
}

// TestSignatureRebound: hashicorp/aws 6.0.0 to 6.33.0 were signed before
// HashiCorp's current binding of its signing subkey, so they verify now but
// not at their own creation time. The runtime check accepts either; the pin
// check (now) accepts them too.
func TestSignatureRebound(t *testing.T) {
	keyFile, err := os.ReadFile("../../keys/hashicorp-security.asc")
	if err != nil {
		t.Skip("HashiCorp key not committed")
	}
	key, err := LoadKey(keyFile, HashiCorpFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	sums, err := os.ReadFile("testdata/sums/terraform-provider-aws_6.0.0_SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile("testdata/sums/terraform-provider-aws_6.0.0_SHA256SUMS.sig")
	if err != nil {
		t.Fatal(err)
	}
	for _, atSigning := range []bool{false, true} {
		if err := VerifySumsSignature(key, sums, sig, time.Now(), atSigning); err != nil {
			t.Errorf("atSigning=%v: %v", atSigning, err)
		}
	}
	if err := VerifySumsSignature(key, append([]byte("x"), sums...), sig, time.Now(), true); err == nil {
		t.Error("altered sums must fail")
	}
}
