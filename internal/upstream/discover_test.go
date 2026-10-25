package upstream

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// embeddedAnchors is the HashiCorp release key the aws wrapper main.go embeds
// (repo root keys/) as the one trust anchor, or nil when it is not committed.
func embeddedAnchors() [][]byte {
	key, err := os.ReadFile("../../keys/hashicorp-security.asc")
	if err != nil {
		return nil
	}
	return [][]byte{key}
}

// registryPath is where a probed directory must hold the pinned binary.
func registryPath(dir string, r *release) string {
	return filepath.Join(dir, "registry.terraform.io", "hashicorp", "aws", testVersion, testOSArch, r.pins.Platforms[testOSArch].Binary)
}

func newSource(t *testing.T, r *release, download func(context.Context, string) (string, error)) *source {
	if download == nil {
		download = func(context.Context, string) (string, error) {
			return "", errors.New("download not expected")
		}
	}
	return &source{pins: r.pins, osArch: testOSArch, download: download, exec: &execDir{dir: t.TempDir()}}
}

// wantCopy requires vb to be a copy of body inside the source's exec dir.
func wantCopy(t *testing.T, s *source, vb VerifiedBinary, err error, body []byte) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(vb.Path()) != s.exec.dir {
		t.Fatalf("%q is not in the exec dir %q", vb.Path(), s.exec.dir)
	}
	if b, rerr := os.ReadFile(vb.Path()); rerr != nil || !bytes.Equal(b, body) {
		t.Fatalf("copy content mismatch: %v", rerr)
	}
}

func TestDiscoverExplicitPathMismatchIsFatal(t *testing.T) {
	r := newRelease(t)
	s := newSource(t, r, func(context.Context, string) (string, error) {
		t.Fatal("explicit path mismatch must not fall back to download")
		return "", nil
	})
	s.explicit = writeBin(t, filepath.Join(t.TempDir(), "aws"), []byte("tampered"))
	// A matching binary elsewhere must not rescue a bad explicit path.
	probe := t.TempDir()
	writeBin(t, registryPath(probe, r), r.bin)
	s.dirs = []string{probe}

	_, err := s.find(context.Background())
	var nv *NotVerifiedError
	if !errors.As(err, &nv) {
		t.Fatalf("want *NotVerifiedError, got %v", err)
	}
}

func TestDiscoverExplicitPathMissingIsFatal(t *testing.T) {
	r := newRelease(t)
	s := newSource(t, r, nil)
	s.explicit = filepath.Join(t.TempDir(), "absent")
	_, err := s.find(context.Background())
	var nf *NotFoundError
	if !errors.As(err, &nf) || !strings.Contains(err.Error(), UpstreamPathEnv) {
		t.Fatalf("want *NotFoundError naming %s, got %v", UpstreamPathEnv, err)
	}
}

func TestDiscoverExplicitPathMatch(t *testing.T) {
	r := newRelease(t)
	s := newSource(t, r, nil)
	s.explicit = writeBin(t, filepath.Join(t.TempDir(), "aws"), r.bin)
	vb, err := s.find(context.Background())
	wantCopy(t, s, vb, err, r.bin)
}

func TestDiscoverSkipsMismatchedCandidates(t *testing.T) {
	r := newRelease(t)
	s := newSource(t, r, nil)
	empty, bad, good := t.TempDir(), t.TempDir(), t.TempDir()
	writeBin(t, registryPath(bad, r), []byte("tampered"))
	writeBin(t, registryPath(good, r), r.bin)
	// A binary for another version is never considered (no semver scan).
	writeBin(t, filepath.Join(empty, "registry.terraform.io", "hashicorp", "aws", "9.9.9", testOSArch, r.pins.Platforms[testOSArch].Binary), r.bin)
	s.dirs = []string{empty, bad, good}

	vb, err := s.find(context.Background())
	wantCopy(t, s, vb, err, r.bin)
}

func TestDiscoverOwnCacheThenDownload(t *testing.T) {
	r := newRelease(t)
	cache := t.TempDir()
	writeBin(t, cachePath(cache, hexSum(r.bin)), r.bin)
	s := newSource(t, r, nil)
	s.cacheDir = cache
	vb, err := s.find(context.Background())
	wantCopy(t, s, vb, err, r.bin)

	calls := 0
	s = newSource(t, r, func(_ context.Context, dir string) (string, error) {
		calls++
		return writeBin(t, cachePath(dir, hexSum(r.bin)), r.bin), nil
	})
	s.cacheDir = t.TempDir()
	if _, err := s.find(context.Background()); err != nil || calls != 1 {
		t.Fatalf("download: calls=%d err=%v", calls, err)
	}
}

func TestDiscoverUnsignedSumsFails(t *testing.T) {
	r := newRelease(t)
	delete(r.files, r.prefix+"terraform-provider-aws_"+testVersion+"_SHA256SUMS.sig")
	base, client := r.serve(t)
	d := downloader{base: base, client: client, key: armoredPublic(t, r.key), fingerprint: fingerprint(r.key)}
	s := newSource(t, r, func(ctx context.Context, dir string) (string, error) {
		return d.download(ctx, r.pins, testOSArch, dir)
	})
	s.cacheDir = t.TempDir()

	_, err := s.find(context.Background())
	var nf *NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("want *NotFoundError, got %v", err)
	}
	want := "Upstream provider not found: No verified hashicorp/aws " + testVersion + " binary for " + testOSArch + "; download failed: "
	if !strings.HasPrefix(err.Error(), want) || !strings.HasSuffix(err.Error(), ". Set COMPLIANCETF_UPSTREAM_PATH for air-gapped installs.") {
		t.Fatalf("message = %q", err)
	}
}

func TestDiscoverFailsClosedWithPlaceholderPins(t *testing.T) {
	pins := rootPins(t)
	if _, err := ParsePins(pins, mustSource(t, awsAddress), HashiCorpFingerprint); err == nil {
		t.Skip("pins.json is populated")
	}
	t.Setenv(UpstreamPathEnv, "")
	t.Setenv("CTFTEST_UPSTREAM_PATH", "") // a ctftest build would launch it unpinned
	_, err := Discover(context.Background(), mustSource(t, awsAddress), pins, embeddedAnchors())
	var nf *NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("placeholder pins: want *NotFoundError, got %v", err)
	}
}

func TestImpliedMirrorDirsNotEmpty(t *testing.T) {
	if len(impliedMirrorDirs()) == 0 {
		t.Fatal("impliedMirrorDirs() returned empty slice")
	}
}

// TestDiscoverUsesConfigPins: Discover verifies against the pins it is given
// (wrapper Config.UpstreamPins), not the embedded aws pins.json.
func TestDiscoverUsesConfigPins(t *testing.T) {
	t.Setenv("CTFTEST_UPSTREAM_PATH", "") // a ctftest build would launch it unpinned
	az := mustSource(t, "registry.terraform.io/hashicorp/azurerm")
	body := []byte("bobthecorp azurerm upstream")
	osArch := runtime.GOOS + "_" + runtime.GOARCH
	p := pinsFor(t, az)
	p.Platforms = map[string]PlatformPin{osArch: {
		Zip: az.ZipName(p.Version, runtime.GOOS, runtime.GOARCH), ZipSHA256: strings.Repeat("a", 64),
		Binary: az.BinaryName(p.Version, runtime.GOOS, 5), BinarySHA256: hexSum(body),
	}}
	pins, err := MarshalPins(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(UpstreamPathEnv, writeBin(t, filepath.Join(t.TempDir(), "azurerm"), body))

	vb, err := Discover(context.Background(), az, pins, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeExecDir(vb.execDir) })
	if vb.SHA256() != hexSum(body) || vb.name != "hashicorp/azurerm" {
		t.Fatalf("VerifiedBinary sha %s name %q", vb.SHA256(), vb.name)
	}
	// The aws pins do not verify an azurerm upstream.
	_, err = Discover(context.Background(), az, rootPins(t), nil)
	var nf *NotFoundError
	if !errors.As(err, &nf) || nf.Upstream != "hashicorp/azurerm" {
		t.Fatalf("aws pins for azurerm: want *NotFoundError for hashicorp/azurerm, got %v", err)
	}
}

// TestDownloaderWantsOneAnchor: a download trusts exactly one configured anchor.
func TestDownloaderWantsOneAnchor(t *testing.T) {
	src := mustSource(t, awsAddress)
	for _, anchors := range [][][]byte{nil, {[]byte("a"), []byte("b")}} {
		if _, err := newDownloader(src, anchors); err == nil || !strings.Contains(err.Error(), "want exactly 1") {
			t.Errorf("%d anchors: err = %v", len(anchors), err)
		}
	}
	if len(embeddedAnchors()) != 1 {
		t.Skip("HashiCorp release key not committed")
	}
	if _, err := newDownloader(src, embeddedAnchors()); err != nil {
		t.Fatal(err)
	}
}

// rootPins is the pins.json the aws wrapper main.go embeds (repo root).
func rootPins(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../pins.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
