package upstream

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// packedPath is where a packed filesystem mirror holds the pinned release zip.
func packedPath(dir string, r *release) string {
	return filepath.Join(dir, "registry.terraform.io", "hashicorp", "aws", r.pins.Platforms[testOSArch].Zip)
}

func releaseZip(r *release) []byte { return r.files[r.prefix+r.pins.Platforms[testOSArch].Zip] }

// pinZip makes z the pinned zip, as if the signed sums named it: the zip
// checks below must hold even for a zip whose hash matches.
func pinZip(r *release, z []byte) {
	pin := r.pins.Platforms[testOSArch]
	pin.ZipSHA256 = hexSum(z)
	r.pins.Platforms[testOSArch] = pin
}

func TestDiscoverPackedMirror(t *testing.T) {
	r := newRelease(t)
	s := newSource(t, r, nil)
	mirror := t.TempDir()
	writeBin(t, packedPath(mirror, r), releaseZip(r))
	s.dirs = []string{t.TempDir(), mirror}
	s.cacheDir = filepath.Join(t.TempDir(), "cache")

	vb, err := s.find(context.Background())
	wantCopy(t, s, vb, err, r.bin)
	entries, _ := os.ReadDir(s.cacheDir)
	if len(entries) != 1 || entries[0].Name() != filepath.Base(cachePath(s.cacheDir, hexSum(r.bin))) {
		t.Fatalf("cache holds %v, want only the extracted binary", entries)
	}
}

func TestDiscoverUnpackedBeforePacked(t *testing.T) {
	r := newRelease(t)
	s := newSource(t, r, nil)
	packed, unpacked := t.TempDir(), t.TempDir()
	writeBin(t, packedPath(packed, r), []byte("not a zip"))
	writeBin(t, registryPath(unpacked, r), r.bin)
	s.dirs = []string{packed, unpacked}
	s.cacheDir = filepath.Join(t.TempDir(), "cache")

	vb, err := s.find(context.Background())
	wantCopy(t, s, vb, err, r.bin)
	if _, err := os.Stat(s.cacheDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("packed zip was opened although an unpacked binary matched: %v", err)
	}
}

func TestDiscoverPackedMismatchFallsThrough(t *testing.T) {
	r := newRelease(t)
	calls := 0
	s := newSource(t, r, func(_ context.Context, dir string) (string, error) {
		calls++
		return writeBin(t, cachePath(dir, hexSum(r.bin)), r.bin), nil
	})
	mirror := t.TempDir()
	// Holds the pinned binary, but the zip itself is not the signed one.
	writeBin(t, packedPath(mirror, r), makeZip(t, map[string]string{r.pins.Platforms[testOSArch].Binary: string(r.bin)}))
	s.dirs = []string{mirror}
	s.cacheDir = filepath.Join(t.TempDir(), "cache")

	vb, err := s.find(context.Background())
	wantCopy(t, s, vb, err, r.bin)
	if calls != 1 {
		t.Fatalf("download calls = %d, want 1", calls)
	}
}

func TestDiscoverPackedNeedsPrivateCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mode bits on Windows")
	}
	r := newRelease(t)
	s := newSource(t, r, func(context.Context, string) (string, error) {
		return "", errors.New("offline")
	})
	mirror := t.TempDir()
	writeBin(t, packedPath(mirror, r), releaseZip(r))
	s.dirs = []string{mirror}
	s.cacheDir = filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(s.cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.cacheDir, 0o777); err != nil {
		t.Fatal(err)
	}

	if _, err := s.find(context.Background()); err == nil {
		t.Fatal("extracted into a world-writable cache")
	}
	if entries, _ := os.ReadDir(s.cacheDir); len(entries) != 0 {
		t.Fatalf("cache holds %d entries", len(entries))
	}
}

func TestUnpackZipRejects(t *testing.T) {
	binName := func(r *release) string { return r.pins.Platforms[testOSArch].Binary }
	symlinkZip := func(t *testing.T, r *release) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		fh := &zip.FileHeader{Name: binName(r)}
		fh.SetMode(os.ModeSymlink | 0o777)
		w, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte("/bin/sh"))
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	// bombZip declares more than MaxBinaryBytes uncompressed.
	bombZip := func(t *testing.T, r *release) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		fh := &zip.FileHeader{Name: binName(r), Method: zip.Store, UncompressedSize64: uint64(MaxBinaryBytes) + 1, CompressedSize64: 1}
		fh.SetMode(0o755)
		w, err := zw.CreateRaw(fh)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte("x"))
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	for _, tc := range []struct {
		name string
		zip  func(t *testing.T, r *release) []byte
		want string
	}{
		{"traversal", func(t *testing.T, r *release) []byte {
			return makeZip(t, map[string]string{"../" + binName(r): "x", binName(r): string(r.bin)})
		}, "zip entry name"},
		{"absolute", func(t *testing.T, r *release) []byte {
			return makeZip(t, map[string]string{"/tmp/" + binName(r): "x", binName(r): string(r.bin)})
		}, "zip entry name"},
		{"symlink", symlinkZip, "not a regular file"},
		{"oversized", bombZip, "larger than"},
		{"not a zip", func(*testing.T, *release) []byte { return []byte("plain") }, "zip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelease(t)
			z := tc.zip(t, r)
			pinZip(r, z)
			mirror := t.TempDir()
			src := writeBin(t, packedPath(mirror, r), z)
			cache := filepath.Join(t.TempDir(), "cache")
			_, err := unpackZip(context.Background(), src, r.pins, testOSArch, cache)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
			if entries, _ := os.ReadDir(cache); len(entries) != 0 {
				t.Fatalf("cache holds %d entries after failure", len(entries))
			}
			if entries, _ := os.ReadDir(filepath.Dir(src)); len(entries) != 1 {
				t.Fatalf("mirror dir holds %d entries, want only the zip", len(entries))
			}
		})
	}
}

func TestUnpackZipRejectsNonRegularSource(t *testing.T) {
	r := newRelease(t)
	cache := filepath.Join(t.TempDir(), "cache")
	dir := filepath.Join(t.TempDir(), "zipdir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := unpackZip(context.Background(), dir, r.pins, testOSArch, cache); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory: err = %v", err)
	}
}

// A packed zip larger than MaxZipBytes is rejected from its size alone: no
// byte is read and no cache entry is made.
func TestUnpackZipRejectsOversizedUnread(t *testing.T) {
	r := newRelease(t)
	src := writeBin(t, packedPath(t.TempDir(), r), nil)
	if err := os.Truncate(src, MaxZipBytes+1); err != nil { // sparse
		t.Fatal(err)
	}
	defer func(f func(io.Writer, io.Reader, int64) (int64, string, error)) { copyBytes = f }(copyBytes)
	copyBytes = func(io.Writer, io.Reader, int64) (int64, string, error) {
		t.Error("oversized zip was read")
		return 0, "", errors.New("read")
	}
	cache := filepath.Join(t.TempDir(), "cache")
	_, err := unpackZip(context.Background(), src, r.pins, testOSArch, cache)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v, want larger than", err)
	}
	if _, err := os.Stat(cache); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache created for a rejected zip: %v", err)
	}
}

// hangCopies makes copyBytes block, for writes accepted by hang, until the
// test ends, and lowers mirrorReadTimeout.
func hangCopies(t *testing.T, hang func(w io.Writer) bool) {
	release := make(chan struct{})
	oldCopy, oldTimeout := copyBytes, mirrorReadTimeout
	copyBytes = func(w io.Writer, r io.Reader, n int64) (int64, string, error) {
		if hang(w) {
			<-release
			return 0, "", errors.New("released")
		}
		return copyHashed(w, r, n)
	}
	mirrorReadTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		close(release)
		copyBytes, mirrorReadTimeout = oldCopy, oldTimeout
		waitReadSlots(t)
	})
}

// waitReadSlots waits for released reads to give back their slots, so the
// next test starts with every slot free.
func waitReadSlots(t *testing.T) {
	for deadline := time.Now().Add(10 * time.Second); len(readSlots) > 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d reads still hold a slot", len(readSlots))
		}
	}
}

// A hung read of a packed mirror zip fails that probe and discovery falls
// through to the download.
func TestDiscoverPackedHungReadFallsThrough(t *testing.T) {
	r := newRelease(t)
	calls := 0
	s := newSource(t, r, func(_ context.Context, dir string) (string, error) {
		calls++
		return writeBin(t, cachePath(dir, hexSum(r.bin)), r.bin), nil
	})
	mirror := t.TempDir()
	writeBin(t, packedPath(mirror, r), releaseZip(r))
	s.dirs = []string{mirror}
	s.cacheDir = filepath.Join(t.TempDir(), "cache")
	hangCopies(t, func(w io.Writer) bool {
		f, ok := w.(*os.File)
		return ok && strings.HasPrefix(filepath.Base(f.Name()), ".download-")
	})

	vb, err := s.find(context.Background())
	wantCopy(t, s, vb, err, r.bin)
	if calls != 1 {
		t.Fatalf("download calls = %d, want 1", calls)
	}
	entries, _ := os.ReadDir(s.cacheDir)
	if len(entries) != 1 {
		t.Fatalf("cache holds %v, want only the downloaded binary", entries)
	}
}

func TestUnpackZipHungReadTimesOut(t *testing.T) {
	r := newRelease(t)
	src := writeBin(t, packedPath(t.TempDir(), r), releaseZip(r))
	hangCopies(t, func(io.Writer) bool { return true })
	cache := filepath.Join(t.TempDir(), "cache")
	_, err := unpackZip(context.Background(), src, r.pins, testOSArch, cache)
	if err == nil || !strings.Contains(err.Error(), "did not finish within") {
		t.Fatalf("err = %v, want a read timeout", err)
	}
	if entries, _ := os.ReadDir(cache); len(entries) != 0 {
		t.Fatalf("cache holds %d entries after a timeout", len(entries))
	}
}

// blockingReader blocks every Read until unblock is closed.
type blockingReader struct{ unblock chan struct{} }

func (b blockingReader) Read([]byte) (int, error) {
	<-b.unblock
	return 0, io.EOF
}

func TestCopyWithinBlockingReader(t *testing.T) {
	r := blockingReader{make(chan struct{})}
	defer waitReadSlots(t)
	defer close(r.unblock)
	old := mirrorReadTimeout
	mirrorReadTimeout = 50 * time.Millisecond
	defer func() { mirrorReadTimeout = old }()

	if _, _, err := copyWithin(context.Background(), io.Discard, r, 10); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mirrorReadTimeout = time.Hour
	if _, _, err := copyWithin(ctx, io.Discard, r, 10); !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "within") {
		t.Fatalf("canceled: err = %v", err)
	}
}

// A canceled ctx stops discovery with ctx.Err(): no timeout message, no
// further candidate and no download.
func TestDiscoverCancelledStopsProbes(t *testing.T) {
	r := newRelease(t)
	s := newSource(t, r, nil)
	a, b := t.TempDir(), t.TempDir()
	writeBin(t, registryPath(a, r), r.bin)
	writeBin(t, registryPath(b, r), r.bin)
	s.dirs = []string{a, b}
	s.cacheDir = filepath.Join(t.TempDir(), "cache")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var reads atomic.Int32
	hangCopies(t, func(io.Writer) bool {
		reads.Add(1)
		cancel()
		return true
	})
	mirrorReadTimeout = time.Hour

	_, err := s.find(ctx)
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "within") {
		t.Fatalf("err = %v, want bare context.Canceled", err)
	}
	if n := reads.Load(); n != 1 {
		t.Fatalf("reads = %d, want 1: probes continued after cancel", n)
	}
}

// A copy that finishes as the deadline fires is kept, even when ctx was
// canceled. beforeCopyWait waits until the result is queued (the read gives
// back its slot after sending it) and then cancels, so both select cases are
// ready and select picks either; 50 runs miss the discard with odds 2^-50.
func TestCopyWithinKeepsCopyDoneAtDeadline(t *testing.T) {
	defer waitReadSlots(t)
	oldCopy, oldTimeout, oldWait := copyBytes, mirrorReadTimeout, beforeCopyWait
	defer func() { copyBytes, mirrorReadTimeout, beforeCopyWait = oldCopy, oldTimeout, oldWait }()
	copyBytes, mirrorReadTimeout = copyHashed, time.Hour
	for i := range 50 {
		ctx, cancel := context.WithCancel(context.Background())
		beforeCopyWait = func() {
			for len(readSlots) > 0 {
				time.Sleep(time.Millisecond)
			}
			cancel()
		}
		if _, sum, err := copyWithin(ctx, io.Discard, strings.NewReader("x"), 10); err != nil || sum == "" {
			t.Fatalf("run %d: finished copy discarded: %v", i, err)
		}
	}
}

// A ctx canceled before the call returns ctx.Err() without taking a slot or
// starting a read, also when every slot is held.
func TestCopyWithinCanceledTakesNoSlot(t *testing.T) {
	var started atomic.Int32
	hangCopies(t, func(io.Writer) bool {
		started.Add(1)
		return true
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := copyWithin(ctx, io.Discard, strings.NewReader("x"), 10); err != context.Canceled {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if n := len(readSlots); n != 0 {
		t.Fatalf("%d slots held after a canceled call", n)
	}
	for range maxBlockedReads {
		if _, _, err := copyWithin(context.Background(), io.Discard, strings.NewReader("x"), 10); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want a timeout", err)
		}
	}
	if _, _, err := copyWithin(ctx, io.Discard, strings.NewReader("x"), 10); err != context.Canceled {
		t.Fatalf("slots full: err = %v, want context.Canceled", err)
	}
	if n := started.Load(); n != maxBlockedReads {
		t.Fatalf("started %d reads, want %d", n, maxBlockedReads)
	}
}

// Abandoned reads are bounded: with every slot held by a hung read, the next
// read fails at once without starting another goroutine.
func TestCopyWithinBoundsBlockedReads(t *testing.T) {
	var started atomic.Int32
	hangCopies(t, func(io.Writer) bool {
		started.Add(1)
		return true
	})
	for range maxBlockedReads {
		if _, _, err := copyWithin(context.Background(), io.Discard, strings.NewReader("x"), 10); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want a timeout", err)
		}
	}
	_, _, err := copyWithin(context.Background(), io.Discard, strings.NewReader("x"), 10)
	if err == nil || !strings.Contains(err.Error(), "still blocked") {
		t.Fatalf("err = %v, want still blocked", err)
	}
	if n := started.Load(); n != maxBlockedReads {
		t.Fatalf("started %d reads, want %d", n, maxBlockedReads)
	}
}
