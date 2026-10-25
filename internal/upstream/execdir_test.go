package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// realTempDir is t.TempDir with symlinks resolved (macOS /var -> /private/var).
func realTempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestExecDirRecordsVerifiedSHA: two verified binaries copied from one path
// carry their own sha256, the key the proxy caches the upstream schema on.
func TestExecDirRecordsVerifiedSHA(t *testing.T) {
	src := filepath.Join(realTempDir(t), "aws")
	var shas []string
	for _, body := range [][]byte{[]byte("release one"), []byte("release two")} {
		writeBin(t, src, body)
		d := mustExecDir(t, []string{realTempDir(t)}, nil)
		vb, err := d.copy(context.Background(), src, testPins(body), testOSArch)
		if err != nil {
			t.Fatal(err)
		}
		if vb.SHA256() != hexSum(body) {
			t.Fatalf("SHA256() = %q, want %q", vb.SHA256(), hexSum(body))
		}
		shas = append(shas, vb.SHA256())
	}
	if shas[0] == shas[1] {
		t.Fatalf("binaries at one path share sha %q", shas[0])
	}
}

func testPins(body []byte) *Pins {
	return &Pins{Version: testVersion, Protocol: 5, Platforms: map[string]PlatformPin{
		testOSArch: {Binary: "terraform-provider-aws_v" + testVersion + "_x5", BinarySHA256: hexSum(body)},
	}}
}

func mustExecDir(t *testing.T, candidates, forbidden []string) *execDir {
	t.Helper()
	d, err := newExecDir(candidates, forbidden)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.remove)
	return d
}

func wantUnsafe(t *testing.T, err error, check string) {
	t.Helper()
	var u *ExecDirUnsafeError
	if !errors.As(err, &u) {
		t.Fatalf("want *ExecDirUnsafeError, got %v", err)
	}
	if !strings.Contains(err.Error(), check) || !strings.HasPrefix(err.Error(), "Upstream exec directory unsafe: No private directory for the upstream copy: ") ||
		!strings.HasSuffix(err.Error(), ". Set XDG_RUNTIME_DIR or fix the permissions.") {
		t.Fatalf("message %q does not name %q", err, check)
	}
}

func TestExecDirNeverUnderPluginCache(t *testing.T) {
	base := realTempDir(t)
	cache := filepath.Join(base, "plugin-cache")
	other := filepath.Join(base, "private")
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	// A symlinked spelling of the cache is the same directory.
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(cache, alias); err != nil {
		t.Fatal(err)
	}
	d := mustExecDir(t, []string{filepath.Join(cache, "compliancetf"), other}, []string{alias})
	if filepath.Dir(d.dir) != other {
		t.Fatalf("exec dir %q, want a child of %q", d.dir, other)
	}
	_, err := newExecDir([]string{filepath.Join(cache, "x")}, []string{cache})
	wantUnsafe(t, err, "Terraform")
	// Component-bounded: a sibling sharing a name prefix is not "under".
	mustExecDir(t, []string{cache + "-not"}, []string{cache})
}

func TestExecDirRefusesSymlinkedParent(t *testing.T) {
	base := realTempDir(t)
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	_, err := newExecDir([]string{filepath.Join(link, "exec")}, nil)
	wantUnsafe(t, err, "symlink")
}

func TestExecDirRefusesGroupWritableParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mode bits on windows")
	}
	base := realTempDir(t)
	if err := os.Chmod(base, 0o770); err != nil {
		t.Fatal(err)
	}
	_, err := newExecDir([]string{filepath.Join(base, "exec")}, nil)
	wantUnsafe(t, err, "writable")
}

func TestExecDirRefusesExistingDestination(t *testing.T) {
	body := []byte("pinned bytes")
	p := testPins(body)
	src := writeBin(t, filepath.Join(realTempDir(t), "aws"), body)
	d := mustExecDir(t, []string{realTempDir(t)}, nil)
	planted := writeBin(t, filepath.Join(d.dir, p.Platforms[testOSArch].Binary), []byte("planted"))
	if _, err := d.copy(context.Background(), src, p, testOSArch); err == nil {
		t.Fatal("copy over an existing destination must fail")
	}
	if b, _ := os.ReadFile(planted); string(b) != "planted" {
		t.Fatalf("existing destination was modified: %q", b)
	}
}

func TestExecDirHashesCopiedBytes(t *testing.T) {
	body := []byte("pinned bytes")
	p := testPins(body)
	src := writeBin(t, filepath.Join(realTempDir(t), "aws"), body)
	d := mustExecDir(t, []string{realTempDir(t)}, nil)
	vb, err := d.copy(context.Background(), src, p, testOSArch)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(vb.Path()) != d.dir || vb.execDir != d.dir {
		t.Fatalf("VerifiedBinary %q is not the copy in %q", vb.Path(), d.dir)
	}
	if b, _ := os.ReadFile(vb.Path()); string(b) != string(body) {
		t.Fatalf("copy holds %q", b)
	}
	if err := os.Remove(vb.Path()); err != nil {
		t.Fatal(err)
	}

	writeBin(t, src, []byte("tampered"))
	_, err = d.copy(context.Background(), src, p, testOSArch)
	var nv *NotVerifiedError
	if !errors.As(err, &nv) || nv.Path != src || nv.Got != hexSum([]byte("tampered")) {
		t.Fatalf("want *NotVerifiedError for %q, got %v", src, err)
	}
	if _, err := os.Lstat(filepath.Join(d.dir, p.Platforms[testOSArch].Binary)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched copy not removed: %v", err)
	}
}

func TestExecDirRejectsUnsafeBinaryName(t *testing.T) {
	body := []byte("x")
	p := testPins(body)
	pin := p.Platforms[testOSArch]
	pin.Binary = filepath.Join("..", "escape")
	p.Platforms[testOSArch] = pin
	src := writeBin(t, filepath.Join(realTempDir(t), "aws"), body)
	d := mustExecDir(t, []string{realTempDir(t)}, nil)
	if _, err := d.copy(context.Background(), src, p, testOSArch); err == nil {
		t.Fatal("binary name with a separator must be refused")
	}
}

func TestExecDirSourceSwapAfterCopy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script")
	}
	good := []byte("#!/bin/sh\necho ok\n")
	p := testPins(good)
	src := writeBin(t, filepath.Join(realTempDir(t), "aws"), good)
	d := mustExecDir(t, []string{realTempDir(t)}, nil)
	vb, err := d.copy(context.Background(), src, p, testOSArch)
	if err != nil {
		t.Fatal(err)
	}
	writeBin(t, src, []byte("#!/bin/sh\necho evil\n"))
	out, err := exec.Command(vb.Path()).Output() //nolint:gosec // test binary
	if err != nil || string(out) != "ok\n" {
		t.Fatalf("ran %q, %v", out, err)
	}
}

func TestExecDirRemovesOwnChildOnExit(t *testing.T) {
	parent := realTempDir(t)
	d := mustExecDir(t, []string{parent}, nil)
	if _, err := os.Stat(d.dir); err != nil {
		t.Fatal(err)
	}
	(&Upstream{execDir: d.dir}).removeExecDir()
	if _, err := os.Stat(d.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("own child still present: %v", err)
	}
	if _, err := os.Stat(parent); err != nil {
		t.Fatalf("parent removed: %v", err)
	}
}

func TestExecDirSweepsDeadChildrenAtStart(t *testing.T) {
	parent := realTempDir(t)
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	dead := cmd.Process.Pid
	tag := hostTag()
	mk := func(name string) string {
		p := filepath.Join(parent, name)
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stale := mk(fmt.Sprintf("%s.%d-1", tag, dead))
	live := mk(fmt.Sprintf("%s.%d-2", tag, os.Getppid()))
	otherHost := mk(fmt.Sprintf("%s.%d-3", "0badf00d", dead))
	foreign := mk("not-ours")
	target := mk("target")
	link := filepath.Join(parent, fmt.Sprintf("%s.%d-4", tag, dead))
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	d := mustExecDir(t, []string{parent}, nil)
	if !childRe.MatchString(filepath.Base(d.dir)) || !strings.HasPrefix(filepath.Base(d.dir), fmt.Sprintf("%s.%d-", tag, os.Getpid())) {
		t.Fatalf("own child name %q does not carry the owner record", filepath.Base(d.dir))
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dead-PID child kept: %v", err)
	}
	for _, keep := range []string{live, otherHost, foreign, target, link} {
		if _, err := os.Lstat(keep); err != nil {
			t.Fatalf("%q removed: %v", keep, err)
		}
	}
}

// A hung read of an unpacked candidate fails closed: an error, and no copy is
// left in the exec dir.
func TestExecDirCopyHungReadTimesOut(t *testing.T) {
	body := []byte("pinned bytes")
	src := writeBin(t, filepath.Join(realTempDir(t), "aws"), body)
	d := mustExecDir(t, []string{realTempDir(t)}, nil)
	hangCopies(t, func(io.Writer) bool { return true })
	_, err := d.copy(context.Background(), src, testPins(body), testOSArch)
	if err == nil || !strings.Contains(err.Error(), "did not finish within") {
		t.Fatalf("err = %v, want a read timeout", err)
	}
	if entries, _ := os.ReadDir(d.dir); len(entries) != 0 {
		t.Fatalf("exec dir holds %d entries after a timeout", len(entries))
	}
}
