//go:build unix

package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// A cache dir another local user could swap or fill is not read at all: the
// cache source is unavailable with a warning, never a candidate.
func TestCacheDirUntrustedIsIgnored(t *testing.T) {
	good := cacheWith(t, map[string]string{"v7.dsse.json": "v7"})

	symOrg := t.TempDir() // profiles/bobthecorp is a symlink to a good dir
	if err := os.MkdirAll(filepath.Join(symOrg, "profiles"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(good, "profiles", "bobthecorp"), filepath.Join(symOrg, "profiles", "bobthecorp")); err != nil {
		t.Fatal(err)
	}
	symMid := t.TempDir() // profiles is a symlink
	if err := os.Symlink(filepath.Join(good, "profiles"), filepath.Join(symMid, "profiles")); err != nil {
		t.Fatal(err)
	}
	symRoot := filepath.Join(t.TempDir(), "cache") // the cache root itself is a symlink
	if err := os.Symlink(good, symRoot); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{"symlinked org dir": symOrg, "symlinked profiles dir": symMid, "symlinked cache root": symRoot}
	if os.Getuid() != 0 {
		cases["foreign-owned cache root"] = "/" // owned by root, not this uid
	}
	for name, cache := range cases {
		c := LoadCandidates(Sources{CacheDir: cache}, "bobthecorp", trust.NoRevocations())
		if len(c.list) != 0 {
			t.Errorf("%s: cached profile trusted", name)
		}
		if len(c.warnings) == 0 || !strings.HasPrefix(c.warnings[0], "Profile cache ignored: ") {
			t.Errorf("%s: warnings %q, want Profile cache ignored", name, c.warnings)
		}
	}

	// The same files through a real, owned path still load; reading never
	// changes the dir mode.
	org := filepath.Join(good, "profiles", "bobthecorp")
	if err := os.Chmod(org, 0o755); err != nil { //nolint:gosec // widened on purpose
		t.Fatal(err)
	}
	c := LoadCandidates(Sources{CacheDir: good}, "bobthecorp", trust.NoRevocations())
	if len(c.list) != 1 || len(c.warnings) != 0 {
		t.Fatalf("owned cache: %d candidates, warnings %q", len(c.list), c.warnings)
	}
	if fi, _ := os.Lstat(org); fi.Mode().Perm() != 0o755 {
		t.Errorf("read changed org dir mode to %o", fi.Mode().Perm())
	}

	// An owned dir others can write may hold planted files: not read, not repaired.
	for _, d := range []string{good, filepath.Join(good, "profiles"), org} {
		if err := os.Chmod(d, 0o777); err != nil { //nolint:gosec // widened on purpose
			t.Fatal(err)
		}
		c = LoadCandidates(Sources{CacheDir: good}, "bobthecorp", trust.NoRevocations())
		if len(c.list) != 0 || len(c.warnings) == 0 || !strings.Contains(c.warnings[0], "writable by other users") {
			t.Errorf("%s 0777: %d candidates, warnings %q", d, len(c.list), c.warnings)
		}
		if fi, _ := os.Lstat(d); fi.Mode().Perm() != 0o777 {
			t.Errorf("read changed %s mode to %o", d, fi.Mode().Perm())
		}
		if err := os.Chmod(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// A missing cache stays silent.
	c = LoadCandidates(Sources{CacheDir: filepath.Join(t.TempDir(), "none")}, "bobthecorp", trust.NoRevocations())
	if len(c.warnings) != 0 || len(c.rejected) != 0 {
		t.Errorf("missing cache: warnings %q, rejected %v", c.warnings, c.rejected)
	}
}
