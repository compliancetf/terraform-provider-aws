package fetch

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/fsutil"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

const (
	maxCacheFiles = 64 // bundle files read per load, as the profile loader caps profiles
	// staleTmpAge is the age after which a .tmp-* file cannot belong to a
	// write still in progress (a write takes well under a second).
	staleTmpAge = time.Hour
)

var bundleNameRE = regexp.MustCompile(`^sha256-([0-9a-f]{64})\.tar\.gz$`)

// cachedBundle is a cached archive that verified and whose file name equals
// its bundle digest.
type cachedBundle struct {
	name string
	b    *bundle.Bundle
}

// Reasons a cached archive (a file named like one) was not used; the
// evidence configure record carries them, never a file name or path.
const (
	SkipNotRegular     = "not_regular"     // a symlink, directory or other non-regular file
	SkipUnreadable     = "unreadable"      // read failed or over the size limit
	SkipUnverified     = "unverified"      // the archive did not verify or parse
	SkipDigestMismatch = "digest_mismatch" // verified, but its digest is not its name
	SkipOverLimit      = "over_limit"      // more than maxCacheFiles archives: all ignored
)

// SkipReasons lists every skip reason, in the evidence enum order.
var SkipReasons = []string{SkipNotRegular, SkipUnreadable, SkipUnverified, SkipDigestMismatch, SkipOverLimit}

// loadCachedBundles verifies every cached archive (regular files only,
// size capped) and keeps those of bundleID. Misnamed or failing files are
// skipped: the cache is never a trust input. skipped holds one reason per
// file named like an archive that was not used (another bundle_id is not a
// skip). A dir failing fsutil.OpenTree is ignored with a warning; files are
// read through its handle.
func loadCachedBundles(root, dir, bundleID string, verify bundle.VerifyFunc) (out []cachedBundle, warns, skipped []string) {
	r, err := fsutil.OpenTree(root, dir, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, []string{fmt.Sprintf("Bundle cache ignored: %v.", err)}, nil
	}
	defer r.Close() //nolint:errcheck // dir handle
	ents, err := fsutil.ReadDir(r)
	if err != nil {
		return nil, []string{fmt.Sprintf("Bundle cache unreadable: %v.", err)}, nil
	}
	var names []string
	for _, e := range ents {
		switch {
		case !bundleNameRE.MatchString(e.Name()):
		case e.Type().IsRegular():
			names = append(names, e.Name())
		default:
			skipped = append(skipped, SkipNotRegular)
		}
	}
	if len(names) > maxCacheFiles {
		for range names {
			skipped = append(skipped, SkipOverLimit)
		}
		return nil, []string{fmt.Sprintf("Bundle cache ignored: more than %d archives in %s.", maxCacheFiles, dir)}, skipped
	}
	for _, name := range names {
		raw, err := fsutil.ReadFile(r, name, maxBundleBytes)
		if err != nil {
			skipped = append(skipped, SkipUnreadable)
			continue
		}
		b, err := bundle.ReadArchive(raw, verify)
		switch {
		case err != nil:
			skipped = append(skipped, SkipUnverified)
		case b.Digest != "sha256:"+bundleNameRE.FindStringSubmatch(name)[1]:
			skipped = append(skipped, SkipDigestMismatch)
		case bundleID == "" || b.Manifest.BundleID == bundleID:
			b.Source = bundle.SourceCache
			out = append(out, cachedBundle{name, b})
		}
	}
	return out, nil, skipped
}

// CachedTrust reads every cached archive that verifies, any bundle_id, before
// the floor: it returns revs merged with their revocations (merge only
// adds; their controls are never used here), their manifests, whose
// minimums the caller applies, and one skip reason per archive not used.
// Only archives whose manifest DSSE verifies under the compiled bundle keys
// and whose name matches their digest count (expired ones included, as the
// T26 manifest-minimum rule says). Any other file is skipped, which equals
// deleting it: a cache writer can do that anyway, revocations of every bundle
// that loaded are already in the trust state, and a floor revocation_epoch
// above the merged set fails closed. Revocations are global.
func CachedTrust(cacheDir string, revs trust.Revocations) (trust.Revocations, []*bundle.Manifest, []string, []string, error) {
	verify := func(env []byte, pt string) (trust.Verified, error) { return trust.Verify(env, pt, revs) }
	cached, warns, skipped := loadCachedBundles(cacheDir, filepath.Join(cacheDir, "bundles"), "", verify)
	var ms []*bundle.Manifest
	for _, c := range cached {
		var err error
		if revs, err = trust.Merge(revs, c.b.Revocations); err != nil {
			return trust.Revocations{}, nil, nil, nil, err
		}
		ms = append(ms, c.b.Manifest)
	}
	return revs, ms, warns, skipped, nil
}

// pickBest is the highest-version cached bundle that accept passes, with
// accept's warning.
func pickBest(cached []cachedBundle, accept func(*bundle.Bundle) (string, error)) (*bundle.Bundle, []string) {
	var best *bundle.Bundle
	var warn string
	for _, c := range cached {
		if best != nil && c.b.Manifest.BundleVersion <= best.Manifest.BundleVersion {
			continue
		}
		if w, err := accept(c.b); err == nil {
			best, warn = c.b, w
		}
	}
	if warn == "" {
		return best, nil
	}
	return best, []string{warn}
}

// storeBundle writes a verified archive under its digest, then removes
// cached copies of the same bundle with a lower version.
func storeBundle(root, dir string, b *bundle.Bundle, raw []byte, cached []cachedBundle) error {
	r, err := fsutil.OpenTree(root, dir, true)
	if err != nil {
		return err
	}
	defer r.Close() //nolint:errcheck // dir handle
	name := "sha256-" + strings.TrimPrefix(b.Digest, "sha256:") + ".tar.gz"
	if err := writeAtomicIn(r, name, raw, true); err != nil {
		return err
	}
	for _, c := range cached {
		if c.b.Manifest.BundleVersion < b.Manifest.BundleVersion && c.name != name {
			r.Remove(c.name) //nolint:errcheck,gosec // best effort; a parallel run may have removed it
		}
	}
	return nil
}

// writeAtomic opens dir through fsutil.OpenTree from the cache root and runs
// writeAtomicIn there.
func writeAtomic(root, dir, name string, data []byte, replace bool) error {
	r, err := fsutil.OpenTree(root, dir, true)
	if err != nil {
		return err
	}
	defer r.Close() //nolint:errcheck // dir handle
	return writeAtomicIn(r, name, data, replace)
}

// writeAtomicIn writes data to name in r through a 0600 temp file, so readers
// in parallel runs see no partial file. replace renames over an existing
// file; otherwise a hard link fails when name exists. Stale temp files are
// swept first. Every operation is relative to r, the checked dir handle.
func writeAtomicIn(r *os.Root, name string, data []byte, replace bool) error {
	sweepTemps(r)
	var rnd [8]byte
	rand.Read(rnd[:]) //nolint:errcheck,gosec // never fails
	tmp := ".tmp-" + hex.EncodeToString(rnd[:])
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer r.Remove(tmp) //nolint:errcheck // gone after a rename; cleanup otherwise
	_, werr := f.Write(data)
	if err := errors.Join(werr, f.Close()); err != nil {
		return err
	}
	if replace {
		return r.Rename(tmp, name)
	}
	return r.Link(tmp, name)
}

// sweepTemps removes this cache's own temp files (regular .tmp-* files)
// older than staleTmpAge, left by a crashed or killed run. Symlinks and
// directories are skipped, never followed; Remove unlinks a name only.
func sweepTemps(r *os.Root) {
	ents, err := fsutil.ReadDir(r)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), ".tmp-") || !e.Type().IsRegular() {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() && time.Since(fi.ModTime()) > staleTmpAge {
			r.Remove(e.Name()) //nolint:errcheck,gosec // best effort; a parallel run may have removed it
		}
	}
}
