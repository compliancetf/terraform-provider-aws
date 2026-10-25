package upstream

// shared.go keeps one verified copy of the pinned upstream per sha256 in
// <UserCacheDir>/compliancetf/exec/v1-<sha256>/ and reuses it on later starts.
// A fresh copy per start cost about 1s of copy and hash, and on macOS about
// 9s of code-signature validation for every new inode of the 800 MB binary.
// Terraform starts the provider three times per plan (docs/performance.md).
//
// Threat model: as in execdir.go, other local users are in scope. The entry,
// every parent and the binary are owner-only, checked before every exec. The
// stamp, link count and mode checks catch accidental change, not a process
// running as our uid. For such a process the entry is a persistent place to
// swap the binary. That is accepted: it can already replace terraform, the
// CLI config or this provider's own binary. Same-uid processes sharing the
// cache (CI jobs under one home) are the same case.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	sharedPrefix  = "v1-"
	stampName     = "stamp"
	sharedMaxIdle = 14 * 24 * time.Hour // GC age of entries for other pins
)

// stamp records the binary's metadata when it was verified. A match skips the
// rehash. ctime is left out: Gatekeeper and EDR tools change xattrs on exec.
type stamp struct {
	Size    int64  `json:"size"`
	MtimeNs int64  `json:"mtime_ns"`
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
}

func stampOf(st os.FileInfo) stamp {
	dev, ino := fileID(st)
	return stamp{Size: st.Size(), MtimeNs: st.ModTime().UnixNano(), Dev: dev, Ino: ino}
}

type entryState int

const (
	entryMissing   entryState = iota // publish one
	entryUse                         // exec it
	entryDefective                   // ours but broken: remove, then publish
	entryTransient                   // unreadable or not ours: private copy, entry untouched
)

// sharedRoot is os.UserCacheDir; tests point it at a temporary directory.
var sharedRoot = os.UserCacheDir

// sharedParent is the shared exec parent, or "" when it fails the checks
// every exec parent passes.
func sharedParent(terraformDirs []string) string {
	d, err := sharedRoot()
	if err != nil {
		return ""
	}
	p, err := checkParent(filepath.Join(d, "compliancetf", "exec"), terraformDirs, true)
	if err != nil {
		log.Printf("[upstream] no shared exec dir: %v", err)
		return ""
	}
	return p
}

// checkEntry classifies the entry dir for pin. repair rehashes a binary whose
// stamp does not match and rewrites the stamp when the bytes still match.
func checkEntry(ctx context.Context, dir string, pin PlatformPin, repair bool) entryState {
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return entryMissing
	} else if err != nil || checkDir(dir, true) != nil {
		return entryTransient
	}
	bin := filepath.Join(dir, pin.Binary)
	st, err := os.Lstat(bin)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return entryDefective
	case err != nil:
		return entryTransient
	case !st.Mode().IsRegular() || st.Size() == 0 || !sealed(st) || checkOwnerPerm(bin, st, true) != nil:
		return entryDefective
	}
	if got, ok := readStamp(dir); ok && got == stampOf(st) {
		return entryUse
	}
	if !repair {
		return entryTransient
	}
	sum, err := hashFile(ctx, bin)
	switch {
	case err != nil:
		return entryTransient
	case sum != pin.BinarySHA256:
		return entryDefective
	}
	if err := writeStamp(dir, st); err != nil {
		log.Printf("[upstream] rewriting stamp in %q: %v", dir, err)
	}
	return entryUse
}

func readStamp(dir string) (stamp, bool) {
	b, err := os.ReadFile(filepath.Join(dir, stampName))
	if err != nil {
		return stamp{}, false
	}
	var s stamp
	return s, json.Unmarshal(b, &s) == nil
}

// writeStamp replaces dir/stamp atomically with the stamp of st.
func writeStamp(dir string, st os.FileInfo) error {
	b, err := json.Marshal(stampOf(st))
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".stamp-*")
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
		os.Remove(f.Name()) //nolint:errcheck,gosec // best-effort temp cleanup
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(dir, stampName)); err != nil {
		os.Remove(f.Name()) //nolint:errcheck,gosec // best-effort temp cleanup
		return err
	}
	return nil
}

// hashFile is the hex sha256 of the file at path, read with the same checks
// as a copy.
func hashFile(ctx context.Context, path string) (string, error) {
	in, err := openSource(path)
	if err != nil {
		return "", err
	}
	defer closeFile(in)
	_, sum, err := copyWithin(ctx, io.Discard, in, MaxBinaryBytes)
	return sum, err
}

// syncDir flushes a directory entry; best effort, and a no-op where
// directories cannot be synced (Windows).
func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		f.Sync()  //nolint:errcheck,gosec // best effort
		f.Close() //nolint:errcheck,gosec // read-only handle
	}
}

// seal flushes the verified copy and, off Windows, drops its write bits. A
// read-only attribute on Windows would stop GC from deleting the entry; the
// DACL keeps others out there.
func seal(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|openNoFollow, 0)
	if err != nil {
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	return os.Chmod(path, 0o500)
}

// publish moves the verified private copy vb into entry and returns the
// binary to run. That is the entry, or vb itself when a step fails. ok is
// false when the rename succeeded but the entry then failed its check; the
// caller makes a fresh private copy, because nothing read from that entry may
// run.
func (s *source) publish(ctx context.Context, vb VerifiedBinary, entry string) (_ VerifiedBinary, ok bool) {
	child := vb.execDir
	if filepath.Dir(child) != filepath.Dir(entry) { // the copy moved to another parent (disk full)
		return vb, true
	}
	if err := seal(vb.path); err != nil {
		log.Printf("[upstream] not sharing %q: %v", vb.path, err)
		return vb, true
	}
	st, err := os.Lstat(vb.path)
	if err == nil {
		err = writeStamp(child, st)
	}
	if err != nil {
		log.Printf("[upstream] not sharing %q: %v", vb.path, err)
		return vb, true
	}
	syncDir(child)
	pin := s.pins.Platforms[s.osArch]
	if err := os.Rename(child, entry); err != nil {
		// Another start won the race: run its entry if it checks out, else our copy.
		if checkEntry(ctx, entry, pin, false) == entryUse {
			removeExecDir(child)
			return sharedBinary(vb, entry), true
		}
		log.Printf("[upstream] not sharing %q: %v", vb.path, err)
		return vb, true
	}
	syncDir(filepath.Dir(entry))
	if checkEntry(ctx, entry, pin, false) != entryUse {
		log.Printf("[upstream] %q failed its check right after publishing", entry)
		return VerifiedBinary{}, false
	}
	gcShared(filepath.Dir(entry), entry)
	return sharedBinary(vb, entry), true
}

// sharedBinary is vb run from entry. Close leaves the entry in place.
func sharedBinary(vb VerifiedBinary, entry string) VerifiedBinary {
	vb.path = filepath.Join(entry, filepath.Base(vb.path))
	vb.execDir, vb.cacheDir = "", entry
	return vb
}

// gcShared removes other pins' entries idle for sharedMaxIdle. Errors are
// ignored, for example a Windows exe that is running.
func gcShared(parent, keep string) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	for _, e := range entries {
		p := filepath.Join(parent, e.Name())
		if !strings.HasPrefix(e.Name(), sharedPrefix) || p == keep {
			continue
		}
		st, err := os.Lstat(p)
		if err != nil || checkDir(p, true) != nil || time.Since(st.ModTime()) < sharedMaxIdle {
			continue
		}
		if again, err := os.Lstat(p); err != nil || !os.SameFile(st, again) || !again.ModTime().Equal(st.ModTime()) {
			continue
		}
		if err := os.RemoveAll(p); err != nil {
			log.Printf("[upstream] removing idle %q: %v", p, err)
		}
	}
}

// discoverShared runs the shared entry for the pin, publishing one first when
// it is missing. done is false when the caller should make a private copy
// instead.
func (s *source) discoverShared(ctx context.Context, parent string) (_ VerifiedBinary, done bool, _ error) {
	pin, ok := s.pins.Platforms[s.osArch]
	if !ok || !plainName(pin.Binary) {
		return VerifiedBinary{}, false, nil // the private path reports it
	}
	if s.explicit != "" {
		if err := s.verifyExplicit(ctx, pin); err != nil {
			return VerifiedBinary{}, true, err
		}
	}
	entry := filepath.Join(parent, sharedPrefix+pin.BinarySHA256)
	switch checkEntry(ctx, entry, pin, true) {
	case entryUse:
		now := time.Now()
		if err := os.Chtimes(entry, now, now); err != nil { // GC age; never the binary's times
			log.Printf("[upstream] touching %q: %v", entry, err)
		}
		vb := VerifiedBinary{path: pin.Binary, sha256: pin.BinarySHA256, protocol: s.pins.Protocol, version: s.pins.Version, name: s.pins.src.Name()}
		return sharedBinary(vb, entry), true, nil
	case entryDefective:
		log.Printf("[upstream] replacing defective %q", entry)
		if err := os.RemoveAll(entry); err != nil {
			log.Printf("[upstream] removing %q: %v", entry, err)
			return VerifiedBinary{}, false, nil
		}
	case entryTransient:
		log.Printf("[upstream] not using %q this start", entry)
		return VerifiedBinary{}, false, nil
	}
	ed, err := newExecDir(append([]string{parent}, execCandidates()...), s.dirs)
	if err != nil {
		return VerifiedBinary{}, true, err
	}
	s.exec = ed
	vb, err := s.find(ctx)
	if err != nil {
		ed.remove()
		return VerifiedBinary{}, true, err
	}
	vb, ok = s.publish(ctx, vb, entry)
	return vb, ok, nil
}

// verifyExplicit hashes COMPLIANCETF_UPSTREAM_PATH against the pin on every
// start, so a mismatch stays fatal even when the shared entry would serve.
func (s *source) verifyExplicit(ctx context.Context, pin PlatformPin) error {
	sum, err := hashFile(ctx, s.explicit)
	switch {
	case err != nil && ctx.Err() != nil:
		return ctx.Err()
	case err != nil:
		return s.notFound(fmt.Sprintf("%s=%q: %v", UpstreamPathEnv, s.explicit, err))
	case sum != pin.BinarySHA256:
		return &NotVerifiedError{Upstream: s.pins.src.Name(), Path: s.explicit, Got: sum, Want: pin.BinarySHA256, Version: s.pins.Version, OSArch: s.osArch}
	}
	return nil
}
