package upstream

// execdir.go copies the upstream binary into a private per-process directory,
// hashing the bytes as they are written, so the file that runs is the file
// that was hashed. Threat model: other local users are in scope (every parent
// is writable only by us or root); a process running as our own uid is not.

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// ExecDirUnsafeSummary is the diagnostic summary for an ExecDirUnsafeError.
const ExecDirUnsafeSummary = "Upstream exec directory unsafe"

// ExecDirUnsafeError means no candidate parent passed the checks.
type ExecDirUnsafeError struct {
	Failures []string // "<path>: <check that failed>", one per candidate
}

// Detail is the diagnostic detail.
func (e *ExecDirUnsafeError) Detail() string {
	return "No private directory for the upstream copy: " + strings.Join(e.Failures, "; ") + ". Set XDG_RUNTIME_DIR or fix the permissions."
}

func (e *ExecDirUnsafeError) Error() string { return ExecDirUnsafeSummary + ": " + e.Detail() }

// childRe matches an exec child name: <host tag>.<owner pid>-<random>.
var childRe = regexp.MustCompile(`^([0-9a-f]{8})\.([0-9]+)-.+$`)

// execDir is this process's private exec child directory. rest are the
// parents after the chosen one, used when the chosen one runs out of space.
type execDir struct {
	dir                 string
	rest, terraformDirs []string
}

// execCandidates lists the parents for the exec child, in preference order.
// Windows keeps to the per-user profile: its DACL check is not yet verified
// on real hosts.
func execCandidates() []string {
	var c []string
	windows := runtime.GOOS == "windows"
	if x := os.Getenv("XDG_RUNTIME_DIR"); !windows && filepath.IsAbs(x) {
		c = append(c, filepath.Join(x, "compliancetf"))
	}
	if d, err := os.UserCacheDir(); err == nil {
		c = append(c, filepath.Join(d, "compliancetf", "exec"))
	}
	if !windows {
		c = append(c, filepath.Join(".terraform", "compliancetf", "exec"))
	}
	return c
}

// newExecDir creates the exec child under the first candidate that is not
// inside a Terraform directory and passes secureDir, after sweeping that
// parent's stale children. The other candidates are swept when they already
// exist and pass the same checks.
func newExecDir(candidates, terraformDirs []string) (*execDir, error) {
	var fails []string
	for i, c := range candidates {
		dir, err := makeChild(c, terraformDirs)
		if err == nil {
			for j, o := range candidates {
				if j != i {
					sweepIfSafe(o, terraformDirs)
				}
			}
			return &execDir{dir: dir, rest: candidates[i+1:], terraformDirs: terraformDirs}, nil
		}
		fails = append(fails, fmt.Sprintf("%s: %v", c, err))
	}
	if len(fails) == 0 {
		fails = append(fails, "(none): no candidate directory")
	}
	return nil, &ExecDirUnsafeError{Failures: fails}
}

func makeChild(parent string, terraformDirs []string) (string, error) {
	parent, err := checkParent(parent, terraformDirs, true)
	if err != nil {
		return "", err
	}
	tag := hostTag()
	sweep(parent, tag)
	child, err := os.MkdirTemp(parent, fmt.Sprintf("%s.%d-*", tag, os.Getpid()))
	if err != nil {
		return "", err
	}
	if err := checkDir(child, true); err != nil {
		removeExecDir(child)
		return "", fmt.Errorf("%s: %w", child, err)
	}
	return child, nil
}

// checkParent returns the absolute parent once it is outside every Terraform
// directory and passes secureDir.
func checkParent(parent string, terraformDirs []string, create bool) (string, error) {
	parent, err := filepath.Abs(parent)
	if err != nil {
		return "", err
	}
	rp := resolvePath(parent)
	for _, t := range terraformDirs {
		if t != "" && within(rp, resolvePath(t)) {
			return "", fmt.Errorf("inside Terraform directory %q", t)
		}
	}
	return parent, secureDir(parent, create)
}

// sweepIfSafe sweeps a candidate that was not chosen, only if it exists and
// passes the checks the chosen one did; it creates nothing.
func sweepIfSafe(parent string, terraformDirs []string) {
	if p, err := checkParent(parent, terraformDirs, false); err == nil {
		sweep(p, hostTag())
	}
}

// secureDir walks dir from the volume root, creating missing components with
// mode 0700 when create (never MkdirAll, which follows symlinked components) and checking
// every component. Once every component is writable only by us or root,
// nobody else can swap one after the check. A root-owned sticky ancestor
// (/tmp) is allowed: others cannot rename or delete our entries in it.
func secureDir(dir string, create bool) error {
	vol := filepath.VolumeName(dir)
	cur := vol + string(filepath.Separator)
	if err := checkDir(cur, false); err != nil && !stickyRootDir(cur) {
		return fmt.Errorf("%s: %w", cur, err)
	}
	parts := strings.Split(strings.Trim(dir[len(vol):], string(filepath.Separator)), string(filepath.Separator))
	for i, part := range parts {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		if create {
			if err := os.Mkdir(cur, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("%s: %w", cur, err)
			}
		}
		if err := checkDir(cur, false); err != nil && (i == len(parts)-1 || !stickyRootDir(cur)) {
			return fmt.Errorf("%s: %w", cur, err)
		}
	}
	return nil
}

// checkDir requires path to be a real directory that only we (or root, unless
// ownOnly) can write.
func checkDir(path string, ownOnly bool) error {
	st, err := os.Lstat(path)
	switch {
	case err != nil:
		return err
	case st.Mode()&fs.ModeSymlink != 0:
		return errors.New("is a symlink")
	case !st.IsDir():
		return errors.New("is not a directory")
	}
	return checkOwnerPerm(path, st, ownOnly)
}

// resolvePath is the absolute path with symlinks resolved on its longest
// existing prefix, case-folded where the filesystem usually is. On Windows
// the \\?\ prefix is dropped and EvalSymlinks expands 8.3 short names.
func resolvePath(p string) string {
	p, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if runtime.GOOS == "windows" {
		p = stripWinPrefix(p)
	}
	var tail []string
	for {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = filepath.Join(append([]string{r}, tail...)...)
			break
		}
		parent := filepath.Dir(p)
		if parent == p {
			p = filepath.Join(append([]string{p}, tail...)...)
			break
		}
		tail = append([]string{filepath.Base(p)}, tail...)
		p = parent
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	return p
}

// within reports whether p is root or below it, component-wise.
func within(p, root string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// hostTag tells this host's (and PID namespace's) exec children from those
// of other hosts or containers sharing the parent, whose PIDs mean nothing here.
func hostTag() string {
	h, err := os.Hostname()
	if err != nil {
		h = "" // every host without a name shares one tag; sweep still checks PIDs
	}
	return hostTagFor(h, pidNamespace())
}

// initPIDNamespace is the host's initial PID namespace (PROC_PID_INIT_INO);
// it keeps the hostname-only tag.
const initPIDNamespace = "pid:[4026531836]"

func hostTagFor(hostname, pidNS string) string {
	if pidNS != "" && pidNS != initPIDNamespace {
		hostname += "\x00" + pidNS
	}
	return fmt.Sprintf("%08x", crc32.ChecksumIEEE([]byte(hostname)))
}

// sweep removes this host's exec children whose owner PID is dead. Anything
// else (other hosts, live owners, symlinks, foreign names or owners) is kept.
func sweep(parent, tag string) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		log.Printf("[upstream] sweeping %q: %v", parent, err)
		return
	}
	for _, e := range entries {
		m := childRe.FindStringSubmatch(e.Name())
		if m == nil || m[1] != tag {
			continue
		}
		pid, err := strconv.Atoi(m[2])
		if err != nil || pid <= 0 || pid == os.Getpid() {
			continue
		}
		p := filepath.Join(parent, e.Name())
		if checkDir(p, true) != nil || pidAlive(pid) {
			continue
		}
		if err := os.RemoveAll(p); err != nil {
			log.Printf("[upstream] removing stale %q: %v", p, err)
		}
	}
}

// copyBytes is copyHashed; tests replace it to simulate a full disk or a hung
// read.
var copyBytes = copyHashed

// copy copies src into the exec child, hashing the bytes written, and returns
// the copy as a VerifiedBinary when they match the pin. The read is bounded by
// ctx and mirrorReadTimeout. Any failure removes the copy. The copy is closed
// before return, so no write fd survives to exec.
// When the parent is out of space (a small tmpfs XDG_RUNTIME_DIR), the child
// moves to the next parent that passes the checks and the copy is retried.
func (d *execDir) copy(ctx context.Context, src string, p *Pins, osArch string) (VerifiedBinary, error) {
	for {
		vb, err := d.copyOnce(ctx, src, p, osArch)
		if err == nil || !diskFull(err) || len(d.rest) == 0 {
			return vb, err
		}
		log.Printf("[upstream] %q is full, trying the next exec parent: %v", d.dir, err)
		d.remove()
		next, nerr := newExecDir(d.rest, d.terraformDirs)
		if nerr != nil {
			d.rest = nil
			return VerifiedBinary{}, errors.Join(err, nerr)
		}
		*d = *next
	}
}

func (d *execDir) copyOnce(ctx context.Context, src string, p *Pins, osArch string) (VerifiedBinary, error) {
	pin, ok := p.Platforms[osArch]
	if !ok {
		return VerifiedBinary{}, fmt.Errorf("%s %s has no pin for %s", p.src.Name(), p.Version, osArch)
	}
	if pin.Binary == "" || pin.Binary != filepath.Base(pin.Binary) || pin.Binary == "." || pin.Binary == ".." {
		return VerifiedBinary{}, fmt.Errorf("pinned binary name %q is not a plain file name", pin.Binary)
	}
	// Links (.terraform/providers into a plugin cache) are resolved first; the
	// O_NOFOLLOW open then fails closed if the target is swapped for a link.
	real, err := filepath.EvalSymlinks(src)
	if err != nil {
		return VerifiedBinary{}, err
	}
	in, err := os.OpenFile(real, os.O_RDONLY|openNoFollow|openNonBlock, 0)
	if err != nil {
		return VerifiedBinary{}, err
	}
	defer closeFile(in)
	st, err := in.Stat()
	switch {
	case err != nil:
		return VerifiedBinary{}, err
	case !st.Mode().IsRegular():
		return VerifiedBinary{}, fmt.Errorf("%q is not a regular file", src)
	case st.Size() > MaxBinaryBytes:
		return VerifiedBinary{}, fmt.Errorf("%q is larger than %d bytes", src, MaxBinaryBytes)
	}

	dst := filepath.Join(d.dir, pin.Binary)
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|openNoFollow, 0o700)
	if err != nil {
		return VerifiedBinary{}, err
	}
	done := false
	defer func() {
		if !done {
			if err := out.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				log.Printf("[upstream] closing %q: %v", dst, err)
			}
			if err := os.Remove(dst); err != nil && !errors.Is(err, fs.ErrNotExist) {
				log.Printf("[upstream] removing %q: %v", dst, err)
			}
		}
	}()
	vb, err := writeCopy(ctx, out, in, dst, src, p, osArch)
	if err != nil {
		return VerifiedBinary{}, err
	}
	done = true
	vb.execDir = d.dir
	return vb, nil
}

func writeCopy(ctx context.Context, out, in *os.File, dst, src string, p *Pins, osArch string) (VerifiedBinary, error) {
	if err := out.Chmod(0o700); err != nil { // umask-proof exec bit
		return VerifiedBinary{}, err
	}
	n, got, err := copyWithin(ctx, out, in, MaxBinaryBytes)
	if err != nil {
		return VerifiedBinary{}, fmt.Errorf("copying %q: %w", src, err)
	}
	if st, err := out.Stat(); err != nil || !st.Mode().IsRegular() || st.Size() != n {
		return VerifiedBinary{}, fmt.Errorf("copy %q changed while written: %v", dst, err)
	}
	if err := out.Close(); err != nil {
		return VerifiedBinary{}, err
	}
	st, err := os.Lstat(dst)
	if err != nil {
		return VerifiedBinary{}, err
	}
	if !st.Mode().IsRegular() || st.Size() != n || checkOwnerPerm(dst, st, true) != nil {
		return VerifiedBinary{}, fmt.Errorf("copy %q was replaced before exec", dst)
	}
	if want := p.Platforms[osArch].BinarySHA256; got != want {
		return VerifiedBinary{}, &NotVerifiedError{Upstream: p.src.Name(), Path: src, Got: got, Want: want, Version: p.Version, OSArch: osArch}
	}
	return VerifiedBinary{path: dst, sha256: got, protocol: p.Protocol, version: p.Version, name: p.src.Name()}, nil
}

// remove deletes the exec child.
func (d *execDir) remove() { removeExecDir(d.dir) }

func removeExecDir(dir string) {
	if dir == "" {
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		log.Printf("[upstream] removing exec dir %q: %v", dir, err)
	}
}
