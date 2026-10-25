package upstream

// discover.go finds the pinned upstream binary: the explicit path, then
// Terraform's directories at the exact pinned path, then the own cache, then
// the pinned zip in a packed mirror, then a signed download. Every candidate
// is hashed against pins.json.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// UpstreamPathEnv names an explicit upstream binary (air-gapped installs). A
// binary there that does not match the pin is fatal.
const UpstreamPathEnv = "COMPLIANCETF_UPSTREAM_PATH"

// NotFoundSummary is the diagnostic summary for a NotFoundError.
const NotFoundSummary = "Upstream provider not found"

// NotFoundError means no source produced a verified binary.
type NotFoundError struct {
	Upstream, Version, OSArch, Reason string // Upstream is Source.Name
}

// Detail is the diagnostic detail.
func (e *NotFoundError) Detail() string {
	return fmt.Sprintf("No verified %s %s binary for %s; download failed: %s. Set %s for air-gapped installs.", e.Upstream, e.Version, e.OSArch, e.Reason, UpstreamPathEnv)
}

func (e *NotFoundError) Error() string { return NotFoundSummary + ": " + e.Detail() }

// source is one discovery run; tests build it directly.
type source struct {
	pins     *Pins
	osArch   string
	explicit string   // COMPLIANCETF_UPSTREAM_PATH
	dirs     []string // Terraform directories, probed in order
	cacheDir string   // own content-addressed cache; "" when unavailable
	cacheErr error    // why cacheDir is unavailable
	exec     *execDir // private copy target; every result is a hashed copy here
	download func(ctx context.Context, cacheDir string) (string, error)
}

// testOverride is set only by ctftest builds (testonly_ctftest.go).
var testOverride func() (VerifiedBinary, bool)

// Discover returns the verified src binary for this platform: a private
// copy whose bytes were hashed as they were written. pins and anchors are the
// wrapper Config.UpstreamPins and Config.TrustAnchors: pins must carry the
// compiled HashiCorpFingerprint and a download trusts only an anchor with that
// fingerprint, so neither input can change the trust root. Errors are
// *NotVerifiedError, *NotFoundError or *ExecDirUnsafeError and are fatal at
// start; a canceled ctx stops the probes and returns ctx.Err().
func Discover(ctx context.Context, src Source, pins []byte, anchors [][]byte) (VerifiedBinary, error) {
	if testOverride != nil {
		if vb, ok := testOverride(); ok {
			return vb, nil
		}
	}
	osArch := runtime.GOOS + "_" + runtime.GOARCH
	p, err := loadPins(pins, src)
	if err != nil {
		return VerifiedBinary{}, &NotFoundError{Upstream: src.Name(), Version: "(unpinned)", OSArch: osArch, Reason: err.Error()}
	}
	s := &source{pins: p, osArch: osArch, explicit: os.Getenv(UpstreamPathEnv), dirs: searchDirs()}
	if dir, err := os.UserCacheDir(); err == nil {
		s.cacheDir = filepath.Join(dir, "compliancetf", "upstream")
	} else {
		s.cacheErr = err
	}
	s.download = func(ctx context.Context, cacheDir string) (string, error) {
		d, err := newDownloader(src, anchors)
		if err != nil {
			return "", err
		}
		return d.download(ctx, p, osArch, cacheDir)
	}
	if parent := sharedParent(s.dirs); parent != "" {
		vb, done, err := s.discoverShared(ctx, parent)
		if done {
			if err == nil && vb.execDir == "" {
				vb.retry = s.discoverPrivate
			}
			return vb, err
		}
	}
	return s.discoverPrivate(ctx)
}

// discoverPrivate copies the binary into a fresh per-process exec child.
func (s *source) discoverPrivate(ctx context.Context) (VerifiedBinary, error) {
	ed, err := newExecDir(execCandidates(), s.dirs)
	if err != nil {
		return VerifiedBinary{}, err
	}
	s.exec = ed
	vb, err := s.find(ctx)
	if err != nil {
		ed.remove()
	}
	return vb, err
}

func (s *source) notFound(reason string) error {
	return &NotFoundError{Upstream: s.pins.src.Name(), Version: s.pins.Version, OSArch: s.osArch, Reason: reason}
}

func (s *source) find(ctx context.Context) (VerifiedBinary, error) {
	notFound := s.notFound
	if s.explicit != "" {
		vb, err := s.exec.copy(ctx, s.explicit, s.pins, s.osArch)
		if err != nil && ctx.Err() != nil {
			return VerifiedBinary{}, ctx.Err()
		}
		var nv *NotVerifiedError
		if err != nil && !errors.As(err, &nv) {
			return VerifiedBinary{}, notFound(fmt.Sprintf("%s=%q: %v", UpstreamPathEnv, s.explicit, err))
		}
		return vb, err
	}
	pin, ok := s.pins.Platforms[s.osArch]
	if !ok {
		return VerifiedBinary{}, notFound("no pin for this platform")
	}
	rel := filepath.Join(s.pins.src.RegistryDir(), s.pins.Version, s.osArch, pin.Binary)
	candidates := make([]string, 0, len(s.dirs)+1)
	for _, dir := range s.dirs {
		candidates = append(candidates, filepath.Join(dir, rel))
	}
	if s.cacheDir != "" {
		candidates = append(candidates, cachePath(s.cacheDir, pin.BinarySHA256))
	}
	for _, c := range candidates {
		vb, err := s.exec.copy(ctx, c, s.pins, s.osArch)
		if err == nil {
			return vb, nil
		}
		if ctx.Err() != nil {
			return VerifiedBinary{}, ctx.Err()
		}
		if !errors.Is(err, fs.ErrNotExist) {
			log.Printf("[upstream] skipping %q: %v", c, err)
		}
	}
	if s.cacheDir == "" {
		return VerifiedBinary{}, notFound(fmt.Sprintf("no cache directory: %v", s.cacheErr))
	}
	for _, dir := range s.dirs {
		zp := packedZipPath(dir, s.pins.src, pin)
		path, err := unpackZip(ctx, zp, s.pins, s.osArch, s.cacheDir)
		if err == nil {
			return s.exec.copy(ctx, path, s.pins, s.osArch)
		}
		if ctx.Err() != nil {
			return VerifiedBinary{}, ctx.Err()
		}
		if !errors.Is(err, fs.ErrNotExist) {
			log.Printf("[upstream] skipping %q: %v", zp, err)
		}
	}
	path, err := s.download(ctx, s.cacheDir)
	if err != nil && ctx.Err() != nil {
		return VerifiedBinary{}, ctx.Err()
	}
	if err != nil {
		return VerifiedBinary{}, notFound(err.Error())
	}
	return s.exec.copy(ctx, path, s.pins, s.osArch)
}

// searchDirs lists Terraform's provider directories in discovery order.
func searchDirs() []string {
	dataDir := os.Getenv("TF_DATA_DIR")
	if dataDir == "" {
		dataDir = ".terraform"
	}
	dirs := []string{filepath.Join(dataDir, "providers")}
	if d := os.Getenv("TF_PLUGIN_CACHE_DIR"); d != "" {
		dirs = append(dirs, d)
	}
	cfg, err := ParseCLIConfig(FindCLIConfigPath())
	if err != nil {
		log.Printf("[upstream] ignoring CLI config: %v", err)
	}
	if cfg != nil {
		if cfg.PluginCacheDir != "" {
			dirs = append(dirs, expandHome(cfg.PluginCacheDir))
		}
		for _, m := range cfg.FilesystemMirrors {
			dirs = append(dirs, expandHome(m))
		}
	}
	return append(dirs, impliedMirrorDirs()...)
}

// expandHome expands a leading ~ as Terraform does for CLI config paths.
func expandHome(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, strings.TrimPrefix(p, "~"))
}

// impliedMirrorDirs returns Terraform's implied local mirror directories.
func impliedMirrorDirs() []string {
	var dirs []string
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	switch runtime.GOOS {
	case "darwin":
		if home != "" {
			dirs = append(dirs,
				filepath.Join(home, ".terraform.d", "plugins"),
				filepath.Join(home, "Library", "Application Support", "io.terraform", "plugins"))
		}
		dirs = append(dirs, filepath.Join("/", "Library", "Application Support", "io.terraform", "plugins"))
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			dirs = append(dirs,
				filepath.Join(appdata, "terraform.d", "plugins"),
				filepath.Join(appdata, "HashiCorp", "Terraform", "plugins"))
		}
	default:
		if home != "" {
			dirs = append(dirs, filepath.Join(home, ".terraform.d", "plugins"))
		}
		dataHome := os.Getenv("XDG_DATA_HOME")
		if dataHome == "" && home != "" {
			dataHome = filepath.Join(home, ".local", "share")
		}
		if dataHome != "" {
			dirs = append(dirs, filepath.Join(dataHome, "terraform", "plugins"))
		}
		dirs = append(dirs,
			filepath.Join("/", "usr", "local", "share", "terraform", "plugins"),
			filepath.Join("/", "usr", "share", "terraform", "plugins"))
	}
	return append(dirs, filepath.Join("terraform.d", "plugins"))
}
