package upstream

// packed.go reads a packed filesystem mirror: the pinned release zip at
// <mirror>/registry.terraform.io/hashicorp/<type>/<zip>. The zip is copied into
// the private cache while hashed and must equal the signed pin before it is
// parsed; the binary is then extracted exactly as a download is.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// packedZipPath is where a packed mirror under dir holds the pinned zip.
func packedZipPath(dir string, src Source, pin PlatformPin) string {
	return filepath.Join(dir, src.RegistryDir(), pin.Zip)
}

// unpackZip returns the cache path of the binary extracted from the packed
// mirror zip at src. A file larger than MaxZipBytes is rejected unread; the
// read is bounded by ctx and mirrorReadTimeout.
func unpackZip(ctx context.Context, src string, p *Pins, osArch, cacheDir string) (string, error) {
	if _, ok := p.Platforms[osArch]; !ok {
		return "", fmt.Errorf("no pin for %s", osArch)
	}
	// Links (a mirror pointing into shared storage) are resolved first; the
	// O_NOFOLLOW open then fails closed if the target is swapped for a link.
	real, err := filepath.EvalSymlinks(src)
	if err != nil {
		return "", err
	}
	in, err := os.OpenFile(real, os.O_RDONLY|openNoFollow|openNonBlock, 0)
	if err != nil {
		return "", err
	}
	defer closeFile(in)
	st, err := in.Stat()
	switch {
	case err != nil:
		return "", err
	case !st.Mode().IsRegular():
		return "", fmt.Errorf("%q is not a regular file", src)
	case st.Size() > MaxZipBytes:
		return "", fmt.Errorf("%q is larger than %d bytes", src, MaxZipBytes)
	}
	if err := privateDir(cacheDir); err != nil {
		return "", err
	}
	zf, err := os.CreateTemp(cacheDir, ".download-*")
	if err != nil {
		return "", err
	}
	defer removeTemp(zf)
	n, got, err := copyWithin(ctx, zf, in, MaxZipBytes)
	if err != nil {
		return "", fmt.Errorf("copying %q: %w", src, err)
	}
	return installZip(zf, n, got, p, osArch, cacheDir)
}
