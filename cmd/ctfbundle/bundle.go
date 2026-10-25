package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// Archive limits from the spec (Bundle archive and manifest); the reader in
// internal/bundle enforces the same values.
const (
	maxCompressed   = 8 << 20
	maxDecompressed = 32 << 20
	maxFile         = 16 << 20
)

// bundleFiles are the files build packs, in archive order. controls.json is
// required; the others are packed when present.
var bundleFiles = []string{bundle.ControlsFile, bundle.RevokesFile, bundle.GraphFile, bundle.IAMActionsFile}

// checkFile parses a bundle file so build never signs one the provider rejects.
func checkFile(name string, data []byte) error {
	var err error
	switch name {
	case bundle.ControlsFile:
		if _, err = bundle.DigestJSON(data); err == nil { // the loader digests it too
			_, err = bundle.ParseControls(data)
		}
	case bundle.RevokesFile:
		_, err = trust.ParseRevocations(data)
	case bundle.GraphFile:
		_, err = bundle.DigestJSON(data)
	case bundle.IAMActionsFile:
		if _, err = bundle.DigestJSON(data); err == nil {
			_, err = iampolicy.LoadCatalog(data)
		}
	}
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// checkCatalog refuses a bundle whose controls call iam.* without
// iam-actions.json in its file list: the provider rejects it
// iam_catalog_missing.
func checkCatalog(names []string, bodies [][]byte) error {
	if slices.Contains(names, bundle.IAMActionsFile) {
		return nil
	}
	cs, err := bundle.ParseControls(bodies[slices.Index(names, bundle.ControlsFile)])
	if err != nil {
		return err
	}
	return celeng.CheckCatalogs(cs, func(*bundle.Control) *iampolicy.Catalog { return nil })
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// build reads <src>/manifest.json (every field but files) and the bundle
// files, fills files, signs the manifest and returns a reproducible tar.gz:
// manifest.dsse.json first, then the files in manifest order.
func build(src string, key crypto.Signer) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(src, "manifest.json"))
	if err != nil {
		return nil, err
	}
	m, err := bundle.DecodeManifest(raw)
	if err != nil {
		return nil, err
	}
	if m.Files != nil {
		return nil, errors.New("manifest: files is computed by build; remove it from manifest.json")
	}
	m.Files = []bundle.FileEntry{}
	names, bodies := []string{bundle.ManifestEntry}, [][]byte{nil}
	for _, name := range bundleFiles {
		b, err := os.ReadFile(filepath.Join(src, name))
		if errors.Is(err, os.ErrNotExist) && name != bundle.ControlsFile {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(b) > maxFile {
			return nil, fmt.Errorf("%s: %d bytes exceeds %d", name, len(b), maxFile)
		}
		if err := checkFile(name, b); err != nil {
			return nil, err
		}
		m.Files = append(m.Files, bundle.FileEntry{Path: name, SHA256: sha256Hex(b), Size: int64(len(b))})
		names, bodies = append(names, name), append(bodies, b)
	}
	if err := checkCatalog(names, bodies); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if _, err := bundle.ParseManifest(payload); err != nil {
		return nil, err
	}
	if bodies[0], err = signEnvelope(trust.PayloadBundleManifest, payload, key); err != nil {
		return nil, err
	}
	return writeArchive(names, bodies)
}

// writeArchive writes a reproducible tar.gz of plain USTAR regular entries.
// It refuses a tar stream above 32 MiB or a gzip above 8 MiB, the reader
// limits.
func writeArchive(names []string, bodies [][]byte) ([]byte, error) {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for i, name := range names {
		if err := writeEntry(tw, &tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(bodies[i]))}, bodies[i]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if tarBuf.Len() > maxDecompressed {
		return nil, fmt.Errorf("tar %d bytes exceeds %d", tarBuf.Len(), maxDecompressed)
	}
	out := gzipBytes(tarBuf.Bytes())
	if len(out) > maxCompressed {
		return nil, fmt.Errorf("archive %d bytes exceeds %d", len(out), maxCompressed)
	}
	return out, nil
}

// writeEntry sets fixed mode and mtime and writes h with body. A header
// without an explicit format is written as USTAR.
func writeEntry(tw *tar.Writer, h *tar.Header, body []byte) error {
	h.Mode, h.ModTime = 0o644, time.Unix(0, 0)
	if h.Format == tar.FormatUnknown {
		h.Format = tar.FormatUSTAR
	}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}

// gzipBytes compresses one gzip member with an empty header (no name, mtime 0).
func gzipBytes(data []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		panic(err) // a bytes.Buffer write cannot fail
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
