//go:build ctftest

// Package bundletest edits signed bundle archives for tests: drop or change
// a file and re-sign the manifest with a test key, which cmd/ctfbundle build
// refuses to do for invalid sources. Tests only.
package bundletest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// Rewrite rebuilds archive entry by entry through edit (keep false drops
// the entry), in the plain USTAR form the reader accepts. The manifest is
// copied as is unless edit changes it.
func Rewrite(archive []byte, edit func(name string, body []byte) (out []byte, keep bool, err error)) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		body, keep, err := edit(h.Name, body)
		if err != nil {
			return nil, err
		}
		if !keep {
			continue
		}
		hdr := &tar.Header{Name: h.Name, Typeflag: tar.TypeReg, Size: int64(len(body)), Mode: 0o644, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// WithoutFile drops name from archive and from its manifest file list and
// signs the manifest again with key (ES256). The old signature is not checked.
func WithoutFile(archive []byte, name string, key *ecdsa.PrivateKey) ([]byte, error) {
	return Rewrite(archive, func(entry string, body []byte) ([]byte, bool, error) {
		switch entry {
		case name:
			return nil, false, nil
		case bundle.ManifestEntry:
			env, err := resign(body, key, func(m *bundle.Manifest) error {
				files := []bundle.FileEntry{}
				for _, f := range m.Files {
					if f.Path != name {
						files = append(files, f)
					}
				}
				if len(files) == len(m.Files) {
					return errors.New("bundletest: " + name + " is not in the manifest")
				}
				m.Files = files
				return nil
			})
			return env, true, err
		}
		return body, true, nil
	})
}

// WithFile replaces the body of name, updates its manifest sha256 and size
// and signs the manifest again with key (ES256). The old signature is not
// checked.
func WithFile(archive []byte, name string, body []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	sum := sha256.Sum256(body)
	return Rewrite(archive, func(entry string, old []byte) ([]byte, bool, error) {
		switch entry {
		case name:
			return body, true, nil
		case bundle.ManifestEntry:
			env, err := resign(old, key, func(m *bundle.Manifest) error {
				for i := range m.Files {
					if m.Files[i].Path == name {
						m.Files[i].SHA256, m.Files[i].Size = hex.EncodeToString(sum[:]), int64(len(body))
						return nil
					}
				}
				return errors.New("bundletest: " + name + " is not in the manifest")
			})
			return env, true, err
		}
		return old, true, nil
	})
}

// WithManifest applies edit to the manifest and signs it again with key
// (ES256). The old signature is not checked.
func WithManifest(archive []byte, key *ecdsa.PrivateKey, edit func(*bundle.Manifest) error) ([]byte, error) {
	return Rewrite(archive, func(entry string, body []byte) ([]byte, bool, error) {
		if entry != bundle.ManifestEntry {
			return body, true, nil
		}
		env, err := resign(body, key, edit)
		return env, true, err
	})
}

// resign applies edit to the manifest payload of env and signs it with key.
func resign(env []byte, key *ecdsa.PrivateKey, edit func(*bundle.Manifest) error) ([]byte, error) {
	var e struct{ Payload string }
	if err := json.Unmarshal(env, &e); err != nil {
		return nil, err
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, err
	}
	m, err := bundle.ParseManifest(payload)
	if err != nil {
		return nil, err
	}
	if err := edit(m); err != nil {
		return nil, err
	}
	if payload, err = json.Marshal(m); err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(trust.PAE(trust.PayloadBundleManifest, payload))
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"payloadType": trust.PayloadBundleManifest,
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures":  []map[string]string{{"keyid": trust.KIDFromSPKI(spki), "sig": base64.StdEncoding.EncodeToString(sig)}},
	})
}
