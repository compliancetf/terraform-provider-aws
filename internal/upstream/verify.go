package upstream

// verify.go is the only producer of VerifiedBinary, and holds the OpenPGP and
// zip checks shared with tools/pinupstream.

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// MaxBinaryBytes caps how much of an upstream binary is read or extracted.
const MaxBinaryBytes int64 = 2 << 30

const (
	maxZipEntries = 16
	clockSkew     = 5 * time.Minute
)

var (
	allowedHashes = []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}
	entryNameRe   = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// NotVerifiedSummary is the diagnostic summary for a NotVerifiedError.
const NotVerifiedSummary = "Upstream provider not verified"

// NotVerifiedError is a candidate binary whose sha256 differs from the pin.
type NotVerifiedError struct {
	Upstream, Path, Got, Want, Version, OSArch string // Upstream is Source.Name
}

// Detail is the diagnostic detail.
func (e *NotVerifiedError) Detail() string {
	return fmt.Sprintf("%s: sha256 %s does not match the pinned %s %s %s checksum %s.", e.Path, e.Got, e.Upstream, e.Version, e.OSArch, e.Want)
}

func (e *NotVerifiedError) Error() string { return NotVerifiedSummary + ": " + e.Detail() }

// Path is the verified file Launch executes.
func (b VerifiedBinary) Path() string { return b.path }

// verifyFile reports whether the regular file at path matches the pin for
// osArch. It only checks a published cache file: nothing runs this path, a
// VerifiedBinary comes only from execDir.copy.
func verifyFile(path string, p *Pins, osArch string) error {
	pin, ok := p.Platforms[osArch]
	if !ok {
		return fmt.Errorf("%s %s has no pin for %s", p.src.Name(), p.Version, osArch)
	}
	// Stat before open so a FIFO cannot block; O_NONBLOCK covers a swap in between.
	if st, err := os.Stat(path); err != nil {
		return err
	} else if !st.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer closeFile(f)
	st, err := f.Stat()
	switch {
	case err != nil:
		return err
	case !st.Mode().IsRegular():
		return fmt.Errorf("%q is not a regular file", path)
	case st.Size() > MaxBinaryBytes:
		return fmt.Errorf("%q is larger than %d bytes", path, MaxBinaryBytes)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, MaxBinaryBytes+1)); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != pin.BinarySHA256 {
		return &NotVerifiedError{Upstream: p.src.Name(), Path: path, Got: got, Want: pin.BinarySHA256, Version: p.Version, OSArch: osArch}
	}
	return nil
}

// Fingerprint is the uppercase hex primary key fingerprint of e.
func Fingerprint(e *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))
}

// LoadKey requires an armored public keyring holding exactly one entity, with
// no private material, whose primary fingerprint is expectFingerprint.
func LoadKey(data []byte, expectFingerprint string) (*openpgp.Entity, error) {
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}
	if len(el) != 1 {
		return nil, fmt.Errorf("key file holds %d keys, want exactly 1", len(el))
	}
	e := el[0]
	if e.PrivateKey != nil {
		return nil, errors.New("key file contains private key material")
	}
	for _, sk := range e.Subkeys {
		if sk.PrivateKey != nil {
			return nil, errors.New("key file contains private key material")
		}
	}
	if fp := Fingerprint(e); fp != strings.ToUpper(expectFingerprint) {
		return nil, fmt.Errorf("key fingerprint %s is not the pinned %s", fp, expectFingerprint)
	}
	return e, nil
}

// VerifySumsSignature checks a binary detached signature over sums made by e.
// The library requires a signing-capable key or cross-signed subkey and
// rejects revoked or expired keys and signatures at the verification time:
// now when atSigning is false (pin generation). When atSigning is true
// (runtime download, where the pinned SHA256SUMS hash is the binding and a
// later key expiry must not brick a released wrapper) the signature passes
// when it verifies at now, at its own creation time, or at the creation time
// of one of e's binding self-signatures. HashiCorp re-binds its signing
// subkey, and the published key keeps only the latest binding, so a release
// signed before it (6.0.0 to 6.33.0) fails at its creation time. A binding's
// creation time is fixed in the embedded key, so that check still passes once
// the binding has expired. A signature dated after now+5m always fails.
func VerifySumsSignature(e *openpgp.Entity, sums, sig []byte, now time.Time, atSigning bool) error {
	r := bytes.NewReader(sig)
	p, err := packet.Read(r)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	s, ok := p.(*packet.Signature)
	switch {
	case !ok || r.Len() != 0:
		return errors.New("signature file must be exactly one signature packet")
	case s.Version != 4 && s.Version != 6:
		return fmt.Errorf("signature version %d", s.Version)
	case s.SigType != packet.SigTypeBinary:
		return fmt.Errorf("signature type %#x, want binary", s.SigType)
	case s.CreationTime.IsZero():
		return errors.New("signature has no creation time")
	case s.CreationTime.After(now.Add(clockSkew)):
		return errors.New("signature created in the future")
	}
	check := func(at time.Time) (*openpgp.Entity, error) {
		cfg := &packet.Config{Time: func() time.Time { return at }}
		return openpgp.CheckDetachedSignatureAndHash(openpgp.EntityList{e}, bytes.NewReader(sums), bytes.NewReader(sig), allowedHashes, cfg)
	}
	signer, err := check(now)
	if atSigning {
		for _, at := range append([]time.Time{s.CreationTime}, bindingTimes(e)...) {
			if err == nil {
				break
			}
			signer, err = check(at)
		}
	}
	if err != nil {
		return fmt.Errorf("SHA256SUMS signature: %w", err)
	}
	if signer != e {
		return errors.New("SHA256SUMS signed by an unexpected key")
	}
	return nil
}

// bindingTimes are the creation times of e's subkey bindings and user ID
// self-signatures, the instants at which each binding made e's keys valid.
func bindingTimes(e *openpgp.Entity) []time.Time {
	var ts []time.Time
	for _, sk := range e.Subkeys {
		if sk.Sig != nil {
			ts = append(ts, sk.Sig.CreationTime)
		}
	}
	for _, id := range e.Identities {
		if id.SelfSignature != nil {
			ts = append(ts, id.SelfSignature.CreationTime)
		}
	}
	return ts
}

// FindBinary returns the entry named want. Every entry must be a regular file
// with a safe, unique (case-folded) name, at most maxZipEntries of them.
func FindBinary(zr *zip.Reader, want string) (*zip.File, error) {
	if len(zr.File) > maxZipEntries {
		return nil, fmt.Errorf("zip has %d entries", len(zr.File))
	}
	folded := map[string]bool{}
	var bin *zip.File
	for _, zf := range zr.File {
		if !entryNameRe.MatchString(zf.Name) || strings.Trim(zf.Name, ".") == "" {
			return nil, fmt.Errorf("zip entry name %q", zf.Name)
		}
		if !zf.Mode().IsRegular() {
			return nil, fmt.Errorf("zip entry %q is not a regular file", zf.Name)
		}
		key := strings.ToLower(zf.Name)
		if folded[key] {
			return nil, fmt.Errorf("zip entry %q duplicated", zf.Name)
		}
		folded[key] = true
		if zf.Name == want {
			bin = zf
		}
	}
	if bin == nil {
		return nil, fmt.Errorf("zip has no %s", want)
	}
	return bin, nil
}
