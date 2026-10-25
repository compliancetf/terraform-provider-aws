package embedded

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// The CIS baseline ships as a signed bundle 2.0 archive built from cis/
// (hand-converted from the v0.1 CIS baseline, ids from the pinned catalog
// snapshot). cisArchive holds one of two copies with the same payload:
//   - release builds embed cis.tar.gz, signed by the owner with the production
//     ES256 bundle key of keyring.json (archive_release.go);
//   - ctftest builds embed cis_ctftest.tar.gz, signed with the derived test
//     bundle key (archive_ctftest.go), so dev builds and tests never need a
//     production signature and release binaries never carry a test-signed one.
//
// After editing cis/, regenerate the test copy (below) and have the owner
// re-sign cis.tar.gz from the same cis/; TestReleaseKeyGuard fails until the
// two payloads match. manifest.json issued_at is signed and must lie inside
// the release bundle key's not_before/not_after window, or TestReleaseGuard
// (and every release Configure) fails: bump it before re-signing.
//
// manifest.json schema_compat_digest = sha256 of the sorted lines
// "<type>\t<read>\t<cty type JSON>" joined by "\n", from the pinned
// hashicorp/aws. make pin VERSION=X.Y.Z regenerates it with pins.json, the
// schema subset, testdata/schema_compat.tsv and the test copy.
//
//go:generate go run -tags ctftest ../../cmd/ctfbundle build -src cis -key test:bundle -out cis_ctftest.tar.gz

// CIS verifies the embedded CIS bundle against the compiled keyring and
// checks it like any bundle, except that expiry never fails closed: past the
// grace window it stays loaded with a warning. Revocation,
// a bad signature or a future issued_at are errors.
func CIS(now time.Time, revs trust.Revocations) (*bundle.Bundle, string, error) {
	return CISFrom(cisArchive, now, revs)
}

// Archive is the compiled CIS archive: the release copy, or the test-signed
// one in ctftest builds.
func Archive() []byte { return bytes.Clone(cisArchive) }

// CISFrom is CIS for archive, the wrapper Config.CISBundle, in place of the
// compiled copy.
func CISFrom(archive []byte, now time.Time, revs trust.Revocations) (*bundle.Bundle, string, error) {
	return load(archive, func(env []byte, payloadType string) (trust.Verified, error) {
		return trust.Verify(env, payloadType, revs)
	}, now, revs)
}

func load(archive []byte, verify bundle.VerifyFunc, now time.Time, revs trust.Revocations) (*bundle.Bundle, string, error) {
	b, err := bundle.ReadArchive(archive, verify)
	if err != nil {
		return nil, "", fmt.Errorf("embedded CIS bundle: %w", err)
	}
	b.Embedded, b.Source = true, bundle.SourceEmbedded
	warn, err := b.Check("", now, revs)
	if errors.Is(err, bundle.ErrExpired) {
		warn, err = "Embedded CIS "+err.Error()+"; it stays loaded.", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("embedded CIS bundle: %w", err)
	}
	return b, warn, nil
}
