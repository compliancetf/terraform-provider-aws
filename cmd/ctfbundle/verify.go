package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

func embeddedVerify(env []byte, payloadType string) (trust.Verified, error) {
	return trust.Verify(env, payloadType, trust.NoRevocations())
}

// verifyFile checks an archive with the provider's reader (internal/bundle)
// or a DSSE envelope, against the embedded keyring.
func verifyFile(path string, stdout io.Writer) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.HasSuffix(path, ".tar.gz") {
		b, err := bundle.ReadArchive(data, embeddedVerify)
		if err != nil {
			return err
		}
		m := b.Manifest
		_, err = fmt.Fprintf(stdout, "ok bundle %s v%d org=%q digest=%s\n", m.BundleID, m.BundleVersion, m.OrgID, b.Digest)
		return err
	}
	var e envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	v, err := embeddedVerify(data, e.PayloadType)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "ok %s kid=%s digest=sha256:%s\n", e.PayloadType, v.KeyID, sha256Hex(data))
	return err
}
