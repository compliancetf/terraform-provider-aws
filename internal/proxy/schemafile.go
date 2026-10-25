package proxy

// schemafile.go keeps the upstream GetSchema response on disk, in the shared
// upstream entry (internal/upstream/shared.go). Later provider processes then
// skip the upstream's schema build: about 0.3 s and 7.5 MB for hashicorp/aws,
// against about 40 ms to read the file. Terraform starts the provider three
// times per plan. The entry is owner-only and named by the binary's sha256,
// so the file is trusted like the binary next to it. The file starts with
// the sha256 of the payload, because a truncated protobuf can still decode
// and would hide schemas. A file that is missing, too large or does not
// match is ignored, and the upstream is asked.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/proto"

	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

const (
	schemaFileName = "schema-v5.pb"
	maxSchemaFile  = 256 << 20
)

// readSchemaFile returns the cached upstream response, or nil.
func readSchemaFile(dir string) *tfplugin5.GetProviderSchema_Response {
	if dir == "" {
		return nil
	}
	f, err := os.Open(filepath.Join(dir, schemaFileName))
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck // read-only
	b, err := io.ReadAll(io.LimitReader(f, maxSchemaFile+1))
	if err != nil || len(b) < sha256.Size || len(b) > maxSchemaFile {
		return nil
	}
	sum, payload := b[:sha256.Size], b[sha256.Size:]
	if got := sha256.Sum256(payload); !bytes.Equal(got[:], sum) {
		log.Printf("[WARN] ignoring %s: checksum mismatch", f.Name())
		return nil
	}
	r := &tfplugin5.GetProviderSchema_Response{}
	if err := proto.Unmarshal(payload, r); err != nil || hasErrorDiag(r.Diagnostics) {
		return nil
	}
	return r
}

// writeSchemaFile stores r, an error-free upstream response, for later
// processes. Best effort: a failure only costs the next process an upstream
// call.
func writeSchemaFile(dir string, r *tfplugin5.GetProviderSchema_Response) {
	if dir == "" {
		return
	}
	payload, err := proto.Marshal(r)
	if err == nil {
		err = writeFileAtomic(dir, schemaFileName, payload)
	}
	if err != nil {
		log.Printf("[WARN] caching the upstream schema in %s: %v", dir, err)
	}
}

func writeFileAtomic(dir, name string, payload []byte) error {
	f, err := os.CreateTemp(dir, "."+name+"-*")
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	_, err = f.Write(append(sum[:], payload...))
	if err = errors.Join(err, f.Sync(), f.Close()); err == nil {
		err = os.Rename(f.Name(), filepath.Join(dir, name))
	}
	if err != nil {
		os.Remove(f.Name()) //nolint:errcheck,gosec // best-effort temp cleanup
	}
	return err
}
