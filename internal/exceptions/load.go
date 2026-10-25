package exceptions

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/compliancetf/terraform-provider-aws/internal/fsutil"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// maxGrantFiles bounds the *.dsse.json entries of exception_grants_dir.
const maxGrantFiles = 256

// Rejection is one grant file that does not apply. Digest is the envelope
// sha256 when the file was read, empty for file-level faults.
type Rejection struct {
	File, Code, Digest string
	Err                error
}

func (r Rejection) String() string { return fmt.Sprintf("exception grant %q: %v", r.File, r.Err) }

// LoadGrants verifies every *.dsse.json file of dir (one grant per file, no
// recursion) once per run. Files are read through fsutil (regular files
// only, never a symlink, at most trust.MaxEnvelopeBytes). A missing or
// unreadable dir, or more than 256 grant files, is an error with no
// results; per-file faults are rejections. Verified grants sharing a
// grant_id apply once when every copy has the same payload, otherwise none
// does. Results are sorted by file name.
func (v *Verifier) LoadGrants(dir string) ([]Grant, []Rejection, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("exception_grants_dir: %w", err)
	}
	defer root.Close() //nolint:errcheck // read-only
	entries, err := fsutil.ReadDir(root)
	if err != nil {
		return nil, nil, fmt.Errorf("exception_grants_dir: %w", err)
	}
	entries = slices.DeleteFunc(entries, func(e os.DirEntry) bool { return !strings.HasSuffix(e.Name(), ".dsse.json") })
	if len(entries) > maxGrantFiles {
		return nil, nil, fmt.Errorf("exception_grants_dir: more than %d grant files", maxGrantFiles)
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })

	var grants []Grant
	var files []string
	var rej []Rejection
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() {
			rej = append(rej, Rejection{File: name, Code: CodeFileNotRegular, Err: errors.New("not a regular file")})
			continue
		}
		if fi, err := e.Info(); err == nil && fi.Size() > trust.MaxEnvelopeBytes {
			rej = append(rej, Rejection{File: name, Code: CodeFileTooLarge, Err: errors.New("file too large")})
			continue
		}
		b, err := fsutil.ReadFile(root, name, trust.MaxEnvelopeBytes)
		if err != nil {
			rej = append(rej, Rejection{File: name, Code: CodeFileUnreadable, Err: err})
			continue
		}
		g, err := v.VerifyGrant(b)
		if err != nil {
			var ge *GrantError
			c := CodeInvalid
			if errors.As(err, &ge) {
				c = ge.Code
			}
			rej = append(rej, Rejection{File: name, Code: c, Digest: digest(b), Err: err})
			continue
		}
		grants, files = append(grants, g), append(files, name)
	}
	return dedupe(grants, files, rej)
}

// dedupe keeps the first file of each grant_id when all copies share one
// payload digest and rejects every copy otherwise.
func dedupe(grants []Grant, files []string, rej []Rejection) ([]Grant, []Rejection, error) {
	conflict := map[string]bool{}
	first := map[string]string{}
	for _, g := range grants {
		if d, ok := first[g.GrantID]; ok && d != g.PayloadDigest {
			conflict[g.GrantID] = true
		} else if !ok {
			first[g.GrantID] = g.PayloadDigest
		}
	}
	var out []Grant
	kept := map[string]bool{}
	for i, g := range grants {
		switch {
		case conflict[g.GrantID]:
			rej = append(rej, Rejection{File: files[i], Code: CodeDuplicateID, Digest: g.Digest,
				Err: fmt.Errorf("grant %s appears with different payloads", g.GrantID)})
		case !kept[g.GrantID]:
			kept[g.GrantID] = true
			out = append(out, g)
		}
	}
	slices.SortFunc(rej, func(a, b Rejection) int { return strings.Compare(a.File, b.File) })
	return out, rej, nil
}
