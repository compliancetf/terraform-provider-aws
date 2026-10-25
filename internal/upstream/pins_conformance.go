//go:build conformance

package upstream

import "os"

// A conformance build reads its pins from $COMPLIANCETF_CONFORMANCE_PINS when
// set, so the conformance runner hands the fake upstream to pinned discovery
// through COMPLIANCETF_UPSTREAM_PATH (hash check and private exec copy) like a
// release build. Release builds do not compile this file.
func init() {
	conformancePins = func() ([]byte, error) {
		p := os.Getenv("COMPLIANCETF_CONFORMANCE_PINS")
		if p == "" {
			return nil, nil
		}
		return os.ReadFile(p) //nolint:gosec // test-only path
	}
}
