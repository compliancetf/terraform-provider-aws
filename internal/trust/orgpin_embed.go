//go:build orgpin

package trust

import (
	_ "embed"
	"sync"
)

// orgPinJSON is written by the org-specific build pipeline; an orgpin build
// without it does not compile.
//
//go:embed org_pin.json
var orgPinJSON []byte

var orgPin = sync.OnceValues(func() (*Pin, error) { return parseOrgPin(orgPinJSON) })

// OrgPin returns the embedded org pin. A bad pin is an error on every call,
// so Configure fails closed.
func OrgPin() (*Pin, error) { return orgPin() }
