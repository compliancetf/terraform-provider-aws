//go:build !orgpin

package trust

// OrgPin returns the embedded org pin; builds without the orgpin tag have none.
func OrgPin() (*Pin, error) { return nil, nil } //nolint:nilnil // no pin is not an error
