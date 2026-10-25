//go:build !ctftest

package lifecycle

// devVersions: a release build checks the provider version exactly; a version
// that is not a release never meets a bundle provider range.
const devVersions = false
