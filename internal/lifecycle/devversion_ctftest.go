//go:build ctftest

package lifecycle

// devVersions: a ctftest (dev) build lets a provider version that is not a
// release meet any well-formed bundle provider range (inRange).
const devVersions = true
