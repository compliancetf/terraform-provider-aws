//go:build !ctftest

package verdict

// ctftestBuild is set by the build tag of the test file, not by alg_*.go,
// so the fixtures check the release allowlist even if allowEd25519 drifts.
const ctftestBuild = false
