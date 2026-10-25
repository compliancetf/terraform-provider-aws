//go:build ctftest

package verdict

// allowEd25519: test verdict, baseline and receipt keys may be Ed25519 only
// in ctftest builds, which never ship (tools/releasegate refuses build tags).
const allowEd25519 = true
