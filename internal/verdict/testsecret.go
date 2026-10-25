//go:build !ctftest

package verdict

// allowTestSecret: a release build refuses the public instance key test
// secret (instance_key FORMAT.md v1, Test secret).
const allowTestSecret = false
