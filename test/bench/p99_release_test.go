//go:build !ctftest

package bench

import "testing"

// BenchmarkP99 needs the ctftest keyring: the reference bundle is signed with
// the ctftest bundle key. Without samples cmd/benchgate fails, so an untagged
// run cannot pass the gate.
func BenchmarkP99(b *testing.B) {
	b.Skip("BenchmarkP99 needs -tags ctftest: run make bench-gate")
}
