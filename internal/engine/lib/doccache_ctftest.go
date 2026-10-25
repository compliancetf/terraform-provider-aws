//go:build ctftest

package lib

// ResetDocCache empties the process document cache, so the next json.path
// and iam.parse calls decode again: the benchmark clears it before
// each measured pass. ctftest builds only.
func ResetDocCache() {
	docs.mu.Lock()
	defer docs.mu.Unlock()
	clear(docs.m)
	docs.bytes = 0
}
