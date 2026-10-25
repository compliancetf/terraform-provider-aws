//go:build ctftest

package celeng

import (
	"encoding/hex"
	"slices"
	"strings"
)

// MemoDump is every memo entry as a "<hex key> <state>" line, sorted: the
// memo dump the value-free scrub test reads. A key is a sha256
// over the projected values, so a low-entropy value can be recovered from
// it by dictionary: the dump exists only in ctftest builds.
func (c *Compiled) MemoDump() string {
	c.memo.mu.RLock()
	defer c.memo.mu.RUnlock()
	lines := make([]string, 0, len(c.memo.m))
	for k, s := range c.memo.m {
		lines = append(lines, hex.EncodeToString(k[:])+" "+s.String())
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}
