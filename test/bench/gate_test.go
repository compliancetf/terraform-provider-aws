package bench

import (
	"testing"
	"time"
)

// TestGatePercentile: nearest-rank p99.
func TestGatePercentile(t *testing.T) {
	for _, n := range []int{1, 100, 500} {
		d := make([]time.Duration, n)
		for i := range d {
			d[i] = time.Duration(n - i) // reverse order: P99 sorts a copy
		}
		want := time.Duration((99*n + 99) / 100)
		if got := P99(d); got != want {
			t.Errorf("P99 of 1..%d = %d, want %d", n, got, want)
		}
		if d[0] != time.Duration(n) {
			t.Error("P99 reordered its input")
		}
	}
}
