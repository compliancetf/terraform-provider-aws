// Package bench is the benchmark harness: BenchmarkP99 reports the p99
// evaluation latency per resource; cmd/benchgate gates it against the
// committed per-runner-class baseline in baseline/<runner-class>.json.
package bench

import (
	"slices"
	"time"
)

// P99 is the nearest-rank 99th percentile of d; d is not reordered.
func P99(d []time.Duration) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	return s[(99*len(s)+99)/100-1]
}
