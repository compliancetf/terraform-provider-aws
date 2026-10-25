// Command benchgate gates `go test -bench` output against a
// committed baseline:
//
//	go run ./cmd/benchgate -baseline test/bench/baseline/<runner-class>.json -in bench.txt
//
// It takes the median of the p99-ns/resource metric of BenchmarkP99 over
// exactly -count runs (10, as go test -count) and exits 1 when it is more than 20% over the baseline p99 or
// above 50 ms, or when the runs disagree with the baseline on the resource
// or control count, or on output of another benchmark or a malformed row.
// -update writes the baseline from the runs instead; it refuses a p99 above
// 50 ms.
// make bench-gate runs the benchmark and this gate.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxRegressionPct: a p99 more than this percent over the baseline fails.
	MaxRegressionPct = 20
	// MaxP99 is the hard cap, the per-resource budget.
	MaxP99 = 50 * time.Millisecond
	metric = "p99-ns/resource"
)

// Baseline is test/bench/baseline/<runner-class>.json.
type Baseline struct {
	RunnerClass string `json:"runner_class"`
	P99Ns       int64  `json:"p99_ns"`
	Resources   int    `json:"resources"`
	Controls    int    `json:"controls"`
	Note        string `json:"note,omitempty"` // how and where it was recorded
}

// Sample is one benchmark run.
type Sample struct {
	P99                 time.Duration
	Resources, Controls int
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("benchgate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	basePath := fs.String("baseline", filepath.Join("test", "bench", "baseline", RunnerClass()+".json"), "baseline file")
	in := fs.String("in", "-", "go test -bench output, - for stdin")
	update := fs.Bool("update", false, "write the baseline from these runs")
	note := fs.String("note", "", "with -update: how and where the baseline was recorded")
	name := fs.String("bench", "BenchmarkP99", "benchmark to gate; any other benchmark result fails")
	count := fs.Int("count", 10, "number of runs the output must hold (go test -count)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := gate(opts{*basePath, *in, *name, *count, *update, *note}, stdin, stdout); err != nil {
		fmt.Fprintln(stderr, "benchgate:", err) //nolint:errcheck // console output
		return 1
	}
	return 0
}

type opts struct {
	basePath, in, name string
	count              int
	update             bool
	note               string
}

func gate(o opts, stdin io.Reader, stdout io.Writer) error {
	r, basePath := stdin, o.basePath
	if o.in != "-" {
		f, err := os.Open(o.in) //nolint:gosec // operator-supplied benchmark output
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck // read only
		r = f
	}
	samples, err := Parse(r, o.name)
	if err != nil {
		return err
	}
	if len(samples) != o.count {
		return fmt.Errorf("%d %s runs in the benchmark output, want %d (go test -count %d)", len(samples), o.name, o.count, o.count)
	}
	got, err := Summarize(samples)
	if err != nil {
		return err
	}
	if o.update {
		if got.P99 > MaxP99 {
			return fmt.Errorf("p99 %v is over the %v cap: not recording it as a baseline", got.P99, MaxP99)
		}
		b := Baseline{RunnerClass: strings.TrimSuffix(filepath.Base(basePath), ".json"), P99Ns: int64(got.P99),
			Resources: got.Resources, Controls: got.Controls, Note: o.note}
		raw, err := json.MarshalIndent(b, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(basePath, append(raw, '\n'), 0o644); err != nil { //nolint:gosec // committed fixture
			return err
		}
		fmt.Fprintf(stdout, "benchgate: wrote %s: p99 %v (median of %d runs)\n", basePath, got.P99, len(samples)) //nolint:errcheck // console output
		return nil
	}
	base, err := LoadBaseline(basePath)
	if err != nil {
		return fmt.Errorf("%w; this run: p99 %v; record a baseline on an idle machine with UPDATE=1 make bench-gate", err, got.P99)
	}
	if base.Resources != got.Resources || base.Controls != got.Controls {
		return fmt.Errorf("baseline %s is for %d resources and %d controls, the runs have %d and %d; re-record it with UPDATE=1 make bench-gate",
			basePath, base.Resources, base.Controls, got.Resources, got.Controls)
	}
	if err := Check(got.P99, base); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "benchgate: ok: p99 %v (median of %d runs), %s baseline %v\n", got.P99, len(samples), base.RunnerClass, time.Duration(base.P99Ns)) //nolint:errcheck // console output
	return nil
}

// RunnerClass names the machine class a baseline is valid for:
// COMPLIANCETF_BENCH_RUNNER_CLASS, else GOOS-GOARCH.
func RunnerClass() string {
	if c := os.Getenv("COMPLIANCETF_BENCH_RUNNER_CLASS"); c != "" {
		return c
	}
	return runtime.GOOS + "-" + runtime.GOARCH
}

// LoadBaseline reads a baseline file; a missing or non-positive p99 fails.
func LoadBaseline(path string) (Baseline, error) {
	var b Baseline
	raw, err := os.ReadFile(path) //nolint:gosec // repo fixture path
	if err != nil {
		return b, fmt.Errorf("baseline: %w", err)
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return b, fmt.Errorf("baseline %s: %w", path, err)
	}
	if b.P99Ns <= 0 {
		return b, fmt.Errorf("baseline %s: p99_ns must be positive", path)
	}
	return b, nil
}

// Check fails when p99 exceeds the baseline by more than MaxRegressionPct
// or exceeds MaxP99.
func Check(p99 time.Duration, b Baseline) error {
	if b.P99Ns <= 0 {
		return fmt.Errorf("baseline p99_ns %d is not positive", b.P99Ns)
	}
	if p99 > MaxP99 {
		return fmt.Errorf("p99 %v is over the %v cap", p99, MaxP99)
	}
	if int64(p99)*100 > b.P99Ns*(100+MaxRegressionPct) {
		return fmt.Errorf("p99 %v is %.1f%% over the %s baseline %v (limit %d%%)",
			p99, float64(int64(p99)-b.P99Ns)*100/float64(b.P99Ns), b.RunnerClass, time.Duration(b.P99Ns), MaxRegressionPct)
	}
	return nil
}

// Parse reads the benchmark result rows of name ("<name>-N <iterations>
// <value> <unit> ..."; the -N GOMAXPROCS suffix is optional). A result row
// of any other benchmark fails, and so does a row of name that is truncated,
// has no positive iteration count, lacks p99-ns/resource, resources or
// controls, or has a count that is not a positive integer. A line holding only the
// name (printed before a benchmark that logs) is not a result.
func Parse(r io.Reader, name string) ([]Sample, error) {
	var out []Sample
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || !strings.HasPrefix(f[0], "Benchmark") {
			continue
		}
		got := f[0]
		if i := strings.LastIndexByte(got, '-'); i > 0 {
			if _, err := strconv.Atoi(got[i+1:]); err == nil {
				got = got[:i]
			}
		}
		if got != name {
			return nil, fmt.Errorf("%q: a result of %s, want only %s", sc.Text(), got, name)
		}
		if len(f) == 1 {
			continue
		}
		if n, err := strconv.Atoi(f[1]); err != nil || n <= 0 || len(f)%2 != 0 {
			return nil, fmt.Errorf("%q: malformed result row", sc.Text())
		}
		var s Sample
		seen := map[string]bool{}
		for i := 2; i+1 < len(f); i += 2 {
			v, err := strconv.ParseFloat(f[i], 64)
			if err != nil {
				return nil, fmt.Errorf("%q: %w", sc.Text(), err)
			}
			seen[f[i+1]] = true
			// Only p99-ns/resource is gated: ns/op also times Configure
			// and the evidence parse.
			switch f[i+1] {
			case metric:
				if !(v > 0) || v >= 1<<63 { // 1<<63 is float64(MaxInt64): it overflows Duration
					return nil, fmt.Errorf("%q: %s %s is not a positive duration", sc.Text(), metric, f[i])
				}
				s.P99 = time.Duration(v)
			case "resources", "controls":
				if v <= 0 || v > math.MaxInt32 || v != math.Trunc(v) {
					return nil, fmt.Errorf("%q: %s %s is not a positive integer", sc.Text(), f[i+1], f[i])
				}
				if f[i+1] == "resources" {
					s.Resources = int(v)
				} else {
					s.Controls = int(v)
				}
			}
		}
		if !seen[metric] || !seen["resources"] || !seen["controls"] {
			return nil, fmt.Errorf("%q: want %s, resources and controls", sc.Text(), metric)
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

// Summarize is the median p99 of samples that agree on the resource and
// control counts.
func Summarize(samples []Sample) (Sample, error) {
	if len(samples) == 0 {
		return Sample{}, errors.New("no " + metric + " results in the benchmark output")
	}
	p := make([]time.Duration, len(samples))
	for i, s := range samples {
		if s.P99 <= 0 || s.Resources != samples[0].Resources || s.Controls != samples[0].Controls {
			return Sample{}, fmt.Errorf("run %d: p99 %v, %d resources, %d controls; run 1 has %d and %d",
				i+1, s.P99, s.Resources, s.Controls, samples[0].Resources, samples[0].Controls)
		}
		p[i] = s.P99
	}
	slices.Sort(p)
	m := p[len(p)/2]
	if len(p)%2 == 0 {
		lo := p[len(p)/2-1]
		m = lo + (m-lo)/2 // a sum of two p99s near MaxInt64 overflows
	}
	return Sample{P99: m, Resources: samples[0].Resources, Controls: samples[0].Controls}, nil
}
