//go:build !conformance

package wrapper

import "github.com/compliancetf/terraform-provider-aws/internal/hook"

// Evaluator is the compliance evaluator Serve serves: the lifecycle evaluator.
// Builds tagged conformance swap in the test evaluator from
// evaluator_conformance.go.
func Evaluator(cfg Config, version, upstreamVersion string) (hook.Evaluator, error) {
	return lifecycleHook(cfg, version, upstreamVersion), nil
}
