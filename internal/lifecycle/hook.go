package lifecycle

import (
	"context"
	"os"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
)

// Hook is a Lifecycle as the hook.Evaluator the proxy serves: Configure takes
// the 0A request, the other methods (Wants, Evaluate, Close) are the
// Lifecycle's.
type Hook struct{ *Lifecycle }

var _ hook.Evaluator = Hook{}

// Configure runs Lifecycle.Configure. Its error is an error diagnostic,
// never a Go error: the 0A Go error rule hides the text, and every
// Configure error is a message for the user that quotes only values the
// user wrote (block or COMPLIANCETF_* env, %q).
func (h Hook) Configure(ctx context.Context, req *hook.ConfigureRequest) ([]hook.Diagnostic, error) {
	p := providerInfo(upstreamRegion(req, os.Getenv))
	p.AccountID, p.AccountKnown = ownAccount(req)
	warns, err := h.configureWith(ctx, req.Compliance, req.TerraformVersion, p, req.Schemas)
	diags := make([]hook.Diagnostic, 0, len(warns)+1)
	if err != nil { // warns: only the evidence warnings of a recorded rejection
		diags = append(diags, hook.Diagnostic{Severity: hook.SeverityError, Summary: "Compliance configuration failed", Detail: err.Error()})
	}
	for _, w := range warns {
		diags = append(diags, hook.Diagnostic{Severity: hook.SeverityWarning, Summary: "Compliance configuration", Detail: w})
	}
	return diags, nil
}

// upstreamRegion is the region the upstream provider uses: the config region
// when it is set, the env and shared config fallback when it is null, and
// not known when it is unknown or not a string.
func upstreamRegion(req *hook.ConfigureRequest, getenv func(string) string) (string, bool) {
	if req.RegionNull {
		return fallbackRegion(getenv, req.SharedConfigSet, req.Profile)
	}
	return req.Region, req.RegionKnown
}
