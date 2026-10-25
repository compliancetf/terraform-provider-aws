// Package lifecycle implements the lifecycle evaluator's enforcement stages. This file is
// the severity matrix: control result to
// diagnostic severity and forward decision.
package lifecycle

import (
	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// Stage names match the 0A hook.Stage values the matrix applies to.
type Stage string

const (
	StagePlan      Stage = "plan"
	StageApplyPre  Stage = "apply_pre"
	StageApplyPost Stage = "apply_post"
	StageRead      Stage = "read"
	// StageImport takes the refresh column: import marks evidence only and
	// the plan that follows enforces.
	StageImport Stage = "import"
	// StageEphemeralOpen takes the apply_pre column: it is the last check
	// before upstream opens the secret, and no later stage re-checks it.
	StageEphemeralOpen Stage = "ephemeral_open"
	// StageDataSource takes the plan column: a blocking
	// failure fails the read; an unknown is never more than pending, since
	// Terraform reads the data source again once its config is known.
	StageDataSource Stage = "data_source"
	// StageRPC records a passthrough RPC the verdict gate decided; it
	// evaluates no control, so the matrix never sees it.
	StageRPC Stage = "rpc"
)

// stageName is the user-facing and evidence name: read is "refresh".
func stageName(s Stage) string {
	if s == StageRead {
		return "refresh"
	}
	return string(s)
}

// Severity is the diagnostic severity a result produces; none means evidence only.
type Severity string

const (
	SeverityNone    Severity = "none"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// Cell is one cell of the severity matrix.
type Cell struct {
	Severity Severity
	Forward  bool // false only when apply_pre must not forward the request upstream
}

// Blocking reports whether a control blocks: action deny and per-control mode
// hard_fail, or grandfather and the violation is not grandfathered (the
// signed baseline matcher).
func Blocking(mode profile.Mode, action bundle.Action, grandfathered bool) bool {
	return action == bundle.ActionDeny && (mode >= profile.HardFail || mode == profile.Grandfather && !grandfathered)
}

// Classify returns the severity matrix cell for a control result.
// not_evaluable takes the fail row. Advisory produces no diagnostics at
// any stage (parent 6.1 "log only"); evidence is still written by the caller.
func Classify(mode profile.Mode, action bundle.Action, state engine.State, stage Stage, op engine.Op, grandfathered bool) Cell {
	switch stage {
	case StageImport:
		stage = StageRead
	case StageEphemeralOpen:
		stage = StageApplyPre
	case StageDataSource:
		stage = StagePlan // op is read, never replace: unknown stays pending
	}
	sev := severity(mode, action, state, stage, op, grandfathered)
	return Cell{Severity: sev, Forward: stage != StageApplyPre || sev != SeverityError}
}

func severity(mode profile.Mode, action bundle.Action, state engine.State, stage Stage, op engine.Op, grandfathered bool) Severity {
	blocking := Blocking(mode, action, grandfathered)
	switch state {
	case engine.Pass:
		return SeverityNone
	case engine.Unknown:
		switch {
		case stage == StageApplyPre && blocking:
			return SeverityError
		case stage == StagePlan && blocking && op == engine.OpReplace:
			return SeverityError
		case stage == StagePlan && mode != profile.Advisory:
			return SeverityWarning // pending: re-checked at apply
		}
		return SeverityNone
	}
	// Fail, NotEvaluable and any unrecognized state take the fail row (fail closed).
	switch {
	case !blocking && mode == profile.Advisory:
		return SeverityNone
	case !blocking, stage == StageRead:
		return SeverityWarning
	case stage == StageApplyPost && (op == engine.OpCreate || op == engine.OpReplace):
		// An error after create would taint the new object; replace reaches
		// apply_post only through its create half.
		return SeverityWarning
	}
	return SeverityError
}
