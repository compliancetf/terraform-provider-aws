//go:build conformance

package wrapper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
)

// Evaluator reads $COMPLIANCETF_CONFORMANCE_EVALUATOR: empty is the no-op,
// "lifecycle" is the 0B lifecycle as release builds wire it (evaluator.go),
// "deny:<type>" blocks every apply of <type> at apply_pre (plan still
// succeeds, so the blocked apply has a prior state to keep), "warn:<type>"
// adds a warning at plan and apply_pre. $COMPLIANCETF_CONFORMANCE_RPCSEQ
// selects the recorder instead. Release builds carry none of this.
func Evaluator(cfg Config, version, upstreamVersion string) (hook.Evaluator, error) {
	spec := os.Getenv("COMPLIANCETF_CONFORMANCE_EVALUATOR")
	if path := os.Getenv("COMPLIANCETF_CONFORMANCE_RPCSEQ"); path != "" {
		if spec != "" {
			return nil, fmt.Errorf("COMPLIANCETF_CONFORMANCE_RPCSEQ and COMPLIANCETF_CONFORMANCE_EVALUATOR are exclusive")
		}
		return recorder{path: path}, nil
	}
	switch spec {
	case "":
		return hook.Noop{}, nil
	case "lifecycle":
		return lifecycleHook(cfg, version, upstreamVersion), nil
	}
	mode, typ, _ := strings.Cut(spec, ":")
	if (mode != "deny" && mode != "warn") || typ == "" {
		return nil, fmt.Errorf("COMPLIANCETF_CONFORMANCE_EVALUATOR=%q: want lifecycle, deny:<type> or warn:<type>", spec)
	}
	return testEvaluator{deny: mode == "deny", typ: typ, spec: spec}, nil
}

type testEvaluator struct {
	hook.Noop
	deny      bool
	typ, spec string
}

func (e testEvaluator) Wants(kind hook.Kind, typeName string) bool {
	return kind == hook.KindResource && typeName == e.typ
}

func (e testEvaluator) Evaluate(_ context.Context, req *hook.Request) (*hook.Result, error) {
	if req.Kind != hook.KindResource || req.TypeName != e.typ {
		return &hook.Result{}, nil
	}
	switch {
	case e.deny && req.Stage == hook.StageApplyPre:
		return result(hook.SeverityError, "deny", fmt.Sprintf("%s blocks apply_pre of %s.", e.spec, e.typ)), nil
	case !e.deny && (req.Stage == hook.StagePlan || req.Stage == hook.StageApplyPre):
		return result(hook.SeverityWarning, "warn", fmt.Sprintf("%s at %s of %s.", e.spec, req.Stage, e.typ)), nil
	}
	return &hook.Result{}, nil
}

// recorder wants every type and appends one JSON line per hook call to path:
// what the lifecycle sees (stage, op, envelope op and imported mark, value
// nullness), never a value. It finds nothing. The rpcseq goldens are made of these lines.
type recorder struct {
	hook.Noop
	path string
}

// recordMu orders the calls of this process. Other provider processes append
// to the same file; one O_APPEND write per line keeps their lines whole, and
// the runner fails a step whose processes overlap (procOrdinals).
var recordMu sync.Mutex

func (recorder) Wants(hook.Kind, string) bool { return true }

func (r recorder) Evaluate(_ context.Context, req *hook.Request) (*hook.Result, error) {
	line := struct {
		Stage           hook.Stage `json:"stage"`
		Kind            hook.Kind  `json:"kind,omitempty"`
		Type            string     `json:"type"`
		Op              hook.Op    `json:"op,omitempty"`
		EnvelopeOp      string     `json:"envelope_op,omitempty"`
		Imported        bool       `json:"imported,omitempty"`
		Config          string     `json:"config,omitempty"`
		Prior           string     `json:"prior,omitempty"`
		Planned         string     `json:"planned,omitempty"`
		New             string     `json:"new,omitempty"`
		RequiresReplace int        `json:"requires_replace,omitempty"`
		Deferred        bool       `json:"deferred,omitempty"`
		PID             int        `json:"pid"` // the runner turns it into a per-step process ordinal
	}{
		PID:   os.Getpid(),
		Stage: req.Stage, Type: req.TypeName, Op: req.Op,
		Config: nullness(req.Config), Prior: nullness(req.Prior), Planned: nullness(req.Planned), New: nullness(req.New),
		RequiresReplace: len(req.RequiresReplace), Deferred: req.Deferred,
	}
	if req.Kind != hook.KindResource {
		line.Kind = req.Kind
	}
	if req.Stage == hook.StageApplyPre {
		line.EnvelopeOp = "absent"
		if req.Envelope != nil {
			line.EnvelopeOp, line.Imported = string(req.Envelope.CTF.Op), req.Envelope.CTF.Imported
		}
	}
	b, err := json.Marshal(line)
	if err != nil {
		return nil, err
	}
	recordMu.Lock()
	defer recordMu.Unlock()
	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	_, err = f.Write(append(b, '\n'))
	return &hook.Result{}, errors.Join(err, f.Close())
}

// nullness is "" for a value absent at this stage, else "null", "set" or
// "undecodable".
func nullness(v *hook.Value) string {
	if v == nil {
		return ""
	}
	tv, err := v.Get()
	switch {
	case err != nil:
		return "undecodable"
	case tv.IsNull():
		return "null"
	}
	return "set"
}

func result(sev hook.Severity, mode, detail string) *hook.Result {
	return &hook.Result{Diagnostics: []hook.Diagnostic{{Severity: sev, Summary: "Conformance test evaluator: " + mode, Detail: detail}}}
}
