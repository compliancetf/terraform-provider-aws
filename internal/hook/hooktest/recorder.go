// Package hooktest provides the test evaluator: it records every call and
// answers with scripted diagnostics.
package hooktest

import (
	"context"
	"sync"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
)

// Recorder is a hook.Evaluator for tests. Wanted lists the type names Wants
// returns true for (nil: every type). Respond, when set, answers Evaluate;
// otherwise Evaluate returns an empty Result.
type Recorder struct {
	Wanted       []string
	Respond      func(*hook.Request) (*hook.Result, error)
	OnConfigure  func(*hook.ConfigureRequest) ([]hook.Diagnostic, error)
	mu           sync.Mutex
	requests     []*hook.Request
	configureReq []*hook.ConfigureRequest
}

var _ hook.Evaluator = (*Recorder)(nil)

func (r *Recorder) Configure(_ context.Context, req *hook.ConfigureRequest) ([]hook.Diagnostic, error) {
	r.mu.Lock()
	r.configureReq = append(r.configureReq, req)
	r.mu.Unlock()
	if r.OnConfigure != nil {
		return r.OnConfigure(req)
	}
	return nil, nil
}

func (r *Recorder) Wants(_ hook.Kind, typeName string) bool {
	if r.Wanted == nil {
		return true
	}
	for _, t := range r.Wanted {
		if t == typeName {
			return true
		}
	}
	return false
}

func (r *Recorder) Evaluate(_ context.Context, req *hook.Request) (*hook.Result, error) {
	r.mu.Lock()
	r.requests = append(r.requests, req)
	r.mu.Unlock()
	if r.Respond != nil {
		return r.Respond(req)
	}
	return &hook.Result{}, nil
}

// Requests returns the Evaluate requests in call order.
func (r *Recorder) Requests() []*hook.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*hook.Request(nil), r.requests...)
}

// Stages returns the stage of each Evaluate call in order.
func (r *Recorder) Stages() []hook.Stage {
	var out []hook.Stage
	for _, q := range r.Requests() {
		out = append(out, q.Stage)
	}
	return out
}

// Configures returns the Configure requests in call order.
func (r *Recorder) Configures() []*hook.ConfigureRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*hook.ConfigureRequest(nil), r.configureReq...)
}

// Deny answers every request with one error diagnostic.
func Deny(summary string) func(*hook.Request) (*hook.Result, error) {
	return func(*hook.Request) (*hook.Result, error) {
		return &hook.Result{Diagnostics: []hook.Diagnostic{{Severity: hook.SeverityError, Summary: summary}}}, nil
	}
}
