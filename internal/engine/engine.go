// Package engine is the expression-engine contract between internal/lifecycle
// and its compiler, celeng (ID "cel"). The engine never sees
// mode, exceptions or stage; lifecycle never inspects an expression.
package engine

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// State is the result of evaluating one control against one resource.
type State uint8

const (
	Pass State = iota
	Fail
	Unknown
	NotEvaluable
)

var stateNames = [...]string{Pass: "pass", Fail: "fail", Unknown: "unknown", NotEvaluable: "not_evaluable"}

func (s State) String() string {
	if int(s) < len(stateNames) {
		return stateNames[s]
	}
	return fmt.Sprintf("State(%d)", uint8(s))
}

func (s State) MarshalText() ([]byte, error) {
	if int(s) >= len(stateNames) {
		return nil, fmt.Errorf("invalid state %d", uint8(s))
	}
	return []byte(stateNames[s]), nil
}

func (s *State) UnmarshalText(b []byte) error {
	for i, n := range stateNames {
		if n == string(b) {
			*s = State(i)
			return nil
		}
	}
	return fmt.Errorf("state %q: want pass, fail, unknown or not_evaluable", b)
}

// ErrClass says why a result is NotEvaluable (or "" when it is not).
type ErrClass string

const (
	ErrNone            ErrClass = ""
	ErrTypeError       ErrClass = "type_error"
	ErrLimit           ErrClass = "limit"
	ErrTimeout         ErrClass = "timeout"
	ErrNoSuchAttribute ErrClass = "no_such_attribute"
	ErrUnresolved      ErrClass = "unresolved"
	ErrScopeUntrusted  ErrClass = "scope_untrusted"
)

// Op is the operation classification (parent 5.6). It is a superset of the
// 0A hook.Op values; no-op and refresh are lifecycle refinements for evidence,
// and open is the op of an ephemeral resource open.
type Op string

const (
	OpCreate  Op = "create"
	OpUpdate  Op = "update"
	OpReplace Op = "replace"
	OpDelete  Op = "delete"
	OpNoOp    Op = "no-op"
	OpImport  Op = "import"
	OpRefresh Op = "refresh"
	OpChange  Op = "change"
	OpOpen    Op = "open"
	OpRead    Op = "read" // a data source read: evidence only, data source controls bind no op
)

// Activation is the input of one evaluation.
type Activation struct {
	Resource tftypes.Value // value chosen by lifecycle per stage and presence_mode
	Config   tftypes.Value
	Prior    tftypes.Value
	Op       Op
	Env      string // trusted environment only (Scope binding)
	EnvKnown bool   // false without trusted scope: the engine treats env as unknown
	Provider ProviderInfo
	// RegionFromResource: a deletion guard (delete or replace) binds the
	// region of Resource (prior), never of Config, so plan and
	// the apply destroy RPC agree.
	RegionFromResource bool
}

// ProviderInfo is bound as provider.region, provider.account_id and
// provider.partition (aws, aws-cn, aws-us-gov, ...); a field not known is
// unknown.
type ProviderInfo struct {
	Region, AccountID, Partition              string
	RegionKnown, AccountKnown, PartitionKnown bool
}

// Outcome is the result of one evaluation.
type Outcome struct {
	State        State
	Err          ErrClass
	UnknownPaths []string // read paths that were unknown; never values
}

// Program is a compiled control.
type Program interface {
	Eval(ctx context.Context, a *Activation) Outcome
}

// Compiler turns a control into a Program for one resource schema.
type Compiler interface {
	ID() string // "cel"
	Compile(c *bundle.Control, schema tftypes.Type) (Program, error)
}

// CompileError is a Compile failure whose not_evaluable outcome has a known
// class (a type or read path missing from the upstream schema is
// no_such_attribute). The lifecycle maps any other Compile error to
// unresolved.
type CompileError struct {
	Class ErrClass
	Err   error
}

func (e *CompileError) Error() string {
	if e.Err == nil {
		return string(e.Class)
	}
	return e.Err.Error()
}
func (e *CompileError) Unwrap() error { return e.Err }
