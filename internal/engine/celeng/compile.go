// Package celeng is the CEL control engine. This file holds
// the environment, compile with the process-wide AST cache, and the load
// rules that need the checked AST: output type, variables by mode and reads
// coverage. Schema-aware rules and evaluation build on it.
package celeng

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/lib"
)

// Variables bound in every control. resource, config and prior are the data
// variables whose reads are tracked against the control's declared reads.
const (
	varResource = "resource"
	varConfig   = "config"
	varPrior    = "prior"
	varOp       = "op"
	varEnv      = "env"
	varProvider = "provider"
	// varCompanion is the one variable of a graph control's companion_expr
	// (companionVars); a control expr does not bind it.
	varCompanion = "companion"
)

// LoadDiag is a bundle load error or warning for one control. Detail names
// paths and types only, never attribute values. Signed bundle content is not
// secret but is unvalidated input, so Detail never quotes control text either:
// it is a fixed reason that may name the control's kind, resource
// type and presence mode, a bound variable and, through detailf, a path only
// when it is attribute-shaped. A compile error is the error class alone, never
// the cel-go issue text with its source excerpt.
type LoadDiag struct {
	ControlID string
	Code      string // load error id, e.g. control_reads_missing
	Detail    string
}

func (d *LoadDiag) Error() string {
	return fmt.Sprintf("control %s: %s: %s", d.ControlID, d.Code, d.Detail)
}

// pathRe is what a Detail may echo from a control: a dotted attribute path,
// a variable or a resource type.
var pathRe = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*$`)

// safe returns s when it is attribute-shaped and a fixed placeholder
// otherwise (a quoted field, a map key or a string literal).
func safe(s string) string {
	if pathRe.MatchString(s) {
		return s
	}
	return "<non-attribute name>"
}

// detailf is fmt.Sprintf with every argument, whatever its type (named
// string, Stringer, error, []byte...), printed and passed through safe; a
// []string is listed element by element, joined by ", ".
func detailf(format string, a ...any) string {
	args := make([]any, len(a))
	for i, v := range a {
		switch v := v.(type) {
		case []string:
			l := make([]string, len(v))
			for j, s := range v {
				l[j] = safe(s)
			}
			args[i] = strings.Join(l, ", ")
		case []byte:
			args[i] = safe(string(v))
		default:
			args[i] = safe(fmt.Sprint(v))
		}
	}
	return fmt.Sprintf(format, args...)
}

// Read is one AST read: a dotted path under a data variable.
type Read struct {
	Var  string // resource | config | prior
	Path string // e.g. "ingress.cidr_blocks"
}

// Checked is a compiled expression and its static analysis. It is shared by
// every control with the same expr and must not be modified.
type Checked struct {
	Ast   *cel.Ast
	Reads []Read   // sorted by Var then Path, unique
	Vars  []string // every bound variable the expression references, sorted
	uses  []use    // non-select uses of data paths, sorted, unique; Load checks them
	// Keys holds, per read, the constant string keys indexed directly below
	// its path (r["k"]). The read ends at r; load resolves the keys
	// against the schema so a key cannot hide a Computed-only attribute.
	Keys map[Read][]string
	// constant is the control_constant detail when the AST proves
	// a condition always true or false, else "".
	constant string
}

// newEnv builds the one environment every control compiles in:
// standard library, ext.Strings with size-capped replace, join and format,
// default macros, optional types and
// ext.Bindings off (no cel.bind fork A1).
var newEnv = sync.OnceValues(func() (*cel.Env, error) {
	return envWith(
		cel.Variable(varResource, dataMap),
		cel.Variable(varConfig, dataMap),
		cel.Variable(varPrior, dataMap),
		cel.Variable(varOp, cel.StringType),
		cel.Variable(varEnv, cel.StringType),
		cel.Variable(varProvider, cel.MapType(cel.StringType, cel.StringType)),
	)
})

var dataMap = cel.MapType(cel.StringType, cel.DynType)

// envWith is an environment with the given variables and the libraries
// every expression compiles with.
func envWith(vars ...cel.EnvOption) (*cel.Env, error) {
	caps, err := stringCaps()
	if err != nil {
		return nil, err
	}
	return cel.NewEnv(append(vars, ext.Strings(), caps, lib.Helpers(), lib.JSON(), lib.IAM(), cel.ParserRecursionLimit(64))...)
}

// astCache maps sha256(expr) to *Checked for the process lifetime: one entry
// per distinct expression of every bundle loaded.
var astCache = struct {
	sync.Mutex
	m map[[sha256.Size]byte]*Checked
}{m: map[[sha256.Size]byte]*Checked{}}

// check parses, type-checks and analyzes one expression, through the cache.
func check(expr string) (*Checked, error) { return checkLint(expr, true) }

// checkLint is check with the iam polarity lint switchable. Without the
// lint (verify mutants only, LoadMutant) the cache is neither read nor
// written, so an unlinted result never reaches a provider Load.
func checkLint(expr string, lintPolarity bool) (*Checked, error) {
	key := sha256.Sum256([]byte(expr))
	if lintPolarity {
		astCache.Lock()
		hit := astCache.m[key]
		astCache.Unlock()
		if hit != nil {
			return hit, nil
		}
	}
	env, err := newEnv()
	if err != nil {
		return nil, fmt.Errorf("celeng: env: %w", err)
	}
	a, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, &LoadDiag{Code: "control_expr", Detail: "expr does not parse or type-check"}
	}
	if t := a.OutputType(); !t.IsExactType(cel.BoolType) && !t.IsExactType(cel.DynType) {
		return nil, &LoadDiag{Code: "control_expr", Detail: "expr output type is not bool or dyn"}
	}
	if lintPolarity {
		if err := polarity(a.NativeRep().Expr()); err != nil {
			return nil, err
		}
	}
	c, err := analyze(a)
	if err != nil {
		return c, err // c is non-nil for a reads-analysis rejection
	}
	c.constant = constant(a.NativeRep())
	if !lintPolarity {
		return c, nil
	}
	astCache.Lock()
	defer astCache.Unlock()
	if hit := astCache.m[key]; hit != nil {
		return hit, nil
	}
	astCache.m[key] = c
	return c, nil
}

// allowedVars is the Control 2.0 variable-by-mode table.
func allowedVars(c *bundle.Control) []string {
	switch {
	case c.Kind == bundle.KindResource && c.PresenceMode == bundle.PresenceEffective:
		return []string{varResource, varPrior, varOp, varEnv, varProvider}
	case c.Kind == bundle.KindResource && c.PresenceMode == bundle.PresenceConfigured:
		return []string{varConfig, varPrior, varOp, varEnv, varProvider}
	case c.Kind == bundle.KindDeletionGuard:
		return []string{varPrior, varOp, varEnv, varProvider}
	case c.Kind == bundle.KindDataSource && c.PresenceMode == bundle.PresenceEffective:
		return []string{varResource, varEnv, varProvider}
	case c.Kind == bundle.KindDataSource && c.PresenceMode == bundle.PresenceConfigured:
		return []string{varConfig, varEnv, varProvider}
	case c.Kind == bundle.KindEphemeral:
		return []string{varConfig, varEnv, varProvider}
	}
	return nil // a control DecodeControls would reject
}

// Compile checks one decoded control: expr compiles to bool or dyn, its
// variables fit the kind and presence mode, and every AST read is covered by
// a declared read. Warnings (control_reads_unused, control_constant) come
// back as diags. The error is a *LoadDiag for load errors.
func Compile(c *bundle.Control) (*Checked, []LoadDiag, error) { return compile(c, true) }

func compile(c *bundle.Control, lintPolarity bool) (*Checked, []LoadDiag, error) {
	fail := func(code, format string, a ...any) error {
		return &LoadDiag{ControlID: c.ID, Code: code, Detail: detailf(format, a...)}
	}
	if c.Expr == nil {
		return nil, nil, fail("control_expr", "control has no expr")
	}
	ch, err := checkLint(*c.Expr, lintPolarity)
	if d, ok := err.(*LoadDiag); ok {
		// ch is non-nil only when reads analysis rejected the expression
		// (analyzer.erasedErr): Load still schema-checks it so a deny on
		// Computed-only attributes reports control_computed_only.
		return ch, nil, &LoadDiag{ControlID: c.ID, Code: d.Code, Detail: d.Detail}
	}
	if err != nil {
		return nil, nil, err
	}
	allowed := allowedVars(c)
	for _, v := range ch.Vars {
		if !slices.Contains(allowed, v) {
			return nil, nil, fail("control_vars", "%s control (presence_mode %q) must not reference %s", c.Kind, c.PresenceMode, v)
		}
	}
	// Coverage (fork C1): a declared read covers an AST read when it is a
	// segment prefix of it. Memo keys, UnknownPaths and the Computed-only
	// rule use the AST reads, never the declared ones.
	used := make([]bool, len(c.Reads))
	for _, r := range ch.Reads {
		covered := false
		for i, d := range c.Reads {
			if segPrefix(d, r.Path) {
				covered, used[i] = true, true
			}
		}
		if !covered {
			return nil, nil, fail("control_reads_missing", "%s.%s is not covered by reads", r.Var, r.Path)
		}
	}
	var diags []LoadDiag
	for i, d := range c.Reads {
		if !used[i] {
			diags = append(diags, LoadDiag{ControlID: c.ID, Code: "control_reads_unused", Detail: detailf("read %s is not used by expr", d)})
		}
	}
	// A deny control that never or always fires is an authoring mistake;
	// a warning only, so a control that is not provably constant is never
	// rejected.
	if c.Action == bundle.ActionDeny && ch.constant != "" {
		diags = append(diags, LoadDiag{ControlID: c.ID, Code: "control_constant", Detail: ch.constant})
	}
	return ch, diags, nil
}

// segPrefix reports whether dotted path p equals q or is a segment prefix of it.
func segPrefix(p, q string) bool {
	return p == q || strings.HasPrefix(q, p+".")
}
