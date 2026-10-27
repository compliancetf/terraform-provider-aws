package celeng

import (
	"fmt"
	"sync"

	"cel.dev/cel-go/cel"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
)

// companionEnv binds companion only: a graph control's companion_expr sees
// the companion's values and nothing else.
var companionEnv = sync.OnceValues(func() (*cel.Env, error) {
	return envWith(cel.Variable(varCompanion, dataMap))
})

// CompanionReads is the reads analysis of a graph control's companion_expr
// over companion schema sc, the analysis a resource control's expr gets:
// the sorted attribute paths it reads. An expression that does not compile
// to bool or dyn is control_expr; one whose reads cannot be bounded (a
// dynamic access, or a use that sees an object's key set) is
// control_dynamic_access. A read the schema lacks is returned; the caller
// resolves it.
func CompanionReads(expr string, sc *tfprotov5.Schema) ([]string, error) {
	if sc == nil || sc.Block == nil {
		return nil, fmt.Errorf("celeng: companion schema has no block")
	}
	env, err := companionEnv()
	if err != nil {
		return nil, fmt.Errorf("celeng: env: %w", err)
	}
	a, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, &LoadDiag{Code: "control_expr", Detail: "companion_expr does not parse or type-check"}
	}
	if t := a.OutputType(); !t.IsExactType(cel.BoolType) && !t.IsExactType(cel.DynType) {
		return nil, &LoadDiag{Code: "control_expr", Detail: "companion_expr output type is not bool or dyn"}
	}
	ch, err := analyzeIn(a, companionVars)
	if err != nil {
		return nil, err
	}
	reads, err := schemaReads(sc.Block, ch)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(reads))
	for i, r := range reads {
		out[i] = r.Path
	}
	return out, nil
}
