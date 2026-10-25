package engine_test

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/pkg/engine"
)

func Example() {
	// One type's schema from `terraform providers schema -json`.
	schema, err := engine.SchemaFromJSON([]byte(`{"block": {"attributes": {
		"identifier": {"type": "string", "optional": true},
		"tags": {"type": ["map", "string"], "optional": true}}}}`))
	if err != nil {
		panic(err)
	}
	sel, err := engine.CompileSelector(`type == 'aws_db_instance' && resource.identifier.startsWith('legacy-') && env == 'prod'`)
	if err != nil {
		panic(err)
	}
	typ := schema.ValueType()
	res := tftypes.NewValue(typ, map[string]tftypes.Value{
		"identifier": tftypes.NewValue(tftypes.String, "legacy-orders"),
		"tags":       tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, nil),
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, env := range []string{"prod", "dev"} {
		out := sel.Eval(ctx, &engine.Input{Type: "aws_db_instance", Schema: schema, Resource: res, Config: res,
			Op: "update", Env: env, EnvKnown: true})
		fmt.Println(env, out.State)
	}
	unknownEnv := sel.Eval(ctx, &engine.Input{Type: "aws_db_instance", Schema: schema, Resource: res, Op: "update"})
	fmt.Println("untrusted", unknownEnv.State, unknownEnv.Err)
	// Output:
	// prod pass
	// dev fail
	// untrusted not_evaluable scope_untrusted
}
