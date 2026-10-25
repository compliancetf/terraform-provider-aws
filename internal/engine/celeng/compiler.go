package celeng

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

// SchemaSource is the upstream schema lookup (the 0A hook.SchemaSource
// method set; the lifecycle passes ConfigureRequest.Schemas).
type SchemaSource interface {
	Resource(typ string) (*tfprotov5.Schema, bool)
	DataSource(typ string) (*tfprotov5.Schema, bool)
	EphemeralResource(typ string) (*tfprotov5.Schema, bool)
}

// Compiler is celeng registered as the 0B engine.Compiler. It loads
// each control once against its upstream schema and keeps the result, a
// program or the error, so a control that does not compile fails the same
// way for every resource without loading again. The lifecycle runs
// Precompile at Configure, so the per-resource budget covers evaluation and
// a cache lookup only. All controls share the one CEL env (newEnv). An
// iam.* control compiles against the iam-actions.json of its own bundle.
type Compiler struct {
	schemas SchemaSource       // nil: no control compiles
	set     *bundle.ControlSet // nil: no control has an action catalog
	digest  string             // the set's content digest: memo and IAM document cache key part
	done    sync.Map           // sha256 of the control JSON -> compiled
	blocks  sync.Map           // target -> *tfprotov5.SchemaBlock (nil: none), looked up by compile or Paths
}

type compiled struct {
	p   engine.Program
	err error
}

var _ engine.Compiler = (*Compiler)(nil)

// NewCompiler returns the cel compiler over the upstream schemas, without
// action catalogs.
func NewCompiler(schemas SchemaSource) *Compiler { return NewCompilerFor(schemas, nil, "") }

// NewCompilerFor returns the cel compiler over the upstream schemas for the
// controls of set: each control gets its bundle's action catalog
// (ControlSet.IAMCatalog). contentDigest is the set's content digest
// (ControlSet.ContentDigest with the effective coverable map); it keys the
// prefilter memo and the IAM document cache. One Compiler serves one set; its
// cache is keyed by control content only.
func NewCompilerFor(schemas SchemaSource, set *bundle.ControlSet, contentDigest string) *Compiler {
	return &Compiler{schemas: schemas, set: set, digest: contentDigest}
}

func (*Compiler) ID() string { return "cel" }

// noBudget leaves the per-resource deadline to the caller's context, where
// the lifecycle sets the profile budget; Eval falls back to defaultBudget
// for a context without a deadline.
const noBudget = 24 * time.Hour

// Compile loads c against the upstream schema of its kind and type. schema
// is the bound value's type; the converter checks values against the
// upstream block, so a value of another type evaluates to type_error. A type
// or read path the upstream schema lacks is a *engine.CompileError of class
// no_such_attribute (load warnings control_schema_type_missing and
// control_schema_path_missing); control_reads_unused stays a warning.
func (cc *Compiler) Compile(c *bundle.Control, _ tftypes.Type) (engine.Program, error) {
	if c == nil || c.Expr == nil {
		return nil, errors.New("celeng: not an expr control")
	}
	data, err := json.Marshal(c) // the whole control: one key per control content
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(data)
	if v, ok := cc.done.Load(key); ok {
		if r, ok := v.(compiled); ok { // only compiled is stored
			return r.p, r.err
		}
	}
	p, err := cc.compile(c)
	// Concurrent first calls may both compile; the first stored result wins.
	if v, loaded := cc.done.LoadOrStore(key, compiled{p, err}); loaded {
		if r, ok := v.(compiled); ok {
			return r.p, r.err
		}
	}
	return p, err
}

// Precompile compiles and plans every control of cs and keeps each result,
// error included; Compile then returns it from the cache.
func (cc *Compiler) Precompile(cs []bundle.Control) {
	for i := range cs {
		_, _ = cc.Compile(&cs[i], nil) //nolint:errcheck // kept for Compile
	}
}

// CheckCatalogs rejects the first control of cs that calls an iam.*
// function while catalog(c), its bundle's iam-actions.json, is nil:
// *LoadDiag iam_catalog_missing. It
// reads the parsed expression only, so it needs no schema and holds for a
// control that fails a later load check; Configure runs it before it records
// the bundles as accepted, and cmd/ctfbundle build before it signs.
func CheckCatalogs(cs []bundle.Control, catalog func(*bundle.Control) *iampolicy.Catalog) error {
	env, err := newEnv()
	if err != nil {
		return fmt.Errorf("celeng: env: %w", err)
	}
	for i := range cs {
		if cs[i].Expr == nil || catalog(&cs[i]) != nil {
			continue
		}
		// An expr that does not parse calls nothing; it fails its own load.
		if a, iss := env.Parse(*cs[i].Expr); iss.Err() == nil && parsedCallsIAM(a.NativeRep().Expr()) {
			return &LoadDiag{ControlID: cs[i].ID, Code: "iam_catalog_missing",
				Detail: "the bundle has iam.* controls and no iam-actions.json"}
		}
	}
	return nil
}

func (cc *Compiler) compile(c *bundle.Control) (engine.Program, error) {
	if cc.schemas == nil {
		return nil, fmt.Errorf("control %s: no upstream schema source", c.ID)
	}
	lookup := cc.schemas.Resource
	switch c.Kind {
	case bundle.KindDataSource:
		lookup = cc.schemas.DataSource
	case bundle.KindEphemeral:
		lookup = cc.schemas.EphemeralResource
	}
	resp := &tfprotov5.GetProviderSchemaResponse{ResourceSchemas: map[string]*tfprotov5.Schema{},
		DataSourceSchemas: map[string]*tfprotov5.Schema{}, EphemeralResourceSchemas: map[string]*tfprotov5.Schema{}}
	var b *tfprotov5.SchemaBlock
	if sc, ok := lookup(c.ResourceType); ok {
		kindSchemas(c.Kind, resp)[c.ResourceType] = sc
		b = sc.Block
	}
	cc.blocks.Store(target{c.Kind, c.ResourceType}, b)
	var content Content
	if cc.set != nil {
		content = Content{Digest: cc.digest, IAMCatalog: cc.set.IAMCatalog(c)}
	}
	compiled, diags, err := New(Options{PerResourceBudget: noBudget}).Load([]bundle.Control{*c}, resp, content)
	if err != nil {
		return nil, fmt.Errorf("control %s: %w", c.ID, err)
	}
	for _, d := range diags {
		if d.Code == "control_schema_type_missing" || d.Code == "control_schema_path_missing" {
			return nil, &engine.CompileError{Class: engine.ErrNoSuchAttribute, Err: &d}
		}
	}
	for _, plan := range compiled.programs {
		plan() // plan the cel.Program now, not inside the first Eval's budget
	}
	return &compiledProgram{c: compiled, kind: c.Kind, typ: c.ResourceType}, nil
}

// Paths is c's declared reads, each cut by mapCut in its upstream schema,
// so evidence that records them never names a map key. The
// schema block compile looked up is reused: after Precompile, Paths looks
// nothing up. No schema keeps the reads.
func (cc *Compiler) Paths(c *bundle.Control) []string {
	k := target{c.Kind, c.ResourceType}
	v, ok := cc.blocks.Load(k)
	if !ok {
		var b *tfprotov5.SchemaBlock
		if sc := schemaOf(cc.schemas, c.Kind, c.ResourceType); sc != nil {
			b = sc.Block
		}
		v, _ = cc.blocks.LoadOrStore(k, b)
	}
	var b *tfprotov5.SchemaBlock
	if x, ok := v.(*tfprotov5.SchemaBlock); ok { // only blocks are stored
		b = x
	}
	out := make([]string, 0, len(c.Reads))
	for _, p := range c.Reads {
		out = append(out, mapCut(b, p))
	}
	return out
}

type compiledProgram struct {
	c    *Compiled
	kind bundle.Kind
	typ  string
}

// Eval maps the 0B Activation onto Bindings and runs the one control.
func (p *compiledProgram) Eval(ctx context.Context, a *engine.Activation) engine.Outcome {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultBudget)
		defer cancel()
	}
	rs := p.c.Evaluate(ctx, Bindings{Kind: p.kind, Type: p.typ, Resource: a.Resource, Config: a.Config, Prior: a.Prior,
		Op: string(a.Op), Env: a.Env, EnvKnown: a.EnvKnown, Provider: a.Provider}, nil)
	if len(rs) != 1 {
		// The Compiled holds exactly this control under (kind, type); any
		// other count means the control did not resolve to one program.
		return engine.Outcome{State: engine.NotEvaluable, Err: engine.ErrUnresolved}
	}
	return engine.Outcome{State: rs[0].State, Err: rs[0].ErrClass, UnknownPaths: rs[0].UnknownPaths}
}
