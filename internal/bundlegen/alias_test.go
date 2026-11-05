package bundlegen

import (
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

const (
	aliasID    = "rds_bobthecorp_storage_encrypted"
	lbListener = "aws_lb_listener"
	albListen  = "aws_alb_listener"
)

// lbInputs moves the fixture's authored rds control (and its disposition
// and fixtures) to aws_lb_listener, with the db schema as both
// aws_lb_listener and its alias aws_alb_listener (identical unless
// aliasSchema edits it).
func lbInputs(t *testing.T, targets []string, aliasSchema func(*tfprotov5.Schema)) Inputs {
	t.Helper()
	in := loadInputs(t, inputs, true)
	rs := in.Schemas.ProviderSchema().ResourceSchemas
	db, _ := LoadSchemas(inputs + "/schema.json") // a second copy: never shared with lbListener
	rs[lbListener] = rs["aws_db_instance"]
	alias, _ := db.Resource("aws_db_instance")
	if aliasSchema != nil {
		aliasSchema(alias)
	}
	rs[albListen] = alias
	d := in.Catalog.Dispositions.Controls[aliasID]
	d.Targets = nil
	for _, typ := range targets {
		d.Targets = append(d.Targets, Target{Kind: "resource", Type: typ})
	}
	in.Catalog.Dispositions.Controls[aliasID] = d
	var cs []bundle.Control
	var fx []Fixture
	for _, typ := range targets {
		for _, c := range in.Authored[aliasID] {
			c.ResourceType = typ
			cs = append(cs, c)
		}
		for _, x := range in.AuthoredFixtures[aliasID] {
			x.Type = typ
			fx = append(fx, x)
		}
	}
	in.Authored[aliasID], in.AuthoredFixtures[aliasID] = cs, fx
	return in
}

func controlsOf(t *testing.T, files map[string][]byte, bundleID, id string) []bundle.Control {
	t.Helper()
	cs, err := bundle.ParseControls(files[bundleID+"/controls.json"])
	if err != nil {
		t.Fatal(err)
	}
	return slices.DeleteFunc(cs, func(c bundle.Control) bool { return c.ID != id })
}

// TestAliasMirror: a control on aws_lb_listener ships on aws_alb_listener
// too, with the same version and renamed cases, in every bundle that has
// it; the engine denies a non-compliant aws_alb_listener with it, and
// coverage, the lock and the review queue are those of the canonical
// control alone.
func TestAliasMirror(t *testing.T) {
	in := lbInputs(t, []string{lbListener}, nil)
	files := generate(t, in)
	for _, b := range []string{"cis-aws", "soc2-aws", "all"} {
		cs := controlsOf(t, files, b, aliasID)
		if len(cs) != 2 || cs[0].ResourceType != albListen || cs[1].ResourceType != lbListener {
			t.Fatalf("%s: controls %v, want %s on %s and %s", b, cs, aliasID, albListen, lbListener)
		}
		m := cs[0]
		m.ResourceType = lbListener
		if want, _ := canonicalJSON(cs[1]); string(want) != string(must(canonicalJSON(m))) {
			t.Fatalf("%s: the mirror differs from the canonical control beyond its type", b)
		}
		for _, name := range []string{"pass", "fail"} {
			p := b + "/cases/" + aliasID + "/resource." + albListen + "." + name + ".json"
			var k Case
			if err := decodeStrict(files[p], &k); err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			if k.ResourceType != albListen || k.Control.ResourceType != albListen || k.ID != aliasID+".resource."+albListen+"."+name {
				t.Fatalf("%s: case %s on %s", p, k.ID, k.ResourceType)
			}
		}
	}

	// the engine enforces the mirror on an aws_alb_listener plan
	cs, err := bundle.ParseControls(files["all/controls.json"])
	if err != nil {
		t.Fatal(err)
	}
	content := celeng.Content{IAMCatalog: must(iampolicy.LoadCatalog(in.IAMActions))}
	if content.Digest, err = ContentDigest("all", bundleFiles(files, "all")); err != nil {
		t.Fatal(err)
	}
	comp, diags, err := verifyEngine().Load(exprControls(cs), in.Schemas.ProviderSchema(), content)
	if err != nil || len(diags) > 0 {
		t.Fatalf("load: %v %v", diags, err)
	}
	sc, _ := in.Schemas.Resource(albListen)
	for v, want := range map[bool]engine.State{false: engine.Fail, true: engine.Pass} {
		plan := tftypes.NewValue(sc.Block.ValueType(), map[string]tftypes.Value{"storage_encrypted": tftypes.NewValue(tftypes.Bool, v)})
		b := celeng.Bindings{Kind: bundle.KindResource, Type: albListen, Op: string(bundle.OnCreate), Resource: plan, Config: plan}
		if got := evalOne(comp, b, aliasID).State; got != want {
			t.Errorf("aws_alb_listener storage_encrypted %v: %s, want %s", v, got, want)
		}
	}

	// counts, lock and queue as without the alias type
	plain := lbInputs(t, []string{lbListener}, nil)
	delete(plain.Schemas.ProviderSchema().ResourceSchemas, albListen)
	ref := generate(t, plain)
	for _, f := range []string{"coverage.json", "coverage.md", LockFile, "review-queue.md", "review-sheet.md"} {
		if string(files[f]) != string(ref[f]) {
			t.Errorf("%s differs with the alias mirrored", f)
		}
	}
	if len(controlsOf(t, ref, "all", aliasID)) != 1 {
		t.Fatal("without the alias type in the schema nothing is mirrored")
	}
}

// TestAliasExplicitTarget: an alias target the disposition names keeps its
// own control and is not mirrored over; one the authored file leaves out
// is filled by the mirror, not queued as a partial target.
func TestAliasExplicitTarget(t *testing.T) {
	in := lbInputs(t, []string{lbListener, albListen}, nil)
	own := "resource.storage_encrypted != false"
	for i := range in.Authored[aliasID] {
		if in.Authored[aliasID][i].ResourceType == albListen {
			in.Authored[aliasID][i].Expr = &own
		}
	}
	cs := controlsOf(t, generate(t, in), "all", aliasID)
	if len(cs) != 2 || cs[0].ResourceType != albListen || *cs[0].Expr != own {
		t.Fatalf("explicit alias target: %v", cs)
	}

	in = lbInputs(t, []string{lbListener, albListen}, nil)
	in.Authored[aliasID] = slices.DeleteFunc(in.Authored[aliasID], func(c bundle.Control) bool { return c.ResourceType == albListen })
	out, err := Generate(in, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.ReviewQueue) != 0 || len(controlsOf(t, out.Files, "all", aliasID)) != 2 {
		t.Fatalf("queue %v, controls %v", out.ReviewQueue, controlsOf(t, out.Files, "all", aliasID))
	}
	if !strings.Contains(string(out.Files["coverage.md"]), "| cis-aws | ga | 2 | 1 |") {
		t.Fatalf("the mirrored target does not count as generated:\n%s", out.Files["coverage.md"])
	}
}

// TestAliasSchemaMismatch: an alias whose schema differs from its
// canonical type fails E_ALIAS_SCHEMA instead of mirroring.
func TestAliasSchemaMismatch(t *testing.T) {
	in := lbInputs(t, []string{lbListener}, func(s *tfprotov5.Schema) {
		s.Block.Attributes[0].Optional, s.Block.Attributes[0].Required = false, true
	})
	if out, err := Generate(in, testOpts); errCode(err) != "E_ALIAS_SCHEMA" || out != nil || !strings.Contains(err.Error(), albListen) {
		t.Fatalf("err = %v, want E_ALIAS_SCHEMA naming %s", err, albListen)
	}
}

// TestPruneKeepsAliases: pruning by controls on a canonical type keeps its
// alias type, so a pruned schema can carry the mirror.
func TestPruneKeepsAliases(t *testing.T) {
	raw := []byte(`{"format_version":"1.0","provider_schemas":{"registry.terraform.io/hashicorp/aws":{` +
		`"resource_schemas":{"aws_lb_listener":{"version":0,"block":{}},"aws_alb_listener":{"version":0,"block":{}},"aws_alb":{"version":0,"block":{}}},` +
		`"data_source_schemas":{},"ephemeral_resource_schemas":{}}}}`)
	data, err := PruneSchema(raw, []bundle.Control{testControl("ctf_lb", lbListener, "true", bundle.PresenceEffective)})
	if err != nil {
		t.Fatal(err)
	}
	if s := string(data); !strings.Contains(s, `"aws_alb_listener": {`) || strings.Contains(s, `"aws_alb": {`) {
		t.Fatalf("pruned:\n%s", s)
	}
}

func must[T any](b T, err error) T {
	if err != nil {
		panic(err)
	}
	return b
}
