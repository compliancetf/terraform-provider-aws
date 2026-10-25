package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// classificationRule is what the lifecycle sees in the last step of every
// rpcseq scenario, as recorded on Terraform 1.5, 1.10, 1.16 and OpenTofu 1.13
// (identical on all four): every hook call except validate, in order, as
// "read", "import <op>", "plan <op> <prior> <planned> rr=<requires_replace>",
// "apply_pre <op> <envelope op> <prior> <planned>[ imported]" or "apply_post <op> <new>".
//
// What it fixes:
//   - Replace without create_before_destroy (requires_replace, -replace and
//     tainted alike): Core re-plans the create half with a null prior, so
//     the destroy RPC carries that create plan's envelope; the create RPC is
//     a plain "create". For requires_replace and -replace the re-plan's
//     PriorPrivate is the first plan's envelope, whose prior identity the
//     re-plan envelope carries under op "replace", so that
//     destroy RPC is classified "replace". A tainted object has no first
//     plan: its destroy RPC carries a plain create envelope and is "change".
//   - create_before_destroy: Core plans the destroy separately (PlanDestroy),
//     so the create and delete RPCs carry their own envelopes: "create" then
//     "delete", never "change".
//   - "change" reaches apply_post only on a destroy RPC (new null), never on
//     a create RPC.
//   - An import {} block applies without an ApplyResourceChange: the import
//     step ends at plan, and import, read and plan run in one process, so
//     that plan is classified "import".
//   - An import {} block with a change applies in a new process that
//     re-plans the object as a plain "update": the apply envelope never
//     carries op import or imported.
//   - A CLI terraform import runs in its own process; the later plan is a
//     plain "update" of a pre-existing object.
var classificationRule = map[string][]string{
	"create": {
		"plan create null set rr=0",
		"plan create null set rr=0", "apply_pre create create null set", "apply_post create set",
	},
	"update": {
		"read", "plan update set set rr=0",
		"plan update set set rr=0", "apply_pre update update set set", "apply_post update set",
	},
	"destroy": {
		"read", "plan update set set rr=0",
		"plan delete set null rr=0", "apply_pre delete delete set null", "apply_post delete null",
	},
	"replace": {
		"read", "plan replace set set rr=1", "plan create null set rr=0",
		"apply_pre replace replace set null", "apply_post replace null",
		"plan create null set rr=0", "apply_pre create create null set", "apply_post create set",
	},
	"replace_flag": {
		"read", "plan update set set rr=0", "plan create null set rr=0",
		"apply_pre replace replace set null", "apply_post replace null",
		"plan create null set rr=0", "apply_pre create create null set", "apply_post create set",
	},
	"tainted": {
		"read", "plan create null set rr=0",
		"apply_pre change create set null", "apply_post change null",
		"plan create null set rr=0", "apply_pre create create null set", "apply_post create set",
	},
	"cbd": {
		"read", "plan replace set set rr=1", "plan create null set rr=0",
		"plan create null set rr=0", "apply_pre create create null set", "apply_post create set",
		"plan delete set null rr=0", "apply_pre delete delete set null", "apply_post delete null",
	},
	"import": {"import import", "read", "plan import set set rr=0"},
	"import_change": {
		"import import", "read", "plan import set set rr=0",
		"plan update set set rr=0", "apply_pre update update set set", "apply_post update set",
	},
	"import_cli": {"read", "plan update set set rr=0"},
	"refresh":    {"read"},
}

type rpcseqCall struct {
	Stage           string `json:"stage"`
	Op              string `json:"op"`
	EnvelopeOp      string `json:"envelope_op"`
	Imported        bool   `json:"imported"`
	Prior           string `json:"prior"`
	Planned         string `json:"planned"`
	New             string `json:"new"`
	RequiresReplace int    `json:"requires_replace"`
}

func (c rpcseqCall) String() string {
	switch c.Stage {
	case "read":
		return c.Stage
	case "import":
		return fmt.Sprintf("%s %s", c.Stage, c.Op)
	case "plan":
		return fmt.Sprintf("%s %s %s %s rr=%d", c.Stage, c.Op, c.Prior, c.Planned, c.RequiresReplace)
	case "apply_pre":
		s := fmt.Sprintf("%s %s %s %s %s", c.Stage, c.Op, c.EnvelopeOp, c.Prior, c.Planned)
		if c.Imported {
			s += " imported"
		}
		return s
	case "apply_post":
		return fmt.Sprintf("%s %s %s", c.Stage, c.Op, c.New)
	}
	return "unexpected stage " + c.Stage
}

// TestRPCSeqClassificationRule checks every committed golden against
// classificationRule, so the rule holds for versions not installed here.
func TestRPCSeqClassificationRule(t *testing.T) {
	versions, err := os.ReadDir(filepath.Join("rpcseq", "goldens"))
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) == 0 {
		t.Fatal("no rpcseq goldens")
	}
	for _, v := range versions {
		for scenario, want := range classificationRule {
			t.Run(v.Name()+"/"+scenario, func(t *testing.T) {
				if len(want) == 0 {
					t.Fatal("classificationRule entry is empty")
				}
				b, err := os.ReadFile(filepath.Join("rpcseq", "goldens", v.Name(), scenario+".json"))
				if err != nil {
					t.Fatal(err)
				}
				var g struct {
					Steps []struct {
						Calls []rpcseqCall `json:"calls"`
					} `json:"steps"`
				}
				if err := json.Unmarshal(b, &g); err != nil {
					t.Fatal(err)
				}
				if len(g.Steps) == 0 {
					t.Fatal("golden has no steps")
				}
				var got []string
				for _, c := range g.Steps[len(g.Steps)-1].Calls {
					// The rule is the resource change classification; the
					// verdict gate's rpc calls (UpgradeResourceState, ...)
					// are pinned by the rpcseq goldens themselves.
					if c.Stage != "validate" && c.Stage != "rpc" {
						got = append(got, c.String())
					}
				}
				if !slices.Equal(got, want) {
					t.Fatalf("calls of the last step\n got %#v\nwant %#v", got, want)
				}
			})
		}
	}
}
