package proxy

// imported.go classifies the plan of an object this provider process
// imported. ImportResourceState records keys of each imported
// object; the first PlanResourceChange whose prior matches one takes the
// object's keys out, and the plan is stamped op import (an update only) and
// imported true. The set lives in memory for the life of the process: state
// never carries it, and a CLI terraform import (its own process) leaves the
// later plan unmarked, which is pre-existing anyway. Both markers are
// evidence only: they never grant an allow or exemption.

import (
	"context"
	"encoding/json"
	"slices"
	"sync"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// importedSet holds the keys of each imported object: (type, identity) when
// the import returned a readable identity, and (type, id) when it had an id.
// shortcut: a slice scanned per plan; it holds only this process's imports,
// within one Terraform command. A second import of the same object adds no
// entry, so only the first matching plan is stamped.
type importedSet struct {
	mu      sync.Mutex
	objects []importedKeys
}

type importedKeys struct{ byIdentity, byID string }

func (s *importedSet) add(k importedKeys) {
	if k == (importedKeys{}) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !slices.Contains(s.objects, k) {
		s.objects = append(s.objects, k)
	}
}

func (s *importedSet) empty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.objects) == 0
}

// take reports whether a prior with keys p is an imported object and removes
// that object. A prior with an identity matches an object by identity, or an
// object imported without one by id; a prior without an identity (Terraform
// before resource identity) matches by id.
func (s *importedSet) take(p importedKeys) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, o := range s.objects {
		byIdentity := p.byIdentity != "" && o.byIdentity == p.byIdentity
		byID := p.byID != "" && o.byID == p.byID && (p.byIdentity == "" || o.byIdentity == "")
		if byIdentity || byID {
			s.objects = append(s.objects[:i], s.objects[i+1:]...)
			return true
		}
	}
	return false
}

// importKeys are the candidate keys of an object of type typ: its resource
// identity when readable, and its top-level string id when present; "" when
// not. An unreadable part gives no key, so a match is never guessed.
func (s *server5) importKeys(ctx context.Context, typ string, state *tfplugin5.DynamicValue, identity *tfplugin5.ResourceIdentityData) importedKeys {
	var k importedKeys
	if obj := identityObject(identity); obj != nil {
		if b, err := json.Marshal(obj); err == nil {
			k.byIdentity = typ + "\x00identity\x00" + string(b)
		}
	}
	if id, err := s.stateID(ctx, typ, state); err == nil && id != "" {
		k.byID = typ + "\x00id\x00" + id
	}
	return k
}

// recordImported adds every object of an import response.
func (s *server5) recordImported(ctx context.Context, resp *tfplugin5.ImportResourceState_Response) {
	for _, r := range resp.ImportedResources {
		s.imported.add(s.importKeys(ctx, r.TypeName, r.State, r.Identity))
	}
}

// planImported reports whether the plan of a pre-existing object (op update
// or replace) is of an object this process imported, taking it out of the
// set. Other ops and an empty set cost nothing.
func (s *server5) planImported(ctx context.Context, op hook.Op, req *tfplugin5.PlanResourceChange_Request) bool {
	if (op != hook.OpUpdate && op != hook.OpReplace) || s.imported.empty() {
		return false
	}
	return s.imported.take(s.importKeys(ctx, req.TypeName, req.PriorState, req.PriorIdentity))
}
