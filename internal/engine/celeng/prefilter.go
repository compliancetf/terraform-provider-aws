package celeng

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/tfval"
)

const defaultMemoEntries = 100_000

type memoKeyT [sha256.Size]byte

// memo is the prefilter: in-process only,
// pass and fail only, cleared when full.
// shortcut: clear-on-full, no LRU; add one when a profile shows churn.
type memo struct {
	mu  sync.RWMutex
	max int
	m   map[memoKeyT]engine.State
}

func newMemo(max int) *memo { return &memo{max: max, m: map[memoKeyT]engine.State{}} }

func (m *memo) get(k memoKeyT) (engine.State, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.m[k]
	return s, ok
}

func (m *memo) put(k memoKeyT, s engine.State) {
	if s != engine.Pass && s != engine.Fail {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.m) >= m.max {
		clear(m.m)
	}
	m.m[k] = s
}

func (m *memo) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.m)
}

// key is sha256 over the content digest, the full control key, sha256(expr)
// and the projection of every value the expression reads. Every part goes
// through enc, which is injective, so values never meet in clear text and
// no two inputs share a key. ok is false when the memo must not be used:
// an unknown under a read's top-level attribute (cel-go makes a container
// with an unknown descendant unknown), an untrusted env, an unknown provider
// field, an absent map key, a dotted map key or a walk that ends early.
func (c *Compiled) key(p *program, in Bindings, vals map[string]tfval.Converted) (memoKeyT, bool) {
	proj := map[string]any{}
	for _, v := range p.ch.Vars {
		switch v {
		case varOp:
			proj["op:"] = in.Op
		case varEnv:
			if !in.EnvKnown {
				return memoKeyT{}, false
			}
			proj["env:"] = in.Env
		case varProvider:
			if !in.Provider.RegionKnown || !in.Provider.AccountKnown || !in.Provider.PartitionKnown {
				return memoKeyT{}, false
			}
			proj["provider:region"], proj["provider:account_id"] = in.Provider.Region, in.Provider.AccountID
			proj["provider:partition"] = in.Provider.Partition
		default:
			if !slices.ContainsFunc(p.ch.Reads, func(r Read) bool { return r.Var == v }) {
				if !project(proj, vals[v], "") { // a data variable used whole
					return memoKeyT{}, false
				}
			}
		}
	}
	for _, r := range p.ch.Reads {
		if !project(proj, vals[r.Var], r.Path) {
			return memoKeyT{}, false
		}
	}
	expr := ""
	if p.c.Expr != nil {
		expr = *p.c.Expr
	}
	exprSum := sha256.Sum256([]byte(expr))
	var b bytes.Buffer
	if !enc(&b, []any{c.digest, map[string]any{
		"id": p.c.ID, "kind": string(p.c.Kind), "resource_type": p.c.ResourceType, "version": p.c.Version,
	}, string(exprSum[:]), proj}) {
		return memoKeyT{}, false
	}
	return sha256.Sum256(b.Bytes()), true
}

// project adds the value at path of one converted variable to proj under
// "<var>:<path>". It walks map keys only and stops at a list (element steps
// are implicit, the whole list is projected) or at the end of the path.
func project(proj map[string]any, cv tfval.Converted, path string) bool {
	if !cv.Known {
		return false
	}
	var segs []string
	if path != "" {
		segs = strings.Split(path, ".")
	}
	for _, u := range cv.Unknown {
		st := u.Steps()
		if len(st) == 0 || len(segs) == 0 {
			return false // root unknown, or the whole variable is read
		}
		switch n := st[0].(type) {
		case tftypes.AttributeName:
			if string(n) == segs[0] {
				return false
			}
		case tftypes.ElementKeyString:
			if string(n) == segs[0] {
				return false
			}
		default:
			return false
		}
	}
	v, done := cv.Value, 0
	for _, s := range segs {
		m, ok := v.(map[string]any)
		if !ok {
			break
		}
		for k := range m {
			if strings.Contains(k, ".") {
				return false // "a.b" as a key and as a path are one read path
			}
		}
		if v, ok = m[s]; !ok {
			return false
		}
		done++
	}
	if _, list := v.([]any); done < len(segs) && !list {
		return false
	}
	proj[cv.Variable+":"+strings.Join(segs[:done], ".")] = v
	return true
}

// enc writes v with one leading tag byte per kind, quoted strings and
// sorted map keys, so equal output means equal CEL value. -0.0 and 0.0
// differ: a miss, never a wrong hit. Any other kind reports false.
func enc(b *bytes.Buffer, v any) bool {
	switch x := v.(type) {
	case nil:
		b.WriteByte('n')
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case int64:
		b.WriteByte('i')
		b.WriteString(strconv.FormatInt(x, 10))
	case float64:
		b.WriteByte('d')
		b.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
	case string:
		b.WriteString(strconv.Quote(x))
	case []any:
		b.WriteByte('[')
		for _, e := range x {
			if !enc(b, e) {
				return false
			}
			b.WriteByte(',')
		}
		b.WriteByte(']')
	case map[string]any:
		b.WriteByte('{')
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			b.WriteString(strconv.Quote(k))
			if !enc(b, x[k]) {
				return false
			}
			b.WriteByte(',')
		}
		b.WriteByte('}')
	default:
		return false
	}
	return true
}
