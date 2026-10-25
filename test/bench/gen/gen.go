package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
)

// Format names the generator output document.
const Format = "compliancetf.bench-instances/v1"

// Doc is the generator output. Values use the crosscheck fixture form:
// omitted attributes are null, {"$unknown": true} is unknown.
type Doc struct {
	Format       string     `json:"format"`
	Seed         uint64     `json:"seed"`
	N            int        `json:"n"`
	SchemaSHA256 string     `json:"schema_sha256"`
	Instances    []Instance `json:"instances"`
}

// Instance is one resource change: Planned is the effective value (the
// engine's resource binding); Prior is null on create.
type Instance struct {
	ResourceType string         `json:"resource_type"`
	Op           string         `json:"op"`
	Config       map[string]any `json:"config"`
	Prior        map[string]any `json:"prior"`
	Planned      map[string]any `json:"planned"`
}

// block is a `terraform providers schema -json` block.
type block struct {
	Attributes map[string]struct {
		Type               json.RawMessage `json:"type"`
		Required, Optional bool
		Computed           bool
	} `json:"attributes"`
	BlockTypes map[string]struct {
		Nesting  string `json:"nesting_mode"`
		MinItems int    `json:"min_items"`
		MaxItems int    `json:"max_items"`
		Block    block  `json:"block"`
	} `json:"block_types"`
}

// Schema is the aws resource schemas of a captured subset.
type Schema map[string]block

// ParseSchema reads `terraform providers schema -json` output (the
// hashicorp/aws resource schemas).
func ParseSchema(data []byte) (Schema, error) {
	var doc struct {
		ProviderSchemas map[string]struct {
			Resources map[string]struct {
				Block block `json:"block"`
			} `json:"resource_schemas"`
		} `json:"provider_schemas"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	s := Schema{}
	for n, r := range doc.ProviderSchemas["registry.terraform.io/hashicorp/aws"].Resources {
		s[n] = r.Block
	}
	if len(s) == 0 {
		return nil, fmt.Errorf("no hashicorp/aws resource schemas")
	}
	return s, nil
}

var unknown = map[string]any{"$unknown": true}

// gen draws one document; every map is walked in sorted key order so the
// output depends on the seed only.
type gen struct {
	rnd *rand.Rand
	typ string
}

// Generate builds n instances round-robin over the resource types of s:
// 60% creates, 40% updates, 10% with one unknown top-level attribute. A
// schema with a cty type or nesting mode it cannot draw is an error, never a
// dropped value: a silent gap would skew not_evaluable on a recapture.
func Generate(s Schema, seed uint64, n int) ([]Instance, error) {
	g := &gen{rnd: rand.New(rand.NewPCG(seed, seed))} //nolint:gosec // deterministic fixture data
	types := slices.Sorted(maps.Keys(s))
	if len(types) == 0 {
		return nil, fmt.Errorf("no resource types to draw from")
	}
	for _, typ := range types {
		if err := checkBlock(s[typ]); err != nil {
			return nil, fmt.Errorf("%s: %w", typ, err)
		}
	}
	out := make([]Instance, n)
	for i := range out {
		g.typ = types[i%len(types)]
		b := s[g.typ]
		config, err := g.object(b, "")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", g.typ, err)
		}
		in := Instance{ResourceType: g.typ, Op: "create", Config: config}
		in.Planned = maps.Clone(in.Config)
		computed := g.computedOnly(b, i)
		for k := range computed {
			in.Planned[k] = unknown
		}
		if g.rnd.IntN(10) < 4 {
			in.Op = "update"
			if in.Prior, err = g.object(b, ""); err != nil {
				return nil, fmt.Errorf("%s: %w", g.typ, err)
			}
			maps.Copy(in.Prior, computed)
			maps.Copy(in.Planned, computed)
		}
		if g.rnd.IntN(10) == 0 {
			if keys := slices.Sorted(maps.Keys(in.Config)); len(keys) > 0 {
				k := keys[g.rnd.IntN(len(keys))]
				in.Config[k], in.Planned[k] = unknown, unknown
			}
		}
		out[i] = in
	}
	return out, nil
}

// checkBlock rejects every attribute type and block nesting mode of b that
// object and value cannot draw, whether this seed draws it or not.
func checkBlock(b block) error {
	for _, k := range slices.Sorted(maps.Keys(b.Attributes)) {
		if err := checkType(b.Attributes[k].Type); err != nil {
			return fmt.Errorf("attribute %s: %w", k, err)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(b.BlockTypes)) {
		bt := b.BlockTypes[k]
		if !slices.Contains([]string{"single", "group", "list", "set"}, bt.Nesting) {
			return fmt.Errorf("block %s: unhandled nesting mode %q", k, bt.Nesting)
		}
		if err := checkBlock(bt.Block); err != nil {
			return fmt.Errorf("block %s: %w", k, err)
		}
	}
	return nil
}

// checkType rejects a cty JSON type value cannot draw: dynamic, tuple or
// anything else outside string, number, bool, list, set, map and object.
func checkType(t json.RawMessage) error {
	var prim string
	if json.Unmarshal(t, &prim) == nil {
		if prim == "string" || prim == "number" || prim == "bool" {
			return nil
		}
		return fmt.Errorf("unhandled cty type %q", prim)
	}
	kind, parts := typeParts(t)
	switch kind {
	case "":
		return fmt.Errorf("unhandled cty type %s", t)
	case "list", "set", "map":
		return checkType(parts[1])
	case "object":
		var attrs map[string]json.RawMessage
		if json.Unmarshal(parts[1], &attrs) != nil || attrs == nil {
			return fmt.Errorf("unhandled cty type %s", t)
		}
		if len(parts) == 3 { // optional attribute names: each one declared
			var names []string
			if json.Unmarshal(parts[2], &names) != nil || names == nil ||
				slices.ContainsFunc(names, func(n string) bool { _, ok := attrs[n]; return !ok }) {
				return fmt.Errorf("unhandled cty type %s", t)
			}
		}
		for _, ak := range slices.Sorted(maps.Keys(attrs)) {
			if err := checkType(attrs[ak]); err != nil {
				return fmt.Errorf("%s: %w", ak, err)
			}
		}
		return nil
	}
	return fmt.Errorf("unhandled cty type %q", kind)
}

// typeParts splits a collection or structural cty JSON type: ["kind", elem],
// or ["object", attrs, [optional names]]. Kind is "" for any other form.
func typeParts(t json.RawMessage) (string, []json.RawMessage) {
	var parts []json.RawMessage
	var kind string
	if json.Unmarshal(t, &parts) != nil || len(parts) < 2 || json.Unmarshal(parts[0], &kind) != nil ||
		len(parts) > 2 && (kind != "object" || len(parts) > 3) {
		return "", nil
	}
	return kind, parts
}

// maxSetDraws bounds the extra elements drawn to refill a deduplicated set.
const maxSetDraws = 100

// object draws the configurable attributes and blocks of b at path ("" for
// the resource itself): required always, optional about 70% of the time. A
// set block holds at least min_items distinct elements or is an error.
func (g *gen) object(b block, path string) (map[string]any, error) {
	out, top := map[string]any{}, path == ""
	for _, k := range slices.Sorted(maps.Keys(b.Attributes)) {
		a := b.Attributes[k]
		if a.Computed && !a.Optional && !a.Required || !a.Required && g.rnd.IntN(10) >= 7 {
			continue
		}
		if v := g.value(k, a.Type, top); v != nil {
			out[k] = v
		}
	}
	for _, k := range slices.Sorted(maps.Keys(b.BlockTypes)) {
		bt := b.BlockTypes[k]
		if bt.Nesting == "single" || bt.Nesting == "group" {
			if bt.MinItems > 0 || g.rnd.IntN(10) < 7 {
				v, err := g.object(bt.Block, path+k+".")
				if err != nil {
					return nil, err
				}
				out[k] = v
			}
			continue
		}
		hi := bt.MaxItems
		if hi == 0 || hi > 3 {
			hi = 3
		}
		lo := bt.MinItems
		hi = max(hi, lo)
		elems := make([]any, lo+g.rnd.IntN(hi-lo+1))
		for j := range elems {
			v, err := g.object(bt.Block, path+k+".")
			if err != nil {
				return nil, err
			}
			elems[j] = v
		}
		if bt.Nesting == "set" {
			// Dedup can drop below min_items: draw more until it is met.
			elems = unique(elems)
			for try := 0; len(elems) < lo && try < maxSetDraws; try++ {
				v, err := g.object(bt.Block, path+k+".")
				if err != nil {
					return nil, err
				}
				elems = unique(append(elems, v))
			}
			if len(elems) < lo {
				return nil, fmt.Errorf("block %s%s: %d distinct set elements after %d extra draws, want min_items %d",
					path, k, len(elems), maxSetDraws, lo)
			}
		}
		if len(elems) > 0 || bt.MinItems > 0 {
			out[k] = elems
		}
	}
	return out, nil
}

// computedOnly gives the computed-only top-level attributes of b their
// known values (prior state on update).
func (g *gen) computedOnly(b block, i int) map[string]any {
	out := map[string]any{}
	for _, k := range slices.Sorted(maps.Keys(b.Attributes)) {
		if a := b.Attributes[k]; a.Computed && !a.Optional && !a.Required {
			switch k {
			case "id":
				out[k] = fmt.Sprintf("bobthecorp-%d", i)
			case "arn":
				out[k] = fmt.Sprintf("arn:aws:%s:eu-west-1:111111111111:bobthecorp-%d", g.typ, i)
			default:
				if v := g.value(k, a.Type, false); v != nil {
					out[k] = v
				}
			}
		}
	}
	return out
}

// value draws a value of the cty JSON type t for attribute k.
func (g *gen) value(k string, t json.RawMessage, top bool) any {
	var prim string
	if json.Unmarshal(t, &prim) == nil {
		switch prim {
		case "string":
			return g.str(k, top)
		case "number":
			return g.num(k)
		case "bool":
			return g.rnd.IntN(2) == 0
		}
		return nil // dynamic
	}
	kind, pair := typeParts(t) // checkType has passed: never "" here
	switch kind {
	case "list", "set":
		n := g.rnd.IntN(4)
		if k == "ingress" || k == "egress" {
			n = 1 + g.rnd.IntN(50)
		}
		elems := make([]any, n)
		for j := range elems {
			elems[j] = g.value(k, pair[1], false)
		}
		if kind == "set" {
			elems = unique(elems)
		}
		return elems
	case "map":
		m := map[string]any{}
		for j := range g.rnd.IntN(4) {
			m[[]string{"Name", "owner", "env", "cost-center"}[j]] = g.value(k, pair[1], false)
		}
		return m
	case "object":
		var attrs map[string]json.RawMessage
		if json.Unmarshal(pair[1], &attrs) != nil {
			return nil
		}
		m := map[string]any{}
		for _, ak := range slices.Sorted(maps.Keys(attrs)) {
			if v := g.value(ak, attrs[ak], false); v != nil {
				m[ak] = v
			}
		}
		return m
	}
	return nil // tuple
}

func (g *gen) pick(vs ...string) string { return vs[g.rnd.IntN(len(vs))] }

// str draws a plausible string for the attribute names the reference
// controls read; anything else is an opaque bobthecorp value.
func (g *gen) str(k string, top bool) string {
	switch k {
	case "policy":
		if top {
			return g.policy()
		}
	case "cidr_blocks", "cidr_ipv4":
		return g.pick("10.0.0.0/16", "10.1.0.0/24", "192.168.0.0/16", "0.0.0.0/0")
	case "ipv6_cidr_blocks", "cidr_ipv6":
		return g.pick("2001:db8::/32", "::/0")
	case "prefix_list_ids", "prefix_list_id":
		return "pl-0bobthecorp"
	case "protocol":
		if g.typ == "aws_lb_listener" {
			return g.pick("HTTPS", "HTTP", "TLS")
		}
		return g.pick("tcp", "udp", "-1")
	case "ip_protocol":
		return g.pick("tcp", "udp", "-1")
	case "type":
		if g.typ == "aws_security_group_rule" {
			return g.pick("ingress", "egress")
		}
	case "kms_key_id", "kms_master_key_id", "cloud_watch_logs_group_arn":
		return fmt.Sprintf("arn:aws:kms:eu-west-1:111111111111:key/bobthecorp-%d", g.rnd.IntN(100))
	case "sse_algorithm":
		return g.pick("aws:kms", "AES256")
	case "status":
		return g.pick("Enabled", "Suspended")
	case "mfa_delete":
		return g.pick("Enabled", "Disabled")
	case "acl":
		return g.pick("private", "public-read", "authenticated-read")
	case "http_tokens":
		return g.pick("required", "optional")
	case "encrypted", "at_rest_encryption_enabled":
		return g.pick("true", "false")
	case "username":
		return g.pick("admin", "bobthecorp_dba")
	case "instance_class":
		return g.pick("db.t3.micro", "db.r6g.large")
	case "enabled_cloudwatch_logs_exports":
		return g.pick("audit", "error", "general", "slowquery")
	case "container_definitions":
		return `[{"name":"bobthecorp","image":"bobthecorp/app:1","essential":true}]`
	}
	return fmt.Sprintf("bobthecorp-%s-%d", k, g.rnd.IntN(1000))
}

func (g *gen) num(k string) int {
	switch k {
	case "from_port", "to_port", "port":
		return []int{22, 80, 443, 3306, 3389, 5432, 9042, 1024 + g.rnd.IntN(1000)}[g.rnd.IntN(8)]
	case "backup_retention_period":
		return g.rnd.IntN(36)
	}
	return g.rnd.IntN(100)
}

var actions = []string{"ec2:DescribeInstances", "iam:CreateRole", "iam:GetRole", "iam:PassRole",
	"kms:CreateKey", "kms:Decrypt", "kms:Encrypt", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion",
	"s3:DeleteBucketPolicy", "s3:GetObject", "s3:PutBucketAcl", "s3:PutBucketPolicy", "s3:PutObject",
	"s3:PutObjectAcl", "s3:*", "kms:*", "*"}

// policy draws an IAM policy document: up to 200 statements for IAM types,
// 1 to 40 with a principal for bucket policies.
func (g *gen) policy() string {
	n, bucket := 1+g.rnd.IntN(200), g.typ == "aws_s3_bucket_policy" || g.typ == "aws_s3_bucket"
	if bucket {
		n = 1 + g.rnd.IntN(40)
	}
	stmts := make([]map[string]any, n)
	for i := range stmts {
		s := map[string]any{
			"Sid":      fmt.Sprintf("S%d", i),
			"Effect":   g.pick("Allow", "Allow", "Deny"),
			"Action":   []string{g.pick(actions...), g.pick(actions...)},
			"Resource": g.pick("*", "arn:aws:s3:::bobthecorp-data/*", "arn:aws:kms:eu-west-1:111111111111:key/bobthecorp"),
		}
		if bucket {
			s["Principal"] = map[string]any{"AWS": g.pick("arn:aws:iam::111111111111:root", "arn:aws:iam::222222222222:root", "*")}
		}
		if g.rnd.IntN(5) == 0 {
			s["Condition"] = map[string]any{"StringNotEquals": map[string]any{"aws:PrincipalAccount": "111111111111"}}
		}
		stmts[i] = s
	}
	raw, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": stmts})
	if err != nil {
		panic(err) // maps of strings always marshal
	}
	return string(raw)
}

// unique drops repeated set elements, keeping the first.
func unique(elems []any) []any {
	seen := map[string]bool{}
	out := elems[:0]
	for _, e := range elems {
		raw, err := json.Marshal(e)
		if err != nil {
			panic(err) // generated values always marshal
		}
		if !seen[string(raw)] {
			seen[string(raw)] = true
			out = append(out, e)
		}
	}
	return out
}
