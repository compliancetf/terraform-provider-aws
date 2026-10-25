package embedded

import (
	"context"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/bundlegen"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// awsSchemas is testdata/schemas/aws-subset.json (captured from the pinned
// hashicorp/aws), the upstream schema the CIS controls load against.
func awsSchemas(t *testing.T) bundlegen.Schemas {
	t.Helper()
	s, err := bundlegen.LoadSchemas("../../testdata/schemas/aws-subset.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// sgFamily is the value type of each SG remote-admin resource type.
func sgFamily(t *testing.T) map[string]tftypes.Object {
	t.Helper()
	s := awsSchemas(t)
	out := map[string]tftypes.Object{}
	for _, name := range []string{"aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"} {
		sc, ok := s.Resource(name)
		if !ok {
			t.Fatalf("%s missing from aws-subset.json", name)
		}
		out[name] = sc.ValueType().(tftypes.Object)
	}
	return out
}

// celPrograms compiles every embedded control of the given types with the
// CEL engine the lifecycle uses, keyed by "<type> <id>".
func celPrograms(t *testing.T, b *bundle.Bundle, types ...string) map[string]engine.Program {
	t.Helper()
	s := awsSchemas(t)
	cc := celeng.NewCompiler(s)
	progs := map[string]engine.Program{}
	for i := range b.Controls {
		c := &b.Controls[i]
		sc, ok := s.Resource(c.ResourceType)
		if !ok || len(types) > 0 && !slices.Contains(types, c.ResourceType) {
			continue
		}
		p, err := cc.Compile(c, sc.ValueType())
		if err != nil {
			t.Fatal(err)
		}
		progs[c.ResourceType+" "+c.ID] = p
	}
	return progs
}

// evalBoth runs p as the lifecycle binds it for any presence mode: the value
// is both the planned resource and the config. A minute deadline: these
// tests check verdicts, not budgets, so a loaded machine must not turn
// them into timeout.
func evalBoth(p engine.Program, v tftypes.Value) engine.Outcome {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return p.Eval(ctx, &engine.Activation{Resource: v, Config: v, Op: engine.OpCreate})
}

type obj = map[string]any

// tv builds a value of type t from x: nil is null, unk is unknown, missing
// object attributes are null.
func tv(t tftypes.Type, x any) tftypes.Value {
	if x == nil {
		return tftypes.NewValue(t, nil)
	}
	if x == unk {
		return tftypes.NewValue(t, tftypes.UnknownValue)
	}
	switch tt := t.(type) {
	case tftypes.Object:
		for k := range x.(obj) {
			if _, ok := tt.AttributeTypes[k]; !ok {
				panic("no attribute " + k)
			}
		}
		m := map[string]tftypes.Value{}
		for k, at := range tt.AttributeTypes {
			m[k] = tv(at, x.(obj)[k])
		}
		return tftypes.NewValue(t, m)
	case tftypes.List:
		return seq(t, tt.ElementType, x.([]any))
	case tftypes.Set:
		return seq(t, tt.ElementType, x.([]any))
	}
	if n, ok := x.(int); ok {
		return tftypes.NewValue(t, big.NewFloat(float64(n)))
	}
	return tftypes.NewValue(t, x)
}

func seq(t, et tftypes.Type, xs []any) tftypes.Value {
	vs := []tftypes.Value{}
	for _, e := range xs {
		vs = append(vs, tv(et, e))
	}
	return tftypes.NewValue(t, vs)
}

// TestEmbeddedSGFamilyRemoteAdmin: the CIS SSH/RDP
// controls cover the standalone rule resources with the inline semantics
// (world source plus a port range covering 22 or 3389, or protocol all,
// fails). An SG reference or self is never a world source, so it passes. A
// prefix list's entries are not known at plan, so a prefix-list source on a
// remote-admin rule is not_evaluable (unresolved), which takes the fail row;
// a world CIDR next to it still fails.
func TestEmbeddedSGFamilyRemoteAdmin(t *testing.T) {
	family := sgFamily(t)
	b, _ := loadTest(t, cisIssued, trust.NoRevocations())
	progs := celPrograms(t, b, "aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule")
	const v4, v6 = "vpc_security_group_remote_administration_ipv4", "vpc_security_group_remote_administration_ipv6"
	const sg, sgr, vir = "aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"
	w4, w6, lan, pl := []any{"0.0.0.0/0"}, []any{"::/0"}, []any{"10.0.0.0/8"}, []any{"pl-0bobthecorp"}
	ing := func(rules ...obj) obj {
		var rs []any
		for _, r := range rules {
			rs = append(rs, r)
		}
		return obj{"ingress": rs}
	}
	rule := func(typ, proto string, from, to any, extra obj) obj {
		r := obj{"protocol": proto, "from_port": from, "to_port": to}
		if typ != "" { // "" for an inline ingress block, which has no type
			r["type"] = typ
		}
		for k, v := range extra {
			r[k] = v
		}
		return r
	}
	vrule := func(proto string, from, to any, extra obj) obj {
		r := obj{"ip_protocol": proto, "from_port": from, "to_port": to}
		for k, v := range extra {
			r[k] = v
		}
		return r
	}
	tcp := func(from, to int, extra obj) obj { return rule("", "tcp", from, to, extra) }
	rows := []struct {
		name     string
		typ, id  string
		resource obj
		want     engine.State
	}{
		// aws_security_group inline ingress: source kinds.
		{"sg prefix list ssh", sg, v4, ing(tcp(22, 22, obj{"prefix_list_ids": pl})), engine.Fail},                    // opv1: not_evaluable (unresolved)
		{"sg prefix list ssh v6", sg, v6, ing(tcp(22, 22, obj{"prefix_list_ids": pl})), engine.Fail},                 // opv1: not_evaluable (unresolved)
		{"sg prefix list all protocols", sg, v4, ing(rule("", "-1", 0, 0, obj{"prefix_list_ids": pl})), engine.Fail}, // opv1: not_evaluable (unresolved)
		{"sg prefix list https", sg, v4, ing(tcp(443, 443, obj{"prefix_list_ids": pl})), engine.Pass},
		{"sg prefix list and world ssh", sg, v4, ing(tcp(22, 22, obj{"prefix_list_ids": pl, "cidr_blocks": w4})), engine.Fail},
		{"sg prefix list unknown ssh", sg, v4, ing(tcp(22, 22, obj{"prefix_list_ids": unk})), engine.Unknown},
		{"sg empty prefix list ssh", sg, v4, ing(tcp(22, 22, obj{"prefix_list_ids": []any{}})), engine.Pass},
		{"sg reference ssh", sg, v4, ing(tcp(22, 22, obj{"security_groups": []any{"sg-0bobthecorp"}})), engine.Pass},
		{"sg self ssh", sg, v6, ing(tcp(22, 22, obj{"self": true})), engine.Pass},
		{"sg lan 22 + prefix list 22", sg, v4, ing(tcp(22, 22, obj{"cidr_blocks": lan}), tcp(22, 22, obj{"prefix_list_ids": pl})), engine.Fail}, // opv1: not_evaluable (unresolved)
		{"sg prefix list 443 + world 22", sg, v4, ing(tcp(443, 443, obj{"prefix_list_ids": pl}), tcp(22, 22, obj{"cidr_blocks": w4})), engine.Fail},
		{"sg prefix list 22 + world 22", sg, v4, ing(tcp(22, 22, obj{"prefix_list_ids": pl}), tcp(22, 22, obj{"cidr_blocks": w4})), engine.Fail},
		{"sg reference and world ssh", sg, v4, ing(tcp(22, 22, obj{"security_groups": []any{"sg-0bobthecorp"}, "cidr_blocks": w4})), engine.Fail},
		{"sg prefix list, empty cidrs", sg, v4, ing(tcp(22, 22, obj{"prefix_list_ids": pl, "cidr_blocks": []any{}})), engine.Fail}, // opv1: not_evaluable (unresolved)

		// aws_security_group_rule.
		{"rule ssh world", sgr, v4, rule("ingress", "tcp", 22, 22, obj{"cidr_blocks": w4}), engine.Fail},
		{"rule rdp world", sgr, v4, rule("ingress", "tcp", 3389, 3389, obj{"cidr_blocks": w4}), engine.Fail},
		{"rule all ports", sgr, v4, rule("ingress", "tcp", 0, 65535, obj{"cidr_blocks": w4}), engine.Fail},
		{"rule protocol -1", sgr, v4, rule("ingress", "-1", 0, 0, obj{"cidr_blocks": w4}), engine.Fail},
		{"rule protocol ALL", sgr, v4, rule("ingress", "ALL", 0, 0, obj{"cidr_blocks": w4}), engine.Fail},
		{"rule world among lan", sgr, v4, rule("ingress", "tcp", 22, 22, obj{"cidr_blocks": []any{"10.0.0.0/8", "0.0.0.0/0"}}), engine.Fail},
		{"rule https", sgr, v4, rule("ingress", "tcp", 443, 443, obj{"cidr_blocks": w4}), engine.Pass},
		{"rule range 23-3388", sgr, v4, rule("ingress", "tcp", 23, 3388, obj{"cidr_blocks": w4}), engine.Pass},
		{"rule icmp", sgr, v4, rule("ingress", "icmp", -1, -1, obj{"cidr_blocks": w4}), engine.Pass},
		{"rule ssh lan", sgr, v4, rule("ingress", "tcp", 22, 22, obj{"cidr_blocks": lan}), engine.Pass},
		{"rule egress ssh world", sgr, v4, rule("egress", "tcp", 22, 22, obj{"cidr_blocks": w4}), engine.Pass},
		{"rule egress all v6", sgr, v6, rule("egress", "-1", 0, 0, obj{"ipv6_cidr_blocks": w6}), engine.Pass},
		{"rule ssh source sg", sgr, v4, rule("ingress", "tcp", 22, 22, obj{"source_security_group_id": "sg-0bobthecorp"}), engine.Pass},
		{"rule ssh self", sgr, v4, rule("ingress", "tcp", 22, 22, obj{"self": true}), engine.Pass},
		{"rule ssh prefix list", sgr, v4, rule("ingress", "tcp", 22, 22, obj{"prefix_list_ids": pl}), engine.Fail},    // opv1: not_evaluable (unresolved)
		{"rule ssh prefix list v6", sgr, v6, rule("ingress", "tcp", 22, 22, obj{"prefix_list_ids": pl}), engine.Fail}, // opv1: not_evaluable (unresolved)
		{"rule https prefix list", sgr, v4, rule("ingress", "tcp", 443, 443, obj{"prefix_list_ids": pl}), engine.Pass},
		{"rule egress prefix list", sgr, v4, rule("egress", "tcp", 22, 22, obj{"prefix_list_ids": pl}), engine.Pass},
		{"rule type unknown", sgr, v4, rule(unk, "tcp", 22, 22, obj{"cidr_blocks": w4}), engine.Unknown},
		{"rule to_port unknown", sgr, v4, rule("ingress", "tcp", 0, unk, obj{"cidr_blocks": w4}), engine.Unknown},
		{"rule cidr unknown", sgr, v4, rule("ingress", "tcp", 22, 22, obj{"cidr_blocks": unk}), engine.Unknown},
		{"rule ssh v6 world", sgr, v6, rule("ingress", "tcp", 22, 22, obj{"ipv6_cidr_blocks": []any{"0::/0"}}), engine.Fail},
		{"rule ssh v6 world on v4 control", sgr, v4, rule("ingress", "tcp", 22, 22, obj{"ipv6_cidr_blocks": w6}), engine.Pass},
		{"rule https v6", sgr, v6, rule("ingress", "tcp", 443, 443, obj{"ipv6_cidr_blocks": w6}), engine.Pass},

		// aws_vpc_security_group_ingress_rule.
		{"vpc ssh world", vir, v4, vrule("tcp", 22, 22, obj{"cidr_ipv4": "0.0.0.0/0"}), engine.Fail},
		{"vpc rdp world", vir, v4, vrule("tcp", 3389, 3389, obj{"cidr_ipv4": "0.0.0.0/0"}), engine.Fail},
		{"vpc range 20-25", vir, v4, vrule("udp", 20, 25, obj{"cidr_ipv4": "0.0.0.0/0"}), engine.Fail},
		{"vpc protocol -1, no ports", vir, v4, vrule("-1", nil, nil, obj{"cidr_ipv4": "0.0.0.0/0"}), engine.Fail},
		{"vpc protocol number 6", vir, v4, vrule("6", 22, 22, obj{"cidr_ipv4": "0.0.0.0/0"}), engine.Fail},
		{"vpc https", vir, v4, vrule("tcp", 443, 443, obj{"cidr_ipv4": "0.0.0.0/0"}), engine.Pass},
		{"vpc icmp", vir, v4, vrule("icmp", -1, -1, obj{"cidr_ipv4": "0.0.0.0/0"}), engine.Pass},
		{"vpc ssh lan", vir, v4, vrule("tcp", 22, 22, obj{"cidr_ipv4": "10.0.0.0/8"}), engine.Pass},
		{"vpc ssh /10", vir, v4, vrule("tcp", 22, 22, obj{"cidr_ipv4": "0.0.0.0/10"}), engine.Pass},
		{"vpc ssh sg reference", vir, v4, vrule("tcp", 22, 22, obj{"referenced_security_group_id": "sg-0bobthecorp"}), engine.Pass},
		{"vpc ssh prefix list", vir, v4, vrule("tcp", 22, 22, obj{"prefix_list_id": "pl-0bobthecorp"}), engine.Fail},     // opv1: not_evaluable (unresolved)
		{"vpc all prefix list v6", vir, v6, vrule("-1", nil, nil, obj{"prefix_list_id": "pl-0bobthecorp"}), engine.Fail}, // opv1: not_evaluable (unresolved)
		{"vpc https prefix list", vir, v4, vrule("tcp", 443, 443, obj{"prefix_list_id": "pl-0bobthecorp"}), engine.Pass},
		{"vpc prefix list unknown", vir, v4, vrule("tcp", 22, 22, obj{"prefix_list_id": unk}), engine.Unknown},
		{"vpc cidr unknown", vir, v4, vrule("tcp", 22, 22, obj{"cidr_ipv4": unk}), engine.Unknown},
		{"vpc from_port unknown", vir, v4, vrule("tcp", unk, 22, obj{"cidr_ipv4": "0.0.0.0/0"}), engine.Unknown},
		{"vpc ssh v6 world", vir, v6, vrule("tcp", 22, 22, obj{"cidr_ipv6": "::/0"}), engine.Fail},
		{"vpc ssh v6 world on v4 control", vir, v4, vrule("tcp", 22, 22, obj{"cidr_ipv6": "::/0"}), engine.Pass},
		{"vpc ssh v6 lan", vir, v6, vrule("tcp", 22, 22, obj{"cidr_ipv6": "fd00::/8"}), engine.Pass},
		{"vpc ssh /00", vir, v4, vrule("tcp", 22, 22, obj{"cidr_ipv4": "0.0.0.0/00"}), engine.Fail},
		{"vpc ssh v6 /00", vir, v6, vrule("tcp", 22, 22, obj{"cidr_ipv6": "::/00"}), engine.Fail},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			p := progs[r.typ+" "+r.id]
			if p == nil {
				t.Fatalf("no control %s for %s", r.id, r.typ)
			}
			got := evalBoth(p, tv(family[r.typ], r.resource))
			if got.State != r.want || got.Err != engine.ErrNone {
				t.Errorf("%s %s: got %v/%q, want %v", r.typ, r.id, got.State, got.Err, r.want)
			}
		})
	}
}
