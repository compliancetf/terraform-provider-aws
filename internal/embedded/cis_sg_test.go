package embedded

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

const unk = "<unknown>"

type sgIngress struct {
	proto    string
	from, to any // int or unk
	v4, v6   []string
}

// sgValue is an aws_security_group of type sgT whose ingress holds rules;
// a nil CIDR list is empty, prefix_list_ids is null.
func sgValue(sgT tftypes.Object, rules ...sgIngress) tftypes.Value {
	list := func(xs []string) []any {
		out := []any{}
		for _, x := range xs {
			out = append(out, x)
		}
		return out
	}
	var ing []any
	for _, r := range rules {
		ing = append(ing, obj{"protocol": r.proto, "from_port": r.from, "to_port": r.to,
			"cidr_blocks": list(r.v4), "ipv6_cidr_blocks": list(r.v6)})
	}
	return tv(sgT, obj{"ingress": ing})
}

// TestEmbeddedSGRemoteAdmin: the CIS SSH/RDP controls fail any
// ingress rule open to the world whose port range covers 22 or 3389 or whose
// protocol is all, not only from_port == 22 or 3389.
func TestEmbeddedSGRemoteAdmin(t *testing.T) {
	b, _ := loadTest(t, cisIssued, trust.NoRevocations())
	sgT := sgFamily(t)["aws_security_group"]
	progs := map[string]engine.Program{}
	for k, p := range celPrograms(t, b, "aws_security_group") {
		progs[strings.TrimPrefix(k, "aws_security_group ")] = p
	}
	const v4, v6 = "vpc_security_group_remote_administration_ipv4", "vpc_security_group_remote_administration_ipv6"
	world4, world6, lan := []string{"0.0.0.0/0"}, []string{"::/0"}, []string{"10.0.0.0/8"}
	rows := []struct {
		name string
		id   string
		rule sgIngress
		want engine.State
	}{
		{"ssh exact", v4, sgIngress{"tcp", 22, 22, world4, nil}, engine.Fail},
		{"rdp exact", v4, sgIngress{"tcp", 3389, 3389, world4, nil}, engine.Fail},
		{"all ports tcp", v4, sgIngress{"tcp", 0, 65535, world4, nil}, engine.Fail},
		{"range 20-25", v4, sgIngress{"tcp", 20, 25, world4, nil}, engine.Fail},
		{"range 3000-4000", v4, sgIngress{"udp", 3000, 4000, world4, nil}, engine.Fail},
		{"protocol -1", v4, sgIngress{"-1", 0, 0, world4, nil}, engine.Fail},
		{"protocol all", v4, sgIngress{"all", 0, 0, world4, nil}, engine.Fail},
		{"from -1", v4, sgIngress{"tcp", -1, 65535, world4, nil}, engine.Fail},
		{"https only", v4, sgIngress{"tcp", 443, 443, world4, nil}, engine.Pass},
		{"range 23-3388", v4, sgIngress{"tcp", 23, 3388, world4, nil}, engine.Pass},
		{"icmp all", v4, sgIngress{"icmp", -1, -1, world4, nil}, engine.Pass},
		{"ssh from lan", v4, sgIngress{"tcp", 22, 22, lan, nil}, engine.Pass},
		{"to_port unknown", v4, sgIngress{"tcp", 0, unk, world4, nil}, engine.Unknown},
		{"protocol unknown", v4, sgIngress{unk, 443, 443, world4, nil}, engine.Unknown},
		{"ipv6 all ports", v6, sgIngress{"tcp", 0, 65535, nil, world6}, engine.Fail},
		{"ipv6 protocol -1", v6, sgIngress{"-1", 0, 0, nil, world6}, engine.Fail},
		{"ipv6 0::/0 ssh", v6, sgIngress{"tcp", 22, 22, nil, []string{"0::/0"}}, engine.Fail},
		{"ipv6 https", v6, sgIngress{"tcp", 443, 443, nil, world6}, engine.Pass},
		{"ipv6 rule on ipv4 control", v4, sgIngress{"tcp", 0, 65535, nil, world6}, engine.Pass},
		{"protocol ALL", v4, sgIngress{"ALL", 0, 0, world4, nil}, engine.Fail},
		{"world among private cidrs", v4, sgIngress{"tcp", 22, 22, []string{"10.0.0.0/8", "0.0.0.0/0"}, nil}, engine.Fail},
	}
	// Several rules: the condition is correlated per rule and any failing rule fails.
	multi := []struct {
		name  string
		rules []sgIngress
		want  engine.State
	}{
		{"world 443 + lan 22", []sgIngress{{"tcp", 443, 443, world4, nil}, {"tcp", 22, 22, lan, nil}}, engine.Pass},
		{"lan 443 + world 22", []sgIngress{{"tcp", 443, 443, lan, nil}, {"tcp", 22, 22, world4, nil}}, engine.Fail},
		{"world 443 + world all", []sgIngress{{"tcp", 443, 443, world4, nil}, {"-1", 0, 0, world4, nil}}, engine.Fail},
		{"lan 22 + world 22 unknown cidr", []sgIngress{{"tcp", 22, 22, lan, nil}, {"tcp", 22, 22, []string{unk}, nil}}, engine.Unknown},
	}
	for _, m := range multi {
		if got := evalBoth(progs[v4], sgValue(sgT, m.rules...)); got.State != m.want {
			t.Errorf("%s: got %v (%q), want %v", m.name, got.State, got.Err, m.want)
		}
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			p := progs[r.id]
			if p == nil {
				t.Fatalf("no control %s", r.id)
			}
			got := evalBoth(p, sgValue(sgT, r.rule))
			if got.State != r.want {
				t.Errorf("%s: got %v (%q), want %v", r.id, got.State, got.Err, r.want)
			}
		})
	}
}
