package lib

import (
	"net/netip"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
)

func cidrFuncs() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("cidr.contains", cel.Overload("cidr_contains_string_string",
			[]*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
			cel.BinaryBinding(func(a, b ref.Val) ref.Val {
				s, ok := strs(a, b)
				if !ok {
					return invalid()
				}
				outer, ok1 := parseCIDR(s[0], false)
				inner, ok2 := parseCIDR(s[1], true)
				if !ok1 || !ok2 {
					return invalid()
				}
				return types.Bool(outer.Addr().Is4() == inner.Addr().Is4() &&
					outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr()))
			}))),
		cel.Function("cidr.overlaps", cel.Overload("cidr_overlaps_string_string",
			[]*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
			cel.BinaryBinding(func(a, b ref.Val) ref.Val {
				s, ok := strs(a, b)
				if !ok {
					return invalid()
				}
				x, ok1 := parseCIDR(s[0], false)
				y, ok2 := parseCIDR(s[1], false)
				if !ok1 || !ok2 {
					return invalid()
				}
				return types.Bool(x.Overlaps(y)) // false across families
			}))),
	}
}

// parseCIDR parses a prefix, or a bare address when addrOK (as a host
// prefix). Host bits are masked (10.1.2.3/8 is 10.0.0.0/8) and an
// IPv4-mapped IPv6 prefix of /96 or longer becomes the IPv4 prefix it maps,
// so ::ffff:10.0.0.0/104 equals 10.0.0.0/8. Zoned addresses are rejected:
// they never lie inside a prefix, which would make a deny control pass.
func parseCIDR(s string, addrOK bool) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if !addrOK || aerr != nil || a.Zone() != "" {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	p = p.Masked()
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p, true
}
