package lib

import (
	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
)

// tagsFuncs declares tags.has(tags, key) and tags.has(tags, key, value):
// exact, case-sensitive key (AWS tag keys are case-sensitive) and value. A
// null map, and a null value, is an unset tag.
func tagsFuncs() []cel.EnvOption {
	tags := cel.MapType(cel.StringType, cel.DynType)
	return []cel.EnvOption{cel.Function("tags.has",
		cel.Overload("tags_has_map_string", []*cel.Type{tags, cel.StringType}, cel.BoolType,
			cel.BinaryBinding(func(m, k ref.Val) ref.Val { return tagsHas(m, k, nil) })),
		cel.Overload("tags_has_null_string", []*cel.Type{cel.NullType, cel.StringType}, cel.BoolType,
			cel.BinaryBinding(func(m, k ref.Val) ref.Val { return tagsHas(m, k, nil) })),
		cel.Overload("tags_has_map_string_string", []*cel.Type{tags, cel.StringType, cel.StringType}, cel.BoolType,
			cel.FunctionBinding(func(a ...ref.Val) ref.Val { return tagsHas(a[0], a[1], a[2]) })),
		cel.Overload("tags_has_null_string_string", []*cel.Type{cel.NullType, cel.StringType, cel.StringType}, cel.BoolType,
			cel.FunctionBinding(func(a ...ref.Val) ref.Val { return tagsHas(a[0], a[1], a[2]) })),
	)}
}

// tagsHas reports whether map m has key k set, and when want is not nil,
// set to want. Anything but a map of strings is ErrInvalid.
func tagsHas(m, k, want ref.Val) ref.Val {
	key, ok := k.(types.String)
	if !ok {
		return invalid()
	}
	if m == types.NullValue {
		return types.False
	}
	mp, ok := m.(traits.Mapper)
	if !ok {
		return invalid()
	}
	v, found := mp.Find(key)
	if !found || v == types.NullValue {
		return types.False
	}
	s, ok := v.(types.String)
	if !ok {
		return invalid()
	}
	if want == nil {
		return types.True
	}
	w, ok := want.(types.String)
	if !ok {
		return invalid()
	}
	return types.Bool(s == w)
}
