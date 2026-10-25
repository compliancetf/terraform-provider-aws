package lib

import "testing"

func TestTagsHas(t *testing.T) {
	runHelperCases(t, map[string]any{"Owner": "bobthecorp", "env": "prod", "Empty": ""}, []helperCase{
		{`tags.has(v, "Owner")`, true, nil},
		{`tags.has(v, "owner")`, false, nil}, // keys are case-sensitive
		{`tags.has(v, "Missing")`, false, nil},
		{`tags.has(v, "Empty")`, true, nil},
		{`tags.has(v, "Owner", "bobthecorp")`, true, nil},
		{`tags.has(v, "Owner", "BobTheCorp")`, false, nil},
		{`tags.has(v, "env", "prod")`, true, nil},
		{`tags.has(v, "Missing", "")`, false, nil},
		{`tags.has(v, "Empty", "")`, true, nil},
		{`tags.has({"a": "b"}, "a")`, true, nil},
	})
	// a null map has no tags
	runHelperCases(t, nil, []helperCase{
		{`tags.has(v, "Owner")`, false, nil},
		{`tags.has(v, "Owner", "x")`, false, nil},
		{`tags.has(null, "Owner")`, false, nil},
	})
	// not a map: type_error, never false
	runHelperCases(t, "Owner", []helperCase{
		{`tags.has(v, "Owner")`, nil, errNoOverload},
		{`tags.has(v, "Owner", "x")`, nil, errNoOverload},
	})
	// a null value is an unset tag (the AWS provider drops it); any other
	// value that is not a string is malformed, never a non-match
	runHelperCases(t, map[string]any{"Owner": 1, "Null": nil}, []helperCase{
		{`tags.has(v, "Null")`, false, nil},
		{`tags.has(v, "Null", "")`, false, nil},
		{`tags.has(v, "Owner")`, nil, ErrInvalid},
		{`tags.has(v, "Owner", "1")`, nil, ErrInvalid},
	})
}
