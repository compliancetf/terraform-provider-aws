package hook

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestValueDecodesOnceAndLazily(t *testing.T) {
	dv, err := tfprotov5.NewDynamicValue(tftypes.String, tftypes.NewValue(tftypes.String, "x"))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	v := NewValue(dv.MsgPack, nil, func() (tftypes.Type, error) { calls++; return tftypes.String, nil })
	if calls != 0 {
		t.Fatal("type resolved before Get")
	}
	for range 2 {
		got, err := v.Get()
		if err != nil || !got.Equal(tftypes.NewValue(tftypes.String, "x")) {
			t.Fatalf("Get = %v, %v", got, err)
		}
	}
	if calls != 1 {
		t.Errorf("type resolved %d times, want 1", calls)
	}
}

func TestValueRejectsDualEncoding(t *testing.T) {
	dv, err := tfprotov5.NewDynamicValue(tftypes.String, tftypes.NewValue(tftypes.String, "x"))
	if err != nil {
		t.Fatal(err)
	}
	v := NewValue(dv.MsgPack, []byte(`"y"`), func() (tftypes.Type, error) { return tftypes.String, nil })
	if _, err := v.Get(); err == nil {
		t.Fatal("value with both encodings decoded")
	}
}

func TestIsNoop(t *testing.T) {
	for name, tc := range map[string]struct {
		ev   Evaluator
		want bool
	}{
		"nil":      {nil, true},
		"value":    {Noop{}, true},
		"pointer":  {&Noop{}, true},
		"embedded": {struct{ Noop }{}, false},
	} {
		if got := IsNoop(tc.ev); got != tc.want {
			t.Errorf("%s: IsNoop = %v, want %v", name, got, tc.want)
		}
	}
}
