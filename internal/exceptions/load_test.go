package exceptions

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

func TestGrantLoad(t *testing.T) {
	exc := testkeys.Exception()
	dir := t.TempDir()
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	other := func(p map[string]any) { p["grant_id"] = "bobthecorp-other" }
	same := func(p map[string]any) { p["grant_id"] = "bobthecorp-same" }
	write("a-good.dsse.json", sign(t, payload(nil), exc))
	write("b-forged-same-id.dsse.json", tamper(t, sign(t, payload(nil), exc), payload(func(p map[string]any) { p["reason"] = "forged" })))
	write("c-same-1.dsse.json", sign(t, payload(same), exc)) // re-signed identical payloads collapse
	write("c-same-2.dsse.json", sign(t, payload(same), exc))
	write("d-other-1.dsse.json", sign(t, payload(other), exc)) // same id, different payloads: both rejected
	write("d-other-2.dsse.json", sign(t, payload(func(p map[string]any) { other(p); p["reason"] = "changed" }), exc))
	write("e-big.dsse.json", make([]byte, 4<<20+1))
	write("ignored.json", []byte("{}"))
	if err := os.Symlink(filepath.Join(dir, "a-good.dsse.json"), filepath.Join(dir, "f-link.dsse.json")); err != nil {
		t.Fatal(err)
	}
	v := verifier(t, table(t, &profile.Scope{Workspace: ws}, profile.Exceptions{}, "", ""))
	gs, rej, err := v.LoadGrants(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, g := range gs {
		got = append(got, g.GrantID)
	}
	if fmt.Sprint(got) != "[bobthecorp-legacy-db bobthecorp-same]" {
		t.Fatalf("grants %v", got)
	}
	want := map[string]string{"b-forged-same-id.dsse.json": CodeSignature, "d-other-1.dsse.json": CodeDuplicateID,
		"d-other-2.dsse.json": CodeDuplicateID, "e-big.dsse.json": CodeFileTooLarge, "f-link.dsse.json": CodeFileNotRegular}
	if len(rej) != len(want) {
		t.Fatalf("rejections %+v", rej)
	}
	for _, r := range rej {
		if want[r.File] != r.Code {
			t.Fatalf("%s: %s, want %s", r.File, r.Code, want[r.File])
		}
		fileLevel := r.Code == CodeFileTooLarge || r.Code == CodeFileNotRegular
		if fileLevel != (r.Digest == "") {
			t.Fatalf("%s: digest %q", r.File, r.Digest)
		}
	}

	for i := range 257 {
		write(fmt.Sprintf("z%03d.dsse.json", i), []byte("{}"))
	}
	if gs, rej, err := v.LoadGrants(dir); err == nil || gs != nil || rej != nil {
		t.Fatalf("over the file limit: %v %v %v", gs, rej, err)
	}
	if _, _, err := v.LoadGrants(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing dir accepted")
	}
}
