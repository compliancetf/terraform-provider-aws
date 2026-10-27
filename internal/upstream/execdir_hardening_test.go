package upstream

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/fsutil"
)

// TestExecDirACLPolicy: an ACL entry that lets anyone but us (or a trusted
// admin) write a parent, or access the child, is refused. Deny and
// inherit-only entries do not apply to the object itself.
func TestExecDirACLPolicy(t *testing.T) {
	const self, admin, other = "me", "admin", "other"
	trusted := map[string]bool{admin: true}
	allow := func(who string, rights uint8) aclEntry { return aclEntry{Who: who, Allow: true, Rights: rights} }
	cases := []struct {
		name            string
		e               aclEntry
		ownOnly, sticky bool
		want            string // "" = accepted
	}{
		{"self full", allow(self, aclAdd|aclModify|aclRead), true, false, ""},
		{"admin full", allow(admin, aclAdd|aclModify|aclRead), true, false, ""},
		{"other read on parent", allow(other, aclRead), false, false, ""},
		{"other add on parent", allow(other, aclAdd), false, false, "write"},
		{"other modify on parent", allow(other, aclModify), false, false, "write"},
		{"other add on sticky ancestor", allow(other, aclAdd|aclRead), false, true, ""},
		{"other delete-child on sticky ancestor", allow(other, aclModify), false, true, "write"},
		{"other read on child", allow(other, aclRead), true, false, "access"},
		{"unknown add", allow("", aclAdd), false, false, "(unknown)"},
		{"deny ignored", aclEntry{Who: other, Rights: aclModify}, true, false, ""},
		{"inherit-only ignored", aclEntry{Who: other, Allow: true, InheritOnly: true, Rights: aclModify}, true, false, ""},
	}
	for _, c := range cases {
		err := fsutil.CheckACL([]aclEntry{c.e}, self, trusted, c.ownOnly, c.sticky)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: got %v, want an error naming %q", c.name, err, c.want)
		}
	}
}

// TestExecDirParseFilesec decodes the kauth_filesec that macOS getattrlist
// returns for ATTR_CMN_EXTENDED_SECURITY, in either byte order.
func TestExecDirParseFilesec(t *testing.T) {
	everyone := guid(0xABCDEFAB, 0xCDEF, 0xABCD, 0xEFAB, 0xCDEF, 0x0000000C)
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		b := filesec(order, []kauthACE{
			{everyone, 1, 1<<2 | 1<<5},   // permit add_file,add_subdirectory
			{everyone, 2 | 1<<8, 1 << 4}, // deny delete, inherit-only
			{compatGUID(501), 1, 1 << 1}, // permit read for uid 501
		})
		got, err := parseFilesec(b)
		if err != nil {
			t.Fatalf("%v: %v", order, err)
		}
		want := []aclEntry{
			{Who: "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C", Allow: true, Rights: aclAdd},
			{Who: "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C", InheritOnly: true, Rights: aclModify},
			{Who: "FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F5", Allow: true, Rights: aclRead},
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%v: got %+v, want %+v", order, got, want)
		}
	}
	// KAUTH_ACE_GENERIC_WRITE is 1<<23 and GENERIC_ALL 1<<21 (sys/kauth.h).
	for _, m := range []uint32{1 << 21, 1 << 23} {
		if fsutil.Coarsen(m, kauthAdd, kauthModify)&aclModify == 0 {
			t.Fatalf("generic mask %#x not treated as modify", m)
		}
	}
	noACL := filesec(binary.LittleEndian, nil)
	binary.LittleEndian.PutUint32(noACL[36:], 0xFFFFFFFF) // KAUTH_FILESEC_NOACL
	if got, err := parseFilesec(noACL); err != nil || len(got) != 0 {
		t.Fatalf("NOACL: %v, %v", got, err)
	}
	for _, bad := range [][]byte{{1, 2, 3}, filesec(binary.LittleEndian, nil)[:40], append(filesec(binary.LittleEndian, []kauthACE{{}}), 0)} {
		if _, err := parseFilesec(bad); err == nil {
			t.Fatalf("malformed filesec %x accepted", bad)
		}
	}
}

type kauthACE struct {
	who           [16]byte
	flags, rights uint32
}

func guid(a uint32, b, c, d, e uint16, f uint32) [16]byte {
	var g [16]byte
	binary.BigEndian.PutUint32(g[0:], a)
	binary.BigEndian.PutUint16(g[4:], b)
	binary.BigEndian.PutUint16(g[6:], c)
	binary.BigEndian.PutUint16(g[8:], d)
	binary.BigEndian.PutUint16(g[10:], e)
	binary.BigEndian.PutUint32(g[12:], f)
	return g
}

func compatGUID(uid uint32) [16]byte { return guid(0xFFFFEEEE, 0xDDDD, 0xCCCC, 0xBBBB, 0xAAAA, uid) }

func filesec(order binary.ByteOrder, aces []kauthACE) []byte {
	b := make([]byte, 44, 44+24*len(aces))
	order.PutUint32(b[0:], 0x012cc16d)
	order.PutUint32(b[36:], uint32(len(aces))) //nolint:gosec // test fixture
	for _, a := range aces {
		var fr [8]byte
		order.PutUint32(fr[0:], a.flags)
		order.PutUint32(fr[4:], a.rights)
		b = append(append(b, a.who[:]...), fr[:]...)
	}
	return b
}

// TestExecDirWindowsPathAliases: the \\?\ and \\.\ spellings of a Windows
// path compare equal to the plain one.
func TestExecDirWindowsPathAliases(t *testing.T) {
	for in, want := range map[string]string{
		`\\?\C:\Users\me\cache`:     `C:\Users\me\cache`,
		`\\.\C:\Users\me`:           `C:\Users\me`,
		`\\?\UNC\srv\share\plugins`: `\\srv\share\plugins`,
		`\\?\unc\srv\share`:         `\\srv\share`,
		`C:\plain`:                  `C:\plain`,
		`\\srv\share\x`:             `\\srv\share\x`,
		`\\?\Volume{1234}\x`:        `\\?\Volume{1234}\x`,
	} {
		if got := stripWinPrefix(in); got != want {
			t.Errorf("stripWinPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestExecDirHostTagPIDNamespace: processes in different PID namespaces that
// share a hostname get different tags, so neither sweeps the other's children
// on a PID that means nothing in its own namespace. The initial namespace
// keeps the hostname-only tag.
func TestExecDirHostTagPIDNamespace(t *testing.T) {
	const init = "pid:[4026531836]"
	if hostTagFor("h", "") != hostTagFor("h", init) {
		t.Fatal("initial PID namespace changed the tag")
	}
	if a, b := hostTagFor("h", "pid:[4026532001]"), hostTagFor("h", "pid:[4026532002]"); a == b || a == hostTagFor("h", init) {
		t.Fatalf("namespaces share a tag: %s %s", a, b)
	}
	if hostTagFor("h", "unknown:a") == hostTagFor("h", "") {
		t.Fatal("hidden namespace shares the host tag")
	}
	if !childRe.MatchString(hostTagFor("h", "pid:[1]") + ".1-x") {
		t.Fatal("tag does not match childRe")
	}
}

// TestExecDirSweepsNonChosenParents: a stale child under a valid parent that
// was not chosen is swept too; a missing candidate is not created.
func TestExecDirSweepsNonChosenParents(t *testing.T) {
	base := realTempDir(t)
	chosen, other, missing := filepath.Join(base, "chosen"), filepath.Join(base, "other"), filepath.Join(base, "missing")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(other, fmt.Sprintf("%s.%d-1", hostTag(), deadPID(t)))
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	d := mustExecDir(t, []string{chosen, other, missing}, nil)
	if filepath.Dir(d.dir) != chosen {
		t.Fatalf("exec dir %q, want a child of %q", d.dir, chosen)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale child under a non-chosen parent kept: %v", err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("non-chosen candidate created: %v", err)
	}
}

// deadPID is the PID of a child that has exited and been reaped.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$") //nolint:gosec // the test binary
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid
}
