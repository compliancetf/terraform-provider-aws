//go:build ctftest

package fetch

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func serveProfile(t *testing.T, body *[]byte, code *int) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/orgs/bobthecorp/profile" || r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("request %s", r.URL.Path)
		}
		if *code != http.StatusOK {
			w.WriteHeader(*code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(*body) //nolint:errcheck // test server
	}
}

func TestProfile(t *testing.T) {
	body, code := fixture(t, "profiles/bobthecorp-bad-sig.dsse.json"), http.StatusOK
	newServer(t, serveProfile(t, &body, &code))
	c, dir := newClient(t, "tok", false)
	pdir := filepath.Join(dir, "profiles", org)
	if _, _, err := c.Profile(context.Background(), org, noRevs); err == nil {
		t.Fatal("bad signature accepted")
	}
	if _, err := os.Stat(pdir); !os.IsNotExist(err) {
		t.Fatal("bad profile cached")
	}
	v7 := fixture(t, "profiles/bobthecorp-v7.dsse.json")
	body = v7
	env, warns, err := c.Profile(context.Background(), org, noRevs)
	if err != nil || !bytes.Equal(env, v7) || len(warns) != 0 {
		t.Fatal(warns, err)
	}
	if cached, err := os.ReadFile(filepath.Join(pdir, "v7.dsse.json")); err != nil || !bytes.Equal(cached, v7) {
		t.Fatal("profile not cached", err)
	}
	for c2, wantErr := range map[int]bool{503: false, 429: false, 403: true, 404: true} {
		code = c2
		env, warns, err := c.Profile(context.Background(), org, noRevs)
		if wantErr != (err != nil) || env != nil || !wantErr && (len(warns) != 1 || !strings.Contains(warns[0], "unreachable")) {
			t.Fatalf("%d: %q %v", c2, warns, err)
		}
	}
}

func TestProfileOfflineTokenlessInvalid(t *testing.T) {
	s := newServer(t, func(http.ResponseWriter, *http.Request) {})
	c, _ := newClient(t, "tok", true)
	if env, warns, err := c.Profile(context.Background(), org, noRevs); err != nil || env != nil || len(warns) != 1 {
		t.Fatal(warns, err)
	}
	c, _ = newClient(t, "", false)
	if env, warns, err := c.Profile(context.Background(), org, noRevs); err != nil || env != nil || warns != nil {
		t.Fatal(warns, err)
	}
	c, _ = newClient(t, "tok", false)
	if _, _, err := c.Profile(context.Background(), "../x", noRevs); err == nil {
		t.Fatal("bad org accepted")
	}
	if s.hits.Load() != 0 {
		t.Fatalf("made %d requests", s.hits.Load())
	}
}

func TestProfileCacheRetention(t *testing.T) {
	body, code := fixture(t, "profiles/bobthecorp-v7.dsse.json"), http.StatusOK
	newServer(t, serveProfile(t, &body, &code))
	c, dir := newClient(t, "tok", false)
	pdir := filepath.Join(dir, "profiles", org)
	for _, v := range []string{"1", "2", "3", "4", "5", "6", "8", "9", "10"} {
		put(t, pdir, "v"+v+".dsse.json", []byte("old"))
	}
	if _, warns, err := c.Profile(context.Background(), org, noRevs); err != nil || len(warns) != 0 {
		t.Fatal(warns, err)
	}
	for v, want := range map[string]bool{"1": false, "2": false, "3": true, "7": true, "10": true} {
		if _, err := os.Stat(filepath.Join(pdir, "v"+v+".dsse.json")); (err == nil) != want {
			t.Fatalf("v%s present=%v", v, err == nil)
		}
	}
	// A different envelope already cached at v7 is kept for the loader's
	// conflict check; the fetched bytes are still returned.
	put(t, pdir, "v7.dsse.json", []byte("other"))
	if env, warns, err := c.Profile(context.Background(), org, noRevs); err != nil || env == nil || len(warns) != 1 {
		t.Fatal(warns, err)
	}
	if got, _ := os.ReadFile(filepath.Join(pdir, "v7.dsse.json")); string(got) != "other" {
		t.Fatal("cached v7 overwritten")
	}
}

func TestWriteNoReplace(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, "v7.dsse.json", []byte("first"))
	if err := writeAtomic(dir, dir, "v7.dsse.json", []byte("second"), false); !os.IsExist(err) {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if got, _ := os.ReadFile(filepath.Join(dir, "v7.dsse.json")); string(got) != "first" || len(ents) != 1 {
		t.Fatalf("replaced or temp left: %q, %d entries", got, len(ents))
	}
}
