// Package sdkregion checks testdata/sdkregion/corpus.json against
// aws-sdk-go-v2 config: each entry's "sdk" is the
// region the SDK reads for its profile from the file ("" for none) and
// "error" whether LoadSharedConfigProfile refuses the profile. The lifecycle test then requires the provider's strict parser to
// agree with it whenever it returns a region. A separate module, so the SDK
// stays out of the provider's go.mod. Synthetic temp files only.
package sdkregion

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
)

var update = flag.Bool("update", false, "rewrite the corpus sdk values")

const corpusPath = "../../testdata/sdkregion/corpus.json"

type entry struct {
	Name    string `json:"name"`
	INI     string `json:"ini"`
	Profile string `json:"profile"`
	SDK     string `json:"sdk"`
	Error   bool   `json:"error"`
}

func sdkRegion(t *testing.T, ini, profile string) (string, bool) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	if err := os.WriteFile(cfg, []byte(ini), 0o600); err != nil {
		t.Fatal(err)
	}
	sc, err := config.LoadSharedConfigProfile(context.Background(), profile, func(o *config.LoadSharedConfigOptions) {
		o.ConfigFiles = []string{cfg}
		o.CredentialsFiles = []string{filepath.Join(dir, "absent")}
	})
	if err != nil {
		return "", true
	}
	return sc.Region, false
}

func TestCorpusMatchesSDK(t *testing.T) {
	b, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	var corpus []entry
	if err := json.Unmarshal(b, &corpus); err != nil {
		t.Fatal(err)
	}
	for i, e := range corpus {
		got, failed := sdkRegion(t, e.INI, e.Profile)
		if *update {
			corpus[i].SDK, corpus[i].Error = got, failed
		} else if got != e.SDK || failed != e.Error {
			t.Errorf("%s: SDK region %q error %v, corpus says %q error %v", e.Name, got, failed, e.SDK, e.Error)
		}
	}
	if *update {
		out, err := json.MarshalIndent(corpus, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(corpusPath, append(out, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
