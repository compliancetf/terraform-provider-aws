package verdict

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
)

// TestTestSecret: only a ctftest build accepts the public golden secret as
// the run key (instance_key FORMAT.md v1, Test secret).
func TestTestSecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("key files load only on unix (file_other.go)")
	}
	p := filepath.Join(t.TempDir(), "ctfkit-run.key")
	if err := os.WriteFile(p, []byte(hex.EncodeToString([]byte(testSecret))), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvKeyFile, p)
	if _, ok := checkKey(verdicttest.KeyCheck(t, []byte(testSecret))); ok != allowTestSecret {
		t.Fatalf("test secret accepted = %v, want %v", ok, allowTestSecret)
	}
}
