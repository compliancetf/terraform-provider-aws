package proxy

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// forbiddenDep matches terraform-plugin-go's gRPC servers and any vendored or
// internal copy of the plugin protocol. The generated internal/tfplugin/tfplugin5
// must be the only registrant of tfplugin5.proto in the provider binary.
var forbiddenDep = regexp.MustCompile(`/tfprotov5/tf5server$|/tfprotov6/tf6server$|/internal/tfplugin[56](/|$)`)

func TestNoPluginGoServerLinked(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", ".")
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps .: %v", err)
	}
	for _, pkg := range strings.Fields(string(out)) {
		if forbiddenDep.MatchString(pkg) {
			t.Errorf("provider binary links %s", pkg)
		}
	}
}
