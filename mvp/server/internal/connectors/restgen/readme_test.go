package restgen

import (
	"os"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// The configuration example in mvp/README.md must parse and validate as it is
// printed, so the documentation cannot drift from the code.
func TestREADMEExampleIsAValidSpec(t *testing.T) {
	raw, err := os.ReadFile("../../../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(raw), "### Generic REST connector (issue #552)")
	if !ok {
		t.Fatal("the README has no Generic REST connector section")
	}
	_, block, ok := strings.Cut(after, "```yaml\n")
	if !ok {
		t.Fatal("the section has no yaml example")
	}
	yamlText, _, _ := strings.Cut(block, "```")
	spec, err := ParseSpec([]byte(yamlText))
	if err != nil {
		t.Fatal(err)
	}
	if errs := spec.Validate(connsync.Runtime{Env: config.Prod}); len(errs) != 0 {
		t.Fatalf("the README example is not valid: %v", errs)
	}
	if spec.Writes == nil || spec.Writes.AddMember == nil || spec.Entitlements == nil || spec.Groups.Members == nil {
		t.Errorf("the example lost a section: %+v", spec)
	}
}
