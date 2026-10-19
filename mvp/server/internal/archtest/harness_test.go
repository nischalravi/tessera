package archtest

import (
	"strings"
	"testing"
)

// The differential harness (design §13.1, §5) does I/O and links the AWS SDK,
// so the server must never link it. Outside tests, only cmd/tessera-harness
// imports internal/aws/harness, and only the harness imports the cassette
// recorder internal/aws/awstest.
const (
	harnessPkg  = "internal/aws/harness"
	harnessMain = "cmd/tessera-harness"
)

func inTree(pkg, tree string) bool { return pkg == tree || strings.HasPrefix(pkg, tree+"/") }

// harnessViolations lists the imports of graph that break the rule.
func harnessViolations(graph map[string][]string) []string {
	var out []string
	for pkg, deps := range graph {
		for _, dep := range deps {
			switch {
			case inTree(dep, harnessPkg) && pkg != harnessMain && !inTree(pkg, harnessPkg):
				out = append(out, pkg+" imports "+dep+"; only "+harnessMain+" may")
			case inTree(dep, awstestPkg) && !inTree(pkg, harnessPkg) && !inTree(pkg, awstestPkg):
				out = append(out, pkg+" imports "+dep+"; only "+harnessPkg+" may")
			}
		}
	}
	return out
}

// TestHarnessOnlyImportedByItsBinary proves from the import graph of non-test
// files that the harness is imported by cmd/tessera-harness alone and that the
// production binary and the API do not reach it, directly or transitively.
func TestHarnessOnlyImportedByItsBinary(t *testing.T) {
	graph := moduleImports(t, moduleRoot(t))
	for _, p := range []string{harnessPkg, awstestPkg, harnessMain} {
		if _, ok := graph[p]; !ok {
			t.Fatalf("package %s not found; the test is not looking at the module", p)
		}
	}
	for _, v := range harnessViolations(graph) {
		t.Error(v)
	}
	for _, root := range productionRoots {
		for _, banned := range []string{harnessPkg, awstestPkg} {
			if chain := reachable(graph, root, banned); chain != nil {
				t.Errorf("%s links %s: %s", root, banned, strings.Join(chain, " -> "))
			}
		}
	}
	// Positive control: the walk does see the harness binary's import.
	if reachable(graph, harnessMain, harnessPkg) == nil || reachable(graph, harnessMain, awstestPkg) == nil {
		t.Fatal("cmd/tessera-harness does not reach the harness; the import graph is incomplete")
	}
}

// TestHarnessRuleCatchesViolations is the control for the rule itself.
func TestHarnessRuleCatchesViolations(t *testing.T) {
	bad := map[string][]string{
		"cmd/tessera":          {"internal/aws/harness"},
		"internal/api":         {"internal/aws/awstest"},
		"internal/aws/eval":    {"internal/aws/harness/sub"},
		"cmd/tessera-harness":  {"internal/aws/harness"},
		"internal/aws/harness": {"internal/aws/awstest"},
	}
	got := strings.Join(harnessViolations(bad), "\n")
	for _, want := range []string{"cmd/tessera imports internal/aws/harness", "internal/api imports internal/aws/awstest", "internal/aws/eval imports internal/aws/harness/sub"} {
		if !strings.Contains(got, want) {
			t.Errorf("no violation %q in:\n%s", want, got)
		}
	}
	if n := len(harnessViolations(bad)); n != 3 {
		t.Errorf("%d violations, want 3:\n%s", n, got)
	}
}
