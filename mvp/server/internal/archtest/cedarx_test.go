package archtest

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// internal/cedarx is the only place that imports cedar-go (AC-1, access-as-code
// design §9), and it imports nothing of Tessera's own: it is pure, which
// TestAWSEvaluatorPackagesArePure also checks for its imports and clock.

const (
	cedarGoModule  = "github.com/cedar-policy/cedar-go"
	cedarxDir      = "internal/cedarx"
	agentscopeDir  = "internal/agentscope"
	moduleInternal = "github.com/nischalravi/tessera/mvp/server/"
)

func TestCedarGoOnlyInCedarx(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	cedarxFiles := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		inCedarx := rel == cedarxDir
		if inCedarx {
			cedarxFiles++
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			switch {
			case (p == cedarGoModule || strings.HasPrefix(p, cedarGoModule+"/")) && !inCedarx:
				t.Errorf("%s imports %s; only %s may", filepath.ToSlash(path), p, cedarxDir)
			case inCedarx && strings.HasPrefix(p, moduleInternal):
				t.Errorf("%s imports %s; %s depends on no Tessera package", filepath.ToSlash(path), p, cedarxDir)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if cedarxFiles == 0 {
		t.Fatalf("%s has no Go files; the rule is vacuous", cedarxDir)
	}
}

// TestPolicyBundleIsOffline: the bundle loader and test runner (AC-2) run in the
// CLI with no tenant and no network, so, besides the purity rule (no os, net,
// database/sql, clock), nothing it imports, directly or through other module
// packages, may reach the store, the HTTP layer or the outbound client; its only
// module dependencies are internal/cedarx and internal/agentscope (AC-7: the agent
// scope document, itself pure and importing no module package).
func TestPolicyBundleIsOffline(t *testing.T) {
	graph := moduleImports(t, moduleRoot(t))
	const bundle = "internal/policybundle"
	deps, ok := graph[bundle]
	if !ok {
		t.Fatalf("package %s not found; the test is not looking at the module", bundle)
	}
	for _, d := range deps {
		if d != cedarxDir && d != agentscopeDir {
			t.Errorf("%s imports %s; its only module dependencies are %s and %s", bundle, d, cedarxDir, agentscopeDir)
		}
	}
	if len(graph[agentscopeDir]) != 0 {
		t.Errorf("%s imports %v; it depends on no Tessera package", agentscopeDir, graph[agentscopeDir])
	}
	for _, banned := range []string{"internal/store", "internal/api", "internal/safehttp", "internal/sod"} {
		if chain := reachable(graph, bundle, banned); chain != nil {
			t.Errorf("%s reaches %s: %s", bundle, banned, strings.Join(chain, " -> "))
		}
	}
}
