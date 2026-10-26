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
