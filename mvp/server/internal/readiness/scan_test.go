package readiness

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// stateWrite matches SQL that writes the state column of connection_revisions.
var stateWrite = regexp.MustCompile(`(?is)\bupdate\s+connection_revisions\b.*\bset\b.*\bstate\s*=`)

// revInsert matches SQL that inserts revisions (and so chooses their first state).
var revInsert = regexp.MustCompile(`(?is)\binsert\s+(or\s+\w+\s+)?into\s+connection_revisions\b`)

type violation struct{ pos, msg string }

// scanSource reports every place outside package readiness that calls
// SetRevisionState, and every SQL literal outside store.SetRevisionState
// (store.InsertRevision for inserts) that writes revision state.
func scanSource(fset *token.FileSet, f *ast.File, path string) []violation {
	var out []violation
	dir := filepath.ToSlash(filepath.Dir(path))
	inReadiness := strings.HasSuffix(dir, "internal/readiness")
	inStore := strings.HasSuffix(dir, "internal/store")
	var fn string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			fn = x.Name.Name
		case *ast.SelectorExpr:
			if x.Sel.Name == "SetRevisionState" && !inReadiness {
				out = append(out, violation{fset.Position(x.Pos()).String(), "calls SetRevisionState outside internal/readiness"})
			}
		case *ast.BasicLit:
			if x.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(x.Value)
			if err != nil {
				return true
			}
			if stateWrite.MatchString(s) && !(inStore && fn == "SetRevisionState") {
				out = append(out, violation{fset.Position(x.Pos()).String(), "SQL writes connection_revisions.state"})
			}
			if revInsert.MatchString(s) && !(inStore && fn == "InsertRevision") {
				out = append(out, violation{fset.Position(x.Pos()).String(), "SQL inserts connection_revisions"})
			}
		}
		return true
	})
	return out
}

func TestOnlyReadinessWritesConnectionState(t *testing.T) {
	root := filepath.Join("..", "..") // mvp/server
	fset := token.NewFileSet()
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".")) && path != root {
			return filepath.SkipDir
		}
		// this file holds deliberate violations as scanner fixtures
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(filepath.ToSlash(path), "internal/readiness/scan_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		for _, v := range scanSource(fset, f, path) {
			t.Errorf("%s: %s", v.pos, v.msg)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 50 {
		t.Fatalf("scanned only %d files; is the root right?", files)
	}
}

// The scanner itself must catch violations.
func TestScanSource_CatchesViolations(t *testing.T) {
	src := `package api
func f(c any) {
	c.SetRevisionState(nil)
	_ = "UPDATE connection_revisions SET config = ?, state = 'active' WHERE id = ?"
	_ = ` + "`INSERT INTO connection_revisions (id, state) VALUES (?, 'active')`" + `
	_ = "UPDATE connection_revisions SET config = ? WHERE id = ?" // allowed: no state
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "internal/api/x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v := scanSource(fset, f, "internal/api/x.go"); len(v) != 3 {
		t.Fatalf("want 3 violations, got %+v", v)
	}
	f2, _ := parser.ParseFile(fset, "internal/store/y.go", `package store
func (c *Conn) SetRevisionState() { _ = "UPDATE connection_revisions SET state = ? WHERE id = ?" }`, 0)
	if v := scanSource(fset, f2, "internal/store/y.go"); len(v) != 0 {
		t.Fatalf("the store's own SetRevisionState flagged: %+v", v)
	}
}
