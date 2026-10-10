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

// The store declares its SQL as package-level statement constants; these are
// the only two allowed to write revision state, and each may be used only by
// its repository method.
var stateStatements = map[string]string{"revisionsSetState": "SetRevisionState", "revisionsInsert": "InsertRevision"}

// scanSource reports every place outside package readiness that calls
// SetRevisionState, and every SQL literal that writes revision state other
// than the store's revisionsSetState and revisionsInsert statements (each
// used only by store.SetRevisionState and store.InsertRevision).
func scanSource(fset *token.FileSet, f *ast.File, path string) []violation {
	var out []violation
	dir := filepath.ToSlash(filepath.Dir(path))
	inReadiness := strings.HasSuffix(dir, "internal/readiness")
	inStore := strings.HasSuffix(dir, "internal/store")
	inspect := func(node ast.Node, fn string) {
		ast.Inspect(node, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if want, ok := stateStatements[x.Name]; ok && inStore && fn != want && fn != x.Name {
					out = append(out, violation{fset.Position(x.Pos()).String(), x.Name + " used outside store." + want})
				}
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
				if stateWrite.MatchString(s) && !(inStore && fn == "revisionsSetState") {
					out = append(out, violation{fset.Position(x.Pos()).String(), "SQL writes connection_revisions.state"})
				}
				if revInsert.MatchString(s) && !(inStore && fn == "revisionsInsert") {
					out = append(out, violation{fset.Position(x.Pos()).String(), "SQL inserts connection_revisions"})
				}
			}
			return true
		})
	}
	// fn is the enclosing function, or the package-level variable being declared.
	for _, d := range f.Decls {
		switch x := d.(type) {
		case *ast.FuncDecl:
			inspect(x, x.Name.Name)
		case *ast.GenDecl:
			for _, sp := range x.Specs {
				fn := ""
				if vs, ok := sp.(*ast.ValueSpec); ok && len(vs.Names) > 0 {
					fn = vs.Names[0].Name
				}
				inspect(sp, fn)
			}
		}
	}
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
var revisionsSetState = tq("x", "UPDATE connection_revisions SET state = @to WHERE tenant_id = @tenant")
var other = tq("y", "UPDATE connection_revisions SET state = @to WHERE tenant_id = @tenant")
func (tx *TenantTx) SetRevisionState() { _ = revisionsSetState }
func (tx *TenantTx) Sneaky() { _ = revisionsSetState }`, 0)
	v := scanSource(fset, f2, "internal/store/y.go")
	if len(v) != 2 || !strings.Contains(v[0].msg, "writes connection_revisions.state") || !strings.Contains(v[1].msg, "outside store.SetRevisionState") {
		t.Fatalf("want the second statement and the Sneaky use flagged, got %+v", v)
	}
}
