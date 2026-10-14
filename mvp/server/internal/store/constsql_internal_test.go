package store

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsolation_StatementsAreConstants enforces "no dynamic SQL" (design
// §14.1): tq and sq are called only in package-level var declarations, with a
// name and a single string literal, so every statement the store can run is
// registered at init and seen by TestIsolation_EveryStatementBindsTenant. The
// SQL argument must be a compile-time constant: string literals, optionally
// joined with + to package-level string constants (shared column lists). The
// executors take a tstmt/sstmt, never a string.
func TestIsolation_StatementsAreConstants(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := gotoken.NewFileSet()
	parsed := map[string]*ast.File{}
	consts := map[string]bool{} // package-level const names
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		parsed[path] = f
		for _, d := range f.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == gotoken.CONST {
				for _, sp := range gd.Specs {
					for _, n := range sp.(*ast.ValueSpec).Names {
						consts[n.Name] = true
					}
				}
			}
		}
	}
	var constant func(e ast.Expr) bool
	constant = func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.BasicLit:
			return x.Kind == gotoken.STRING
		case *ast.Ident:
			return consts[x.Name]
		case *ast.BinaryExpr:
			return x.Op == gotoken.ADD && constant(x.X) && constant(x.Y)
		case *ast.ParenExpr:
			return constant(x.X)
		}
		return false
	}
	calls := 0
	for _, f := range parsed {
		// Calls inside package-level var specs are allowed; record them.
		allowed := map[*ast.CallExpr]bool{}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != gotoken.VAR {
				continue
			}
			for _, sp := range gd.Specs {
				for _, v := range sp.(*ast.ValueSpec).Values {
					if c, ok := v.(*ast.CallExpr); ok {
						allowed[c] = true
					}
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := c.Fun.(*ast.Ident)
			if !ok || (id.Name != "tq" && id.Name != "sq" && id.Name != "lq") {
				return true
			}
			calls++
			pos := fset.Position(c.Pos())
			if !allowed[c] {
				t.Errorf("%s: %s called outside a package-level var declaration", pos, id.Name)
			}
			if len(c.Args) != 2 {
				t.Errorf("%s: %s takes a name and one SQL literal", pos, id.Name)
				return true
			}
			if lit, ok := c.Args[0].(*ast.BasicLit); !ok || lit.Kind != gotoken.STRING {
				t.Errorf("%s: %s name is not a string literal", pos, id.Name)
			}
			if !constant(c.Args[1]) {
				t.Errorf("%s: %s SQL is not a compile-time constant (literals and package consts only)", pos, id.Name)
			}
			return true
		})
	}
	if calls != len(statements) {
		t.Errorf("found %d tq/sq/lq calls but %d registered statements", calls, len(statements))
	}
}
