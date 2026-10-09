// Package archtest holds architecture tests that keep tenant isolation
// enforceable by construction (docs/design/phase-0-platform-security.md §14.4).
package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// storeDir is the only directory (module-relative) allowed to talk to the
// database. Its subpackages (storetest) are not.
const storeDir = "internal/store"

// bannedImports may be imported only by storeDir. A path ending in "/" bans
// the whole tree.
var bannedImports = []string{
	"database/sql",
	"database/sql/driver",
	"modernc.org/sqlite",
	"modernc.org/sqlite/",
	"github.com/jackc/pgx/",
	"github.com/mattn/go-sqlite3",
	"unsafe",
}

// bannedCalls are method names that run SQL or reach a raw connection.
var bannedCalls = map[string]bool{
	"Query": true, "QueryContext": true, "QueryRow": true, "QueryRowContext": true,
	"Exec": true, "ExecContext": true, "Prepare": true, "PrepareContext": true,
	"Raw": true, "Conn": true,
}

// bannedReflect are reflect calls that read or write unexported fields.
var bannedReflect = map[string]bool{"NewAt": true, "UnsafeAddr": true, "UnsafePointer": true}

// allowedCall is a syntactic allowlist for banned method names on types that
// have nothing to do with a database. Without type information the receiver
// is recognised by the last name in its expression.
func allowedCall(method string, recv ast.Expr) bool {
	// (*net/url.URL).Query, as in r.URL.Query().
	return method == "Query" && lastName(recv) == "URL"
}

func lastName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	}
	return ""
}

func banned(path string) bool {
	for _, b := range bannedImports {
		if path == b || (strings.HasSuffix(b, "/") && strings.HasPrefix(path, b)) {
			return true
		}
	}
	return false
}

// checkFile returns the isolation violations in one parsed file.
func checkFile(fset *token.FileSet, f *ast.File) []string {
	var out []string
	at := func(p token.Pos, msg string) { out = append(out, fset.Position(p).String()+": "+msg) }
	reflectName := ""
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if banned(path) {
			at(imp.Pos(), "imports "+path+" (only "+storeDir+" may)")
		}
		if path == "reflect" {
			reflectName = "reflect"
			if imp.Name != nil {
				reflectName = imp.Name.Name
			}
		}
	}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//go:linkname") {
				at(c.Pos(), "go:linkname can reach unexported store internals")
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := sel.Sel.Name
		if bannedCalls[name] && !allowedCall(name, sel.X) {
			at(sel.Sel.Pos(), "calls ."+name+"(…), which runs SQL outside "+storeDir)
		}
		if bannedReflect[name] && reflectName != "" {
			at(sel.Sel.Pos(), "uses reflect ."+name+", which can read unexported fields")
		}
		return true
	})
	return out
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// TestIsolation_NoRawSQLOutsideStore parses every .go file of the module,
// tests included. Outside internal/store it fails on imports of database/sql,
// database drivers or unsafe, on calls of Query/Exec/Prepare/Raw/Conn-style
// methods, on reflect calls that reach unexported fields, and on go:linkname.
func TestIsolation_NoRawSQLOutsideStore(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	files, storeFiles := 0, 0
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
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		if filepath.ToSlash(filepath.Dir(rel)) == storeDir {
			storeFiles++
			return nil
		}
		files++
		for _, v := range checkFile(fset, f) {
			t.Error(v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 20 || storeFiles == 0 {
		t.Fatalf("scanned %d files outside the store and %d inside; the walk is not covering the module", files, storeFiles)
	}
}

// TestArchtestCatchesViolations is the positive control: every rule fires on
// a file that breaks it, and the allowlist lets url.URL.Query through.
func TestArchtestCatchesViolations(t *testing.T) {
	src := `package bad

import (
	"database/sql"
	_ "modernc.org/sqlite"
	"unsafe"
	rf "reflect"
	"net/http"
)

//go:linkname x github.com/nischalravi/tessera/mvp/server/internal/store.x

func f(db *sql.DB, tx *sql.Tx, r *http.Request, v rf.Value) {
	db.QueryContext(nil, "SELECT 1")
	tx.Exec("DELETE FROM agent_delegations")
	db.Conn(nil)
	_ = r.URL.Query()
	_ = v.UnsafePointer()
	_ = rf.NewAt(nil, unsafe.Pointer(nil))
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "bad.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(checkFile(fset, f), "\n")
	for _, want := range []string{
		"imports database/sql", "imports modernc.org/sqlite", "imports unsafe", "go:linkname",
		".QueryContext(", ".Exec(", ".Conn(", "reflect .UnsafePointer", "reflect .NewAt",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no violation %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, ".Query(") {
		t.Errorf("r.URL.Query() was flagged:\n%s", got)
	}
	if n := len(checkFile(fset, f)); n != 9 {
		t.Errorf("%d violations, want 9:\n%s", n, got)
	}
}
