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

// devidpPkg is the dev IdP (docs/design/phase-0-platform-security.md §18.4,
// §18.5). Only its own command and its own subpackages may import it outside
// tests; the production binary must not link it.
const devidpPkg = "internal/devidp"

// productionRoots are the packages of the production binary and the API.
var productionRoots = []string{"cmd/tessera", "internal/api"}

// moduleImports maps every package directory of the module (module-relative)
// to the module-internal packages its non-test files import. Build tags are
// ignored, so every file counts: the graph is a superset of any real build.
func moduleImports(t *testing.T, root string) map[string][]string {
	t.Helper()
	const module = "github.com/nischalravi/tessera/mvp/server/"
	graph := map[string][]string{}
	fset := token.NewFileSet()
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
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		dir := filepath.ToSlash(rel)
		if _, ok := graph[dir]; !ok {
			graph[dir] = nil
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if strings.HasPrefix(p, module) {
				graph[dir] = append(graph[dir], strings.TrimPrefix(p, module))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return graph
}

// reachable returns the import path from root to a package under target, or
// nil if there is none.
func reachable(graph map[string][]string, root, target string) []string {
	prev := map[string]string{root: ""}
	queue := []string{root}
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if pkg == target || strings.HasPrefix(pkg, target+"/") {
			var chain []string
			for p := pkg; p != ""; p = prev[p] {
				chain = append([]string{p}, chain...)
			}
			return chain
		}
		for _, dep := range graph[pkg] {
			if _, seen := prev[dep]; !seen {
				prev[dep] = pkg
				queue = append(queue, dep)
			}
		}
	}
	return nil
}

// TestIsolation_DevIdPNotImportedByAPI proves, from the module's import
// graph, that neither the production binary (cmd/tessera) nor internal/api
// reaches internal/devidp directly or transitively, and that outside tests
// only cmd/tessera-devidp and the dev IdP's own packages import it.
func TestIsolation_DevIdPNotImportedByAPI(t *testing.T) {
	graph := moduleImports(t, moduleRoot(t))
	for _, root := range productionRoots {
		if _, ok := graph[root]; !ok {
			t.Fatalf("package %s not found; the test is not looking at the module", root)
		}
		if chain := reachable(graph, root, devidpPkg); chain != nil {
			t.Errorf("%s links the dev IdP: %s", root, strings.Join(chain, " -> "))
		}
	}
	for pkg, deps := range graph {
		if pkg == "cmd/tessera-devidp" || pkg == devidpPkg || strings.HasPrefix(pkg, devidpPkg+"/") {
			continue
		}
		for _, dep := range deps {
			if dep == devidpPkg || strings.HasPrefix(dep, devidpPkg+"/") {
				t.Errorf("%s imports %s; only cmd/tessera-devidp may (tests excepted)", pkg, dep)
			}
		}
	}
	// Positive control: the walk does see the dev IdP binary's import.
	if reachable(graph, "cmd/tessera-devidp", devidpPkg) == nil {
		t.Fatal("cmd/tessera-devidp does not reach internal/devidp; the import graph is incomplete")
	}
}

// TestFakeTargetOnlyImportedByTheBinary: the in-process fake provisioning
// target (and the replay helper) is a dev and test tool. Outside tests only
// cmd/tessera (which starts it behind TESSERA_DEV_FAKE_TARGET, refused in
// prod) imports it; the API and the engine never do.
func TestFakeTargetOnlyImportedByTheBinary(t *testing.T) {
	graph := moduleImports(t, moduleRoot(t))
	const fakePkg, replayPkg = "internal/provision/fake", "internal/provision/replay"
	found := false
	for pkg, deps := range graph {
		for _, dep := range deps {
			switch dep {
			case fakePkg:
				found = found || pkg == "cmd/tessera"
				if pkg != "cmd/tessera" {
					t.Errorf("%s imports %s; only cmd/tessera may (tests excepted)", pkg, dep)
				}
			case replayPkg:
				t.Errorf("%s imports %s; it is for tests only", pkg, dep)
			}
		}
	}
	if !found {
		t.Fatal("cmd/tessera does not import the fake target; the import graph is incomplete")
	}
}

// TestReachableFindsTransitiveImports is the control for the graph walk.
func TestReachableFindsTransitiveImports(t *testing.T) {
	g := map[string][]string{"cmd/tessera": {"internal/api"}, "internal/api": {"internal/x"}, "internal/x": {"internal/devidp/devidptest"}}
	got := strings.Join(reachable(g, "cmd/tessera", devidpPkg), " -> ")
	if got != "cmd/tessera -> internal/api -> internal/x -> internal/devidp/devidptest" {
		t.Fatalf("chain %q", got)
	}
	if reachable(map[string][]string{"cmd/tessera": {"internal/api"}}, "cmd/tessera", devidpPkg) != nil {
		t.Fatal("false positive")
	}
}

// authtestPkg is the test-only session helper (design §19 PR5): it mints
// sessions without an IdP, so no non-test file may import it.
const authtestPkg = "internal/auth/authtest"

// TestAuthtestOnlyInTests proves from the import graph of non-test files
// that nothing but tests imports internal/auth/authtest (it also refuses to
// run unless TESSERA_ENV=test).
func TestAuthtestOnlyInTests(t *testing.T) {
	graph := moduleImports(t, moduleRoot(t))
	if _, ok := graph[authtestPkg]; !ok {
		t.Fatalf("package %s not found; the test is not looking at the module", authtestPkg)
	}
	for pkg, deps := range graph {
		for _, dep := range deps {
			if dep == authtestPkg {
				t.Errorf("%s imports %s outside a _test.go file", pkg, dep)
			}
		}
	}
	for _, root := range productionRoots {
		if chain := reachable(graph, root, authtestPkg); chain != nil {
			t.Errorf("%s links the test-only session helper: %s", root, strings.Join(chain, " -> "))
		}
	}
}
