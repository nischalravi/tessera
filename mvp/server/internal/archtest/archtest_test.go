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

// unsafeAllowed are the files outside the store that may import unsafe (every
// other rule still applies to them). There is one: the Directory Agent's
// Windows DPAPI wrapper (DR-11), which must read and free a native buffer.
// TestUnsafeExemptionIsNarrow pins it to a Windows-only file.
var unsafeAllowed = map[string]bool{"internal/agent/dpapi_windows.go": true}

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
			if unsafeAllowed[rel] && strings.HasSuffix(v, "imports unsafe (only "+storeDir+" may)") {
				continue // the one exemption, see unsafeAllowed
			}
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
var productionRoots = []string{"cmd/tessera", "cmd/tessera-agent", "internal/api"}

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

// safehttpPath is the SSRF-guarded client. Production code builds clients
// only with safehttp.ForConfig (environment and loopback exception from the
// validated config); safehttp.NewForTest takes any Options and is for tests.
const safehttpPath = "github.com/nischalravi/tessera/mvp/server/internal/safehttp"

// testOnlySafehttp are the safehttp identifiers non-test files may not use.
var testOnlySafehttp = map[string]bool{"NewForTest": true}

// checkSafehttpUse reports uses of test-only safehttp constructors in f.
func checkSafehttpUse(fset *token.FileSet, f *ast.File) []string {
	names := map[string]bool{}
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == safehttpPath {
			name := "safehttp"
			if imp.Name != nil {
				name = imp.Name.Name
			}
			names[name] = true
		}
	}
	if len(names) == 0 {
		return nil
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok && names[x.Name] && testOnlySafehttp[sel.Sel.Name] {
			out = append(out, fset.Position(sel.Pos()).String()+": safehttp."+sel.Sel.Name+" outside a _test.go file (use safehttp.ForConfig)")
		}
		return true
	})
	return out
}

// TestSafehttpForConfigOnly (L5): no non-test file of the module calls
// safehttp.NewForTest, so production clients come only from ForConfig.
func TestSafehttpForConfigOnly(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	files := 0
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
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		for _, v := range checkSafehttpUse(fset, f) {
			t.Error(v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 20 {
		t.Fatalf("scanned %d files; the walk is not covering the module", files)
	}
}

// TestSafehttpRuleCatchesViolations is the positive control.
func TestSafehttpRuleCatchesViolations(t *testing.T) {
	src := `package bad

import (
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	sh "github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

func f() {
	_, _ = safehttp.NewForTest(nil, safehttp.Options{Env: "dev", AllowLoopback: true})
	g := sh.NewForTest
	_, _ = safehttp.ForConfig(nil)
	_ = g
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "bad.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := checkSafehttpUse(fset, f)
	if len(got) != 2 {
		t.Errorf("%d violations, want 2 (NewForTest under both import names):\n%s", len(got), strings.Join(got, "\n"))
	}
}

// TestUnsafeExemptionIsNarrow: the unsafe exemption is one Windows-only file
// and nothing else in it relaxes (it still may not touch SQL or reflect).
func TestUnsafeExemptionIsNarrow(t *testing.T) {
	root := moduleRoot(t)
	if len(unsafeAllowed) != 1 {
		t.Fatalf("%d unsafe exemptions; there must be exactly one", len(unsafeAllowed))
	}
	for rel := range unsafeAllowed {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(rel, "_windows.go") || !strings.HasPrefix(string(raw), "//go:build windows\n") {
			t.Errorf("%s must be a Windows-only file (name suffix and build tag)", rel)
		}
	}
}

// TestDialSeamOnlyInTests: safedial's TestDial hook redirects a checked
// connection to a lab server. Production code must never set it, so it is
// named only in safedial itself, the agent executor that passes it through
// from tests, and _test.go files.
func TestDialSeamOnlyInTests(t *testing.T) {
	root := moduleRoot(t)
	allowed := map[string]bool{"internal/safedial/safedial.go": true, "internal/agent/executor.go": true}
	n := 0
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
		n++
		rel, _ := filepath.Rel(root, path)
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(raw), "TestDial") && !allowed[filepath.ToSlash(rel)] {
			t.Errorf("%s names safedial's TestDial seam", rel)
		}
		return nil
	})
	if err != nil || n < 50 {
		t.Fatalf("walk: %v, %d files", err, n)
	}
}
