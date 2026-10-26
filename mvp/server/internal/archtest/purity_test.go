package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The AWS evaluator is pure (design §5, brief "Purity"): its matching, model,
// parsing and snapshot packages do no I/O, touch no database, make no HTTP call
// and read no clock (time arrives as a value). This rule bans, in their
// non-test files, the imports that would allow it and the clock-reading calls.

// pureDirs are the module-relative directories under the rule.
var pureDirs = []string{
	"internal/aws/eval",
	"internal/cedarx",
	"internal/policybundle",
	"internal/aws/glob",
	"internal/aws/index",
	"internal/aws/model",
	"internal/aws/policy",
	"internal/aws/query",
	"internal/aws/render",
	"internal/aws/snapshot",
}

// awstestPkg is the synthetic-snapshot generator and fake catalog that the
// evaluator's tests and benchmarks share. Only tests may import it.
const awstestPkg = "internal/aws/awstest"

// TestAWSTestkitOnlyInTests proves from the import graph of non-test files that
// nothing but tests (and the offline harness) imports internal/aws/awstest.
func TestAWSTestkitOnlyInTests(t *testing.T) {
	graph := moduleImports(t, moduleRoot(t))
	if _, ok := graph[awstestPkg]; !ok {
		t.Fatalf("package %s not found; the test is not looking at the module", awstestPkg)
	}
	for pkg, deps := range graph {
		for _, dep := range deps {
			// the offline harness records and replays cassettes with it; TestHarnessOnlyImportedByItsBinary
			// keeps the harness itself out of every production binary
			if dep == awstestPkg && !inTree(pkg, harnessPkg) {
				t.Errorf("%s imports %s outside a _test.go file", pkg, dep)
			}
		}
	}
	for _, root := range productionRoots {
		if chain := reachable(graph, root, awstestPkg); chain != nil {
			t.Errorf("%s links the evaluator test kit: %s", root, strings.Join(chain, " -> "))
		}
	}
}

// pureBannedImports are exact paths; a trailing "/" bans a whole tree.
var pureBannedImports = []string{
	"os", "os/exec", "os/signal", "os/user", "io/ioutil", "io/fs", "syscall", "unsafe",
	"net", "net/http", "net/http/", "net/rpc", "net/smtp", "net/textproto",
	"database/sql", "database/sql/driver", "modernc.org/sqlite", "modernc.org/sqlite/",
	"math/rand", "math/rand/v2", "crypto/rand", "plugin",
	"github.com/aws/aws-sdk-go-v2/",
	"github.com/nischalravi/tessera/mvp/server/internal/store",
	"github.com/nischalravi/tessera/mvp/server/internal/store/",
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp",
	"github.com/nischalravi/tessera/mvp/server/internal/api",
}

// clockCalls are package time functions that read the clock or wait on it.
var clockCalls = map[string]bool{
	"Now": true, "Since": true, "Until": true, "Sleep": true, "After": true, "AfterFunc": true,
	"Tick": true, "NewTimer": true, "NewTicker": true,
}

func pureBanned(path string) bool {
	for _, b := range pureBannedImports {
		if path == b || (strings.HasSuffix(b, "/") && strings.HasPrefix(path, b)) {
			return true
		}
	}
	return false
}

// checkPure returns the purity violations of one parsed file.
func checkPure(fset *token.FileSet, f *ast.File) []string {
	var out []string
	at := func(p token.Pos, msg string) { out = append(out, fset.Position(p).String()+": "+msg) }
	timeName := ""
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if pureBanned(path) {
			at(imp.Pos(), "imports "+path+", which a pure evaluator package must not")
		}
		if path == "time" {
			timeName = "time"
			if imp.Name != nil {
				timeName = imp.Name.Name
			}
		}
	}
	if timeName == "" {
		return out
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == timeName && clockCalls[sel.Sel.Name] {
			at(sel.Pos(), "reads or waits on the clock with time."+sel.Sel.Name+"; pass the time in")
		}
		return true
	})
	return out
}

// TestAWSEvaluatorPackagesArePure parses the non-test files of the pure
// packages. Tests may use os and the clock (they load testdata).
func TestAWSEvaluatorPackagesArePure(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	for _, dir := range pureDirs {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil {
			t.Fatalf("%s: %v (the rule is not looking at the package)", dir, err)
		}
		files := 0
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			files++
			f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(dir), e.Name()), nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range checkPure(fset, f) {
				t.Error(v)
			}
		}
		if files == 0 {
			t.Errorf("%s has no non-test Go files; the rule is vacuous", dir)
		}
	}
}

// TestPurityRuleCatchesViolations is the positive control.
func TestPurityRuleCatchesViolations(t *testing.T) {
	src := `package bad

import (
	"net/http"
	"os"
	"database/sql"
	"math/rand"
	t "time"
)

func f() {
	_ = t.Now()
	_ = t.Since(t.Time{})
	_ = t.Duration(1) // allowed: not a clock read
	_, _, _, _ = http.Get, os.Open, sql.Open, rand.Int
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "bad.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(checkPure(fset, f), "\n")
	for _, want := range []string{"imports net/http", "imports os", "imports database/sql", "imports math/rand", "time.Now", "time.Since"} {
		if !strings.Contains(got, want) {
			t.Errorf("no violation %q in:\n%s", want, got)
		}
	}
	if n := len(checkPure(fset, f)); n != 6 {
		t.Errorf("%d violations, want 6:\n%s", n, got)
	}
	ok, _ := parser.ParseFile(fset, "ok.go", "package ok\nimport (\"net/netip\"\n\"time\")\nvar _ = netip.Addr{}\nvar _ time.Time\n", 0)
	if v := checkPure(fset, ok); len(v) != 0 {
		t.Errorf("net/netip and time.Time flagged: %v", v)
	}
}

// awsreplayPkg is the AWS connector's HTTP replay double (the SigV4-aware one
// the connector tests use, distinct from the awstest cassette replay).
const awsreplayPkg = "internal/aws/awsreplay"

// TestAWSReplayOnlyInTests proves nothing outside _test.go files imports the
// connector's HTTP replay double, and no production binary links it.
func TestAWSReplayOnlyInTests(t *testing.T) {
	graph := moduleImports(t, moduleRoot(t))
	if _, ok := graph[awsreplayPkg]; !ok {
		t.Fatalf("package %s not found; the test is not looking at the module", awsreplayPkg)
	}
	for pkg, deps := range graph {
		for _, dep := range deps {
			if dep == awsreplayPkg {
				t.Errorf("%s imports %s outside a _test.go file", pkg, dep)
			}
		}
	}
	for _, root := range productionRoots {
		if chain := reachable(graph, root, awsreplayPkg); chain != nil {
			t.Errorf("%s links the AWS replay double: %s", root, strings.Join(chain, " -> "))
		}
	}
}
