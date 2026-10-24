package archtest

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestSQLDBExemptionIsNarrow: the customer-database connector may import
// database/sql and the drivers, but nothing in it may reach Tessera's store,
// and it has no subpackage the exemption could spread to.
func TestSQLDBExemptionIsNarrow(t *testing.T) {
	root := moduleRoot(t)
	dir := filepath.Join(root, filepath.FromSlash(sqlDBDir))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("%s: %v", sqlDBDir, err)
	}
	fset := token.NewFileSet()
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			t.Errorf("%s has a subpackage %s; the exemption covers the one directory only", sqlDBDir, e.Name())
			continue
		}
		if !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		n++
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if strings.Contains(path, "/internal/store") || strings.HasPrefix(path, "modernc.org/sqlite") || path == "unsafe" {
				t.Errorf("%s imports %s: the connector must never reach Tessera's own data", e.Name(), path)
			}
		}
	}
	if n < 5 {
		t.Fatalf("only %d files in %s; the test is not looking at the connector", n, sqlDBDir)
	}
}

// TestSQLDBExemptionPositiveControl: the exemption lets the connector's own
// kinds through and nothing else (unsafe and the SQLite driver stay banned).
func TestSQLDBExemptionPositiveControl(t *testing.T) {
	src := `package x

import (
	"database/sql"
	"github.com/go-sql-driver/mysql"
	mssql "github.com/microsoft/go-mssqldb"
	_ "github.com/sijms/go-ora/v2"
	"github.com/jackc/pgx/v5/stdlib"
	"unsafe"
	_ "modernc.org/sqlite"
)

func f(db *sql.DB) { db.ExecContext(nil, "x") }
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var all, kept []string
	for _, v := range checkFile(fset, f) {
		all = append(all, v)
		if !sqlDBAllows(v) {
			kept = append(kept, v)
		}
	}
	if len(all) != 8 || len(kept) != 2 {
		t.Fatalf("%d violations, %d outside the exemption; want 8 and 2:\n%s", len(all), len(kept), strings.Join(all, "\n"))
	}
	for _, v := range kept {
		if !strings.Contains(v, "unsafe") && !strings.Contains(v, "modernc.org/sqlite") {
			t.Errorf("unexpected violation stays banned in the connector: %s", v)
		}
	}
}
