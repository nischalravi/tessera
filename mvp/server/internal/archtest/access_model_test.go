package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Intended and observed access are written by different code (issue #301):
// connector ingest records what systems report, approval-side code records
// what was decided. These tests fail when one side calls the other side's
// writers. (The store's own tests pin the behaviour; this pins the structure.)

// intentWriters write intended_grants (directly or through the edge writers
// that record intent beside the live edge).
var intentWriters = []string{"InsertEdge", "KeepIntent", "BackfillAccessModel", "SetEdgeExpiry", "recordEdgeIntent",
	"insertIntent", "closeEdgeIntent"}

// observedWriters write observed_runs and observed_entitlements.
var observedWriters = []string{"RecordObservedRun", "recordRun"}

// calls returns the selector names called in the non-test Go files of dir.
func calls(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				out[sel.Sel.Name] = fset.Position(sel.Pos()).String()
			}
			return true
		})
	}
	return out
}

func TestIngestCannotWriteIntendedGrants(t *testing.T) {
	root := moduleRoot(t)
	for _, pkg := range []string{"internal/ingest", "internal/connectors", "internal/connectors/ldap"} {
		c := calls(t, filepath.Join(root, pkg))
		for _, w := range intentWriters {
			if at, bad := c[w]; bad {
				t.Errorf("%s calls %s (%s): connector code must not write intended access", pkg, w, at)
			}
		}
	}
}

func TestApprovalCodeCannotWriteObservedEntitlements(t *testing.T) {
	root := moduleRoot(t)
	for _, pkg := range []string{"internal/requests", "internal/jit", "internal/roles", "internal/reviews", "internal/jml",
		"internal/lifecycle", "internal/provision", "internal/reconcile"} {
		c := calls(t, filepath.Join(root, pkg))
		for _, w := range observedWriters {
			if at, bad := c[w]; bad {
				t.Errorf("%s calls %s (%s): only connector ingest may write observed access", pkg, w, at)
			}
		}
	}
}

// The observed writers have one caller outside the store: connector ingest.
func TestObservedWritersCalledOnlyByIngest(t *testing.T) {
	root := moduleRoot(t)
	found := false
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() || strings.HasSuffix(path, "internal/store") || strings.Contains(path, "/store/") {
			return err
		}
		c := calls(t, path)
		if at, ok := c["RecordObservedRun"]; ok {
			if !strings.HasSuffix(path, "internal/ingest") {
				t.Errorf("RecordObservedRun called outside ingest: %s", at)
			}
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Error("ingest no longer records observed runs")
	}
}
