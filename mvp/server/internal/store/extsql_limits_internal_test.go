package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunExtQuery_RuntimeLimits: a loader query that is deep or wide enough to
// stress SQLite's parser and planner (the stack-exhaustion class of bug fixed
// in SQLite 3.54) is refused as an ordinary error on the loader connection,
// well below SQLite's own default limits, and a normal query still runs.
func TestRunExtQuery_RuntimeLimits(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "src.db")
	src, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.ExecContext(ctx, `CREATE TABLE people (id TEXT)`); err != nil {
		t.Fatal(err)
	}
	src.Close()

	nest := func(n int) string { return "SELECT " + strings.Repeat("1+(", n) + "1" + strings.Repeat(")", n) }
	union := func(n int) string { return "SELECT 1" + strings.Repeat(" UNION ALL SELECT 1", n) }
	for _, tc := range []struct {
		name, q string
		ok      bool
	}{
		{"shallow expression", nest(10), true},
		{"small compound", union(10), true},
		{"deep expression", nest(200), false},
		{"wide compound", union(100), false},
		{"small value", "SELECT hex(randomblob(1000))", true},
		{"huge blob", "SELECT length(randomblob(2000000))", false},
		{"huge string", "SELECT hex(randomblob(600000))", false},
	} {
		if err := CheckReadOnlySQL(tc.q); err != nil {
			t.Fatalf("%s: refused by the static check: %v", tc.name, err)
		}
		_, err := RunExtQuery(ctx, ExtQuery{Path: path, SQL: tc.q})
		if tc.ok && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: the query ran", tc.name)
		}
	}
	// the length cap is the static check's, before a connection is opened
	long := "SELECT '" + strings.Repeat("x", MaxExtQueryBytes) + "'"
	if _, err := RunExtQuery(ctx, ExtQuery{Path: path, SQL: long}); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("over-long query = %v", err)
	}
}
