package store

import (
	"context"
	"path/filepath"
	"testing"
)

// schema/0207 denies the later duplicates of a pending request before it
// builds the unique index, so a database that predates the index still opens.
func TestMigrate_PendingRequestDuplicatesAreDenied(t *testing.T) {
	ctx := context.Background()
	d, err := Open(ctx, filepath.Join(t.TempDir(), "dups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := d.sql.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`DROP INDEX ux_access_requests_pending`)
	const ins = `INSERT INTO access_requests (tenant_id, identity_id, account_id, group_id, justification, duration_hours,
		status, requested_at) VALUES (?, ?, 1, ?, 'x', 1, ?, '2026-10-08T09:30:00')`
	// tenant t1: ids 1-3 are the same identity and group, 4 is another group, 5 is decided
	exec(ins, "t1", 1, 1, "pending")
	exec(ins, "t1", 1, 1, "pending")
	exec(ins, "t1", 1, 1, "pending")
	exec(ins, "t1", 1, 2, "pending")
	exec(ins, "t1", 1, 1, "approved")
	exec(ins, "t2", 1, 1, "pending") // same ids in another tenant: untouched

	if err := d.Migrate(ctx, false); err != nil {
		t.Fatalf("Migrate over duplicates: %v", err)
	}
	rows, err := d.sql.QueryContext(ctx, `SELECT status FROM access_requests ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		got = append(got, s)
	}
	want := []string{"pending", "denied", "denied", "pending", "approved", "pending"}
	if len(got) != len(want) {
		t.Fatalf("statuses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("statuses = %v, want %v", got, want)
		}
	}
}
