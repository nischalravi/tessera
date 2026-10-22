package store

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A database whose admin_change_requests has the CHECK of before groups.folder.delete_recursive is rebuilt on
// open: rows kept exactly, children still pointing at them, the new type accepted, an unknown type still
// refused, and a second open changes nothing.
func TestUpgradeAdminChangeTypes(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	d, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := d.sql.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// the tables as an older server made them: the old CHECK, with the table's index and triggers kept
	conn, err := d.sql.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var def string
	if err := conn.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name = ?`, adminChangeTable).Scan(&def); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(def, adminChangeNewType) {
		t.Fatal("a new database lacks the new type")
	}
	rows, err := conn.QueryContext(ctx, `SELECT sql FROM sqlite_master WHERE tbl_name = ? AND type IN ('index','trigger') AND sql IS NOT NULL`, adminChangeTable)
	if err != nil {
		t.Fatal(err)
	}
	var extra []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		extra = append(extra, s)
	}
	_ = rows.Close()
	old := regexp.MustCompile(`,\s*(--[^\n]*\n\s*)?`+regexp.QuoteMeta(adminChangeNewType)).ReplaceAllString(def, "")
	if old == def {
		t.Fatal("could not build the old definition")
	}
	for _, q := range append([]string{"PRAGMA foreign_keys = OFF", "DROP TABLE " + adminChangeTable, old}, extra...) {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	_ = conn.Close()
	d.sql.SetMaxOpenConns(1) // foreign_keys is per connection: keep the setting for the inserts below
	exec(`PRAGMA foreign_keys = ON`)

	exec(`INSERT INTO tenants (id, slug, name, created_at) VALUES ('t1', 'tenant-one', 'One', '2026-10-01T00:00:00Z')`)
	exec(`INSERT INTO platform_users (id, tenant_id, email, display_name, created_at) VALUES ('u1', 't1', 'a@x.example', 'A', '2026-10-01T00:00:00Z')`)
	types := []string{"role.grant", "groups.loader.save", "retention.update", "breakglass.revoke"}
	for i, typ := range types {
		exec(`INSERT INTO admin_change_requests (id, tenant_id, type, payload, payload_hash, target_id, status, two_person, cooling_off_seconds,
			requested_by_user_id, requested_at, expires_at) VALUES (?, 't1', ?, '{"n":1}', ?, 'x', 'pending_approval', 1, 0, 'u1', '2026-10-01T00:00:00Z', '2026-10-08T00:00:00Z')`,
			"c"+string(rune('0'+i)), typ, strings.Repeat("a", 64))
	}
	exec(`INSERT INTO admin_notifications (id, tenant_id, change_request_id, kind, recipient_type, recipient_user_id, subject, body, dedupe_key, created_at)
		VALUES ('n1', 't1', 'c1', 'k', 'admin', 'u1', 's', 'b', 'd1', '2026-10-01T00:00:00Z')`)
	dump := func(d *DB) string {
		t.Helper()
		rs, err := d.sql.QueryContext(ctx, `SELECT id, tenant_id, type, payload, payload_hash, target_id, status, two_person, requested_by_user_id, requested_at, expires_at
			FROM admin_change_requests ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rs.Close()
		var b strings.Builder
		for rs.Next() {
			cols := make([]string, 11)
			ptr := make([]any, 11)
			for i := range cols {
				ptr[i] = &cols[i]
			}
			if err := rs.Scan(ptr...); err != nil {
				t.Fatal(err)
			}
			b.WriteString(strings.Join(cols, "|") + "\n")
		}
		return b.String()
	}
	before := dump(d)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	d, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("open the old database: %v", err)
	}
	defer d.Close()
	if after := dump(d); after != before {
		t.Fatalf("rows changed:\nbefore %s\nafter  %s", before, after)
	}
	ins := func(id, typ string) error {
		_, err := d.sql.ExecContext(ctx, `INSERT INTO admin_change_requests (id, tenant_id, type, payload, payload_hash, status, two_person, cooling_off_seconds,
			requested_by_user_id, requested_at, expires_at) VALUES (?, 't1', ?, '{}', ?, 'pending_approval', 1, 0, 'u1', '2026-10-01T00:00:00Z', '2026-10-08T00:00:00Z')`,
			id, typ, strings.Repeat("b", 64))
		return err
	}
	if err := ins("new1", "groups.folder.delete_recursive"); err != nil {
		t.Errorf("the new type is refused: %v", err)
	}
	if err := ins("bad1", "no.such.type"); err == nil {
		t.Error("an unknown type is accepted")
	}
	var n int
	if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM admin_notifications WHERE change_request_id = 'c1'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("the notification lost its change request: %d, %v", n, err)
	}
	if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE tbl_name = ? AND type IN ('index','trigger') AND sql IS NOT NULL`, adminChangeTable).Scan(&n); err != nil || n != len(extra) {
		t.Errorf("indexes and triggers = %d, want %d (%v)", n, len(extra), err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	var def2 string
	_ = d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name = ?`, adminChangeTable).Scan(&def2)
	if strings.Count(def2, adminChangeNewType) != 1 {
		t.Errorf("the second open changed the definition: %s", def2)
	}
	if err := d.upgradeAdminChangeTypes(ctx); err != nil {
		t.Errorf("a second upgrade: %v", err)
	}
}
