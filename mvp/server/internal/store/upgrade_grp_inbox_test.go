package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// A database whose grp_inbox_tasks has the CHECKs of before the deletion_held task is rebuilt on open:
// rows kept exactly, the table's indexes recreated (the open-key index still dedupes), the new kind and
// object type accepted, an unknown kind still refused, and a second open changes nothing.
func TestUpgradeGrpInboxKinds(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	d, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(d *DB, q string, args ...any) error {
		_, err := d.sql.ExecContext(ctx, q, args...)
		return err
	}
	must := func(d *DB, q string, args ...any) {
		t.Helper()
		if err := exec(d, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	var def string
	if err := d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name = ?`, grpInboxTable).Scan(&def); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(def, "'deletion_held'") || !strings.Contains(def, "'deletion_hold'") {
		t.Fatal("a new database lacks the new kind or object type")
	}
	old := def
	for _, r := range grpInboxReplacements {
		old = strings.Replace(old, r[1], r[0], 1)
	}
	if strings.Contains(old, "deletion_hold") {
		t.Fatal("could not build the old definition")
	}
	var nIdx int
	if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE tbl_name = ? AND type = 'index' AND sql IS NOT NULL`, grpInboxTable).Scan(&nIdx); err != nil || nIdx == 0 {
		t.Fatalf("indexes = %d, %v", nIdx, err)
	}
	d.sql.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA foreign_keys = OFF", "DROP TABLE " + grpInboxTable, old,
		`CREATE INDEX grp_inbox_status ON grp_inbox_tasks (tenant_id, status, created_at)`,
		`CREATE UNIQUE INDEX grp_inbox_open_key ON grp_inbox_tasks (tenant_id, dedupe_key) WHERE status = 'open' AND dedupe_key IS NOT NULL`,
		"PRAGMA foreign_keys = ON"} {
		must(d, q)
	}
	must(d, `INSERT INTO tenants (id, slug, name, created_at) VALUES ('t1', 'tenant-one', 'One', '2026-10-01T00:00:00Z')`)
	for i, k := range []string{"rule", "attestation", "deprovisioning"} {
		must(d, `INSERT INTO grp_inbox_tasks (id, tenant_id, kind, title, detail, object_type, object_id, status, dedupe_key, created_at, closed_at)
			VALUES (?, 't1', ?, ?, '{"n":1}', 'group', 'g1', ?, ?, '2026-10-01T00:00:00Z', ?)`,
			"task"+string(rune('0'+i)), k, "title "+k, map[bool]string{true: "open", false: "done"}[i != 2], "key"+string(rune('0'+i)),
			map[bool]any{true: nil, false: "2026-10-02T00:00:00Z"}[i != 2])
	}
	if err := exec(d, `INSERT INTO grp_inbox_tasks (id, tenant_id, kind, title, object_type, object_id, created_at)
		VALUES ('x', 't1', 'deletion_held', 't', 'deletion_hold', 'h1', '2026-10-01T00:00:00Z')`); err == nil {
		t.Fatal("the old table accepts the new kind")
	}
	dump := func(d *DB) string {
		t.Helper()
		rs, err := d.sql.QueryContext(ctx, `SELECT id, tenant_id, kind, title, detail, object_type, object_id, status, dedupe_key, created_at, closed_at
			FROM grp_inbox_tasks ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rs.Close()
		var b strings.Builder
		for rs.Next() {
			cols := make([]*string, 11)
			ptr := make([]any, 11)
			for i := range cols {
				ptr[i] = &cols[i]
			}
			if err := rs.Scan(ptr...); err != nil {
				t.Fatal(err)
			}
			for _, c := range cols {
				if c == nil {
					b.WriteString("NULL|")
				} else {
					b.WriteString(*c + "|")
				}
			}
			b.WriteString("\n")
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
	if after := dump(d); after != before || strings.Count(before, "\n") != 3 {
		t.Fatalf("rows changed:\nbefore %s\nafter  %s", before, after)
	}
	if err := exec(d, `INSERT INTO grp_inbox_tasks (id, tenant_id, kind, title, object_type, object_id, status, dedupe_key, created_at)
		VALUES ('new1', 't1', 'deletion_held', 't', 'deletion_hold', 'h1', 'open', 'deletion_hold:h1', '2026-10-01T00:00:00Z')`); err != nil {
		t.Errorf("the new kind is refused: %v", err)
	}
	if err := exec(d, `INSERT INTO grp_inbox_tasks (id, tenant_id, kind, title, object_type, object_id, status, dedupe_key, created_at)
		VALUES ('new2', 't1', 'deletion_held', 't', 'deletion_hold', 'h1', 'open', 'deletion_hold:h1', '2026-10-01T00:00:00Z')`); err == nil {
		t.Errorf("the open-key index was not recreated: a second open task with the key was accepted")
	}
	if err := exec(d, `INSERT INTO grp_inbox_tasks (id, tenant_id, kind, title, object_type, object_id, created_at)
		VALUES ('bad', 't1', 'no_such_kind', 't', 'group', 'g', '2026-10-01T00:00:00Z')`); err == nil {
		t.Error("an unknown kind is accepted")
	}
	if err := exec(d, `INSERT INTO grp_inbox_tasks (id, tenant_id, kind, title, object_type, object_id, created_at)
		VALUES ('bad2', 't1', 'rule', 't', 'nothing', 'g', '2026-10-01T00:00:00Z')`); err == nil {
		t.Error("an unknown object type is accepted")
	}
	var n int
	if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE tbl_name = ? AND type = 'index' AND sql IS NOT NULL`, grpInboxTable).Scan(&n); err != nil || n < 2 {
		t.Errorf("indexes after = %d, %v", n, err)
	}
	var def2 string
	_ = d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name = ?`, grpInboxTable).Scan(&def2)
	if err := d.upgradeGrpInboxKinds(ctx); err != nil { // idempotent
		t.Errorf("a second upgrade: %v", err)
	}
	var def3 string
	_ = d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name = ?`, grpInboxTable).Scan(&def3)
	if def2 != def3 || strings.Count(def3, "'deletion_held'") != 1 {
		t.Errorf("the second upgrade changed the definition: %s", def3)
	}
}
