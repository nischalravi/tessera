package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// A database whose siem_sinks has the narrow kind CHECK and no event_filter, region or access_key_id columns
// (before issue #498) is upgraded on open: rows and their dead letters kept, the s3 kind accepted, the new
// columns defaulted, the indexes and triggers back, and a second open changes nothing.
func TestUpgradeSiemSinks(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	d, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	must := func(d *DB, q string, args ...any) {
		t.Helper()
		if _, err := d.sql.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	var def string
	if err := d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name = ?`, siemSinksTable).Scan(&def); err != nil {
		t.Fatal(err)
	}
	old := strings.Replace(def, "'syslog','webhook','s3'", "'syslog','webhook'", 1)
	for _, c := range siemSinkNewColumns {
		start := strings.Index(old, "  "+c[0]+" ")
		if start < 0 {
			t.Fatalf("column %s not in the schema", c[0])
		}
		end := start + strings.Index(old[start:], "\n") + 1
		old = old[:start] + old[end:]
	}
	if strings.Contains(old, "event_filter") || strings.Contains(old, "'s3'") {
		t.Fatal("could not build the old definition")
	}
	d.sql.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA foreign_keys = OFF", "DROP TABLE siem_dead_letters", "DROP TABLE " + siemSinksTable, old,
		`CREATE INDEX ix_siem_sinks_tenant ON siem_sinks (tenant_id, enabled)`,
		`CREATE TABLE siem_dead_letters (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants (id), sink_id TEXT NOT NULL REFERENCES siem_sinks (id),
			from_seq INTEGER NOT NULL, to_seq INTEGER NOT NULL, events INTEGER NOT NULL, error TEXT NOT NULL, created_at TEXT NOT NULL)`,
		"PRAGMA foreign_keys = ON"} {
		must(d, q)
	}
	must(d, `INSERT INTO tenants (id, slug, name, created_at) VALUES ('t1', 'tenant-one', 'One', '2026-10-01T00:00:00Z')`)
	must(d, `INSERT INTO siem_sinks (id, tenant_id, name, kind, format, target, flavor, secret_sealed, created_at, updated_at)
		VALUES ('s1', 't1', 'Splunk', 'webhook', 'json', 'https://x.example', 'hec', x'0a0b', 'x', 'x')`)
	must(d, `INSERT INTO siem_dead_letters (id, tenant_id, sink_id, from_seq, to_seq, events, error, created_at) VALUES ('d1', 't1', 's1', 1, 2, 2, 'e', 'x')`)
	if _, err := d.sql.ExecContext(ctx, `INSERT INTO siem_sinks (id, tenant_id, name, kind, format, target, created_at, updated_at)
		VALUES ('s2', 't1', 'B', 's3', 'json', 'https://b.example', 'x', 'x')`); err == nil {
		t.Fatal("the old table accepted the s3 kind")
	}
	_ = d.Close()

	for range 2 { // the second open finds nothing to do
		d, err = Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		var name, filter, region, keyID string
		var sealed []byte
		if err := d.sql.QueryRowContext(ctx, `SELECT name, secret_sealed, event_filter, region, access_key_id FROM siem_sinks WHERE id = 's1'`).
			Scan(&name, &sealed, &filter, &region, &keyID); err != nil || name != "Splunk" || len(sealed) != 2 || filter != "[]" || region != "" || keyID != "" {
			t.Fatalf("row after the upgrade: %q %v %q %q %q %v", name, sealed, filter, region, keyID, err)
		}
		var n int
		if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM siem_dead_letters WHERE sink_id = 's1'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("dead letters after the upgrade: %d %v", n, err)
		}
		if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE tbl_name = 'siem_sinks' AND type IN ('index','trigger')`).Scan(&n); err != nil || n < 3 {
			t.Errorf("indexes and triggers on siem_sinks = %d, %v", n, err)
		}
		_, err := d.sql.ExecContext(ctx, `INSERT OR REPLACE INTO siem_sinks (id, tenant_id, name, kind, format, target, region, access_key_id, event_filter, created_at, updated_at)
			VALUES ('s2', 't1', 'B', 's3', 'json', 'https://b.example', 'eu-west-1', 'AKIAEXAMPLE', '["auth.*"]', 'x', 'x')`)
		if err != nil {
			t.Errorf("s3 sink refused: %v", err)
		}
		if _, err := d.sql.ExecContext(ctx, `INSERT INTO siem_sinks (id, tenant_id, name, kind, format, target, created_at, updated_at)
			VALUES ('s3', 't1', 'C', 'carrier-pigeon', 'json', 'x', 'x', 'x')`); err == nil {
			t.Error("an unknown kind was accepted")
		}
		_ = d.Close()
	}
}
