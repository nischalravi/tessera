package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// A database that already has the vault and ERP kinds but not the database kind
// (issue #553) takes it too, keeping its rows.
func TestUpgradeProvTargetKinds_AddsTheSQLKind(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "mid.db")
	d, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	var ddl string
	if err := d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name = 'provisioning_targets'`).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	mid := strings.Replace(ddl, ",'sql','salesforce'", "", 1)
	if mid == ddl {
		t.Fatal("the schema does not list the sql kind")
	}
	for _, q := range []string{"DROP TABLE provisioning_targets", mid,
		`INSERT INTO provisioning_targets (id, tenant_id, connection_id, kind, base_url, created_by, created_at, updated_at)
		 VALUES ('pt1', 't1', 'c1', 'sap', 'https://a.example', 'alice', 'x', 'x')`} {
		if _, err := d.sql.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	_ = d.Close()
	d, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var kind string
	if err := d.sql.QueryRowContext(ctx, `SELECT kind FROM provisioning_targets WHERE id = 'pt1'`).Scan(&kind); err != nil || kind != "sap" {
		t.Fatalf("row after the upgrade: %q %v", kind, err)
	}
	if _, err := d.sql.ExecContext(ctx, `INSERT INTO provisioning_targets (id, tenant_id, connection_id, kind, base_url, created_by, created_at, updated_at)
		VALUES ('pt2', 't1', 'c2', 'sql', 'sql://db.example:5432/postgres', 'a', 'x', 'x')`); err != nil {
		t.Errorf("the sql kind was refused: %v", err)
	}
}
