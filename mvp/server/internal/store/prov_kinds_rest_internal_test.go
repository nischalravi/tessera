package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// A SQLite database that already has the vault and ERP kinds (issue #304) takes the generic
// REST kind (issue #552) without losing its targets or their sealed credentials.
func TestUpgradeProvTargetKinds_AddsRESTToTheEightKindTable(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "eight.db")
	d, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	var ddl string
	if err := d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name = 'provisioning_targets'`).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	eight := strings.Replace(ddl, "'sap','oracle','rest','sql','salesforce','servicenow','atlassian','ldap','ad','aws'", "'sap','oracle'", 1)
	if eight == ddl {
		t.Fatal("the schema does not list the rest kind")
	}
	for _, q := range []string{"DROP TABLE provisioning_targets", eight,
		`INSERT INTO provisioning_targets (id, tenant_id, connection_id, kind, base_url, settings, credential_enc, write_back, created_by, created_at, updated_at)
		 VALUES ('pt1', 't1', 'c1', 'sap', 'https://a.example', '{}', x'0102', 1, 'alice', 'x', 'x')`} {
		if _, err := d.sql.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const insertRest = `INSERT INTO provisioning_targets (id, tenant_id, connection_id, kind, base_url, created_by, created_at, updated_at)
		VALUES ('pt2', 't1', 'c2', 'rest', 'https://b.example', 'a', 'x', 'x')`
	if _, err := d.sql.ExecContext(ctx, insertRest); err == nil {
		t.Fatal("the eight-kind table accepted rest")
	}
	_ = d.Close()

	d, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var kind string
	var enc []byte
	if err := d.sql.QueryRowContext(ctx, `SELECT kind, credential_enc FROM provisioning_targets WHERE id = 'pt1'`).Scan(&kind, &enc); err != nil || kind != "sap" || len(enc) != 2 {
		t.Fatalf("row after the upgrade: %q %v %v", kind, enc, err)
	}
	if _, err := d.sql.ExecContext(ctx, insertRest); err != nil {
		t.Errorf("rest refused after the upgrade: %v", err)
	}
}
