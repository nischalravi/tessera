package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// A SQLite database created before the vault and ERP target kinds (issue #304)
// takes them without losing the targets it holds, sealed credentials included.
func TestUpgradeProvTargetKinds_KeepsRowsAndWidensTheCheck(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	d, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	// put the table back as it was: the narrow CHECK and one row
	var ddl string
	if err := d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name = 'provisioning_targets'`).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	narrow := strings.Replace(ddl, "'fake','cyberark','delinea','beyondtrust','sap','oracle','sql'", "'fake'", 1)
	if narrow == ddl {
		t.Fatal("the schema does not list the new kinds")
	}
	for _, q := range []string{"DROP TABLE provisioning_targets", narrow,
		`INSERT INTO provisioning_targets (id, tenant_id, connection_id, kind, base_url, settings, credential_enc, write_back, created_by, created_at, updated_at)
		 VALUES ('pt1', 't1', 'c1', 'scim', 'https://a.example', '{}', x'0102', 1, 'alice', 'x', 'x')`} {
		if _, err := d.sql.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := d.sql.ExecContext(ctx, `INSERT INTO provisioning_targets (id, tenant_id, connection_id, kind, base_url, created_by, created_at, updated_at)
		VALUES ('pt2', 't1', 'c2', 'cyberark', 'https://b.example', 'a', 'x', 'x')`); err == nil {
		t.Fatal("the old table accepted a new kind")
	}
	_ = d.Close()

	d, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var kind string
	var enc []byte
	if err := d.sql.QueryRowContext(ctx, `SELECT kind, credential_enc FROM provisioning_targets WHERE id = 'pt1'`).Scan(&kind, &enc); err != nil || kind != "scim" || len(enc) != 2 {
		t.Fatalf("row after the upgrade: %q %v %v", kind, enc, err)
	}
	for _, k := range []string{"cyberark", "delinea", "beyondtrust", "sap", "oracle", "sql"} {
		if _, err := d.sql.ExecContext(ctx, `INSERT INTO provisioning_targets (id, tenant_id, connection_id, kind, base_url, created_by, created_at, updated_at)
			VALUES ('k-`+k+`', 't1', 'c-`+k+`', '`+k+`', 'https://b.example', 'a', 'x', 'x')`); err != nil {
			t.Errorf("kind %s refused: %v", k, err)
		}
	}
	if _, err := d.sql.ExecContext(ctx, `INSERT INTO provisioning_targets (id, tenant_id, connection_id, kind, base_url, created_by, created_at, updated_at)
		VALUES ('bad', 't1', 'cb', 'lastpass', 'https://b.example', 'a', 'x', 'x')`); err == nil {
		t.Error("an unknown kind was accepted")
	}
	// the indexes and guard triggers came back with the schema run
	var n int
	if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE tbl_name = 'provisioning_targets' AND type IN ('index','trigger')`).Scan(&n); err != nil || n < 3 {
		t.Errorf("indexes and triggers on provisioning_targets = %d, %v", n, err)
	}
}
