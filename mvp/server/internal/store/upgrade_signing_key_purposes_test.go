package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// A SQLite database created before the aws_federation key purpose (issue #676) takes it
// without losing the sealed signing keys it holds.
func TestUpgradeSigningKeyPurposes_KeepsRowsAndWidensTheCheck(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	d, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	var ddl string
	if err := d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name = 'tenant_signing_keys'`).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	narrow := strings.Replace(ddl, ",'aws_federation'", "", 1)
	if narrow == ddl {
		t.Fatal("the schema does not list aws_federation")
	}
	insert := func(kid, purpose string) error {
		_, err := d.sql.ExecContext(ctx, `INSERT INTO tenant_signing_keys (kid, tenant_id, purpose, public_jwk, private_key_enc, status, created_at)
			VALUES (?, 't1', ?, '{}', x'0102', 'active', 'x')`, kid, purpose)
		return err
	}
	for _, q := range []string{"PRAGMA foreign_keys = OFF", "DROP TABLE tenant_signing_keys", narrow} {
		if _, err := d.sql.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := insert("k1", "access_token"); err != nil {
		t.Fatal(err)
	}
	if err := insert("k2", "aws_federation"); err == nil {
		t.Fatal("the old table accepted aws_federation")
	}
	_ = d.Close()

	d, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var enc []byte
	if err := d.sql.QueryRowContext(ctx, `SELECT private_key_enc FROM tenant_signing_keys WHERE kid = 'k1'`).Scan(&enc); err != nil || len(enc) != 2 {
		t.Fatalf("row after the upgrade: %v %v", enc, err)
	}
	if err := insert("k2", "aws_federation"); err != nil {
		t.Errorf("aws_federation refused after the upgrade: %v", err)
	}
	if err := insert("k3", "bogus"); err == nil {
		t.Error("an unknown purpose was accepted")
	}
	var n int
	if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE tbl_name = 'tenant_signing_keys' AND type = 'index' AND name LIKE 'tenant_signing_keys_%'`).Scan(&n); err != nil || n != 3 {
		t.Errorf("indexes on tenant_signing_keys = %d, %v", n, err)
	}
}
