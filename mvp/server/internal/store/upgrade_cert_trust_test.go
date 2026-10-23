package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// A database whose tenant_certificates has no trust_pem column (before issue #498) gets it on open, defaulted
// to empty (the system roots), and its rows survive.
func TestUpgradeCertTrust(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	d, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	var def string
	if err := d.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name = 'tenant_certificates'`).Scan(&def); err != nil {
		t.Fatal(err)
	}
	old := strings.Replace(def, "  trust_pem TEXT NOT NULL DEFAULT '',\n", "", 1)
	if old == def {
		t.Fatal("trust_pem is not in the schema")
	}
	d.sql.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA foreign_keys = OFF", "DROP TABLE tenant_certificates", old, "PRAGMA foreign_keys = ON",
		`INSERT INTO tenants (id, slug, name, created_at) VALUES ('t1', 'tenant-one', 'One', '2026-10-01T00:00:00Z')`,
		`INSERT INTO tenant_certificates (id, tenant_id, purpose, label, status, cert_pem, subject, issuer, not_before, not_after, fingerprint,
			key_algorithm, sig_algorithm, created_by, created_at)
		 VALUES ('c1', 't1', 'mtls_client', 'old', 'active', 'PEM', 'CN=a', 'CN=a', 'x', 'x', '` + strings.Repeat("a", 64) + `', 'RSA', 'SHA256', 'me', 'x')`} {
		if _, err := d.sql.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	_ = d.Close()
	for range 2 {
		d, err = Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		var trust, pemText string
		if err := d.sql.QueryRowContext(ctx, `SELECT trust_pem, cert_pem FROM tenant_certificates WHERE id = 'c1'`).Scan(&trust, &pemText); err != nil || trust != "" || pemText != "PEM" {
			t.Fatalf("row after the upgrade: %q %q %v", trust, pemText, err)
		}
		_ = d.Close()
	}
}
