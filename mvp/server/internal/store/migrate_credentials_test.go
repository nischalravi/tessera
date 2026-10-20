package store

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The DDL of the two tables #220 merged, as 0205_connection_secrets.sql and
// 0205_containment.sql created them.
const oldCredentialTables = `
CREATE TABLE connection_secrets (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  secret_ref TEXT NOT NULL,
  sealed BLOB NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, secret_ref)
);
CREATE TABLE containment_credentials (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connection_id TEXT NOT NULL REFERENCES connections (id),
  base_url TEXT NOT NULL DEFAULT '',
  org TEXT NOT NULL DEFAULT '',
  token_enc BLOB NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, connection_id)
);`

type migFixture struct {
	db       *DB
	sealer   *seal.Sealer
	tenant   [2]tenancy.ID
	conn     [2]string // one connection per tenant
	bindRef  [2]string
	orphaned string
}

// newMigFixture builds two tenants with a connection each, a revision that
// references a sealed:<id> credential, and the old tables holding one bind
// secret and one containment token per tenant (sealed under the old AADs) plus
// one bind secret no revision references.
func newMigFixture(t *testing.T) *migFixture {
	t.Helper()
	ctx := context.Background()
	db := openTest(t)
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	f := &migFixture{db: db, sealer: sealer, orphaned: "sealed:orphan"}
	if _, err := db.sql.ExecContext(ctx, oldCredentialTables); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for i, slug := range []string{"mig-a", "mig-b"} {
		if err := db.InSystem(ctx, "test", func(s *SystemTx) error {
			tn, err := s.CreateTenant(Tenant{Slug: slug, Name: slug})
			f.tenant[i] = tn.ID
			return err
		}); err != nil {
			t.Fatal(err)
		}
		f.conn[i], f.bindRef[i] = NewID(), "sealed:"+NewID()
		if err := db.InTenant(ctx, f.tenant[i], func(c *TenantTx) error {
			if err := c.InsertConnection(&Connection{ID: f.conn[i], Name: "ldap", ConnectorType: "ldap", System: "ldap",
				Role: "account_source", CreatedAt: now, UpdatedAt: now}); err != nil {
				return err
			}
			ref := f.bindRef[i]
			return c.InsertRevision(&ConnectionRevision{ID: NewID(), ConnectionID: f.conn[i], Rev: 1, TemplateID: "ldap",
				TemplateVersion: "1.0", Config: "{}", SecretRef: &ref, ConfigHash: "h", WriteMode: "off", CreatedBy: "t",
				CreatedAt: now, UpdatedAt: now})
		}); err != nil {
			t.Fatal(err)
		}
		bind, err := sealer.Seal([]byte("bind-pw-"+slug), seal.AAD(f.tenant[i], "connection_secrets", "sealed", f.bindRef[i]))
		if err != nil {
			t.Fatal(err)
		}
		tok, err := sealer.Seal([]byte("token-"+slug), seal.AAD(f.tenant[i], "containment_credentials", "token_enc", f.conn[i]))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.sql.ExecContext(ctx, `INSERT INTO connection_secrets VALUES (?, ?, ?, ?)`,
			f.tenant[i].String(), f.bindRef[i], bind, RT(now)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.sql.ExecContext(ctx, `INSERT INTO containment_credentials VALUES (?, ?, ?, ?, ?, ?, ?)`,
			f.tenant[i].String(), f.conn[i], "https://"+slug+".okta.com", "org-"+slug, tok, "admin", RT(now)); err != nil {
			t.Fatal(err)
		}
	}
	orphan, err := sealer.Seal([]byte("lost"), seal.AAD(f.tenant[0], "connection_secrets", "sealed", f.orphaned))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO connection_secrets VALUES (?, ?, ?, ?)`,
		f.tenant[0].String(), f.orphaned, orphan, RT(now)); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *migFixture) hasTable(t *testing.T, name string) bool {
	t.Helper()
	ok, err := f.db.tableExists(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// TestMigrateCredentials_RoundTrip: rows of both old tables are readable in
// the new store, re-sealed under the new AAD (the old AAD no longer opens
// them), and the old tables are gone.
func TestMigrateCredentials_RoundTrip(t *testing.T) {
	ctx := context.Background()
	f := newMigFixture(t)
	res, err := f.db.MigrateCredentials(ctx, f.sealer)
	if err != nil {
		t.Fatal(err)
	}
	if want := (CredentialMigration{Bind: 2, Containment: 2, Orphaned: 1}); res != want {
		t.Fatalf("migration = %+v, want %+v", res, want)
	}
	for _, old := range []string{"connection_secrets", "containment_credentials"} {
		if f.hasTable(t, old) {
			t.Errorf("%s still exists", old)
		}
	}
	for i, slug := range []string{"mig-a", "mig-b"} {
		if err := f.db.ReadTenant(ctx, f.tenant[i], func(c *TenantTx) error {
			bind, err := c.Credential(f.conn[i], PurposeBind, f.bindRef[i])
			if err != nil {
				return err
			}
			pt, err := f.sealer.Open(bind.Sealed, CredentialAAD(c.Tenant(), f.conn[i], PurposeBind, f.bindRef[i]))
			if err != nil || string(pt) != "bind-pw-"+slug {
				t.Errorf("%s bind: %q %v", slug, pt, err)
			}
			if _, err := f.sealer.Open(bind.Sealed, seal.AAD(c.Tenant(), "connection_secrets", "sealed", f.bindRef[i])); err == nil {
				t.Errorf("%s bind opens under the old AAD", slug)
			}
			ct, err := c.Credential(f.conn[i], PurposeContainment, "")
			if err != nil {
				return err
			}
			pt, err = f.sealer.Open(ct.Sealed, CredentialAAD(c.Tenant(), f.conn[i], PurposeContainment, ""))
			if err != nil || string(pt) != "token-"+slug {
				t.Errorf("%s containment: %q %v", slug, pt, err)
			}
			if ct.BaseURL != "https://"+slug+".okta.com" || ct.Org != "org-"+slug || ct.UpdatedBy != "admin" {
				t.Errorf("%s containment settings: %+v", slug, ct)
			}
			if _, err := f.sealer.Open(ct.Sealed, seal.AAD(c.Tenant(), "containment_credentials", "token_enc", f.conn[i])); err == nil {
				t.Errorf("%s containment opens under the old AAD", slug)
			}
			// another tenant's blob never opens here
			if _, err := f.sealer.Open(ct.Sealed, CredentialAAD(f.tenant[1-i], f.conn[i], PurposeContainment, "")); err == nil {
				t.Errorf("%s containment opens under another tenant's AAD", slug)
			}
			if _, err := c.Credential(f.conn[i], PurposeBind, f.orphaned); !errors.Is(err, ErrNotFound) {
				t.Errorf("orphan migrated: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// A second run finds nothing to do.
	if res, err := f.db.MigrateCredentials(ctx, f.sealer); err != nil || res != (CredentialMigration{}) {
		t.Errorf("second run = %+v, %v", res, err)
	}
}

// TestMigrateCredentials_FailsClosed: a blob that does not open (another KEK),
// or no sealer at all, aborts the whole migration; nothing is moved and the
// old tables stay.
func TestMigrateCredentials_FailsClosed(t *testing.T) {
	ctx := context.Background()
	other, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func(f *migFixture) error{
		"wrong KEK": func(f *migFixture) error { _, err := f.db.MigrateCredentials(ctx, other); return err },
		"no sealer": func(f *migFixture) error { _, err := f.db.MigrateCredentials(ctx, nil); return err },
		"AAD mismatch": func(f *migFixture) error {
			// a containment token sealed for another connection's row
			bad, err := f.sealer.Seal([]byte("x"), seal.AAD(f.tenant[0], "containment_credentials", "token_enc", f.conn[1]))
			if err != nil {
				return err
			}
			if _, err := f.db.sql.ExecContext(ctx, `UPDATE containment_credentials SET token_enc = ? WHERE connection_id = ?`,
				bad, f.conn[0]); err != nil {
				return err
			}
			_, err = f.db.MigrateCredentials(ctx, f.sealer)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newMigFixture(t)
			if err := run(f); err == nil {
				t.Fatal("migration succeeded")
			} else if strings.Contains(err.Error(), "bind-pw") || strings.Contains(err.Error(), "token-") {
				t.Errorf("error carries secret material: %v", err)
			}
			for _, old := range []string{"connection_secrets", "containment_credentials"} {
				if !f.hasTable(t, old) {
					t.Errorf("%s dropped by a failed migration", old)
				}
			}
			var n int
			if err := f.db.sql.QueryRowContext(ctx, `SELECT count(*) FROM connection_credentials`).Scan(&n); err != nil || n != 0 {
				t.Errorf("rows in the new table after a failed migration: %d %v", n, err)
			}
		})
	}
}

// TestMigrateCredentials_FreshDatabase: with no old tables it does nothing,
// even without a sealer.
func TestMigrateCredentials_FreshDatabase(t *testing.T) {
	db := openTest(t)
	if res, err := db.MigrateCredentials(context.Background(), nil); err != nil || res != (CredentialMigration{}) {
		t.Fatalf("fresh database: %+v, %v", res, err)
	}
}

// TestCredentialAAD binds tenant, connection, purpose and ref.
func TestCredentialAAD(t *testing.T) {
	a, b := tenancy.MustParse("00000000-0000-4000-8000-0000000000a1"), tenancy.MustParse("00000000-0000-4000-8000-0000000000b2")
	base := CredentialAAD(a, "c1", PurposeBind, "sealed:1")
	for name, other := range map[string][]byte{
		"tenant":     CredentialAAD(b, "c1", PurposeBind, "sealed:1"),
		"connection": CredentialAAD(a, "c2", PurposeBind, "sealed:1"),
		"purpose":    CredentialAAD(a, "c1", PurposeContainment, "sealed:1"),
		"ref":        CredentialAAD(a, "c1", PurposeBind, "sealed:2"),
		"no ref":     CredentialAAD(a, "c1", PurposeBind, ""),
	} {
		if bytes.Equal(base, other) {
			t.Errorf("AAD ignores the %s", name)
		}
	}
}
