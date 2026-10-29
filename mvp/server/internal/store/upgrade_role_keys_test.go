package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

func TestRoleKeySlug(t *testing.T) {
	taken := map[string]bool{"engineer": true, "engineer-2": true}
	cases := []struct{ name, want string }{
		{"Engineer", "engineer-3"},
		{"  Payments  analyst (read-only) ", "payments-analyst-read-only"},
		{"R&D / Lab", "r-d-lab"},
		{"Ünï", "n"},
		{"!!!", "role"},
		{"", "role"},
	}
	for _, tc := range cases {
		if got := RoleKeySlug(tc.name, func(k string) bool { return taken[k] }); got != tc.want {
			t.Errorf("RoleKeySlug(%q) = %q; want %q", tc.name, got, tc.want)
		}
	}
	long := RoleKeySlug(strings.Repeat("abc ", 40), func(k string) bool { return false })
	if len(long) > RoleKeyMax-8 || strings.HasSuffix(long, "-") || !strings.HasPrefix(long, "abc-abc") {
		t.Errorf("a long name made %q", long)
	}
}

// A database created before issue #650 gets business_roles.key and business_role_versions.policy_ref on open; each
// existing role gets the slug of its name, made unique within its tenant, and its rows survive.
func TestUpgradeRoleKeys(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	d, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	d.sql.SetMaxOpenConns(1)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := d.sql.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// the tables as they were: no key, no policy_ref, no index
	exec(`PRAGMA foreign_keys = OFF`)
	exec(`DROP INDEX IF EXISTS ux_business_roles_key`)
	exec(`ALTER TABLE business_roles DROP COLUMN key`)
	exec(`ALTER TABLE business_role_versions DROP COLUMN policy_ref`)
	ids := map[string]tenancy.ID{"t1": tenancy.New(), "t2": tenancy.New()}
	for slug, id := range ids {
		if err := d.InSystem(ctx, "test", func(s *SystemTx) error {
			_, err := s.CreateTenant(Tenant{ID: id, Slug: "tenant-" + slug, Name: slug, CreatedAt: time.Now()})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	ins := func(id, slug, name, created string) {
		tenant := ids[slug].String()
		exec(`INSERT INTO business_roles (id, tenant_id, name, risk, status, version, created_at, updated_at)
			VALUES (?, ?, ?, 'low', 'active', 1, ?, ?)`, id, tenant, name, created, created)
	}
	ins("a", "t1", "Support agent", "2026-01-01T00:00:00Z")
	ins("b", "t1", "Support Agent!", "2026-01-02T00:00:00Z") // the same slug: the later one gets -2
	ins("c", "t2", "Support agent", "2026-01-01T00:00:00Z")  // another tenant: the plain slug again
	_ = d.Close()

	for range 2 { // opening twice changes nothing more
		if d, err = Open(ctx, path); err != nil {
			t.Fatal(err)
		}
		d.sql.SetMaxOpenConns(1)
		got := map[string]string{}
		rows, err := d.sql.QueryContext(ctx, `SELECT id, key FROM business_roles`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var id, key string
			if err := rows.Scan(&id, &key); err != nil {
				t.Fatal(err)
			}
			got[id] = key
		}
		_ = rows.Close()
		if got["a"] != "support-agent" || got["b"] != "support-agent-2" || got["c"] != "support-agent" || len(got) != 3 {
			t.Fatalf("keys = %v", got)
		}
		var n int
		if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('business_role_versions') WHERE name = 'policy_ref'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("policy_ref column: %d, %v", n, err)
		}
		// the unique index is back: a second role with a key of its tenant is refused
		if _, err := d.sql.ExecContext(ctx, "INSERT INTO business_roles (id, tenant_id, key, name, risk, status, version, created_at, updated_at) "+
			"VALUES ('z', '"+ids["t1"].String()+"', 'support-agent', 'Z', 'low', 'active', 1, '2026-01-03T00:00:00Z', '2026-01-03T00:00:00Z')"); err == nil {
			t.Fatal("a duplicate key within a tenant was accepted")
		}
		_ = d.Close()
	}
}
