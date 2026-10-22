package store

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
)

// TestPG_ArchiveDefinerFunctionsNeedATenant (issue #436): with app.tenant_id unset or empty the
// tenant guard of both archive SECURITY DEFINER functions raises insufficient_privilege instead of
// comparing with NULL and running the guarded statements for any tenant. A mismatching tenant is
// refused too.
func TestPG_ArchiveDefinerFunctionsNeedATenant(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	tenant := pgTenantA.String()
	calls := map[string]string{
		"mark_verified": fmt.Sprintf(`SELECT tessera_archive_mark_verified('%s', 'seg', 'x')`, tenant),
		"purge_audit":   fmt.Sprintf(`SELECT tessera_archive_purge_audit('%s', 'seg')`, tenant),
	}
	for name, call := range calls {
		for _, tc := range []struct {
			setting string
			set     bool
			value   string
		}{
			{"unset", false, ""},
			{"empty", true, ""},
			{"other tenant", true, pgTenantB.String()},
		} {
			t.Run(name+"/"+tc.setting, func(t *testing.T) {
				f.asApp(t, "", func(tx *sql.Tx) {
					if tc.set {
						if _, err := tx.ExecContext(ctx, pgSetTenant, tc.value); err != nil {
							t.Fatal(err)
						}
					}
					_, err := tx.ExecContext(ctx, call)
					if got := sqlState(err); got != "42501" {
						t.Errorf("SQLSTATE %q, want 42501: %v", got, err)
					}
				})
			})
		}
	}
}
