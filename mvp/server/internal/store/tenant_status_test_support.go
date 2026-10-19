package store

import (
	"context"
	"database/sql"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

var tenantForceStatus = sq("tenants.force_status_for_test", `UPDATE tenants SET status = @status WHERE id = @id`)

// SetTenantStatusForTest sets a tenant's status, including suspended, which
// no product path does yet, so tests can prove a suspended tenant is refused.
// Test binaries only.
func (d *DB) SetTenantStatusForTest(ctx context.Context, t tenancy.ID, status string) error {
	tm, err := d.TamperForTest()
	if err != nil {
		return err
	}
	return tm.db.InSystem(ctx, "test: set tenant status", func(s *SystemTx) error {
		_, err := s.exec(tenantForceStatus, sql.Named("id", t.String()), sql.Named("status", status))
		return err
	})
}
