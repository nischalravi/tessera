package readiness

import (
	"context"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Scope is one tenant's view of the store. Validation runs and dry runs
// commit in phases (the run row, then the checks or the discovery outside
// any transaction, then the results), so they open their own transactions
// instead of running inside one request transaction; every phase is a
// transaction of the same tenant. Everything else takes a *store.TenantTx.
type Scope struct {
	DB     *store.DB
	Tenant tenancy.ID
}

// Write runs fn in a write transaction of the scope's tenant. A zero tenant
// fails closed (store.ErrNoTenant).
func (sc Scope) Write(ctx context.Context, fn func(*store.TenantTx) error) error {
	return sc.DB.InTenant(ctx, sc.Tenant, fn)
}

// Read runs fn in a read-only transaction of the scope's tenant.
func (sc Scope) Read(ctx context.Context, fn func(*store.TenantTx) error) error {
	return sc.DB.ReadTenant(ctx, sc.Tenant, fn)
}
