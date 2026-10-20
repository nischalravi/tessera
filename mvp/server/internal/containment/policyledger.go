package containment

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// policyLedger coordinates the workers that edit one shared Deny policy: a
// lease per policy (lock) and the list of entries Tessera must keep in it
// (mark, held). The database implementation is dbLedger.
type policyLedger interface {
	// lock waits for the policy's lease and returns the function that releases it.
	lock(ctx context.Context, policyID string) (release func(), err error)
	// mark records that Tessera holds userID in the policy, pending or active.
	mark(ctx context.Context, policyID, userID, state string, now time.Time) error
	// held lists the user ids Tessera holds in the policy, recorded since since.
	held(ctx context.Context, policyID string, since time.Time) ([]string, error)
}

const (
	// leaseTTL bounds how long a crashed worker can block a policy. A policy
	// edit is a few calls inside the containment time budget.
	leaseTTL = 60 * time.Second
	// leaseWait bounds how long a worker waits for another's lease.
	leaseWait = 25 * time.Second
)

// errLeaseBusy: another worker held the policy lease for the whole wait.
var errLeaseBusy = errors.New("another containment run is editing the Deny service control policy and did not finish in time; it will be retried")

// dbLedger is the policyLedger kept in the tenant's database. The lease is
// real wall-clock time (it coordinates processes), whatever the service clock.
type dbLedger struct {
	db     *store.DB
	tenant tenancy.ID
}

// ledgerFor returns the ledger of a tenant, or nil when the service has no
// database or the job names no tenant (a unit test of a provider).
func (s *Service) ledgerFor(tenant tenancy.ID) policyLedger {
	if s.DB == nil || tenant == (tenancy.ID{}) {
		return nil
	}
	return &dbLedger{db: s.DB, tenant: tenant}
}

func (l *dbLedger) lock(ctx context.Context, policyID string) (func(), error) {
	holder := uuid.NewString()
	deadline := time.Now().Add(leaseWait)
	for wait := 10 * time.Millisecond; ; wait = min(wait*2, 250*time.Millisecond) {
		var ok bool
		err := l.db.InTenant(ctx, l.tenant, func(c *store.TenantTx) (err error) {
			now := time.Now()
			ok, err = c.AcquirePolicyLease(policyID, holder, now, now.Add(leaseTTL))
			return err
		})
		if err != nil {
			return nil, err
		}
		if ok {
			return func() {
				// released even when the run's context ended
				rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer cancel()
				_ = l.db.InTenant(rctx, l.tenant, func(c *store.TenantTx) error { return c.ReleasePolicyLease(policyID, holder) })
			}, nil
		}
		if time.Now().Add(wait).After(deadline) {
			return nil, errLeaseBusy
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

func (l *dbLedger) mark(ctx context.Context, policyID, userID, state string, now time.Time) error {
	return l.db.InTenant(ctx, l.tenant, func(c *store.TenantTx) error {
		return c.MarkPolicyDenial(policyID, userID, state, now)
	})
}

func (l *dbLedger) held(ctx context.Context, policyID string, since time.Time) ([]string, error) {
	var out []string
	// entries past the hold are forgotten: the policy's owner may remove them by hand
	err := l.db.InTenant(ctx, l.tenant, func(c *store.TenantTx) (err error) {
		if err = c.PrunePolicyDenials(policyID, since); err != nil {
			return err
		}
		out, err = c.PolicyDenials(policyID, since)
		return err
	})
	return out, err
}
