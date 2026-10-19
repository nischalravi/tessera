package abac

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Resolver supplies the identity.* attributes of people in one tenant: the
// ones on the identity record (IdentityAttrs) plus those kept elsewhere, which
// it loads once up front so evaluating many identities costs no further
// queries. It is scoped to the transaction it was built from and so to its
// tenant.
//
// To add a stored attribute (location, a custom HRIS field): load it in
// NewResolver, add it in Identity, and list it in Catalog. A person without a
// value leaves the key out, and a missing attribute denies.
type Resolver struct {
	now         time.Time
	workerTypes map[int64]string // identity id -> worker type, from the lifecycle record
}

// NewResolver loads the stored attributes the tenant holds.
func NewResolver(tx *store.TenantTx, now time.Time) (*Resolver, error) {
	ls, err := tx.Lifecycles()
	if err != nil {
		return nil, err
	}
	r := &Resolver{now: now, workerTypes: make(map[int64]string, len(ls))}
	for _, l := range ls {
		r.workerTypes[l.IdentityID] = l.WorkerType
	}
	return r, nil
}

// Identity returns the identity.* attributes of a person.
//
// identity.worker_type (employee, contractor, intern, partner, vendor or
// guest) is only set for people. A person with no lifecycle record is an
// employee, as everywhere else in lifecycle (#159); services and AI agents
// have no worker type, so a test on it denies for them.
func (r *Resolver) Identity(i *store.Identity) Attrs {
	a := IdentityAttrs(i, r.now)
	if i.Type == "human" {
		if wt, ok := r.workerTypes[i.ID]; ok {
			a["identity.worker_type"] = wt
		} else {
			a["identity.worker_type"] = "employee"
		}
	}
	return a
}
