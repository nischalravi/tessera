package helpdesk

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Checker answers "is this identity privileged" for one transaction. An
// identity is privileged when it can exercise a privileged permission through
// any path of the access graph (standing or JIT, so a JIT grant active now
// counts), or when a platform user linked to it holds a Tessera admin role.
// The graph is built once, on first use.
type Checker struct {
	c   *store.TenantTx
	now time.Time
	g   *graph.Snapshot
}

// NewChecker returns a checker reading through c at now.
func NewChecker(c *store.TenantTx, now time.Time) *Checker { return &Checker{c: c, now: now} }

// Privileged reports whether the identity is privileged.
func (k *Checker) Privileged(identityID int64) (bool, error) {
	admin, err := k.c.IdentityHoldsAdminRole(identityID, k.now)
	if err != nil || admin {
		return admin, err
	}
	if k.g == nil {
		if k.g, err = graph.Build(k.c, k.now); err != nil {
			return false, err
		}
	}
	for _, p := range k.g.EffectivePermissions(identityID).Values() {
		if p.Privileged {
			return true, nil
		}
	}
	return false, nil
}
