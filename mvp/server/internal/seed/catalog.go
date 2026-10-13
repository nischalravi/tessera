package seed

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// seedCatalog makes the demo's groups requestable (issue #164): ordinary
// groups until removed; privileged ones (the JIT groups among them) for 8
// hours by default and at most 72. It writes no audit event, so the ledger
// of a fresh seed is unchanged.
func seedCatalog(c *store.TenantTx, now time.Time) error {
	groups, err := c.Groups()
	if err != nil {
		return err
	}
	def, max := 8.0, 72.0
	for _, g := range groups {
		it := &store.CatalogItem{ID: uuid.NewString(), GroupID: g.ID, Requestable: true, Risk: "low", UpdatedAt: now}
		if g.Description != nil {
			it.Description = *g.Description
		}
		if g.Privileged {
			it.Risk, it.DefaultHours, it.MaxHours = "high", &def, &max
		}
		if err := c.PutCatalogItem(it); err != nil {
			return fmt.Errorf("seed: catalog item for %s: %w", g.Name, err)
		}
	}
	return nil
}
