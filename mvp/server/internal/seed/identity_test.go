package seed_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/identity"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/affiliations"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// TestSeedIdentityModel: a seeded tenant has the populations, and every
// person has a source record, an HR affiliation and identifiers, without audit
// events of its own (a fresh ledger keeps its recorded ids).
func TestSeedIdentityModel(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	g := seed.Globex(now)
	g.Identifiers = storetest.IdentityKeyer(t)
	if _, err := seed.Run(ctx, db, now, nil, []seed.Tenant{g}); err != nil {
		t.Fatal(err)
	}
	err = db.ReadTenant(ctx, seed.GlobexID, func(c *store.TenantTx) error {
		pops, err := c.GuestPopulations()
		if err != nil || len(pops) != len(identity.DefaultPopulations) {
			t.Errorf("populations = %v, %v", pops, err)
		}
		people, err := c.Identities()
		if err != nil {
			return err
		}
		humans := 0
		for _, p := range people {
			if p.Type != "human" {
				continue
			}
			humans++
			affs, err := c.AffiliationsFor(p.ID)
			if err != nil {
				return err
			}
			if got := affiliations.Derive(p.Status, affs, now, affiliations.DefaultNotice); got != affiliations.StateActive && p.Status == "active" {
				t.Errorf("%s: derived state %s", p.ExternalID, got)
			}
			if xs, err := c.IdentifiersFor(p.ID); err != nil || len(xs) == 0 {
				t.Errorf("%s: identifiers %v, %v", p.ExternalID, xs, err)
			}
		}
		if humans == 0 {
			t.Fatal("no humans seeded")
		}
		evs, err := c.AuditLog(-1)
		if err != nil {
			return err
		}
		for _, e := range evs { // the demo campaign writes its own event; the back-fill writes none
			if strings.Contains(e.Action, "affiliation") || strings.Contains(e.Action, "identifier") || strings.Contains(e.Action, "source") {
				t.Errorf("the back-fill wrote audit event %s", e.Action)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
