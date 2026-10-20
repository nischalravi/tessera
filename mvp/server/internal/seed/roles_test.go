package seed_test

import (
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// TestSeedRoles: the demo company gets its six business roles with owners
// and a first version; rule members are only people who already hold every
// entitlement, so seeding grants nothing (no edge has source "role") and the
// rest show in each role's reconcile plan.
func TestSeedRoles(t *testing.T) {
	db := testkit.Demo(t)
	testkit.Read(t, db, func(c *store.TenantTx) error {
		rs, err := c.BusinessRoles()
		if err != nil {
			return err
		}
		if len(rs) != 6 {
			t.Fatalf("%d roles", len(rs))
		}
		members := 0
		for _, r := range rs {
			if r.OwnerIdentityID == nil {
				t.Errorf("%s has no owner", r.Name)
			}
			if vs, err := c.RoleVersions(r.ID); err != nil || len(vs) != 1 {
				t.Errorf("%s versions = %v, %v", r.Name, vs, err)
			}
			ms, err := c.RoleMembers(r.ID)
			if err != nil {
				return err
			}
			members += len(ms)
			t.Logf("%s: %d members", r.Name, len(ms))
			d, err := roles.RoleDrift(c, r.ID, time.Now())
			if err != nil {
				return err
			}
			if len(d.Missing) != 0 {
				t.Errorf("%s: seeded members miss entitlements: %+v", r.Name, d.Missing)
			}
		}
		if members == 0 {
			t.Error("no seeded role has members")
		}
		edges, err := c.Edges()
		if err != nil {
			return err
		}
		for _, e := range edges {
			if e.Source == "role" {
				t.Fatalf("seeding granted %s -> %s", e.Src, e.Dst)
			}
		}
		log, err := c.AuditLog(-1)
		for _, e := range log {
			if len(e.Action) > 5 && e.Action[:5] == "role." {
				t.Errorf("seeding wrote %s", e.Action)
			}
		}
		return err
	})
}
