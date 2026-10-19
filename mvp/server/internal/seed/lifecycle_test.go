package seed_test

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// TestSeedLifecycle: five demo people are non-employees with a sponsor and
// an end date, none of them a dev sign-in, and seeding writes no lifecycle
// audit event.
func TestSeedLifecycle(t *testing.T) {
	db := testkit.Demo(t)
	testkit.Read(t, db, func(c *store.TenantTx) error {
		ls, err := c.Lifecycles()
		if err != nil {
			return err
		}
		if len(ls) != 5 {
			t.Fatalf("%d lifecycle rows", len(ls))
		}
		for _, l := range ls {
			if l.WorkerType == store.WorkerEmployee || l.SponsorID == nil || l.EndsAt == nil {
				t.Errorf("row %+v", l)
			}
			p, err := c.Identity(l.IdentityID)
			if err != nil {
				return err
			}
			if p.ExternalID == "emp-1006" || p.ExternalID == "emp-1012" {
				t.Errorf("%s signs in and should stay an employee", p.Name)
			}
		}
		log, err := c.AuditLog(-1)
		for _, e := range log {
			if strings.HasPrefix(e.Action, "lifecycle.") {
				t.Errorf("seeding wrote %s", e.Action)
			}
		}
		return err
	})
}
