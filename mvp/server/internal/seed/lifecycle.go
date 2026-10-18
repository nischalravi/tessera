package seed

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// seedLifecycle gives a few demo people a non-employee lifecycle (issue
// #159): contractors, an intern, a vendor and a partner, sponsored by their
// managers, with end dates from 3 to 120 days out so the "Expiring soon"
// view and the warnings have something to show. It picks active people with
// a manager who are not managers themselves, in id order, skipping the ones
// linked to dev sign-ins. It writes no audit event and grants nothing.
func seedLifecycle(c *store.TenantTx, now time.Time, skip map[int64]bool) error {
	people, err := c.Identities()
	if err != nil {
		return err
	}
	managers := map[int64]bool{}
	for _, p := range people {
		if p.ManagerID != nil {
			managers[*p.ManagerID] = true
		}
	}
	plan := []struct {
		wt   string
		org  string
		days int
	}{
		{store.WorkerContractor, "Northwind Consulting", 9},
		{store.WorkerContractor, "Northwind Consulting", 45},
		{store.WorkerIntern, "", 60},
		{store.WorkerVendor, "Fabrikam Support", 3},
		{store.WorkerPartner, "Contoso Partners", 120},
	}
	i := 0
	for _, p := range people {
		if i == len(plan) {
			break
		}
		if p.Type != "human" || p.Status != "active" || p.ManagerID == nil || managers[p.ID] || skip[p.ID] {
			continue
		}
		d := plan[i]
		ends := now.Add(time.Duration(d.days) * 24 * time.Hour)
		l := &store.Lifecycle{IdentityID: p.ID, WorkerType: d.wt, SponsorID: p.ManagerID, EndsAt: &ends, Source: "hris", UpdatedAt: now}
		if d.org != "" {
			org := d.org
			l.Organization = &org
		}
		if err := c.PutLifecycle(l); err != nil {
			return err
		}
		wt := d.wt
		if err := c.AddLifecycleEvent(&store.LifecycleEvent{IdentityID: p.ID, Event: "set", WorkerType: &wt, EndsAt: &ends,
			Actor: "hris", At: now}); err != nil {
			return err
		}
		i++
	}
	return nil
}
