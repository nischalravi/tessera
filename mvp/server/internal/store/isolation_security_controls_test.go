package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Help-desk risk signal attribution and dismissal (issue #510) and timed schedule pauses (issue #512) are per
// tenant: another tenant cannot read, dismiss, pause or resume them.

func TestIsolation_HelpdeskRiskDismissal(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := map[string]string{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		tn := tn
		if err := f.DB.InTenant(t.Context(), tn.ID, func(c *store.TenantTx) error {
			r := &store.HelpdeskIdPRisk{IdentityID: tn.IDs["alice"], Kind: "auth_method_added", Source: "entra", OccurredAt: storetest.Now,
				SubmittedBy: "admin of " + tn.Slug, SubmittedByUser: "user-" + tn.Slug}
			ids[tn.Slug] = ""
			if err := c.InsertHelpdeskIdPRisk(r, storetest.Now); err != nil {
				return err
			}
			ids[tn.Slug] = r.ID
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.HelpdeskIdPRisk(ids[f.A.Slug]); err != store.ErrNotFound {
			t.Errorf("B reads A's risk signal: %v", err)
		}
		if err := c.DismissHelpdeskIdPRisk(ids[f.A.Slug], "u", "B admin", "no", storetest.Now); err != store.ErrNotFound {
			t.Errorf("B dismisses A's risk signal: %v", err)
		}
		list, err := c.HelpdeskIdPRiskList(50)
		if err != nil || len(list) != 1 || list[0].ID != ids[f.B.Slug] || list[0].SubmittedBy != "admin of "+f.B.Slug {
			t.Errorf("B's list = %v, %v", list, err)
		}
		if err := c.DismissHelpdeskIdPRisk(ids[f.B.Slug], "u2", "B other", "wrong", storetest.Now); err != nil {
			t.Fatal(err)
		}
		if err := c.DismissHelpdeskIdPRisk(ids[f.B.Slug], "u2", "B other", "again", storetest.Now); err != store.ErrNotFound {
			t.Errorf("a second dismissal: %v", err)
		}
		r, err := c.HelpdeskIdPRisk(ids[f.B.Slug])
		if err != nil || r.DismissedAt == nil || r.DismissedBy != "B other" || r.DismissReason != "wrong" {
			t.Errorf("dismissed risk = %+v, %v", r, err)
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		if r, err := c.HelpdeskIdPRisk(ids[f.A.Slug]); err != nil || r.DismissedAt != nil {
			t.Errorf("A's risk signal = %+v, %v (B's dismissal leaked)", r, err)
		}
		return nil
	})
}

func TestIsolation_TimedSchedulePause(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		if err := f.DB.InTenant(t.Context(), tn.ID, func(c *store.TenantTx) error {
			return c.EnsureQueueSchedule(&store.QueueSchedule{Name: "s", Kind: "k", Spec: "@every 1m", NextRunAt: now.Add(-time.Minute)}, now)
		}); err != nil {
			t.Fatal(err)
		}
	}
	inA(t, f, func(c *store.TenantTx) error { return c.PauseQueueScheduleUntil("s", now.Add(time.Hour), now) })
	inB(t, f, func(c *store.TenantTx) error {
		if rs, err := c.QueueSchedulesToResume(now.Add(2 * time.Hour)); err != nil || len(rs) != 0 {
			t.Errorf("B sees A's paused schedule: %v, %v", rs, err)
		}
		if s, err := c.QueueSchedule("s"); err != nil || !s.Enabled || s.PausedUntil != nil {
			t.Errorf("B's schedule = %+v, %v", s, err)
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		if rs, err := c.QueueSchedulesToResume(now.Add(30 * time.Minute)); err != nil || len(rs) != 0 {
			t.Errorf("resumed before the end: %v, %v", rs, err)
		}
		rs, err := c.QueueSchedulesToResume(now.Add(2 * time.Hour))
		if err != nil || len(rs) != 1 || rs[0].Name != "s" || rs[0].PausedUntil == nil {
			t.Fatalf("to resume = %v, %v", rs, err)
		}
		if err := c.SetQueueScheduleEnabled("s", true, now); err != nil {
			t.Fatal(err)
		}
		if s, _ := c.QueueSchedule("s"); !s.Enabled || s.PausedUntil != nil {
			t.Errorf("after resume = %+v", s)
		}
		return nil
	})
}

// TestIsolation_PausedWithoutEnd (issue #522): the schedules disabled with no pause end are listed per tenant, and the
// client approver is set on this tenant's client only.
func TestIsolation_PausedWithoutEnd(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		if err := f.DB.InTenant(t.Context(), tn.ID, func(c *store.TenantTx) error {
			if err := c.EnsureQueueSchedule(&store.QueueSchedule{Name: "s", Kind: "k", Spec: "@every 1m", NextRunAt: now}, now); err != nil {
				return err
			}
			return c.SetQueueScheduleEnabled("s", false, now) // an old pause: no end
		}); err != nil {
			t.Fatal(err)
		}
	}
	inA(t, f, func(c *store.TenantTx) error { return c.PauseQueueScheduleUntil("s", now.Add(time.Hour), now) })
	inA(t, f, func(c *store.TenantTx) error {
		if ss, err := c.QueueSchedulesPausedWithoutEnd(); err != nil || len(ss) != 0 {
			t.Errorf("A, paused with an end: %v, %v", ss, err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		if ss, err := c.QueueSchedulesPausedWithoutEnd(); err != nil || len(ss) != 1 || ss[0].Name != "s" {
			t.Errorf("B, paused with no end: %v, %v", ss, err)
		}
		return nil
	})
	rowsA, rowsB := seedOAuthRows(t, f.DB, f.A.ID, 0x61), seedOAuthRows(t, f.DB, f.B.ID, 0x62)
	_ = rowsB
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.SetAPIClientApprover(rowsA.machine.ClientID, "someone"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B set the approver of A's client: %v", err)
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.SetAPIClientApprover(rowsA.machine.ClientID, "someone"); err != nil {
			t.Fatal(err)
		}
		if cl, err := c.APIClientByClientID(rowsA.machine.ClientID); err != nil || cl.ApprovedBy != "someone" {
			t.Errorf("approver = %+v, %v", cl, err)
		}
		return nil
	})
}

func securityControlsCovered() map[string]bool {
	return map[string]bool{"HelpdeskIdPRisk": true, "HelpdeskIdPRiskList": true, "DismissHelpdeskIdPRisk": true,
		"PauseQueueScheduleUntil": true, "QueueSchedulesToResume": true, "QueueSchedulesPausedWithoutEnd": true,
		"SetAPIClientApprover": true} // the tests above
}
