package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Scheduled-review isolation (issue #166): a tenant sees and changes only its
// own templates and launches.

type schedRows struct {
	tmpl, launch string
	campaign     int64
	item         int64
	carol        int64
}

func seedSchedRows(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) schedRows {
	t.Helper()
	r := schedRows{tmpl: "tmpl-" + tag, launch: "launch-" + tag, campaign: tn.IDs["campaign"], item: tn.IDs["item"], carol: tn.IDs["carol"]}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		next := storetest.Now.Add(-time.Hour)
		if err := c.InsertReviewTemplate(&store.ReviewTemplate{ID: r.tmpl, Name: "Quarterly " + tag, UnusedDays: 60, DurationDays: 14,
			ReminderDays: 3, CloseOut: "escalate", EscalationIdentityID: &r.carol, EscalationDays: 7, Recurrence: "quarterly",
			NextRunAt: &next, Enabled: true, CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		return c.InsertReviewLaunch(&store.ReviewLaunch{ID: r.launch, TemplateID: r.tmpl, PeriodKey: "2026-Q3", CampaignID: r.campaign,
			LaunchedAt: storetest.Now, DueAt: storetest.Now.Add(14 * 24 * time.Hour)})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func schedFixture(t *testing.T) (*storetest.Fixture, schedRows, schedRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedSchedRows(t, f.DB, f.A, "a"), seedSchedRows(t, f.DB, f.B, "b")
}

func TestIsolation_ReviewScheduleReads(t *testing.T) {
	f, a, b := schedFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if ts, err := c.ReviewTemplates(); err != nil || len(ts) != 1 || ts[0].ID != b.tmpl {
			t.Errorf("ReviewTemplates = %v, %v", ts, err)
		}
		if _, err := c.ReviewTemplate(a.tmpl); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ReviewTemplate(A's) = %v", err)
		}
		if ts, err := c.DueReviewTemplates(storetest.Now); err != nil || len(ts) != 1 || ts[0].ID != b.tmpl {
			t.Errorf("DueReviewTemplates = %v, %v", ts, err)
		}
		if n, err := c.CountDueReviewTemplates(storetest.Now); err != nil || n != 1 {
			t.Errorf("CountDueReviewTemplates = %d, %v", n, err)
		}
		if ls, err := c.ReviewLaunches(""); err != nil || len(ls) != 1 || ls[0].ID != b.launch {
			t.Errorf("ReviewLaunches = %v, %v", ls, err)
		}
		if ls, err := c.ReviewLaunches(a.tmpl); err != nil || len(ls) != 0 {
			t.Errorf("ReviewLaunches(A's) = %v, %v", ls, err)
		}
		if ls, err := c.OpenReviewLaunches(); err != nil || len(ls) != 1 || ls[0].ID != b.launch {
			t.Errorf("OpenReviewLaunches = %v, %v", ls, err)
		}
		if ok, err := c.ReviewPeriodLaunched(a.tmpl, "2026-Q3"); err != nil || ok {
			t.Errorf("ReviewPeriodLaunched(A's) = %v, %v", ok, err)
		}
		return nil
	})
}

var schedMutations = map[string]func(c *store.TenantTx, a, b schedRows) error{
	"UpdateReviewTemplate": func(c *store.TenantTx, a, _ schedRows) error {
		return c.UpdateReviewTemplate(&store.ReviewTemplate{ID: a.tmpl, Name: "x", UnusedDays: 1, DurationDays: 1, CloseOut: "revoke",
			EscalationDays: 7, Recurrence: "once", UpdatedAt: storetest.Now})
	},
	"AdvanceReviewTemplate": func(c *store.TenantTx, a, _ schedRows) error {
		return c.AdvanceReviewTemplate(a.tmpl, storetest.Now.Add(-time.Hour), nil)
	},
	"SaveReviewLaunch": func(c *store.TenantTx, a, _ schedRows) error {
		now := storetest.Now
		return c.SaveReviewLaunch(&store.ReviewLaunch{ID: a.launch, DueAt: now, ClosedAt: &now})
	},
	"SetItemReviewer": func(c *store.TenantTx, a, b schedRows) error { return c.SetItemReviewer(a.item, b.carol) },
	"InsertReviewTemplate": func(c *store.TenantTx, a, _ schedRows) error {
		return c.InsertReviewTemplate(&store.ReviewTemplate{ID: "x", Name: "x", UnusedDays: 1, DurationDays: 1, CloseOut: "escalate",
			EscalationIdentityID: &a.carol, EscalationDays: 7, Recurrence: "once", CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	},
	"InsertReviewLaunch": func(c *store.TenantTx, a, b schedRows) error {
		return c.InsertReviewLaunch(&store.ReviewLaunch{ID: "x", TemplateID: b.tmpl, PeriodKey: "x", CampaignID: a.campaign,
			LaunchedAt: storetest.Now, DueAt: storetest.Now})
	},
}

func TestIsolation_ReviewScheduleMutationsScoped(t *testing.T) {
	for name, fn := range schedMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := schedFixture(t)
			before := schedDump(t, f.DB, f.A.ID)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v", name, err)
			}
			if schedDump(t, f.DB, f.A.ID) != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

func schedDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	out := storetest.Dump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		ts, err := c.ReviewTemplates()
		if err != nil {
			return err
		}
		ls, err := c.ReviewLaunches("")
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{ts, ls})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func reviewSchedulesCovered() map[string]bool {
	out := map[string]bool{}
	for k := range schedMutations {
		out[k] = true
	}
	for _, k := range []string{"ReviewTemplates", "ReviewTemplate", "DueReviewTemplates", "CountDueReviewTemplates",
		"ReviewLaunches", "OpenReviewLaunches", "ReviewPeriodLaunched"} {
		out[k] = true
	}
	return out
}
