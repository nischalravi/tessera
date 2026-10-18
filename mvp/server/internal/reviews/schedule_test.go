package reviews_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// The fixture is the tiny world in tenant B (no sentinel). Its grants
// include unused and privileged ones, so a generated campaign has items.

func pols(t *testing.T) []*policy.Policy {
	t.Helper()
	ps, err := policy.NewLoader(policies.FS).Load()
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

type sched struct {
	t   *testing.T
	f   *storetest.Fixture
	ps  []*policy.Policy
	now time.Time
}

func newSched(t *testing.T) *sched {
	return &sched{t: t, f: storetest.TwoTenants(t), ps: pols(t), now: storetest.Now}
}

func (s *sched) tx(fn func(c *store.TenantTx) error) {
	s.t.Helper()
	if err := s.f.DB.InTenant(context.Background(), s.f.B.ID, fn); err != nil {
		s.t.Fatal(err)
	}
}

func (s *sched) template(mod func(*store.ReviewTemplate)) *store.ReviewTemplate {
	s.t.Helper()
	next := s.now.Add(-time.Hour)
	tm := &store.ReviewTemplate{ID: "t1", Name: "Quarterly review", UnusedDays: 60, DurationDays: 14, ReminderDays: 3,
		CloseOut: "revoke", EscalationDays: 7, Recurrence: "quarterly", NextRunAt: &next, Enabled: true,
		CreatedAt: s.now, UpdatedAt: s.now}
	if mod != nil {
		mod(tm)
	}
	s.tx(func(c *store.TenantTx) error {
		if err := reviews.ValidateTemplate(c, tm); err != nil {
			return err
		}
		return c.InsertReviewTemplate(tm)
	})
	return tm
}

func (s *sched) tick(at time.Time) reviews.TickResult {
	s.t.Helper()
	var r reviews.TickResult
	s.tx(func(c *store.TenantTx) (err error) { r, err = reviews.Tick(c, at, s.ps); return })
	return r
}

func (s *sched) launches() []*store.ReviewLaunch {
	var ls []*store.ReviewLaunch
	s.tx(func(c *store.TenantTx) (err error) { ls, err = c.ReviewLaunches(""); return })
	return ls
}

func TestPeriodAndNext(t *testing.T) {
	at := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	for rec, want := range map[string]string{"quarterly": "2026-Q4", "semiannual": "2026-H2", "annual": "2026", "once": "once"} {
		if got := reviews.PeriodKey(rec, at); got != want {
			t.Errorf("PeriodKey(%s) = %s, want %s", rec, got, want)
		}
	}
	if n := reviews.Next("quarterly", at); n == nil || !n.Equal(time.Date(2027, 2, 3, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("Next(quarterly) = %v", n)
	}
	if reviews.Next("once", at) != nil {
		t.Error("a one-off schedule has a next run")
	}
}

func TestSchedule_LaunchesOncePerPeriod(t *testing.T) {
	s := newSched(t)
	tm := s.template(nil)
	if r := s.tick(s.now); r.Launched != 1 {
		t.Fatalf("first tick launched %d", r.Launched)
	}
	if r := s.tick(s.now.Add(time.Minute)); r.Launched != 0 {
		t.Errorf("second tick launched %d", r.Launched)
	}
	ls := s.launches()
	if len(ls) != 1 || ls[0].PeriodKey != reviews.PeriodKey("quarterly", *tm.NextRunAt) || !ls[0].DueAt.Equal(s.now.Add(14*24*time.Hour)) {
		t.Fatalf("launches = %+v", ls)
	}
	s.tx(func(c *store.TenantTx) error {
		got, err := c.ReviewTemplate(tm.ID)
		if err == nil && (got.NextRunAt == nil || !got.NextRunAt.Equal(tm.NextRunAt.AddDate(0, 3, 0))) {
			t.Errorf("next run = %v", got.NextRunAt)
		}
		cmp, err := c.Campaign(ls[0].CampaignID)
		if err == nil && cmp.Name != "Quarterly review · "+ls[0].PeriodKey {
			t.Errorf("campaign name %q", cmp.Name)
		}
		return err
	})
	// a restart that rewinds next_run_at (a stale copy) does not launch the period again
	s.tx(func(c *store.TenantTx) error {
		got, _ := c.ReviewTemplate(tm.ID)
		got.NextRunAt = tm.NextRunAt
		return c.UpdateReviewTemplate(got)
	})
	if r := s.tick(s.now.Add(2 * time.Minute)); r.Launched != 0 {
		t.Errorf("relaunched a period: %d", r.Launched)
	}
}

func TestSchedule_MissedPeriodsCollapse(t *testing.T) {
	s := newSched(t)
	s.template(func(tm *store.ReviewTemplate) {
		long := s.now.AddDate(0, -7, 0) // three quarters missed
		tm.NextRunAt = &long
	})
	if r := s.tick(s.now); r.Launched != 1 {
		t.Fatalf("launched %d after an outage, want 1", r.Launched)
	}
	s.tx(func(c *store.TenantTx) error {
		got, err := c.ReviewTemplate("t1")
		if err == nil && !got.NextRunAt.After(s.now) {
			t.Errorf("next run %v is not in the future", got.NextRunAt)
		}
		return err
	})
}

func TestSchedule_ReminderAndRevokeAtDue(t *testing.T) {
	s := newSched(t)
	s.template(nil)
	s.tick(s.now)
	l := s.launches()[0]
	var open int
	s.tx(func(c *store.TenantTx) (err error) { open, err = c.CountOpenItems(l.CampaignID); return })
	if open == 0 {
		t.Fatal("the campaign has no items to review")
	}
	if r := s.tick(l.DueAt.Add(-48 * time.Hour)); r.Reminded != 1 {
		t.Errorf("reminder: %+v", r)
	}
	if r := s.tick(l.DueAt.Add(-47 * time.Hour)); r.Reminded != 0 {
		t.Errorf("second reminder: %+v", r)
	}
	r := s.tick(l.DueAt.Add(time.Minute))
	if r.Closed != 1 || r.Revoked != open {
		t.Fatalf("close-out = %+v, want %d revoked", r, open)
	}
	s.tx(func(c *store.TenantTx) error {
		cmp, err := c.Campaign(l.CampaignID)
		if err == nil && cmp.Status != "completed" {
			t.Errorf("campaign status %s", cmp.Status)
		}
		items, err := c.CampaignItems(l.CampaignID)
		for _, it := range items {
			if it.Decision == nil || *it.Decision != "revoke" || it.Comment == nil {
				t.Errorf("item %d = %v %v", it.ID, it.Decision, it.Comment)
			}
			if _, err := c.EdgeBetween(it.EdgeSrc, it.EdgeDst); err == nil {
				t.Errorf("revoked grant %s → %s still there", it.EdgeSrc, it.EdgeDst)
			}
		}
		return err
	})
}

func TestSchedule_EscalateThenRevoke(t *testing.T) {
	s := newSched(t)
	carol := s.f.B.IDs["carol"]
	s.template(func(tm *store.ReviewTemplate) { tm.CloseOut, tm.EscalationIdentityID = "escalate", &carol })
	s.tick(s.now)
	l := s.launches()[0]
	if r := s.tick(l.DueAt.Add(time.Minute)); r.Escalated != 1 || r.Revoked != 0 {
		t.Fatalf("at due: %+v", r)
	}
	l2 := s.launches()[0]
	if !l2.DueAt.Equal(l.DueAt.Add(time.Minute).Add(7 * 24 * time.Hour)) {
		t.Errorf("escalated due = %v", l2.DueAt)
	}
	s.tx(func(c *store.TenantTx) error {
		items, err := c.CampaignItems(l.CampaignID)
		for _, it := range items {
			if it.ReviewerID == nil || *it.ReviewerID != carol {
				t.Errorf("item %d reviewer %v, want carol", it.ID, it.ReviewerID)
			}
		}
		return err
	})
	if r := s.tick(l2.DueAt.Add(time.Minute)); r.Closed != 1 || r.Revoked == 0 {
		t.Errorf("after escalation: %+v", r)
	}
}

func TestSchedule_ScopeAndValidation(t *testing.T) {
	s := newSched(t)
	s.template(func(tm *store.ReviewTemplate) { tm.PrivilegedOnly = true; tm.Recurrence = "once" })
	s.tick(s.now)
	l := s.launches()[0]
	s.tx(func(c *store.TenantTx) error {
		items, err := c.CampaignItems(l.CampaignID)
		if err == nil && len(items) == 0 {
			t.Error("the privileged-only campaign is empty")
		}
		for _, it := range items {
			if string(it.Context) == "" || !strings.Contains(string(it.Context), `"privileged":true`) {
				t.Errorf("privileged-only campaign has %s: %s", it.GrantLabel, it.Context)
			}
		}
		got, _ := c.ReviewTemplate("t1")
		if got.NextRunAt != nil {
			t.Errorf("a one-off has a next run %v", got.NextRunAt)
		}
		return err
	})
	s.tx(func(c *store.TenantTx) error {
		for _, tc := range []struct {
			mod  func(*store.ReviewTemplate)
			want string
		}{
			{func(t *store.ReviewTemplate) { t.Recurrence = "weekly" }, "invalid_recurrence"},
			{func(t *store.ReviewTemplate) { t.ReminderDays = 14 }, "invalid_reminder"},
			{func(t *store.ReviewTemplate) { t.CloseOut = "escalate" }, "escalation_reviewer_required"},
			{func(t *store.ReviewTemplate) { t.NextRunAt = nil }, "first_run_required"},
		} {
			next := s.now
			tm := &store.ReviewTemplate{Name: "x", UnusedDays: 60, DurationDays: 14, ReminderDays: 3, CloseOut: "revoke",
				EscalationDays: 7, Recurrence: "quarterly", NextRunAt: &next, Enabled: true}
			tc.mod(tm)
			err := reviews.ValidateTemplate(c, tm)
			if se, ok := err.(*reviews.SpecError); !ok || se.Code != tc.want {
				t.Errorf("%v, want %s", err, tc.want)
			}
		}
		return nil
	})
}
