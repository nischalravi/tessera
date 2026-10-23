package api

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Security schedules (issue #512): pausing one needs a reason, ends by itself within 24 hours, is audited and
// raises an alert; turning every connector sync off needs step-up and raises the same alert.
func TestProtectedSchedulePauseResumesByItself(t *testing.T) {
	f := storetest.TwoTenants(t)
	var offset atomic.Int64 // seconds added to the frozen clock
	srv := newIsolationServerWith(f, func(c *Config) {
		c.Clock = func() time.Time { return storetest.Now.Add(time.Duration(offset.Load()) * time.Second) }
	})
	h := srv.Handler()
	tick := func() {
		t.Helper()
		if err := srv.Queue().Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		srv.Queue().Wait()
	}
	tick()
	admin := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)

	name := jobs.ContainmentRetry
	pause, resume := "/api/queue/schedules/"+name+"/pause", "/api/queue/schedules/"+name+"/resume"
	for label, body := range map[string]string{"no reason": ``, "blank reason": `{"reason":"  "}`,
		"too long a pause": `{"reason":"x","resume_after_hours":25}`, "negative": `{"reason":"x","resume_after_hours":-1}`} {
		if rec := corrDo(h, admin, "POST", pause, body); rec.Code != 422 && rec.Code != 400 {
			t.Errorf("%s: %d %s", label, rec.Code, rec.Body)
		}
	}
	if got := auditActions(t, f, f.A.ID); got["queue.schedule_paused"] != 0 {
		t.Errorf("a refused pause was audited: %v", got)
	}
	rec := corrDo(h, admin, "POST", pause, `{"reason":"upgrading the IdP","resume_after_hours":2}`)
	var out queueScheduleView
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 || out.Enabled || !out.Protected || out.PausedUntil == nil {
		t.Fatalf("pause: %d %s", rec.Code, rec.Body)
	}
	if want := storetest.Now.Add(2 * time.Hour).UTC().Format(time.RFC3339); *out.PausedUntil != want {
		t.Errorf("paused_until = %s, want %s", *out.PausedUntil, want)
	}
	// the default is the 24-hour maximum
	if rec = corrDo(h, admin, "POST", resume, ""); rec.Code != 200 {
		t.Fatalf("resume: %d", rec.Code)
	}
	rec = corrDo(h, admin, "POST", pause, `{"reason":"upgrading the IdP"}`)
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.PausedUntil == nil ||
		*out.PausedUntil != storetest.Now.Add(MaxProtectedPause).UTC().Format(time.RFC3339) {
		t.Fatalf("default pause: %d %s", rec.Code, rec.Body)
	}
	// still paused before the end, running again after it, and audited as automatic
	enabled := func() bool {
		var on bool
		_ = f.DB.ReadTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error {
			s, err := tx.QueueSchedule(name)
			on = err == nil && s.Enabled && s.PausedUntil == nil
			return err
		})
		return on
	}
	// an ordinary schedule keeps today's behaviour: no reason needed, paused until resumed, no automatic resume
	if rec = corrDo(h, admin, "POST", "/api/queue/schedules/"+jobs.Maintenance+"/pause", ""); rec.Code != 200 {
		t.Errorf("pausing an ordinary schedule: %d %s", rec.Code, rec.Body)
	}
	if rec = corrDo(h, admin, "POST", "/api/queue/schedules/"+jobs.Maintenance+"/pause", `{"resume_after_hours":3}`); rec.Code != 200 {
		t.Errorf("a repeated pause is a no-op: %d", rec.Code)
	}
	offset.Store(int64(23 * time.Hour / time.Second))
	tick()
	if enabled() {
		t.Error("the schedule resumed before its pause ended")
	}
	offset.Store(int64(25 * time.Hour / time.Second))
	tick()
	if !enabled() {
		t.Error("the schedule did not resume by itself")
	}
	got := auditActions(t, f, f.A.ID)
	if got["queue.schedule_paused"] != 3 || got["queue.schedule_resumed"] != 2 {
		t.Errorf("audit %v", got)
	}
}

func TestScheduleAlertRule(t *testing.T) {
	r := alerts.RuleByID("schedule_paused")
	if r == nil {
		t.Fatal("no schedule_paused rule")
	}
	ev := func(action, detail string) *store.AuditEvent {
		return &store.AuditEvent{Action: action, Detail: json.RawMessage(detail), ActorType: "user"}
	}
	for name, tc := range map[string]struct {
		e    *store.AuditEvent
		want bool
	}{
		"a protected pause":      {ev("queue.schedule_paused", `{"schedule":"containment_retries","protected":true,"reason":"x"}`), true},
		"an ordinary pause":      {ev("queue.schedule_paused", `{"schedule":"sweep_requests"}`), false},
		"all syncs off":          {ev("connectors.schedule_updated", `{"delta_every_minutes":0,"full_every_hours":0,"all_syncs_off":true}`), true},
		"a schedule that is set": {ev("connectors.schedule_updated", `{"delta_every_minutes":15,"full_every_hours":0,"all_syncs_off":false}`), false},
		"something else":         {ev("grant.revoke", `{}`), false},
	} {
		if _, ok := r.Match(tc.e); ok != tc.want {
			t.Errorf("%s: matched = %v", name, ok)
		}
	}
}

func TestSyncScheduleNeedsStepUp(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	now := storetest.Now
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: now.Add(-20 * time.Minute)}, now)
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	if rec := reqDo(h, stale, "PUT", "/api/connectors/sync-schedule", `{"delta_every_minutes":0,"full_every_hours":0}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("turning every sync off without step-up: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "PUT", "/api/connectors/sync-schedule", `{"delta_every_minutes":0,"full_every_hours":0}`); rec.Code != 200 {
		t.Fatalf("with step-up: %d %s", rec.Code, rec.Body)
	}
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		evs, _ := tx.AuditEvents(store.AuditFilter{})
		n := 0
		for _, e := range evs {
			if e.Action == "connectors.schedule_updated" && strings.Contains(string(e.Detail), `"all_syncs_off":true`) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("all_syncs_off audit events = %d", n)
		}
		return nil
	})
}
