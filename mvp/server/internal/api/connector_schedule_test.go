package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

// A tenant schedules its delta and full syncs; the schedule is validated, audited, per tenant and role-gated, and it
// really fires the connector_sync job in the mode it names.
func TestConnectorSyncSchedule(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	now := storetest.Now
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	adminA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now)

	status := func(l authtest.Login) map[string]any {
		t.Helper()
		rec := reqDo(h, l, "GET", "/api/connectors/sync-status", "")
		if rec.Code != 200 {
			t.Fatalf("sync-status: %d %s", rec.Code, rec.Body)
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	sch := func(m map[string]any) map[string]any { return m["schedule"].(map[string]any) }
	if got := sch(status(admin)); got["delta_every_minutes"] != float64(0) || got["full_every_hours"] != float64(0) || got["next_delta_at"] != nil {
		t.Errorf("a new tenant has a schedule: %v", got)
	}
	if rows := status(admin)["connectors"].([]any); len(rows) == 0 {
		t.Error("no connectors in the status")
	} else if r := rows[0].(map[string]any); r["accounts"] == nil || r["groups"] == nil || r["resources"] == nil || r["permissions"] == nil {
		t.Errorf("a connector row has no counts: %v", r)
	}

	put := func(l authtest.Login, body string) (int, string) {
		rec := reqDo(h, l, "PUT", "/api/connectors/sync-schedule", body)
		return rec.Code, rec.Body.String()
	}
	if code, _ := put(viewer, `{"delta_every_minutes":15}`); code != 403 {
		t.Errorf("a viewer sets the schedule: %d", code)
	}
	for name, body := range map[string]string{"too often": `{"delta_every_minutes":2}`, "too rarely": `{"delta_every_minutes":2000}`,
		"negative": `{"full_every_hours":-1}`, "full too rarely": `{"full_every_hours":9999}`, "unknown field": `{"delta_every_minutes":15,"x":1}`,
		"a string": `{"delta_every_minutes":"15"}`} {
		if code, out := put(admin, body); code != 422 && code != 400 {
			t.Errorf("%s: %d %s", name, code, out)
		}
	}
	if code, out := put(admin, `{"delta_every_minutes":15,"full_every_hours":24}`); code != 200 || !strings.Contains(out, `"delta_every_minutes":15`) || !strings.Contains(out, `"full_every_hours":24`) {
		t.Fatalf("set: %d %s", code, out)
	}
	if got := sch(status(admin)); got["delta_every_minutes"] != float64(15) || got["full_every_hours"] != float64(24) || got["next_delta_at"] == nil {
		t.Errorf("schedule after set: %v", got)
	}
	if got := sch(status(adminA)); got["delta_every_minutes"] != float64(0) {
		t.Errorf("tenant A sees B's schedule: %v", got)
	}
	// turning one off keeps the other
	if code, out := put(admin, `{"delta_every_minutes":0,"full_every_hours":24}`); code != 200 || !strings.Contains(out, `"delta_every_minutes":0`) || !strings.Contains(out, `"full_every_hours":24`) {
		t.Errorf("turn delta off: %d %s", code, out)
	}
	acts := 0
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{Action: "connectors.schedule_updated"})
		acts = len(evs)
		return err
	})
	if acts != 2 {
		t.Errorf("connectors.schedule_updated audited %d times, want 2", acts)
	}
	// the queue fires them: due schedules enqueue connector_sync jobs in the mode of each
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		return worker.SetSyncSchedule(tx, now.Add(-48*time.Hour), 15, 24)
	}); err != nil {
		t.Fatal(err)
	}
	// SetSyncSchedule keeps an unchanged full schedule in its cycle; make both due by a change of interval
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		return worker.SetSyncSchedule(tx, now.Add(-48*time.Hour), 20, 12)
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Queue().FireSchedules(context.Background(), f.B.ID); err != nil {
		t.Fatal(err)
	}
	modes := map[string]bool{}
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		js, err := tx.QueueJobs(store.QueueJobFilter{})
		for _, j := range js {
			if j.Kind == jobs.ConnectorSync {
				modes[j.Payload] = true
			}
		}
		return err
	})
	if !modes[`{"mode":"incremental"}`] || !modes[`{"mode":"full"}`] {
		t.Errorf("queued connector_sync payloads = %v", modes)
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error {
		js, err := tx.QueueJobs(store.QueueJobFilter{})
		for _, j := range js {
			if strings.Contains(j.Payload, "mode") {
				t.Errorf("tenant A got a scheduled sync of B: %v", j)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
