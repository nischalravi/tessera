package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Create, run and delete a custom job schedule; pause and resume work on it like on a built-in one.
func TestQueueSchedulesCustom(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	admin := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	stale := signIn(t, f.DB, f.A.ID, authtest.User{Email: "stale@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	auditor := signIn(t, f.DB, f.A.ID, authtest.User{Email: "au@a.example", Roles: []auth.Role{auth.RoleAuditor}}, authtest.Phr, storetest.Now)
	adminB := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)

	body := `{"name":"custom.nightly-sync","kind":"connector_sync","spec":"0 2 * * *","payload":{"mode":"full"}}`
	if rec := corrDo(h, auditor, "GET", "/api/queue/schedule-kinds", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "connector_sync") || !strings.Contains(rec.Body.String(), "review_tick") {
		t.Errorf("kinds: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, auditor, "POST", "/api/queue/schedules", body); rec.Code != 403 {
		t.Errorf("auditor creates: %d", rec.Code)
	}
	if rec := corrDo(h, stale, "POST", "/api/queue/schedules", body); rec.Code != 401 {
		t.Errorf("stale creates: %d", rec.Code)
	}
	for name, bad := range map[string]string{
		"built-in name":  `{"name":"job_maintenance","kind":"connector_sync","spec":"@every 1h"}`,
		"unknown kind":   `{"name":"custom.x","kind":"jit_sweep","spec":"@every 1h"}`,
		"bad spec":       `{"name":"custom.x","kind":"connector_sync","spec":"whenever"}`,
		"too frequent":   `{"name":"custom.x","kind":"connector_sync","spec":"@every 10s"}`,
		"bad payload":    `{"name":"custom.x","kind":"connector_sync","spec":"@every 1h","payload":{"mode":"sideways"}}`,
		"extra payload":  `{"name":"custom.x","kind":"connector_sync","spec":"@every 1h","payload":{"requested_by":"x"}}`,
		"review payload": `{"name":"custom.x","kind":"review_tick","spec":"@every 1h","payload":{"a":1}}`,
		"attempts":       `{"name":"custom.x","kind":"review_tick","spec":"@every 1h","max_attempts":99}`,
	} {
		if rec := corrDo(h, admin, "POST", "/api/queue/schedules", bad); rec.Code != 422 && rec.Code != 400 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	rec := corrDo(h, admin, "POST", "/api/queue/schedules", body)
	var v queueScheduleView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != 201 || !v.Enabled || v.Kind != "connector_sync" || v.Protected {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, admin, "POST", "/api/queue/schedules", body); rec.Code != 409 {
		t.Errorf("duplicate: %d", rec.Code)
	}
	if rec := corrDo(h, adminB, "GET", "/api/queue/schedules", ""); strings.Contains(rec.Body.String(), "custom.nightly-sync") {
		t.Error("tenant B sees tenant A's schedule")
	}
	run := "/api/queue/schedules/custom.nightly-sync/run"
	if rec := corrDo(h, auditor, "POST", run, ""); rec.Code != 403 {
		t.Errorf("auditor runs: %d", rec.Code)
	}
	if rec := corrDo(h, adminB, "POST", run, ""); rec.Code != 404 {
		t.Errorf("tenant B runs A's schedule: %d", rec.Code)
	}
	if rec := corrDo(h, admin, "POST", run, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"queued":true`) {
		t.Errorf("run now: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, admin, "POST", run, ""); rec.Code != 409 {
		t.Errorf("run twice in a minute: %d", rec.Code)
	}
	var queued int
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		js, err := c.QueueJobs(store.QueueJobFilter{Kind: "connector_sync"})
		for _, j := range js {
			if strings.Contains(j.Payload, `"full"`) {
				queued++
			}
		}
		return err
	}); err != nil || queued != 1 {
		t.Errorf("queued jobs with the schedule's payload = %d (%v)", queued, err)
	}
	if rec := corrDo(h, admin, "POST", "/api/queue/schedules/custom.nightly-sync/pause", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Errorf("pause: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, admin, "POST", "/api/queue/schedules/custom.nightly-sync/resume", ""); rec.Code != 200 {
		t.Errorf("resume: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, admin, "DELETE", "/api/queue/schedules/job_maintenance", ""); rec.Code != 422 && rec.Code != 400 {
		t.Errorf("delete a built-in: %d", rec.Code)
	}
	if rec := corrDo(h, adminB, "DELETE", "/api/queue/schedules/custom.nightly-sync", ""); rec.Code != 404 {
		t.Errorf("tenant B deletes A's schedule: %d", rec.Code)
	}
	if rec := corrDo(h, admin, "DELETE", "/api/queue/schedules/custom.nightly-sync", ""); rec.Code != 200 {
		t.Errorf("delete: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, admin, "DELETE", "/api/queue/schedules/custom.nightly-sync", ""); rec.Code != 404 {
		t.Errorf("delete again: %d", rec.Code)
	}
	got := auditActions(t, f, f.A.ID)
	for _, a := range []string{"queue.schedule_created", "queue.schedule_run_now", "queue.schedule_deleted", "queue.schedule_paused", "queue.schedule_resumed"} {
		if got[a] != 1 {
			t.Errorf("audit %s = %d (%v)", a, got[a], got)
		}
	}
}
