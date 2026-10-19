package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// deadJob leaves a dead job in the tenant's queue.
func deadJob(t *testing.T, f *storetest.Fixture, tenant tenancy.ID, kind string) string {
	t.Helper()
	var id string
	err := f.DB.InTenant(context.Background(), tenant, func(c *store.TenantTx) error {
		j := &store.QueueJob{Kind: kind, RunAt: storetest.Now, MaxAttempts: 1}
		if _, err := c.EnqueueQueueJob(j, storetest.Now); err != nil {
			return err
		}
		id = j.ID
		got, _, err := c.ClaimQueueJobs(storetest.Now, "w", time.Minute, []string{kind}, 10)
		if err != nil || len(got) != 1 {
			t.Fatalf("claim: %v %v", got, err)
		}
		return c.FailQueueJob(id, "w", storetest.Now, "it kept failing", nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestQueueAPI: the queue's recurring jobs run for every tenant, the admin
// routes list them per tenant, and retrying a dead job needs jobs.manage and a
// fresh authentication, is audited, and cannot reach another tenant's job.
func TestQueueAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	for range 4 { // six jobs per tenant, four run at a time
		if err := srv.Queue().Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		srv.Queue().Wait()
	}

	admin := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	stale := signIn(t, f.DB, f.A.ID, authtest.User{Email: "stale@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	auditor := signIn(t, f.DB, f.A.ID, authtest.User{Email: "au@a.example", Roles: []auth.Role{auth.RoleAuditor}}, authtest.Phr, storetest.Now)
	viewer := signIn(t, f.DB, f.A.ID, authtest.User{Email: "v@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	adminB := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)

	// The schedules exist for both tenants and fired once: every sweep ran.
	var scheds []queueScheduleView
	rec := corrDo(h, auditor, "GET", "/api/queue/schedules", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &scheds); err != nil || rec.Code != 200 || len(scheds) != 7 {
		t.Fatalf("schedules: %d %s", rec.Code, rec.Body)
	}
	for _, s := range scheds {
		if !s.Enabled || s.LastEnqueuedAt == nil || !strings.HasPrefix(s.Spec, "@every ") {
			t.Errorf("schedule %+v", s)
		}
	}
	var list []queueJobView
	rec = corrDo(h, auditor, "GET", "/api/queue/jobs?limit=100", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != 200 || len(list) != 7 {
		t.Fatalf("jobs: %d %s", rec.Code, rec.Body)
	}
	seen := map[string]bool{}
	for _, j := range list {
		seen[j.Kind] = true
		if j.Status != store.QueueSucceeded || j.Attempts != 1 {
			t.Errorf("job %s is %s after %d attempts: %s", j.Kind, j.Status, j.Attempts, j.LastError)
		}
	}
	for _, k := range []string{jobs.JITSweep, jobs.SweepRequests, jobs.SweepLifecycle, jobs.SweepAdminChanges, jobs.ContainmentRetry, jobs.SweepSoDMitigations, jobs.Maintenance} {
		if !seen[k] {
			t.Errorf("no %s job ran", k)
		}
	}

	// listing: filters, validation, RBAC
	dead := deadJob(t, f, f.A.ID, "boom")
	deadB := deadJob(t, f, f.B.ID, "boom")
	rec = corrDo(h, auditor, "GET", "/api/queue/jobs?status=dead&kind=boom", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), dead) || strings.Contains(rec.Body.String(), deadB) {
		t.Errorf("A's dead list: %d %s", rec.Code, rec.Body)
	}
	for _, q := range []string{"status=nope", "kind=Bad_Kind", "limit=0", "limit=x"} {
		if rec = corrDo(h, auditor, "GET", "/api/queue/jobs?"+q, ""); rec.Code != 422 {
			t.Errorf("?%s: %d", q, rec.Code)
		}
	}
	for _, p := range []string{"/api/queue/jobs", "/api/queue/schedules"} {
		if rec = corrDo(h, viewer, "GET", p, ""); rec.Code != 403 {
			t.Errorf("viewer GET %s: %d", p, rec.Code)
		}
	}

	// retry: permission, step-up, state, tenant
	path := "/api/queue/jobs/" + dead + "/retry"
	if rec = corrDo(h, auditor, "POST", path, ""); rec.Code != 403 {
		t.Errorf("auditor retry: %d %s", rec.Code, rec.Body)
	}
	if rec = corrDo(h, stale, "POST", path, ""); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale retry: %d %s", rec.Code, rec.Body)
	}
	cross := corrDo(h, adminB, "POST", path, "")
	missing := corrDo(h, adminB, "POST", "/api/queue/jobs/00000000-0000-4000-8000-00000000dead/retry", "")
	if cross.Code != http.StatusNotFound || cross.Code != missing.Code || cross.Body.String() != missing.Body.String() {
		t.Errorf("cross-tenant retry %d %s vs missing %d %s", cross.Code, cross.Body, missing.Code, missing.Body)
	}
	if rec = corrDo(h, admin, "POST", "/api/queue/jobs/not-a-uuid/retry", ""); rec.Code != 404 {
		t.Errorf("bad id: %d", rec.Code)
	}
	if got := auditActions(t, f, f.A.ID); got["queue.job_retried"] != 0 {
		t.Errorf("a refused retry was audited: %v", got)
	}
	rec = corrDo(h, admin, "POST", path, "")
	var out queueJobView
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 || out.Status != store.QueueQueued || out.Attempts != 0 {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body)
	}
	if got := auditActions(t, f, f.A.ID); got["queue.job_retried"] != 1 {
		t.Errorf("audit %v", got)
	}
	if rec = corrDo(h, admin, "POST", path, ""); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "not_dead") {
		t.Errorf("retrying a queued job: %d %s", rec.Code, rec.Body)
	}
	// B's dead job was never touched
	rec = corrDo(h, adminB, "GET", "/api/queue/jobs?status=dead", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), deadB) || strings.Contains(rec.Body.String(), dead) {
		t.Errorf("B's dead list: %d %s", rec.Code, rec.Body)
	}
}

// TestQueueRecordsJobRuns: a sweep that finds nothing leaves no job run; one
// that expires something is recorded in the run history (issue #185's view),
// with the route that lets the history retry it.
func TestQueueRecordsJobRuns(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	for range 4 {
		if err := srv.Queue().Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		srv.Queue().Wait()
	}
	runs := func(tenant tenancy.ID) (out []*store.JobRun) {
		if err := f.DB.ReadTenant(context.Background(), tenant, func(c *store.TenantTx) (err error) {
			out, err = c.JobRuns(store.JobRunFilter{})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, r := range runs(f.A.ID) {
		if r.Kind != jobs.JITSweep || r.Trigger != "schedule" || r.Actor != "jit.sweeper" || r.Method == nil || *r.Method != "POST" {
			t.Errorf("unexpected job run %s %s by %s", r.Kind, r.Trigger, r.Actor)
		}
	}
	// a failing job is recorded as failed and audited as job.failed
	srv.Queue().Register("always_fails", failing)
	if _, err := srv.Queue().Enqueue(context.Background(), f.A.ID, "always_fails", "", "", time.Time{}, 1); err != nil {
		t.Fatal(err)
	}
	if err := srv.Queue().Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv.Queue().Wait()
	var failed *store.JobRun
	for _, r := range runs(f.A.ID) {
		if r.Kind == "always_fails" {
			failed = r
		}
	}
	if failed == nil || failed.Status != "failed" || failed.Error == nil || !strings.Contains(*failed.Error, "nope") {
		t.Fatalf("failed run = %+v", failed)
	}
	if got := auditActions(t, f, f.A.ID); got["job.failed"] != 1 || got["queue.job_dead"] != 1 {
		t.Errorf("audit %v", got)
	}
}

var failing = queue.Kind{Actor: "test.actor", Handler: func(context.Context, queue.Job) (any, error) { return nil, errors.New("nope") }}
