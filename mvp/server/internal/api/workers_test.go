package api

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// drain runs the server's queue until its work is done (a few ticks: the
// sweepers share the four slots).
func drain(t *testing.T, srv *Server) {
	t.Helper()
	for range 25 {
		if err := srv.Queue().Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		srv.Queue().Wait()
	}
}

func beatWorker(t *testing.T, f *storetest.Fixture, tenant tenancy.ID, id string, last time.Time) {
	t.Helper()
	w := &store.QueueWorker{WorkerID: id, Mode: store.WorkerModeWorker, Hostname: "node-1", PID: 42, Version: "0.1.0",
		Kinds: "connector_sync,provision_push", Concurrency: 4, Running: 1, StartedAt: last.Add(-time.Hour)}
	if err := f.DB.InTenant(context.Background(), tenant, func(c *store.TenantTx) error { return c.BeatQueueWorker(w, last) }); err != nil {
		t.Fatal(err)
	}
}

// TestQueueWorkersAPI (issue #302, #403): Admin -> Jobs lists the workers that serve the
// kinds the tenant uses, with an opaque label and their last heartbeat; one that has not
// beaten for a while is stale; no host name, PID, build or raw worker id reaches the
// tenant; a worker serving none of its kinds and another tenant's workers are not visible;
// reading needs jobs.read.
func TestQueueWorkersAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler() // the server's clock is storetest.Now
	admin := signIn(t, f.DB, f.A.ID, testAdmin, authtest.Phr, storetest.Now)
	// tenant A uses connector_sync only (one queued job)
	if rec := corrDo(h, admin, "POST", "/api/connectors/sync?async=true", ""); rec.Code != http.StatusOK {
		t.Fatalf("queue a sync: %d %s", rec.Code, rec.Body)
	}
	beatWorker(t, f, f.A.ID, "node-1-100-aaaa", storetest.Now.Add(-5*time.Second))
	other := &store.QueueWorker{WorkerID: "node-9-900-zzzz", Mode: store.WorkerModeWorker, Kinds: "scim_export", Concurrency: 1, StartedAt: storetest.Now}
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error { return c.BeatQueueWorker(other, storetest.Now) }); err != nil {
		t.Fatal(err)
	}
	beatWorker(t, f, f.A.ID, "node-2-200-bbbb", storetest.Now.Add(-10*time.Minute))
	beatWorker(t, f, f.B.ID, "node-3-300-cccc", storetest.Now)
	auditor := signIn(t, f.DB, f.A.ID, authtest.User{Email: "au@a.example", Roles: []auth.Role{auth.RoleAuditor}}, authtest.Phr, storetest.Now)
	viewer := signIn(t, f.DB, f.A.ID, authtest.User{Email: "v@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)

	rec := corrDo(h, auditor, "GET", "/api/queue/workers", "")
	var ws []queueWorkerView
	if err := json.Unmarshal(rec.Body.Bytes(), &ws); err != nil || rec.Code != http.StatusOK || len(ws) != 2 {
		t.Fatalf("workers: %d %s", rec.Code, rec.Body)
	}
	byID := map[string]queueWorkerView{}
	for _, w := range ws {
		byID[w.WorkerID] = w
	}
	fresh, old := byID[workerLabel(f.A.ID, "node-1-100-aaaa")], byID[workerLabel(f.A.ID, "node-2-200-bbbb")]
	if fresh.Status != "healthy" || fresh.LagSeconds != 5 || fresh.Concurrency != 4 || fresh.Running != 1 || fresh.Mode != "worker" ||
		!slices.Equal(fresh.Kinds, []string{"connector_sync"}) {
		t.Errorf("fresh worker = %+v", fresh)
	}
	for _, leak := range []string{"node-1", "node-2", "node-9", "-100-", "hostname", `"pid"`, "version", "provision_push", "scim_export"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("the tenant view of the workers has %q: %s", leak, rec.Body)
		}
	}
	if workerLabel(f.A.ID, "node-1-100-aaaa") == workerLabel(f.B.ID, "node-1-100-aaaa") {
		t.Error("the same worker has the same label for two tenants")
	}
	if len(ws) != 2 {
		t.Errorf("workers = %d, want the two that serve connector_sync", len(ws))
	}
	if old.Status != "stale" || old.LagSeconds != 600 {
		t.Errorf("silent worker = %+v", old)
	}
	if strings.Contains(rec.Body.String(), "node-3-300-cccc") || strings.Contains(rec.Body.String(), workerLabel(f.B.ID, "node-3-300-cccc")) {
		t.Error("another tenant's worker is listed")
	}
	// the job's lease owner is the worker's label, never host-pid-random
	rec = corrDo(h, auditor, "GET", "/api/queue/jobs", "")
	if strings.Contains(rec.Body.String(), "node-") {
		t.Errorf("a job lists a raw lease owner: %s", rec.Body)
	}
	if rec := corrDo(h, viewer, "GET", "/api/queue/workers", ""); rec.Code != http.StatusForbidden {
		t.Errorf("viewer: %d", rec.Code)
	}
}

// TestAsyncSyncRunsOnAWorker (issue #302): ?async=true queues the sync instead
// of running it in the request; the queue runs it with the same code, in the
// requesting tenant only, and the default stays synchronous.
func TestAsyncSyncRunsOnAWorker(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	admin := signIn(t, f.DB, f.A.ID, testAdmin, authtest.Phr, storetest.Now)

	if rec := corrDo(h, admin, "POST", "/api/connectors/sync?async=maybe", ""); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("async=maybe: %d %s", rec.Code, rec.Body)
	}
	rec := corrDo(h, admin, "POST", "/api/connectors/sync?async=true&mode=full", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"queued":true`) {
		t.Fatalf("async sync: %d %s", rec.Code, rec.Body)
	}
	if got := auditActions(t, f, f.A.ID); got["connectors.sync_queued"] != 1 || got["connectors.sync"] != 0 {
		t.Errorf("audit after queueing: %v", got)
	}
	var queued []*store.QueueJob
	_ = f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) (err error) {
		queued, err = c.QueueJobs(store.QueueJobFilter{Kind: jobs.ConnectorSync})
		return err
	})
	if len(queued) != 1 || queued[0].Payload != `{"mode":"full"}` {
		t.Fatalf("queued jobs: %+v", queued)
	}

	// the queue (here the in-process one, in production a `tessera worker`) runs it
	drain(t, srv)
	if auditActions(t, f, f.B.ID)["connectors.sync"] != 0 {
		t.Errorf("another tenant was synced: %v", auditActions(t, f, f.B.ID))
	}
	if got := auditActions(t, f, f.A.ID); got["connectors.sync"] != 1 {
		t.Errorf("audit after the worker ran: %v", got)
	}

	// the default is unchanged: no async, no job, the stats come back
	rec = corrDo(h, admin, "POST", "/api/connectors/sync", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"accounts"`) || strings.Contains(rec.Body.String(), "queued") {
		t.Errorf("synchronous sync: %d %s", rec.Code, rec.Body)
	}
}

// TestExternalKindsAreLeftToWorkers (issue #302): a server told that
// connector_sync belongs to workers neither registers nor runs it, and the
// job waits in the shared queue for a worker; the default registers it here.
func TestExternalKindsAreLeftToWorkers(t *testing.T) {
	f := storetest.TwoTenants(t)
	def := newIsolationServer(f)
	if !slices.Contains(def.Queue().Kinds(), jobs.ConnectorSync) || def.ExternalKind(jobs.ConnectorSync) {
		t.Fatalf("by default a server runs connector_sync itself: %v", def.Queue().Kinds())
	}
	srv := newIsolationServerWith(f, func(c *Config) { c.ExternalKinds = []string{jobs.ConnectorSync, jobs.ProvisionPush} })
	if slices.Contains(srv.Queue().Kinds(), jobs.ConnectorSync) || !srv.ExternalKind(jobs.ConnectorSync) || !srv.ExternalKind(jobs.ProvisionPush) {
		t.Fatalf("an external kind is still registered: %v", srv.Queue().Kinds())
	}
	admin := signIn(t, f.DB, f.A.ID, testAdmin, authtest.Phr, storetest.Now)
	if rec := corrDo(srv.Handler(), admin, "POST", "/api/connectors/sync?async=true", ""); rec.Code != http.StatusOK {
		t.Fatalf("async sync: %d %s", rec.Code, rec.Body)
	}
	drain(t, srv)
	var js []*store.QueueJob
	_ = f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) (err error) {
		js, err = c.QueueJobs(store.QueueJobFilter{Kind: jobs.ConnectorSync})
		return err
	})
	if len(js) != 1 || js[0].Status != store.QueueQueued || js[0].Attempts != 0 {
		t.Fatalf("the job was not left for a worker: %+v", js)
	}
	// a worker (a server that does not hold the kind back) takes it
	drain(t, def)
	_ = f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) (err error) {
		js, err = c.QueueJobs(store.QueueJobFilter{Kind: jobs.ConnectorSync})
		return err
	})
	if len(js) != 1 || js[0].Status != store.QueueSucceeded {
		t.Fatalf("the worker did not run it: %+v", *js[0])
	}
}

// TestQueueWorkersShowBreakerState (issue #302): a worker's view of the
// connections it called (breaker state, calls in flight, the last error) is
// listed with the worker, under the connection's name, to the tenant that owns
// the connection only.
func TestQueueWorkersShowBreakerState(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := signIn(t, f.DB, f.A.ID, testAdmin, authtest.Phr, storetest.Now)
	if rec := corrDo(h, admin, "POST", "/api/connectors/sync?async=true", ""); rec.Code != http.StatusOK {
		t.Fatalf("queue a sync: %d %s", rec.Code, rec.Body)
	}
	beatWorker(t, f, f.A.ID, "node-1-100-aaaa", storetest.Now)
	beatWorker(t, f, f.B.ID, "node-1-100-aaaa", storetest.Now)
	conn := f.A.Refs["connection:ad"]
	until := storetest.Now.Add(time.Minute)
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.ReplaceWorkerTargetStates("node-1-100-aaaa", []store.WorkerTargetState{{ConnectionID: conn, State: store.BreakerOpen,
			ConsecutiveFailures: 5, OpenUntil: &until, LastError: "503 from the target", InFlight: 1, Calls: 9, Failures: 5, Rejected: 3}},
			storetest.Now)
	}); err != nil {
		t.Fatal(err)
	}
	rec := corrDo(h, admin, "GET", "/api/queue/workers", "")
	var ws []queueWorkerView
	if err := json.Unmarshal(rec.Body.Bytes(), &ws); err != nil || rec.Code != http.StatusOK || len(ws) != 1 || len(ws[0].Targets) != 1 {
		t.Fatalf("workers: %d %s", rec.Code, rec.Body)
	}
	tg := ws[0].Targets[0]
	if tg.ConnectionID != conn || tg.Connection == "" || tg.Breaker != "open" || tg.ConsecutiveFailures != 5 ||
		tg.OpenUntil == nil || *tg.OpenUntil != until.UTC().Format(time.RFC3339) || tg.LastError != "503 from the target" ||
		tg.InFlight != 1 || tg.Calls != 9 || tg.Failures != 5 || tg.Rejected != 3 {
		t.Errorf("target = %+v", tg)
	}
	// a worker with no targets lists an empty array, and B (same worker id) sees none of A's
	adminB := signIn(t, f.DB, f.B.ID, authtest.User{Email: "admin@b.example", Roles: []auth.Role{auth.RoleTenantAdmin, auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)
	if rec := corrDo(h, adminB, "POST", "/api/connectors/sync?async=true", ""); rec.Code != http.StatusOK {
		t.Fatalf("queue B's sync: %d %s", rec.Code, rec.Body)
	}
	rec = corrDo(h, adminB, "GET", "/api/queue/workers", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"targets":[]`) || strings.Contains(rec.Body.String(), conn) {
		t.Errorf("B's workers: %d %s", rec.Code, rec.Body)
	}
}

// TestConnectionLimitsAPI (issue #302): per-connection worker limits are read
// with connections.read, set and cleared with connections.manage and step-up,
// validated at the boundary, scoped to the tenant's live connections, and
// audited.
func TestConnectionLimitsAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := signIn(t, f.DB, f.A.ID, testAdmin, authtest.Phr, storetest.Now)
	viewer := signIn(t, f.DB, f.A.ID, authtest.User{Email: "v@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	conn, bConn := f.A.Refs["connection:ad"], f.B.Refs["connection:ad"]
	path := "/api/queue/limits?connection_id=" + conn

	rec := corrDo(h, admin, "GET", path, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"set":false`) {
		t.Fatalf("defaults: %d %s", rec.Code, rec.Body)
	}
	body := `{"connection_id":"` + conn + `","max_concurrency":2,"rate_per_min":120,"burst":5,"breaker_threshold":3,"breaker_cooldown_seconds":45}`
	rec = corrDo(h, admin, "PUT", "/api/queue/limits", body)
	var v connectionLimitsView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != http.StatusOK || !v.Set || v.MaxConcurrency != 2 ||
		v.RatePerMin != 120 || v.Burst != 5 || v.BreakerThreshold != 3 || v.BreakerCooldownSecs != 45 || v.UpdatedBy == nil {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, admin, "GET", path, ""); !strings.Contains(rec.Body.String(), `"rate_per_min":120`) {
		t.Errorf("get after put: %s", rec.Body)
	}
	// validation at the boundary: nothing is written
	for name, bad := range map[string]string{
		"concurrency": `{"max_concurrency":65}`, "negative": `{"rate_per_min":-1}`, "rate": `{"rate_per_min":60001}`,
		"burst": `{"burst":1001}`, "threshold": `{"breaker_threshold":101}`, "cooldown too short": `{"breaker_cooldown_seconds":1}`,
		"cooldown too long": `{"breaker_cooldown_seconds":3601}`, "unknown field": `{"max_concurrency":1,"surprise":true}`, "empty": ``,
	} {
		if rec := corrDo(h, admin, "PUT", "/api/queue/limits", strings.Replace(bad, "{", `{"connection_id":"`+conn+`",`, 1)); rec.Code < 400 || rec.Code >= 500 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := corrDo(h, admin, "GET", path, ""); !strings.Contains(rec.Body.String(), `"max_concurrency":2`) {
		t.Errorf("a refused write changed the limits: %s", rec.Body)
	}
	// permissions and tenancy
	if rec := corrDo(h, viewer, "PUT", "/api/queue/limits", body); rec.Code != http.StatusForbidden {
		t.Errorf("viewer PUT: %d", rec.Code)
	}
	if rec := corrDo(h, viewer, "DELETE", path, ""); rec.Code != http.StatusForbidden {
		t.Errorf("viewer DELETE: %d", rec.Code)
	}
	for _, method := range []string{"GET", "DELETE"} {
		if rec := corrDo(h, admin, method, "/api/queue/limits?connection_id="+bConn, ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s another tenant's connection: %d", method, rec.Code)
		}
		if rec := corrDo(h, admin, method, "/api/queue/limits?connection_id=not-an-id", ""); method == "DELETE" && rec.Code != http.StatusNotFound {
			t.Errorf("DELETE a malformed id: %d", rec.Code)
		}
	}
	if rec := corrDo(h, admin, "PUT", "/api/queue/limits", strings.Replace(body, conn, bConn, 1)); rec.Code != http.StatusNotFound {
		t.Errorf("PUT another tenant's connection: %d", rec.Code)
	}
	if rec := corrDo(h, admin, "PUT", "/api/queue/limits", `{"max_concurrency":1}`); rec.Code != http.StatusNotFound {
		t.Errorf("PUT with no connection: %d", rec.Code)
	}
	// the list holds only this tenant's rows
	if rec := corrDo(h, admin, "GET", "/api/queue/limits", ""); !strings.Contains(rec.Body.String(), conn) || strings.Contains(rec.Body.String(), bConn) {
		t.Errorf("list: %s", rec.Body)
	}
	// clearing returns to the defaults, and clearing twice is harmless
	for range 2 {
		if rec := corrDo(h, admin, "DELETE", path, ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"set":false`) {
			t.Errorf("delete: %d %s", rec.Code, rec.Body)
		}
	}
	if got := auditActions(t, f, f.A.ID); got["connection.limits_set"] != 1 || got["connection.limits_cleared"] != 1 {
		t.Errorf("audit = %v", got)
	}
	if got := auditActions(t, f, f.B.ID); got["connection.limits_set"] != 0 {
		t.Errorf("B's audit = %v", got)
	}
}
