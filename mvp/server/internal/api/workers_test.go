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

// TestQueueWorkersAPI (issue #302): Admin -> Jobs lists the workers of the
// tenant with their last heartbeat; one that has not beaten for a while is
// stale; another tenant's workers are not visible; reading needs jobs.read.
func TestQueueWorkersAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler() // the server's clock is storetest.Now
	beatWorker(t, f, f.A.ID, "node-1-100-aaaa", storetest.Now.Add(-5*time.Second))
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
	fresh, old := byID["node-1-100-aaaa"], byID["node-2-200-bbbb"]
	if fresh.Status != "healthy" || fresh.LagSeconds != 5 || fresh.Concurrency != 4 || fresh.Running != 1 || fresh.Mode != "worker" ||
		!slices.Equal(fresh.Kinds, []string{"connector_sync", "provision_push"}) || fresh.Hostname != "node-1" {
		t.Errorf("fresh worker = %+v", fresh)
	}
	if old.Status != "stale" || old.LagSeconds != 600 {
		t.Errorf("silent worker = %+v", old)
	}
	if strings.Contains(rec.Body.String(), "node-3-300-cccc") {
		t.Error("another tenant's worker is listed")
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
