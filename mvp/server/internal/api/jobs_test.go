package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// failingConnector fails discovery until ok is set.
type failingConnector struct {
	connectors.Tiny
	ok *bool
}

func (f failingConnector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	if !*f.ok {
		return nil, errors.New("okta: 503 from the source")
	}
	return f.Tiny.Discover(ctx)
}

func auditActionList(t *testing.T, db *store.DB, tn tenancy.ID) string {
	t.Helper()
	var out []string
	for _, e := range ledger(t, db, tn) {
		out = append(out, e.Action)
	}
	return strings.Join(out, " ")
}

func TestJobs_SyncRecordedFailedAndRetried(t *testing.T) {
	st, _ := testkit.Tiny(t)
	ok := false
	c := client{t, testServer(t, st, func(cfg *Config) {
		cfg.Connectors = func(now time.Time) ([]connectors.Connector, error) {
			return []connectors.Connector{failingConnector{connectors.Tiny{Now: now}, &ok}}, nil
		}
	})}
	if rec := c.do("POST", "/api/connectors/sync", "{}"); rec.Code != http.StatusInternalServerError {
		t.Fatalf("failing sync: %d %s", rec.Code, rec.Body)
	}
	failed := c.json("GET", "/api/jobs?status=failed", "", 200).([]any)
	if len(failed) != 1 || at(failed, 0, "kind") != "sync" || at(failed, 0, "retryable") != true ||
		!strings.Contains(at(failed, 0, "error").(string), "503 from the source") {
		t.Fatalf("failed runs %v", failed)
	}
	id := at(failed, 0, "id").(string)
	if !strings.Contains(auditActionList(t, st.DB, st.Tenant), "job.failed") {
		t.Error("no job.failed event")
	}

	ok = true
	retried := c.json("POST", "/api/jobs/"+id+"/retry", "", 200)
	if at(retried, "identities") == nil {
		t.Errorf("retry returned %v", retried)
	}
	all := c.json("GET", "/api/jobs", "", 200).([]any)
	if len(all) != 2 || at(all, 0, "trigger") != "retry" || at(all, 0, "retry_of") != id || at(all, 0, "status") != "succeeded" {
		t.Fatalf("runs after retry %v", all)
	}
	if at(all, 0, "result", "identities") == nil || at(all, 0, "duration_ms") == nil {
		t.Errorf("result not recorded: %v", at(all, 0))
	}
	if !strings.Contains(auditActionList(t, st.DB, st.Tenant), "job.retried") {
		t.Error("no job.retried event")
	}
	one := c.json("GET", "/api/jobs/"+id, "", 200)
	if at(one, "status") != "failed" {
		t.Errorf("GET job %v", one)
	}
	if rec := c.do("GET", "/api/jobs?status=bogus", ""); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad status filter %d", rec.Code)
	}
}

// TestJobs_RefusedRequestIsNotARun: a request refused before the job ran
// (a missing connection, a blocked gate) leaves no run behind.
func TestJobs_RefusedRequestIsNotARun(t *testing.T) {
	st, _ := testkit.Tiny(t)
	c := client{t, testServer(t, st)}
	c.do("POST", "/api/connections/"+missingUUID+"/validate", "")
	c.do("POST", "/api/connections/not-a-uuid/dry-run", "")
	if runs := c.json("GET", "/api/jobs", "", 200).([]any); len(runs) != 0 {
		t.Errorf("refused requests recorded as runs: %v", runs)
	}
}

func TestJobs_ProvisionIsNotRetryable(t *testing.T) {
	st, _ := testkit.Tiny(t)
	c := client{t, testServer(t, st)}
	c.json("POST", "/api/jit/sweep", "{}", 200)
	testkit.Write(t, st, func(tx *store.TenantTx) error {
		return tx.InsertJobRun(&store.JobRun{ID: "00000000-0000-4000-8000-0000000000f1", Kind: "provision", Trigger: "manual",
			Status: "failed", Actor: "x", StartedAt: testkit.Now, Method: strp("POST"), Path: strp("/api/hris/events/1/execute"),
			Body: strp("{}")})
	})
	rec := c.do("POST", "/api/jobs/00000000-0000-4000-8000-0000000000f1/retry", "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "not_retryable") {
		t.Errorf("retry provision: %d %s", rec.Code, rec.Body)
	}
	runs := c.json("GET", "/api/jobs?kind=jit_sweep", "", 200).([]any)
	if len(runs) != 1 || at(runs, 0, "status") != "succeeded" {
		t.Errorf("jit sweep run %v", runs)
	}
}

// TestJobs_RetryNeedsTheJobsPermission: an auditor reads the history but a
// retry replays the original route, which needs connectors.sync.
func TestJobs_RetryNeedsTheJobsPermission(t *testing.T) {
	st, _ := testkit.Tiny(t)
	admin := client{t, testServer(t, st)}
	admin.json("POST", "/api/connectors/sync", "{}", 200)
	id := at(admin.json("GET", "/api/jobs", "", 200), 0, "id").(string)

	auditor := authtest.User{Email: "a.udit@larkspur.example", Display: "A. Udit", Roles: []auth.Role{auth.RoleAuditor}}
	h := testSrv{newTestAPIServer(t, st), signIn(t, st.DB, st.Tenant, auditor, authtest.Phr, testkit.Now)}.Handler()
	ac := client{t, h}
	if runs := ac.json("GET", "/api/jobs", "", 200).([]any); len(runs) != 1 {
		t.Fatalf("auditor sees %v", runs)
	}
	rec := ac.do("POST", "/api/jobs/"+id+"/retry", "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("auditor retry: %d %s", rec.Code, rec.Body)
	}
	if runs := admin.json("GET", "/api/jobs", "", 200).([]any); len(runs) != 1 {
		t.Errorf("a refused retry was recorded: %v", runs)
	}
}

// TestIsolation_JobRoutes: as tenant A, tenant B's run answers exactly as a
// run that exists nowhere, and a retry of it changes nothing in B.
func TestIsolation_JobRoutes(t *testing.T) {
	f := storetest.TwoTenants(t)
	bJob := insertJobRun(t, f.DB, f.B.ID)
	h := isolationServer(t, f, f.A.ID).Handler()
	beforeB := storetest.Dump(t, f.DB, f.B.ID)
	for _, m := range []struct{ method, suffix string }{{"GET", ""}, {"POST", "/retry"}} {
		cross := serveOnce(h, m.method, "/api/jobs/"+bJob+m.suffix, "")
		missing := serveOnce(h, m.method, "/api/jobs/"+missingUUID+m.suffix, "")
		if cross.Code != http.StatusNotFound || cross.Body.String() != missing.Body.String() {
			t.Errorf("%s: cross %d %s, missing %d %s", m.method, cross.Code, cross.Body, missing.Code, missing.Body)
		}
	}
	if rec := serveOnce(h, "GET", "/api/jobs", ""); strings.Contains(rec.Body.String(), bJob) {
		t.Error("A lists B's run")
	}
	if storetest.Dump(t, f.DB, f.B.ID) != beforeB {
		t.Error("tenant B changed")
	}
}

func insertJobRun(t *testing.T, db *store.DB, tn tenancy.ID) string {
	t.Helper()
	id := store.NewID()
	if err := db.InTenant(context.Background(), tn, func(tx *store.TenantTx) error {
		return tx.InsertJobRun(&store.JobRun{ID: id, Kind: "sync", Trigger: "manual", Status: "failed", Actor: "b",
			StartedAt: storetest.Now, Method: strp("POST"), Path: strp("/api/connectors/sync"), Body: strp("{}"), Retryable: true,
			Error: strp(fmt.Sprintf("sentinel %s", tn))})
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func strp(s string) *string { return &s }

// newTestAPIServer is testServer's server, without a session.
func newTestAPIServer(t *testing.T, st *testkit.DB) *Server {
	t.Helper()
	return New(Config{
		Store: st.DB, Clock: timeutil.Frozen(testkit.Now), Policies: policy.NewLoader(policies.FS),
		Connectors:     func(time.Time) ([]connectors.Connector, error) { return connectors.Load("demo", testkit.Now) },
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		AllowedOrigins: []string{"http://localhost:5173"},
	})
}
