package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/awsreplay"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	policies "github.com/nischalravi/tessera/mvp/server/policies"
)

// The AWS collection job (issue #637) over the awsorg recordings: the route
// queues a run, a queue worker collects and evaluates it, an unchanged estate
// writes nothing, and the scheduled collection records only what changed.

const (
	collectKeyID  = "AKIAEXAMPLEEXAMPLE1"
	collectSecret = "baseSecretKeyForTestsOnly0123456789abcd"
	collectRoot   = "../connectors/awsorg/testdata/http"
)

// collectDoer serves a fresh replay of the recordings per collection, so
// paginated calls start from their first page each time. edit rewrites the
// responses, to change the estate.
type collectDoer struct {
	mu    sync.Mutex
	cur   *awsreplay.Replay
	edit  func(string) string
	calls int
}

func (d *collectDoer) next(edit func(string) string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := awsreplay.NewReplay(os.DirFS(collectRoot))
	r.RepeatLast = true
	r.Verify(collectKeyID, collectSecret).Verify("ASIAEXAMPLEEXAMPLE1", "secretsecretsecretsecretsecret0123456789")
	d.cur, d.edit = r, edit
}

func (d *collectDoer) Do(req *http.Request) (*http.Response, error) {
	d.mu.Lock()
	r, edit := d.cur, d.edit
	d.calls++
	d.mu.Unlock()
	resp, err := r.Do(req)
	if err != nil || edit == nil {
		return resp, err
	}
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	out := edit(string(b))
	resp.Body, resp.ContentLength = io.NopCloser(strings.NewReader(out)), int64(len(out))
	return resp, nil
}

type collectEnv struct {
	srv   *Server
	c     rdClient
	doer  *collectDoer
	connr string
}

func newCollectEnv(t *testing.T, mutate ...func(*Config)) *collectEnv {
	t.Helper()
	st := testkit.Demo(t)
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	d := &collectDoer{}
	d.next(nil)
	cfg := Config{Store: st.DB, Clock: timeutil.Frozen(testkit.Now), Policies: policy.NewLoader(policies.FS),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Env: "test", Sealer: sealer, AWSCatalog: testAWSCatalog, AWSHTTP: d, AWSAllowStaticKeys: true,
		RateLimits: noRateLimits, AllowedOrigins: []string{"http://localhost:5173"}}
	for _, m := range mutate {
		m(&cfg)
	}
	srv := New(cfg)
	c := rdClient{client{t, asLinkedAdmin(t, srv, st.DB, st.Tenant, testkit.Now).Handler()}, st}
	body := `{"name":"prod","config":{"regions":["us-east-1"],"management_account_id":"111111111111","identity_center_region":"us-east-1"},` +
		`"credentials":{"access_key_id":"` + collectKeyID + `","secret_access_key":"` + collectSecret + `"}}`
	created := c.json("POST", "/api/aws/connectors", body, 201)
	return &collectEnv{srv: srv, c: c, doer: d, connr: created["id"].(string)}
}

// pause switches the scheduled collection off, so a test of the requested one
// is not raced by it (the schedule fires at once on a new tenant, like the other
// recurring jobs).
func (e *collectEnv) pause(t *testing.T) {
	t.Helper()
	now := testkit.Now
	if err := e.c.st.DB.InTenant(context.Background(), e.c.st.Tenant, func(tx *store.TenantTx) error {
		if err := tx.EnsureQueueSchedule(&store.QueueSchedule{Name: jobs.AWSCollect, Kind: jobs.AWSCollect, Spec: "@every " + awsCollectEvery.String(),
			MaxAttempts: 1, NextRunAt: now}, now); err != nil {
			return err
		}
		return tx.SetQueueScheduleEnabled(jobs.AWSCollect, false, now)
	}); err != nil {
		t.Fatal(err)
	}
}

// drain runs the queue until its aws_collect jobs are all done: at least two
// ticks (the first fires a due schedule), then more while one is waiting or
// running (the tenant's other jobs share the workers).
func (e *collectEnv) drain(t *testing.T) {
	t.Helper()
	for i := 0; i < 40; i++ {
		if err := e.srv.Queue().Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		e.srv.Queue().Wait()
		if i < 1 {
			continue
		}
		pending := false
		e.c.read(func(tx *store.TenantTx) error {
			js, err := tx.QueueJobs(store.QueueJobFilter{Kind: jobs.AWSCollect})
			for _, j := range js {
				pending = pending || j.Status == "queued" || j.Status == "running" || j.Status == "failed"
			}
			return err
		})
		if !pending {
			return
		}
	}
	t.Fatal("the aws_collect jobs did not finish")
}

func (e *collectEnv) collect(t *testing.T) string {
	t.Helper()
	v := e.c.json("POST", "/api/aws/connectors/"+e.connr+"/collect", "", http.StatusAccepted)
	if v["status"] != "queued" || v["connector_id"] != e.connr {
		t.Fatalf("collect = %v", v)
	}
	return v["run_id"].(string)
}

func (e *collectEnv) run(t *testing.T, id string) map[string]any {
	t.Helper()
	return e.c.json("GET", "/api/aws/collection-runs/"+id, "", 200)
}

type collectCounts struct {
	snaps, trust, runs, jobRuns int
	audit                       map[string]int
}

func (e *collectEnv) counts(t *testing.T) collectCounts {
	t.Helper()
	var n collectCounts
	e.c.read(func(tx *store.TenantTx) error {
		snaps, err := tx.AWSSnapshots(0)
		if err != nil {
			return err
		}
		n.snaps = len(snaps)
		for _, s := range snaps {
			ts, _ := tx.AWSTrustEdges(s.ID)
			n.trust += len(ts)
		}
		runs, _ := tx.AWSCollectionRuns("", 0)
		n.runs = len(runs)
		js, _ := tx.JobRuns(store.JobRunFilter{Kind: jobs.AWSCollect})
		n.jobRuns = len(js)
		evs, err := tx.AuditLog(0)
		n.audit = map[string]int{}
		for _, ev := range evs {
			// the tenant's other recurring jobs write events of their own while the queue ticks
			if strings.HasPrefix(ev.Action, "aws.") || strings.HasPrefix(ev.Action, "job.") {
				n.audit[ev.Action]++
			}
		}
		return err
	})
	return n
}

func sameCounts(a, b collectCounts) bool {
	if a.snaps != b.snaps || a.trust != b.trust || a.runs != b.runs || a.jobRuns != b.jobRuns || len(a.audit) != len(b.audit) {
		return false
	}
	for k, v := range a.audit {
		if b.audit[k] != v {
			return false
		}
	}
	return true
}

func TestAWSCollectJob(t *testing.T) {
	e := newCollectEnv(t)
	e.pause(t)

	// the request queues a run, and a second one while it is queued is a conflict naming it
	first := e.collect(t)
	rec := e.c.do("POST", "/api/aws/connectors/"+e.connr+"/collect", "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "collection_in_progress") || !strings.Contains(rec.Body.String(), first) {
		t.Errorf("second collect = %d %s", rec.Code, rec.Body.String())
	}
	if r := e.run(t, first); r["status"] != "queued" || r["trigger"] != "manual" || r["started_at"] != nil {
		t.Errorf("queued run = %v", r)
	}
	if e.doer.calls != 0 {
		t.Errorf("%d AWS calls inside the request; the collection is the job's", e.doer.calls)
	}

	// the worker collects and evaluates it
	e.drain(t)
	r := e.run(t, first)
	res, _ := r["result"].(map[string]any)
	if r["status"] != "succeeded" || r["changed"] != true || r["snapshot_id"] == "" || res["changed"] != true || r["error"] != "" || r["finished_at"] == nil {
		t.Fatalf("first run = %v", r)
	}
	conns := e.c.json("GET", "/api/aws/connectors", "", 200)["items"].([]any)
	if k := conns[0].(map[string]any); k["status"] != "ok" || k["last_snapshot_id"] != r["snapshot_id"] {
		t.Errorf("connector = %v", k)
	}
	snap, _ := e.c.json("GET", "/api/aws/snapshots/"+r["snapshot_id"].(string), "", 200)["snapshot"].(map[string]any)
	if snap["connector_id"] != e.connr || snap["source"] != "connector" {
		t.Errorf("snapshot = %v", snap)
	}
	after1 := e.counts(t)
	for _, a := range []string{"aws.collection.queued", "aws.snapshot.collected", "aws.snapshot.materialized"} {
		if after1.audit[a] != 1 {
			t.Errorf("%d %s events, want 1", after1.audit[a], a)
		}
	}
	if after1.jobRuns != 1 {
		t.Errorf("%d aws_collect job runs, want 1", after1.jobRuns)
	}
	var jobsList []any
	if err := json.Unmarshal(e.c.do("GET", "/api/jobs?kind=aws_collect", "").Body.Bytes(), &jobsList); err != nil || len(jobsList) != 1 ||
		jobsList[0].(map[string]any)["status"] != "succeeded" {
		t.Errorf("jobs = %v, %v", jobsList, err)
	}
	list := e.c.json("GET", "/api/aws/collection-runs?connector_id="+e.connr, "", 200)["items"].([]any)
	if len(list) != 1 {
		t.Errorf("runs = %v", list)
	}

	// the same estate again: a run that says so, and nothing else written
	second := e.collect(t)
	e.doer.next(nil)
	e.drain(t)
	r2 := e.run(t, second)
	if r2["status"] != "unchanged" || r2["changed"] != false || r2["snapshot_id"] != r["snapshot_id"] {
		t.Fatalf("second run = %v", r2)
	}
	after2 := e.counts(t)
	want := after1
	want.runs++
	want.jobRuns++
	want.audit = map[string]int{}
	for k, v := range after1.audit {
		want.audit[k] = v
	}
	want.audit["aws.collection.queued"]++
	if !sameCounts(after2, want) {
		t.Errorf("an unchanged estate wrote more than its run: before %+v, after %+v", after1, after2)
	}

	// a changed estate: a new snapshot and its evaluation
	third := e.collect(t)
	e.doer.next(func(b string) string { return strings.ReplaceAll(b, "<Value>data</Value>", "<Value>data2</Value>") })
	e.drain(t)
	r3 := e.run(t, third)
	if r3["status"] != "succeeded" || r3["changed"] != true || r3["snapshot_id"] == r["snapshot_id"] {
		t.Fatalf("third run = %v", r3)
	}
	if n := e.counts(t); n.snaps != 2 || n.audit["aws.snapshot.materialized"] != 2 {
		t.Errorf("after a change: %+v", n)
	}
}

// The scheduled collection is the aws_collect schedule of the queue: it records
// a run only when the estate changed or the run failed, so an unchanged estate
// leaves no run row, no job run, no event and no snapshot; a connector with a
// run already queued is left to it.
func TestAWSCollectScheduled(t *testing.T) {
	e := newCollectEnv(t)
	ctx := context.Background()
	// a new tenant's schedule fires at once (every 6 hours after that), so the first Tick collects the estate
	e.drain(t)
	var sched *store.QueueSchedule
	e.c.read(func(tx *store.TenantTx) (err error) { sched, err = tx.QueueSchedule(jobs.AWSCollect); return err })
	if sched.Kind != jobs.AWSCollect || !sched.Enabled || sched.Spec != "@every "+awsCollectEvery.String() || sched.MaxAttempts != 1 {
		t.Fatalf("schedule = %+v", sched)
	}
	n := 0
	fire := func() {
		t.Helper()
		n++
		due := *sched
		due.NextRunAt = testkit.Now.Add(-time.Duration(n) * time.Hour)
		if err := e.c.st.DB.InTenant(ctx, e.c.st.Tenant, func(tx *store.TenantTx) error { return tx.SetQueueSchedule(&due, testkit.Now) }); err != nil {
			t.Fatal(err)
		}
		e.drain(t)
	}
	// the clock is frozen, so runs are told apart by what is new
	seen := map[string]bool{}
	lastRun := func() *store.AWSCollectionRun {
		t.Helper()
		var rs []*store.AWSCollectionRun
		e.c.read(func(tx *store.TenantTx) (err error) { rs, err = tx.AWSCollectionRuns("", 0); return err })
		var fresh *store.AWSCollectionRun
		for _, r := range rs {
			if !seen[r.ID] {
				if fresh != nil {
					t.Fatalf("more than one new run: %+v and %+v", fresh, r)
				}
				fresh = r
			}
			seen[r.ID] = true
		}
		return fresh
	}

	// the first collection of the estate is a change
	first := lastRun()
	r := first
	if r == nil || r.Trigger != store.AWSRunSchedule || r.Status != store.AWSRunSucceeded || !r.Changed || r.RequestedBy != awsCollectActor || r.ConnectorID != e.connr {
		t.Fatalf("first scheduled run = %+v", r)
	}
	after1 := e.counts(t)
	if after1.snaps != 1 || after1.runs != 1 || after1.jobRuns != 1 || after1.audit["aws.snapshot.materialized"] != 1 || after1.audit["aws.collection.queued"] != 0 {
		t.Fatalf("after the first scheduled run: %+v", after1)
	}

	// the same estate: nothing is written
	e.doer.next(nil)
	callsBefore := e.doer.calls
	fire()
	if e.doer.calls == callsBefore {
		t.Error("the scheduled run did not read the estate")
	}
	if after2 := e.counts(t); !sameCounts(after1, after2) {
		t.Errorf("an unchanged estate wrote: before %+v, after %+v", after1, after2)
	}

	// a connector with a run queued is left to it
	if err := e.c.st.DB.InTenant(ctx, e.c.st.Tenant, func(tx *store.TenantTx) error {
		return tx.InsertAWSCollectionRun(&store.AWSCollectionRun{ID: store.NewID(), ConnectorID: e.connr, Trigger: store.AWSRunManual,
			Status: store.AWSRunQueued, RequestedBy: "someone", QueuedAt: testkit.Now})
	}); err != nil {
		t.Fatal(err)
	}
	lastRun() // the queued run is not the scheduler's
	e.doer.next(func(b string) string { return strings.ReplaceAll(b, "<Value>data</Value>", "<Value>data2</Value>") })
	callsBefore = e.doer.calls
	fire()
	if e.doer.calls != callsBefore {
		t.Error("the scheduled run collected a connector that has a run queued")
	}
	if err := e.c.st.DB.InTenant(ctx, e.c.st.Tenant, func(tx *store.TenantTx) error {
		cur, err := tx.ActiveAWSCollectionRun(e.connr)
		if err != nil {
			return err
		}
		return tx.FinishAWSCollectionRun(cur.ID, store.AWSRunFailed, "", false, nil, "cleared by the test", testkit.Now)
	}); err != nil {
		t.Fatal(err)
	}

	// a changed estate is recorded
	fire()
	r = lastRun()
	if r.Status != store.AWSRunSucceeded || !r.Changed || r.SnapshotID == first.SnapshotID {
		t.Errorf("scheduled run of a changed estate = %+v", r)
	}
	if n := e.counts(t); n.snaps != 2 || n.jobRuns != 2 || n.audit["aws.snapshot.materialized"] != 2 {
		t.Errorf("after the change: %+v", n)
	}

	// a failure is recorded, and audited as a failed job
	bad := awsreplay.NewReplay(os.DirFS(collectRoot))
	bad.Enqueue("sts/AssumeRole", awsreplay.Response{Status: 403, Body: `<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>`})
	e.doer.mu.Lock()
	e.doer.cur, e.doer.edit = bad, nil
	e.doer.mu.Unlock()
	fire()
	r = lastRun()
	if r.Status != store.AWSRunFailed || !strings.Contains(r.Error, "AccessDenied") || r.Trigger != store.AWSRunSchedule {
		t.Errorf("scheduled run that failed = %+v", r)
	}
	if n := e.counts(t); n.audit["job.failed"] != 1 || n.audit["aws.collection.failed"] != 1 {
		t.Errorf("after the failure: %+v", n)
	}
}

// The collection routes need connections.manage (an auditor, who has connections.read, cannot queue a run) and a fresh sign-in to queue a
// run, connections.read to list runs; a connector that is not the tenant's is
// a 404; a server with no AWS client or catalog refuses with 503.
func TestAWSCollectAuthorization(t *testing.T) {
	e := newCollectEnv(t)
	e.pause(t)
	st := e.c.st
	h := e.srv.Handler()
	viewer := signIn(t, st.DB, st.Tenant, authtest.User{Email: "au@larkspur.example", Roles: []auth.Role{auth.RoleAuditor}}, authtest.Phr, testkit.Now)
	stale := signIn(t, st.DB, st.Tenant, authtest.User{Email: "s@larkspur.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: testkit.Now.Add(-20 * time.Minute)}, testkit.Now)
	path := "/api/aws/connectors/" + e.connr + "/collect"
	if rec := serve(h, authed(viewer, "POST", path, "")); rec.Code != http.StatusForbidden {
		t.Errorf("auditor POST collect = %d", rec.Code)
	}
	if rec := serve(h, authed(stale, "POST", path, "")); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale sign-in POST collect = %d %s, want a step-up refusal", rec.Code, rec.Body.String())
	}
	if n := e.counts(t); n.runs != 0 || n.audit["aws.collection.queued"] != 0 {
		t.Errorf("a refused request queued a run: %+v", n)
	}
	if rec := serve(h, authed(viewer, "GET", "/api/aws/collection-runs", "")); rec.Code != 200 {
		t.Errorf("auditor GET collection-runs = %d", rec.Code)
	}
	if rec := serve(h, authed(viewer, "GET", "/api/aws/collection-runs/"+store.NewID(), "")); rec.Code != 404 {
		t.Errorf("auditor GET an unknown run = %d, want 404", rec.Code)
	}
	for _, bad := range []string{"/api/aws/connectors/" + store.NewID() + "/collect", "/api/aws/connectors/not-an-id/collect"} {
		if rec := e.c.do("POST", bad, ""); rec.Code != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404", bad, rec.Code)
		}
	}
	for _, bad := range []string{"/api/aws/collection-runs?limit=0", "/api/aws/collection-runs?limit=x", "/api/aws/collection-runs?connector_id=%27x"} {
		if rec := e.c.do("GET", bad, ""); rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("GET %s = %d, want a 4xx", bad, rec.Code)
		}
	}

	// no outbound client, or no catalog: 503, and nothing is queued
	for name, mut := range map[string]func(*Config){
		"no client":  func(c *Config) { c.AWSHTTP = nil },
		"no catalog": func(c *Config) { c.AWSCatalog = nil },
	} {
		x := newCollectEnv(t, mut)
		if rec := x.c.do("POST", "/api/aws/connectors/"+x.connr+"/collect", ""); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: POST collect = %d %s", name, rec.Code, rec.Body.String())
		}
		if n := x.counts(t); n.runs != 0 {
			t.Errorf("%s: queued a run", name)
		}
	}
}

// A collection that fails at AWS is the run's outcome, audited, with no
// credential in what is stored, and the connector can be collected again.
func TestAWSCollectFailure(t *testing.T) {
	e := newCollectEnv(t)
	e.pause(t)
	r := awsreplay.NewReplay(os.DirFS(collectRoot))
	r.Enqueue("sts/AssumeRole", awsreplay.Response{Status: 403, Body: `<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>`})
	e.doer.mu.Lock()
	e.doer.cur = r
	e.doer.mu.Unlock()
	id := e.collect(t)
	e.drain(t)
	run := e.run(t, id)
	if run["status"] != "failed" || !strings.Contains(run["error"].(string), "AccessDenied") || run["changed"] != false {
		t.Fatalf("run = %v", run)
	}
	b, _ := json.Marshal(run)
	if strings.Contains(string(b), collectSecret) || strings.Contains(string(b), collectKeyID) {
		t.Errorf("the run leaks a credential: %s", b)
	}
	if n := e.counts(t); n.snaps != 0 || n.audit["aws.collection.failed"] != 1 {
		t.Errorf("after a failure: %+v", n)
	}
	e.doer.next(nil)
	again := e.collect(t) // the failed run no longer blocks the connector
	e.drain(t)
	if r := e.run(t, again); r["status"] != "succeeded" {
		t.Errorf("run after the failure = %v", r)
	}
}

// Two tenants on one server: B can neither see, nor collect, nor learn of A's
// connector and runs, and the queue runs each tenant's job against its own.
func TestAWSCollectTenantIsolation(t *testing.T) {
	f := storetest.TwoTenants(t)
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	d := &collectDoer{}
	d.next(nil)
	srv := New(Config{Store: f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Env: "test", Sealer: sealer, AWSCatalog: testAWSCatalog, AWSHTTP: d, AWSAllowStaticKeys: true,
		RateLimits: noRateLimits, AllowedOrigins: []string{"http://localhost:5173"}})
	h := srv.Handler()
	la := signIn(t, f.DB, f.A.ID, testAdmin, authtest.Phr, storetest.Now)
	lb := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
	a := func(method, path, body string) *httptest.ResponseRecorder {
		return serve(h, authed(la, method, path, body))
	}
	b := func(method, path, body string) *httptest.ResponseRecorder {
		return serve(h, authed(lb, method, path, body))
	}
	body := `{"name":"prod","config":{"regions":["us-east-1"],"management_account_id":"111111111111","identity_center_region":"us-east-1"},` +
		`"credentials":{"access_key_id":"` + collectKeyID + `","secret_access_key":"` + collectSecret + `"}}`
	rec := a("POST", "/api/aws/connectors", body)
	var conn map[string]any
	if rec.Code != 201 || json.Unmarshal(rec.Body.Bytes(), &conn) != nil {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	connID := conn["id"].(string)
	rec = a("POST", "/api/aws/connectors/"+connID+"/collect", "")
	var queued map[string]any
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &queued) != nil {
		t.Fatalf("collect: %d %s", rec.Code, rec.Body.String())
	}
	runID := queued["run_id"].(string)

	// B cannot collect A's connector, nor reach its run, before or after it ran
	for phase := 0; phase < 2; phase++ {
		if rec := b("POST", "/api/aws/connectors/"+connID+"/collect", ""); rec.Code != 404 {
			t.Errorf("B collect A's connector = %d", rec.Code)
		}
		if rec := b("GET", "/api/aws/collection-runs/"+runID, ""); rec.Code != 404 {
			t.Errorf("B GET A's run = %d %s", rec.Code, rec.Body.String())
		}
		if rec := b("GET", "/api/aws/collection-runs?connector_id="+connID, ""); rec.Code != 200 || strings.Contains(rec.Body.String(), runID) ||
			!strings.Contains(rec.Body.String(), `"items":[]`) {
			t.Errorf("B list = %d %s", rec.Code, rec.Body.String())
		}
		if phase == 0 {
			for range 10 { // two tenants' recurring jobs share the workers
				if err := srv.Queue().Tick(context.Background()); err != nil {
					t.Fatal(err)
				}
				srv.Queue().Wait()
			}
		}
	}
	if rec := a("GET", "/api/aws/collection-runs/"+runID, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"succeeded"`) {
		t.Errorf("A's run = %d %s", rec.Code, rec.Body.String())
	}
	// nothing of A's collection is in B
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		if rs, err := tx.AWSCollectionRuns("", 0); err != nil || len(rs) != 0 {
			t.Errorf("B has runs: %v, %v", rs, err)
		}
		if ss, err := tx.AWSSnapshots(0); err != nil || len(ss) != 0 {
			t.Errorf("B has snapshots: %v, %v", ss, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
