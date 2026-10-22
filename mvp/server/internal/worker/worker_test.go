package worker_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

func TestMain(m *testing.M) { testkit.Main(m) }

var (
	tenantA = tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")
	tenantB = tenancy.MustParse("00000000-0000-4000-8000-0000000000b1")
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	db  *store.DB
	clk *fakeClock
}

func newEnv(t *testing.T, tenants ...tenancy.ID) *env {
	t.Helper()
	db := testkit.Open(t)
	if len(tenants) == 0 {
		tenants = []tenancy.ID{tenantA}
	}
	for i, id := range tenants {
		testkit.CreateTenant(t, db, id, string(rune('a'+i))+"-corp")
	}
	return &env{db: db, clk: &fakeClock{t: testkit.Now}}
}

// queue is one worker process: a queue with its own owner on the shared
// database and clock, running the pool's handlers over deps.
func (e *env) queue(t *testing.T, owner string, lease time.Duration, deps *worker.Deps, kinds ...string) *queue.Queue {
	t.Helper()
	q := &queue.Queue{DB: e.db, Clock: e.clk.Now, Owner: owner, Lease: lease, Poll: time.Millisecond,
		Backoff: queue.Backoff{Base: 10 * time.Second, Max: time.Hour, Rand: func() float64 { return 0.5 }}}
	deps.DB, deps.Clock = e.db, e.clk.Now
	if err := deps.Register(q, kinds, nil); err != nil {
		t.Fatal(err)
	}
	return q
}

func (e *env) job(t *testing.T, tenant tenancy.ID, id string) *store.QueueJob {
	t.Helper()
	var j *store.QueueJob
	if err := e.db.ReadTenant(t.Context(), tenant, func(tx *store.TenantTx) (err error) {
		j, err = tx.QueueJob(id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return j
}

func (e *env) onlyJob(t *testing.T, tenant tenancy.ID, kind string) *store.QueueJob {
	t.Helper()
	var js []*store.QueueJob
	if err := e.db.ReadTenant(t.Context(), tenant, func(tx *store.TenantTx) (err error) {
		js, err = tx.QueueJobs(store.QueueJobFilter{Kind: kind})
		return err
	}); err != nil || len(js) != 1 {
		t.Fatalf("jobs of %s: %v %v", kind, js, err)
	}
	return js[0]
}

func (e *env) enqueue(t *testing.T, q *queue.Queue, tenant tenancy.ID, kind, key string) {
	t.Helper()
	if created, err := q.Enqueue(t.Context(), tenant, kind, "{}", key, time.Time{}, 3); err != nil || !created {
		t.Fatalf("enqueue: %v %v", created, err)
	}
}

func (e *env) audit(t *testing.T, tenant tenancy.ID, action string) []*store.AuditEvent {
	t.Helper()
	var evs []*store.AuditEvent
	if err := e.db.ReadTenant(t.Context(), tenant, func(tx *store.TenantTx) (err error) {
		evs, err = tx.AuditEvents(store.AuditFilter{Action: action})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return evs
}

func noConnectors(time.Time) ([]connectors.Connector, error) { return nil, nil }

func TestParseKinds(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want []string
		bad  bool
	}{
		"both":            {"connector_sync,provision_push", []string{"connector_sync", "provision_push"}, false},
		"sorted, trimmed": {" provision_push , connector_sync ", []string{"connector_sync", "provision_push"}, false},
		"repeats":         {"connector_sync,connector_sync", []string{"connector_sync"}, false},
		"empty":           {"", nil, false},
		"unknown":         {"connector_sync,sweep_requests", nil, true},
		"typo":            {"connector-sync", nil, true},
	} {
		got, err := worker.ParseKinds(tc.in)
		if (err != nil) != tc.bad || !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
	if !slices.Equal(worker.Kinds, config.WorkerKinds) {
		t.Errorf("worker.Kinds %v and config.WorkerKinds %v differ", worker.Kinds, config.WorkerKinds)
	}
	for _, k := range worker.Kinds {
		if !slices.Contains(jobs.Kinds, k) {
			t.Errorf("%s is not a job kind of the run history", k)
		}
	}
}

// TestCrashMidJobIsRetriedByAnotherWorker: a worker dies while it runs a job
// (here: its handler never returns and its heartbeat never comes). Nothing
// releases the lease, so the job is not run twice while the lease is live, and
// once it expires another worker claims it, runs it to the end and the job
// succeeds on its second attempt. The dead worker's late answer, if any,
// changes nothing.
func TestCrashMidJobIsRetriedByAnotherWorker(t *testing.T) {
	e := newEnv(t)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	crashing := &worker.Deps{Connectors: func(time.Time) ([]connectors.Connector, error) {
		once.Do(func() { close(started) })
		<-release
		return nil, errors.New("the worker process is gone")
	}}
	healthy := &worker.Deps{Connectors: noConnectors}
	w1 := e.queue(t, "worker-1", time.Hour, crashing, jobs.ConnectorSync) // no heartbeat within the test
	w2 := e.queue(t, "worker-2", time.Minute, healthy, jobs.ConnectorSync)
	e.enqueue(t, w1, tenantA, jobs.ConnectorSync, "sync-1")
	if err := w1.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("worker 1 never started the job")
	}
	j := e.onlyJob(t, tenantA, jobs.ConnectorSync)
	if j.Status != store.QueueRunning || j.LeaseOwner == nil || *j.LeaseOwner != "worker-1" || j.Attempts != 1 {
		t.Fatalf("after the claim: %+v", j)
	}
	// the lease is live: the other worker leaves it alone
	e.clk.Add(30 * time.Minute)
	if err := w2.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	w2.Wait()
	if j := e.job(t, tenantA, j.ID); j.Status != store.QueueRunning || *j.LeaseOwner != "worker-1" || j.Attempts != 1 {
		t.Fatalf("a live lease was taken: %+v", j)
	}
	// the lease expires
	e.clk.Add(31 * time.Minute)
	if err := w2.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	w2.Wait()
	got := e.job(t, tenantA, j.ID)
	if got.Status != store.QueueSucceeded || got.Attempts != 2 || got.LeaseOwner != nil {
		t.Fatalf("after the retry: %+v", got)
	}
	if evs := e.audit(t, tenantA, "connectors.sync"); len(evs) != 1 {
		t.Errorf("connectors.sync events: %d", len(evs))
	}
	// the dead worker's handler returns late: its outcome is ignored
	close(release)
	w1.Wait()
	if got := e.job(t, tenantA, j.ID); got.Status != store.QueueSucceeded || got.Attempts != 2 {
		t.Errorf("a late answer from the dead worker changed the job: %+v", got)
	}
}

// TestWorkerClaimsOnlyItsKinds: a worker started for one kind never takes a job
// of the other, and the other kind's worker does.
func TestWorkerClaimsOnlyItsKinds(t *testing.T) {
	e := newEnv(t)
	var ran sync.Map
	syncDeps := &worker.Deps{Connectors: func(time.Time) ([]connectors.Connector, error) { ran.Store("sync", true); return nil, nil }}
	provOnly := e.queue(t, "prov-worker", time.Minute, &worker.Deps{Provision: &provision.Engine{DB: e.db, Clock: e.clk.Now}}, jobs.ProvisionPush)
	syncOnly := e.queue(t, "sync-worker", time.Minute, syncDeps, jobs.ConnectorSync)
	if got := provOnly.Kinds(); !slices.Equal(got, []string{jobs.ProvisionPush}) {
		t.Fatalf("kinds = %v", got)
	}
	e.enqueue(t, syncOnly, tenantA, jobs.ConnectorSync, "k1")
	if err := provOnly.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	provOnly.Wait()
	if j := e.onlyJob(t, tenantA, jobs.ConnectorSync); j.Status != store.QueueQueued || j.Attempts != 0 {
		t.Fatalf("the provisioning worker took a sync job: %+v", j)
	}
	if _, ok := ran.Load("sync"); ok {
		t.Fatal("the sync handler ran in the provisioning worker")
	}
	if err := syncOnly.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	syncOnly.Wait()
	if j := e.onlyJob(t, tenantA, jobs.ConnectorSync); j.Status != store.QueueSucceeded {
		t.Fatalf("the sync worker left its job: %+v", j)
	}
	// each kind's registration needs what it runs on
	for kind, deps := range map[string]*worker.Deps{jobs.ConnectorSync: {}, jobs.ProvisionPush: {}, "sweep_requests": {Provision: &provision.Engine{}}} {
		if err := deps.Register(&queue.Queue{DB: e.db}, []string{kind}, nil); err == nil {
			t.Errorf("%s registered without its dependencies", kind)
		}
	}
}

// TestGracefulShutdownReleasesTheLease: SIGTERM while a sync runs. The job
// gets its grace to finish; one that does not is cancelled and handed back at
// once, with its attempt given back, for another worker.
func TestGracefulShutdownReleasesTheLease(t *testing.T) {
	e := newEnv(t)
	started := make(chan struct{})
	var once sync.Once
	// discovery uses the job's context, so a connector that waits on it is a
	// sync that outlasts the grace and ends only when it is cancelled
	slow := &worker.Deps{Connectors: func(time.Time) ([]connectors.Connector, error) {
		once.Do(func() { close(started) })
		return []connectors.Connector{waitConnector{}}, nil
	}}
	w1 := e.queue(t, "worker-1", time.Minute, slow, jobs.ConnectorSync)
	w1.ShutdownGrace = 50 * time.Millisecond
	e.enqueue(t, w1, tenantA, jobs.ConnectorSync, "sync-1")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { w1.Run(ctx); close(done) }()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("the job never started")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the worker did not stop")
	}
	j := e.onlyJob(t, tenantA, jobs.ConnectorSync)
	if j.Status != store.QueueQueued || j.Attempts != 0 || j.LeaseOwner != nil || j.LeaseExpiresAt != nil {
		t.Fatalf("the interrupted job was not released: %+v", j)
	}
	w2 := e.queue(t, "worker-2", time.Minute, &worker.Deps{Connectors: noConnectors}, jobs.ConnectorSync)
	if err := w2.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	w2.Wait()
	if j := e.job(t, tenantA, j.ID); j.Status != store.QueueSucceeded || j.Attempts != 1 {
		t.Fatalf("the second worker's run: %+v", j)
	}
}

// waitConnector blocks in Discover until its context ends, like a connector
// waiting on a slow source.
type waitConnector struct{ connectors.Connector }

func (waitConnector) System() string { return "wait" }
func (waitConnector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestSyncJobFailureRetriesThenDeadLetters: the same retry and dead-letter
// semantics as every queue kind; a bad payload is dead at once.
func TestSyncJobFailureRetriesThenDeadLetters(t *testing.T) {
	e := newEnv(t)
	calls := 0
	deps := &worker.Deps{Connectors: func(time.Time) ([]connectors.Connector, error) { calls++; return nil, errors.New("source down") }}
	q := e.queue(t, "w", time.Minute, deps, jobs.ConnectorSync)
	e.enqueue(t, q, tenantA, jobs.ConnectorSync, "k")
	for i := 0; i < 3; i++ {
		if err := q.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		q.Wait()
		e.clk.Add(time.Hour)
	}
	if j := e.onlyJob(t, tenantA, jobs.ConnectorSync); j.Status != store.QueueDead || j.Attempts != 3 || calls != 3 {
		t.Fatalf("after three failures: %+v (%d calls)", j, calls)
	}
	if evs := e.audit(t, tenantA, "queue.job_dead"); len(evs) != 1 {
		t.Errorf("queue.job_dead events: %d", len(evs))
	}
	if created, err := q.Enqueue(t.Context(), tenantA, jobs.ConnectorSync, `{"mode":"sideways"}`, "bad", time.Time{}, 3); err != nil || !created {
		t.Fatal(err)
	}
	if err := q.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	q.Wait()
	var bad *store.QueueJob
	_ = e.db.ReadTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
		js, err := tx.QueueJobs(store.QueueJobFilter{Status: store.QueueDead})
		for _, j := range js {
			if j.IdempotencyKey != nil && *j.IdempotencyKey == "bad" {
				bad = j
			}
		}
		return err
	})
	if bad == nil || bad.Attempts != 1 {
		t.Errorf("a payload that cannot run was retried: %+v", bad)
	}
}

// TestProvisionPushIsQuietWithoutWork: the scheduled pass of an idle tenant
// leaves no run in the history (the in-process loop never did either), and
// each tenant gets its own schedule.
func TestProvisionPushIsQuietWithoutWork(t *testing.T) {
	e := newEnv(t, tenantA, tenantB)
	q := e.queue(t, "w", time.Minute, &worker.Deps{Provision: &provision.Engine{DB: e.db, Clock: e.clk.Now}}, jobs.ProvisionPush)
	if err := q.Tick(t.Context()); err != nil { // creates the schedules
		t.Fatal(err)
	}
	e.clk.Add(2 * worker.ProvisionEvery)
	if err := q.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	q.Wait()
	for _, tn := range []tenancy.ID{tenantA, tenantB} {
		if err := e.db.ReadTenant(t.Context(), tn, func(tx *store.TenantTx) error {
			js, err := tx.QueueJobs(store.QueueJobFilter{Kind: jobs.ProvisionPush})
			if err != nil || len(js) == 0 {
				t.Errorf("tenant %s: no provisioning jobs: %v %v", tn, js, err)
			}
			for _, j := range js {
				if j.Status != store.QueueSucceeded {
					t.Errorf("tenant %s: %+v", tn, j)
				}
			}
			rs, err := tx.JobRuns(store.JobRunFilter{})
			if len(rs) != 0 {
				t.Errorf("tenant %s: an idle pass left runs: %v", tn, rs)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestBeaterRecordsWorkerHealth: every active tenant sees the worker, with its
// kinds, concurrency and last heartbeat; a clean stop removes the rows and a
// crashed worker's rows age out.
func TestBeaterRecordsWorkerHealth(t *testing.T) {
	e := newEnv(t, tenantA, tenantB)
	q := e.queue(t, "worker-1", time.Minute, &worker.Deps{Connectors: noConnectors}, jobs.ConnectorSync)
	q.Concurrency = 6
	b := &worker.Beater{DB: e.db, Queue: q, Mode: store.WorkerModeWorker, Version: "0.1.0", Clock: e.clk.Now}
	if err := b.Beat(t.Context()); err != nil {
		t.Fatal(err)
	}
	list := func(tn tenancy.ID) (ws []*store.QueueWorker) {
		_ = e.db.ReadTenant(t.Context(), tn, func(tx *store.TenantTx) (err error) { ws, err = tx.QueueWorkers(); return err })
		return ws
	}
	for _, tn := range []tenancy.ID{tenantA, tenantB} {
		ws := list(tn)
		if len(ws) != 1 || ws[0].WorkerID != "worker-1" || ws[0].Mode != store.WorkerModeWorker || ws[0].Kinds != jobs.ConnectorSync ||
			ws[0].Concurrency != 6 || ws[0].Version != "0.1.0" || !ws[0].LastHeartbeatAt.Equal(testkit.Now) ||
			ws[0].Hostname != "" || ws[0].PID != 0 { // shared infrastructure: host and PID are not stored per tenant (#403)
			t.Fatalf("tenant %s: %+v", tn, ws)
		}
	}
	e.clk.Add(time.Minute)
	if err := b.Beat(t.Context()); err != nil {
		t.Fatal(err)
	}
	ws := list(tenantA)
	if len(ws) != 1 || !ws[0].LastHeartbeatAt.Equal(testkit.Now.Add(time.Minute)) || !ws[0].StartedAt.Equal(testkit.Now) {
		t.Fatalf("after the second beat: %+v", ws)
	}
	// another worker that then crashes: its row stays, ageing, and is forgotten after a day
	q2 := e.queue(t, "worker-2", time.Minute, &worker.Deps{Connectors: noConnectors}, jobs.ConnectorSync)
	b2 := &worker.Beater{DB: e.db, Queue: q2, Mode: store.WorkerModeWorker, Clock: e.clk.Now}
	if err := b2.Beat(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(list(tenantA)) != 2 {
		t.Fatal("two workers expected")
	}
	b.Forget() // worker 1 stops cleanly
	if ws := list(tenantA); len(ws) != 1 || ws[0].WorkerID != "worker-2" {
		t.Fatalf("after a clean stop: %+v", ws)
	}
	e.clk.Add(25 * time.Hour)
	b3 := &worker.Beater{DB: e.db, Queue: e.queue(t, "worker-3", time.Minute, &worker.Deps{Connectors: noConnectors}, jobs.ConnectorSync),
		Mode: store.WorkerModeAPI, Clock: e.clk.Now}
	if err := b3.Beat(t.Context()); err != nil {
		t.Fatal(err)
	}
	if ws := list(tenantB); len(ws) != 1 || ws[0].WorkerID != "worker-3" || ws[0].Mode != store.WorkerModeAPI {
		t.Fatalf("a crashed worker was not forgotten: %+v", ws)
	}
}

// TestServeBeatsWhileRunningAndWithdrawsAtTheEnd: worker.Serve is what both
// `tessera worker` and the API process run.
func TestServeBeatsWhileRunningAndWithdrawsAtTheEnd(t *testing.T) {
	e := newEnv(t)
	q := e.queue(t, "worker-1", time.Minute, &worker.Deps{Connectors: noConnectors}, jobs.ConnectorSync)
	b := &worker.Beater{DB: e.db, Queue: q, Mode: store.WorkerModeWorker, Clock: e.clk.Now, Every: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { worker.Serve(ctx, q, b); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var n int
		_ = e.db.ReadTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
			ws, err := tx.QueueWorkers()
			n = len(ws)
			return err
		})
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the worker never beat")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	_ = e.db.ReadTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
		if ws, err := tx.QueueWorkers(); err != nil || len(ws) != 0 {
			t.Errorf("a worker that stopped cleanly is still listed: %v %v", ws, err)
		}
		return nil
	})
}

// TestBeaterPublishesTargetStates: the guard's view of each target the worker
// called goes out with the heartbeat, to the tenant that owns the connection
// only, replaces itself on every beat, and is withdrawn when the worker stops.
func TestBeaterPublishesTargetStates(t *testing.T) {
	e := newEnv(t, tenantA, tenantB)
	conn := e.connection(t, "a", "ad-corp")
	g := e.guard(worker.Limits{BreakerThreshold: 1, BreakerCooldown: time.Minute})
	q := e.queue(t, "worker-1", time.Minute, &worker.Deps{Connectors: noConnectors}, jobs.ConnectorSync)
	b := &worker.Beater{DB: e.db, Queue: q, Mode: store.WorkerModeWorker, Clock: e.clk.Now, Guard: g}
	_ = g.Do(t.Context(), tenantA, conn, func(context.Context) error { return errors.New("503 from the directory") })
	if err := b.Beat(t.Context()); err != nil {
		t.Fatal(err)
	}
	states := func(tn tenancy.ID) (ts []*store.WorkerTargetState) {
		_ = e.db.ReadTenant(t.Context(), tn, func(tx *store.TenantTx) (err error) { ts, err = tx.WorkerTargetStates(); return err })
		return ts
	}
	ts := states(tenantA)
	if len(ts) != 1 || ts[0].WorkerID != "worker-1" || ts[0].ConnectionID != conn || ts[0].State != store.BreakerOpen ||
		ts[0].OpenUntil == nil || ts[0].LastError != "503 from the directory" || ts[0].Failures != 1 {
		t.Fatalf("tenant A: %+v", ts)
	}
	if got := states(tenantB); len(got) != 0 {
		t.Errorf("tenant B sees A's targets: %+v", got)
	}
	// the breaker closes (cooldown over, a good probe): the next beat replaces the row
	e.clk.Add(2 * time.Minute)
	if err := g.Do(t.Context(), tenantA, conn, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := b.Beat(t.Context()); err != nil {
		t.Fatal(err)
	}
	if ts := states(tenantA); len(ts) != 1 || ts[0].State != store.BreakerClosed || ts[0].ConsecutiveFailures != 0 || ts[0].LastError != "" {
		t.Fatalf("after recovery: %+v", ts)
	}
	b.Forget()
	if ts := states(tenantA); len(ts) != 0 {
		t.Errorf("a worker that stopped cleanly left target rows: %+v", ts)
	}
}
