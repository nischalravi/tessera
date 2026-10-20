package queue_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestMain(m *testing.M) { testkit.Main(m) }

var tenantA = tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")

// fakeClock is a clock tests move by hand.
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

func newEnv(t *testing.T) *env {
	t.Helper()
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "alpha")
	return &env{db: db, clk: &fakeClock{t: testkit.Now}}
}

// worker is a queue with its own owner name on the shared database and clock.
func (e *env) worker(owner string, register func(*queue.Queue)) *queue.Queue {
	q := &queue.Queue{DB: e.db, Clock: e.clk.Now, Owner: owner, Lease: time.Minute, Poll: time.Millisecond,
		Backoff: queue.Backoff{Base: 10 * time.Second, Max: time.Hour, Rand: func() float64 { return 0.5 }}}
	register(q)
	return q
}

func (e *env) tick(t *testing.T, qs ...*queue.Queue) {
	t.Helper()
	for _, q := range qs {
		if err := q.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		q.Wait()
	}
}

func (e *env) job(t *testing.T, id string) *store.QueueJob {
	t.Helper()
	var j *store.QueueJob
	if err := e.db.ReadTenant(t.Context(), tenantA, func(tx *store.TenantTx) (err error) {
		j, err = tx.QueueJob(id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return j
}

func (e *env) jobs(t *testing.T, f store.QueueJobFilter) []*store.QueueJob {
	t.Helper()
	var js []*store.QueueJob
	if err := e.db.ReadTenant(t.Context(), tenantA, func(tx *store.TenantTx) (err error) {
		js, err = tx.QueueJobs(f)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return js
}

func (e *env) enqueue(t *testing.T, q *queue.Queue, kind, key string, max int) string {
	t.Helper()
	var id string
	if err := e.db.InTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
		j := &store.QueueJob{Kind: kind, RunAt: e.clk.Now(), MaxAttempts: max}
		if key != "" {
			j.IdempotencyKey = &key
		}
		_, err := tx.EnqueueQueueJob(j, e.clk.Now())
		id = j.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) auditActions(t *testing.T) map[string]int {
	t.Helper()
	out := map[string]int{}
	if err := e.db.ReadTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
		log, err := tx.AuditLog(-1)
		for _, ev := range log {
			out[ev.Action]++
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *env) runs(t *testing.T, kind string) []*store.JobRun {
	t.Helper()
	var rs []*store.JobRun
	if err := e.db.ReadTenant(t.Context(), tenantA, func(tx *store.TenantTx) (err error) {
		rs, err = tx.JobRuns(store.JobRunFilter{Kind: kind})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return rs
}

// TestTwoWorkersNeverRunTheSameJob: two workers poll one queue at once; every
// job runs exactly once and never twice at the same time.
func TestTwoWorkersNeverRunTheSameJob(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	runs, active := map[string]int{}, map[string]bool{}
	overlap := false
	h := func(_ context.Context, j queue.Job) (any, error) {
		mu.Lock()
		if active[j.ID] {
			overlap = true
		}
		active[j.ID] = true
		runs[j.ID]++
		mu.Unlock()
		time.Sleep(3 * time.Millisecond)
		mu.Lock()
		active[j.ID] = false
		mu.Unlock()
		return nil, nil
	}
	reg := func(q *queue.Queue) { q.Register("work", queue.Kind{Handler: h}) }
	w1, w2 := e.worker("w1", reg), e.worker("w2", reg)
	var ids []string
	for i := 0; i < 24; i++ {
		ids = append(ids, e.enqueue(t, w1, "work", "", 3))
	}
	var wg sync.WaitGroup
	for _, w := range []*queue.Queue{w1, w2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				if err := w.Tick(context.Background()); err != nil {
					t.Error(err)
					return
				}
				w.Wait()
			}
		}()
	}
	wg.Wait()
	if overlap {
		t.Error("a job ran twice at once")
	}
	for _, id := range ids {
		if runs[id] != 1 {
			t.Errorf("job %s ran %d times", id, runs[id])
		}
		if j := e.job(t, id); j.Status != store.QueueSucceeded || j.Attempts != 1 || j.LeaseOwner != nil {
			t.Errorf("job %s = %s attempts %d owner %v", id, j.Status, j.Attempts, j.LeaseOwner)
		}
	}
}

// TestExpiredLeaseIsReclaimed: a job whose worker vanished stays with it until
// the lease expires, then another worker runs it (a second attempt).
func TestExpiredLeaseIsReclaimed(t *testing.T) {
	e := newEnv(t)
	var ran atomic.Int32
	w := e.worker("w2", func(q *queue.Queue) {
		q.Register("work", queue.Kind{Handler: func(context.Context, queue.Job) (any, error) { ran.Add(1); return nil, nil }})
	})
	id := e.enqueue(t, w, "work", "", 3)
	// a worker that claims the job and dies
	if err := e.db.InTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
		got, _, err := tx.ClaimQueueJobs(e.clk.Now(), "dead", time.Minute, []string{"work"}, 1)
		if err == nil && len(got) != 1 {
			t.Fatalf("claimed %d", len(got))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.clk.Add(59 * time.Second)
	e.tick(t, w)
	if ran.Load() != 0 {
		t.Fatal("a job under a live lease was run")
	}
	e.clk.Add(2 * time.Second)
	e.tick(t, w)
	if ran.Load() != 1 {
		t.Fatalf("ran %d times after the lease expired", ran.Load())
	}
	if j := e.job(t, id); j.Status != store.QueueSucceeded || j.Attempts != 2 {
		t.Errorf("job = %s attempts %d", j.Status, j.Attempts)
	}
}

// TestLeaseExpiryAfterLastAttemptBuries: a job that keeps killing its worker
// is dead after max attempts, not run for ever.
func TestLeaseExpiryAfterLastAttemptBuries(t *testing.T) {
	e := newEnv(t)
	w := e.worker("w", func(q *queue.Queue) {
		q.Register("work", queue.Kind{Handler: func(context.Context, queue.Job) (any, error) { t.Error("ran"); return nil, nil }})
	})
	id := e.enqueue(t, w, "work", "", 1)
	if err := e.db.InTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
		_, _, err := tx.ClaimQueueJobs(e.clk.Now(), "dead", time.Minute, []string{"work"}, 1)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.clk.Add(2 * time.Minute)
	e.tick(t, w)
	if j := e.job(t, id); j.Status != store.QueueDead || j.LastError == "" {
		t.Errorf("job = %s %q", j.Status, j.LastError)
	}
	if e.auditActions(t)["queue.job_dead"] != 1 {
		t.Error("no queue.job_dead event")
	}
}

// TestHeartbeatKeepsTheLease: a job that outlives its lease is not taken by
// another worker while its heartbeat runs.
func TestHeartbeatKeepsTheLease(t *testing.T) {
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "alpha")
	var ran atomic.Int32
	release := make(chan struct{})
	reg := func(q *queue.Queue) {
		q.Register("slow", queue.Kind{Handler: func(context.Context, queue.Job) (any, error) {
			ran.Add(1)
			<-release
			return nil, nil
		}})
	}
	mk := func(owner string) *queue.Queue {
		q := &queue.Queue{DB: db, Owner: owner, Lease: 300 * time.Millisecond}
		reg(q)
		return q
	}
	w1, w2 := mk("w1"), mk("w2")
	if _, err := w1.Enqueue(t.Context(), tenantA, "slow", "", "", time.Time{}, 3); err != nil {
		t.Fatal(err)
	}
	if err := w1.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(900 * time.Millisecond) // three leases
	for time.Now().Before(deadline) {
		if err := w2.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ran.Load() != 1 {
		t.Fatalf("the job ran %d times while its heartbeat was alive", ran.Load())
	}
	close(release)
	w1.Wait()
	w2.Wait()
}

// TestRestartResumesWork: a new process finds the queued jobs and the one the
// old process was running when it died.
func TestRestartResumesWork(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	ran := map[string]int{}
	reg := func(q *queue.Queue) {
		q.Register("work", queue.Kind{Handler: func(_ context.Context, j queue.Job) (any, error) {
			mu.Lock()
			ran[j.ID]++
			mu.Unlock()
			return nil, nil
		}})
	}
	old := e.worker("old", reg)
	a, b, c := e.enqueue(t, old, "work", "", 3), e.enqueue(t, old, "work", "", 3), e.enqueue(t, old, "work", "", 3)
	if err := e.db.InTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
		_, _, err := tx.ClaimQueueJobs(e.clk.Now(), "old", time.Minute, []string{"work"}, 1) // running when it died
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.clk.Add(2 * time.Minute)
	fresh := e.worker("fresh", reg)
	e.tick(t, fresh)
	for _, id := range []string{a, b, c} {
		if ran[id] != 1 || e.job(t, id).Status != store.QueueSucceeded {
			t.Errorf("job %s ran %d times, status %s", id, ran[id], e.job(t, id).Status)
		}
	}
}

// TestGracefulShutdownReleasesLeases: a job still running when the grace
// period ends is cancelled and handed back (queued, attempt not used).
func TestGracefulShutdownReleasesLeases(t *testing.T) {
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "alpha")
	started := make(chan struct{})
	q := &queue.Queue{DB: db, Owner: "w1", Poll: 5 * time.Millisecond, ShutdownGrace: 50 * time.Millisecond}
	q.Register("slow", queue.Kind{Handler: func(ctx context.Context, _ queue.Job) (any, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	if _, err := q.Enqueue(t.Context(), tenantA, "slow", "", "", time.Time{}, 3); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { q.Run(ctx); close(done) }()
	<-started
	stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	var j *store.QueueJob
	if err := db.ReadTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
		js, err := tx.QueueJobs(store.QueueJobFilter{})
		if len(js) == 1 {
			j = js[0]
		}
		return err
	}); err != nil || j == nil {
		t.Fatalf("jobs: %v %v", j, err)
	}
	if j.Status != store.QueueQueued || j.Attempts != 0 || j.LeaseOwner != nil {
		t.Errorf("after shutdown: %s attempts %d owner %v", j.Status, j.Attempts, j.LeaseOwner)
	}
}

// TestBackoffRetriesThenDeadLetterThenOperatorRetry follows a failing job
// through its backoff waits, its last attempt, the dead letter and a retry.
func TestBackoffRetriesThenDeadLetterThenOperatorRetry(t *testing.T) {
	e := newEnv(t)
	var calls atomic.Int32
	fail := atomic.Bool{}
	fail.Store(true)
	w := e.worker("w", func(q *queue.Queue) {
		q.Register("flaky", queue.Kind{Actor: "flaky.actor", Handler: func(context.Context, queue.Job) (any, error) {
			calls.Add(1)
			if fail.Load() {
				return nil, errors.New("boom")
			}
			return map[string]int{"done": 1}, nil
		}})
	})
	id := e.enqueue(t, w, "flaky", "", 3)

	e.tick(t, w) // attempt 1 fails: wait 10s
	j := e.job(t, id)
	if j.Status != store.QueueFailed || j.Attempts != 1 || j.LastError != "boom" || !j.RunAt.Equal(e.clk.Now().Add(10*time.Second)) {
		t.Fatalf("after attempt 1: %s attempts %d err %q run_at %v (now %v)", j.Status, j.Attempts, j.LastError, j.RunAt, e.clk.Now())
	}
	e.clk.Add(9 * time.Second)
	e.tick(t, w)
	if calls.Load() != 1 {
		t.Fatal("ran before its backoff ended")
	}
	e.clk.Add(time.Second)
	e.tick(t, w) // attempt 2 fails: wait 20s
	if j = e.job(t, id); j.Status != store.QueueFailed || j.Attempts != 2 || !j.RunAt.Equal(e.clk.Now().Add(20*time.Second)) {
		t.Fatalf("after attempt 2: %s attempts %d run_at %v", j.Status, j.Attempts, j.RunAt)
	}
	e.clk.Add(20 * time.Second)
	e.tick(t, w) // attempt 3 fails: max attempts, dead
	if j = e.job(t, id); j.Status != store.QueueDead || j.Attempts != 3 || j.FinishedAt == nil {
		t.Fatalf("after attempt 3: %s attempts %d", j.Status, j.Attempts)
	}
	e.clk.Add(time.Hour)
	e.tick(t, w)
	if calls.Load() != 3 {
		t.Fatalf("a dead job ran again: %d calls", calls.Load())
	}
	acts := e.auditActions(t)
	if acts["queue.job_dead"] != 1 || acts["job.failed"] != 3 {
		t.Errorf("audit events = %v", acts)
	}
	runs := e.runs(t, "flaky")
	if len(runs) != 3 || runs[0].Actor != "flaky.actor" {
		t.Fatalf("job runs = %d", len(runs))
	}

	// the operator retry gives it a fresh budget
	fail.Store(false)
	if err := e.db.InTenant(t.Context(), tenantA, func(tx *store.TenantTx) error { return w.Retry(tx, id, "olu") }); err != nil {
		t.Fatal(err)
	}
	if err := e.db.InTenant(t.Context(), tenantA, func(tx *store.TenantTx) error { return w.Retry(tx, id, "olu") }); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("retrying a job that is not dead = %v", err)
	}
	e.tick(t, w)
	if j = e.job(t, id); j.Status != store.QueueSucceeded || j.Attempts != 1 || j.LastError != "" {
		t.Errorf("after retry: %s attempts %d err %q", j.Status, j.Attempts, j.LastError)
	}
	if e.auditActions(t)["queue.job_retried"] != 1 {
		t.Error("no queue.job_retried event")
	}
}

func TestPermanentErrorAndPanicGoDeadOrRetry(t *testing.T) {
	e := newEnv(t)
	w := e.worker("w", func(q *queue.Queue) {
		q.Register("perm", queue.Kind{Handler: func(context.Context, queue.Job) (any, error) {
			return nil, queue.Permanent(errors.New("bad payload"))
		}})
		q.Register("panic", queue.Kind{Handler: func(context.Context, queue.Job) (any, error) { panic("oops") }})
	})
	perm, pan := e.enqueue(t, w, "perm", "", 5), e.enqueue(t, w, "panic", "", 5)
	e.tick(t, w)
	if j := e.job(t, perm); j.Status != store.QueueDead || j.Attempts != 1 {
		t.Errorf("permanent error: %s attempts %d", j.Status, j.Attempts)
	}
	if j := e.job(t, pan); j.Status != store.QueueFailed || j.LastError == "" {
		t.Errorf("panic: %s %q", j.Status, j.LastError)
	}
}

func TestIdempotencyKeyMakesOneJob(t *testing.T) {
	e := newEnv(t)
	w := e.worker("w", func(q *queue.Queue) {
		q.Register("work", queue.Kind{Handler: func(context.Context, queue.Job) (any, error) { return nil, nil }})
	})
	for i, want := range []bool{true, false} {
		got, err := w.Enqueue(t.Context(), tenantA, "work", "{}", "once", time.Time{}, 3)
		if err != nil || got != want {
			t.Errorf("enqueue %d = %v, %v; want %v", i, got, err, want)
		}
	}
	e.tick(t, w)
	if got, err := w.Enqueue(t.Context(), tenantA, "work", "{}", "once", time.Time{}, 3); err != nil || got { // even after it succeeded
		t.Errorf("enqueue after success = %v, %v", got, err)
	}
	if n := len(e.jobs(t, store.QueueJobFilter{})); n != 1 {
		t.Errorf("%d jobs", n)
	}
}

// TestScheduleEnqueuesOncePerWindowUnderTwoWorkers: two workers tick the same
// schedule at once for several windows; each window yields one job, and after
// downtime a schedule fires once rather than once per missed window.
func TestScheduleEnqueuesOncePerWindowUnderTwoWorkers(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	windows := map[string]int{}
	reg := func(q *queue.Queue) {
		q.Register("beat", queue.Kind{Handler: func(_ context.Context, j queue.Job) (any, error) {
			mu.Lock()
			windows[j.ID]++
			mu.Unlock()
			return nil, nil
		}})
		q.Schedule("beat", "beat", "@every 1m", 3)
	}
	w1, w2 := e.worker("w1", reg), e.worker("w2", reg)
	both := func() {
		var wg sync.WaitGroup
		for _, w := range []*queue.Queue{w1, w2} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 5; i++ {
					if err := w.Tick(context.Background()); err != nil {
						t.Error(err)
					}
					w.Wait()
				}
			}()
		}
		wg.Wait()
	}
	both() // the first window opens when the schedule is created
	if n := len(e.jobs(t, store.QueueJobFilter{Kind: "beat"})); n != 1 {
		t.Fatalf("window 1: %d jobs", n)
	}
	for w := 2; w <= 4; w++ {
		e.clk.Add(61 * time.Second)
		both()
		if n := len(e.jobs(t, store.QueueJobFilter{Kind: "beat"})); n != w {
			t.Fatalf("window %d: %d jobs", w, n)
		}
	}
	e.clk.Add(30 * time.Minute) // downtime: one catch-up run, not thirty
	both()
	js := e.jobs(t, store.QueueJobFilter{Kind: "beat"})
	if len(js) != 5 {
		t.Fatalf("after downtime: %d jobs", len(js))
	}
	for _, j := range js {
		if windows[j.ID] != 1 || j.Status != store.QueueSucceeded || j.ScheduleID == nil {
			t.Errorf("job %s ran %d times, status %s, schedule %v", j.ID, windows[j.ID], j.Status, j.ScheduleID)
		}
	}
	var ss []*store.QueueSchedule
	if err := e.db.ReadTenant(t.Context(), tenantA, func(tx *store.TenantTx) (err error) { ss, err = tx.QueueSchedules(); return err }); err != nil {
		t.Fatal(err)
	}
	if len(ss) != 1 || ss[0].Name != "beat" || ss[0].LastEnqueuedAt == nil || !ss[0].NextRunAt.After(e.clk.Now()) {
		t.Errorf("schedules = %+v", ss)
	}
}

// TestScheduleSpecChangeKeepsTheClock: re-declaring a schedule with another
// spec updates it without moving its next run.
func TestScheduleSpecChangeKeepsTheClock(t *testing.T) {
	e := newEnv(t)
	mk := func(spec string) *queue.Queue {
		return e.worker("w", func(q *queue.Queue) {
			q.Register("beat", queue.Kind{Handler: func(context.Context, queue.Job) (any, error) { return nil, nil }})
			q.Schedule("beat", "beat", spec, 3)
		})
	}
	e.tick(t, mk("@every 1m"))
	e.tick(t, mk("*/5 * * * *"))
	var s *store.QueueSchedule
	if err := e.db.ReadTenant(t.Context(), tenantA, func(tx *store.TenantTx) (err error) { s, err = tx.QueueSchedule("beat"); return err }); err != nil {
		t.Fatal(err)
	}
	if s.Spec != "*/5 * * * *" || !s.NextRunAt.Equal(e.clk.Now().Add(time.Minute)) {
		t.Errorf("schedule = %q next %v", s.Spec, s.NextRunAt)
	}
}
