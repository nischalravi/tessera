// Package queue is Tessera's durable job queue (issue #300): leased,
// retried with jittered backoff, dead-lettered after max attempts, with
// recurring work as schedule rows. It runs on SQLite and Postgres and is safe
// to run on several instances at once: a job is claimed by setting a lease in
// one write transaction (BEGIN IMMEDIATE on SQLite, FOR UPDATE SKIP LOCKED on
// Postgres), and the lease holder heartbeats until it finishes. A worker that
// dies leaves a lease that expires, and the job is claimed again.
//
// Delivery is at least once: a handler must be safe to run again.
//
// The queue is per tenant. Every statement goes through the tenant-scoped
// store handle; a worker finds the tenants the way the sweepers do, through
// the active tenant list.
package queue

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Job is a claimed job as a handler sees it.
type Job struct {
	ID          string
	Tenant      tenancy.ID
	Kind        string
	Payload     string // JSON
	Attempt     int    // 1 on the first run
	MaxAttempts int
	ScheduleID  string // set when a schedule enqueued it
}

// Handler runs a job. A nil result and nil error mean "nothing to report": no
// job run is recorded (the sweepers run every 30 seconds and mostly find
// nothing). A non-nil result, or an error, is recorded in the job_runs
// history; an error retries the job with backoff until MaxAttempts.
type Handler func(ctx context.Context, j Job) (result any, err error)

// Kind registers a handler.
type Kind struct {
	Handler Handler
	// Actor names the job in its job_runs record and audit events.
	Actor string
	// Method and Route, when set, are the API route that runs the same work on
	// demand; the recorded runs then carry them so the run history can retry
	// them (see jobs.Record).
	Method, Route string
}

type permanent struct{ err error }

func (p permanent) Error() string { return p.err.Error() }
func (p permanent) Unwrap() error { return p.err }

// Permanent marks a handler error as not worth retrying: the job goes
// straight to dead.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return permanent{err}
}

var kindRE = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

// Queue holds the handler registry and the worker. Set the exported fields
// before Run; zero values take the defaults noted.
type Queue struct {
	DB *store.DB
	// Clock defaults to time.Now.
	Clock func() time.Time
	// Owner names this worker in leases; the default is host-pid-random.
	Owner string
	// Concurrency is how many jobs run at once (4).
	Concurrency int
	// Poll is how often Run looks for work (2s).
	Poll time.Duration
	// Lease is how long a claim lasts without a heartbeat (60s); the
	// heartbeat runs every Lease/3.
	Lease time.Duration
	// ShutdownGrace is how long Run lets running jobs finish after its context
	// ends before cancelling them and releasing their leases (10s).
	ShutdownGrace time.Duration
	Backoff       Backoff
	// Retention is how long succeeded jobs are kept (7 days); see Prune.
	Retention time.Duration
	Log       *slog.Logger

	mu        sync.Mutex
	kinds     map[string]Kind
	schedules []scheduleDef
	ensured   map[tenancy.ID]bool

	initOnce sync.Once
	sem      chan struct{}
	wg       sync.WaitGroup
	rot      atomic.Int64
	workCtx  context.Context
	cancel   context.CancelFunc
}

type scheduleDef struct {
	name, kind, payload string
	spec                *Spec
	maxAttempts         int
}

func (q *Queue) init() {
	q.initOnce.Do(func() {
		if q.Clock == nil {
			q.Clock = time.Now
		}
		if q.Owner == "" {
			host, _ := os.Hostname()
			var b [4]byte
			_, _ = rand.Read(b[:])
			q.Owner = fmt.Sprintf("%s-%d-%s", host, os.Getpid(), hex.EncodeToString(b[:]))
		}
		if q.Concurrency <= 0 {
			q.Concurrency = 4
		}
		if q.Poll <= 0 {
			q.Poll = 2 * time.Second
		}
		if q.Lease <= 0 {
			q.Lease = 60 * time.Second
		}
		if q.ShutdownGrace <= 0 {
			q.ShutdownGrace = 10 * time.Second
		}
		if q.Backoff.Base <= 0 {
			q.Backoff = DefaultBackoff
		}
		if q.Retention <= 0 {
			q.Retention = 7 * 24 * time.Hour
		}
		if q.Log == nil {
			q.Log = slog.Default()
		}
		q.sem = make(chan struct{}, q.Concurrency)
		q.workCtx, q.cancel = context.WithCancel(context.Background())
		q.ensured = map[tenancy.ID]bool{}
	})
}

// Register adds the handler of a kind. It panics on a bad or repeated kind
// (a programming error, found at startup).
func (q *Queue) Register(kind string, k Kind) {
	if !kindRE.MatchString(kind) || k.Handler == nil {
		panic(fmt.Sprintf("queue: bad registration of kind %q", kind))
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.kinds == nil {
		q.kinds = map[string]Kind{}
	}
	if _, dup := q.kinds[kind]; dup {
		panic(fmt.Sprintf("queue: kind %q registered twice", kind))
	}
	q.kinds[kind] = k
}

// Schedule declares a recurring job, created for every active tenant the
// first time the worker sees it. spec is "@every 30s" or a cron expression
// (see ParseSpec). It panics on a bad spec or an unregistered kind.
func (q *Queue) Schedule(name, kind, spec string, maxAttempts int) {
	sp, err := ParseSpec(spec)
	if err != nil {
		panic(err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.kinds[kind]; !ok || !kindRE.MatchString(name) {
		panic(fmt.Sprintf("queue: bad schedule %q of kind %q", name, kind))
	}
	q.schedules = append(q.schedules, scheduleDef{name: name, kind: kind, spec: sp, maxAttempts: maxAttempts})
}

// Kinds lists the registered kinds, sorted.
func (q *Queue) Kinds() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]string, 0, len(q.kinds))
	for k := range q.kinds {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Enqueue adds a job to the tenant's queue. With a non-empty key, enqueueing
// the same kind and key again is a no-op (created is false), whatever the
// first job's status. runAt zero means now.
func (q *Queue) Enqueue(ctx context.Context, t tenancy.ID, kind, payload, key string, runAt time.Time, maxAttempts int) (created bool, err error) {
	q.init()
	err = q.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		created, err = q.EnqueueTx(tx, kind, payload, key, runAt, maxAttempts)
		return err
	})
	return created, err
}

// EnqueueTx is Enqueue inside the caller's transaction, so the job exists
// exactly when the caller's change does.
func (q *Queue) EnqueueTx(tx *store.TenantTx, kind, payload, key string, runAt time.Time, maxAttempts int) (bool, error) {
	q.init()
	if !kindRE.MatchString(kind) {
		return false, fmt.Errorf("queue: bad kind %q", kind)
	}
	now := q.Clock()
	if runAt.IsZero() {
		runAt = now
	}
	j := &store.QueueJob{Kind: kind, Payload: payload, RunAt: runAt, MaxAttempts: maxAttempts}
	if key != "" {
		j.IdempotencyKey = &key
	}
	return tx.EnqueueQueueJob(j, now)
}

// ---------------------------------------------------------------- worker

// Run works the queue until ctx ends: every Poll it makes schedules due,
// claims work and runs it. When ctx ends it stops claiming, waits up to
// ShutdownGrace for running jobs, then cancels them; jobs interrupted that way
// are released (queued again, no attempt used). Run returns when all have stopped.
func (q *Queue) Run(ctx context.Context) {
	q.init()
	t := time.NewTicker(q.Poll)
	defer t.Stop()
	for {
		if err := q.Tick(ctx); err != nil && ctx.Err() == nil {
			q.Log.Error("queue tick failed", "err", err)
		}
		select {
		case <-ctx.Done():
			q.Shutdown()
			return
		case <-t.C:
		}
	}
}

// Shutdown waits for running jobs up to ShutdownGrace, then cancels them and
// waits for their leases to be released. Run calls it; tests may too.
func (q *Queue) Shutdown() {
	q.init()
	done := make(chan struct{})
	go func() { q.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(q.ShutdownGrace):
		q.cancel()
		<-done
	}
}

// Wait blocks until the jobs started so far have finished (for tests).
func (q *Queue) Wait() { q.wg.Wait() }

// Tick is one poll: for every active tenant it makes the declared schedules
// exist, enqueues the due ones, and claims and starts due jobs while there is
// capacity. It returns before the started jobs finish (see Wait). An error in
// one tenant does not stop the others.
func (q *Queue) Tick(ctx context.Context) error {
	q.init()
	tenants, err := q.DB.ActiveTenants(ctx)
	if err != nil {
		return err
	}
	var errs []error
	// Start at a different tenant each tick, so a tenant with a lot of work
	// cannot always take the free slots before the others are looked at.
	if n := len(tenants); n > 1 {
		start := int(q.rot.Add(1) % int64(n))
		tenants = append(slices.Clone(tenants[start:]), tenants[:start]...)
	}
	for _, t := range tenants {
		if ctx.Err() != nil {
			return errors.Join(append(errs, ctx.Err())...)
		}
		if err := q.tickTenant(ctx, t.ID); err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t.Slug, err))
		}
	}
	return errors.Join(errs...)
}

func (q *Queue) tickTenant(ctx context.Context, t tenancy.ID) error {
	if err := q.ensureSchedules(ctx, t); err != nil {
		return err
	}
	if err := q.FireSchedules(ctx, t); err != nil {
		return err
	}
	return q.claim(ctx, t)
}

func (q *Queue) ensureSchedules(ctx context.Context, t tenancy.ID) error {
	q.mu.Lock()
	done, defs := q.ensured[t], slices.Clone(q.schedules)
	q.mu.Unlock()
	if done || len(defs) == 0 {
		return nil
	}
	err := q.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		now := q.Clock()
		for _, d := range defs {
			if err := tx.EnsureQueueSchedule(&store.QueueSchedule{Name: d.name, Kind: d.kind, Payload: d.payload,
				Spec: d.spec.String(), MaxAttempts: d.maxAttempts, NextRunAt: d.spec.First(now)}, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		q.mu.Lock()
		q.ensured[t] = true
		q.mu.Unlock()
	}
	return err
}

// FireSchedules enqueues the tenant's due schedules, once per window: the
// schedule is moved to its next time and the job enqueued (keyed by the
// window) in one transaction, so two workers, or a worker that crashes
// half-way, never enqueue a window twice or skip it. After downtime a
// schedule fires once, not once per missed window.
func (q *Queue) FireSchedules(ctx context.Context, t tenancy.ID) error {
	q.init()
	now := q.Clock()
	var due bool
	if err := q.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		ss, err := tx.DueQueueSchedules(now)
		due = len(ss) > 0
		return err
	}); err != nil || !due {
		return err
	}
	return q.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		ss, err := tx.DueQueueSchedules(now)
		if err != nil {
			return err
		}
		for _, s := range ss {
			sp, err := ParseSpec(s.Spec)
			if err != nil {
				q.Log.Error("queue schedule has a bad spec; skipped", "schedule", s.Name, "err", err)
				continue
			}
			if err := tx.AdvanceQueueSchedule(s.ID, s.NextRunAt, sp.Next(now), now); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					continue
				}
				return err
			}
			key := "schedule:" + s.Name + ":" + store.RT(s.NextRunAt)
			sid := s.ID
			if _, err := tx.EnqueueQueueJob(&store.QueueJob{Kind: s.Kind, Payload: s.Payload, IdempotencyKey: &key,
				ScheduleID: &sid, RunAt: s.NextRunAt, MaxAttempts: s.MaxAttempts}, now); err != nil {
				return err
			}
		}
		return nil
	})
}

func (q *Queue) registeredKinds() []string { return q.Kinds() }

func (q *Queue) claim(ctx context.Context, t tenancy.ID) error {
	kinds := q.registeredKinds()
	if len(kinds) == 0 {
		return nil
	}
	n := 0
	for n < q.Concurrency {
		select {
		case q.sem <- struct{}{}:
			n++
			continue
		default:
		}
		break
	}
	if n == 0 {
		return nil
	}
	free := func(k int) {
		for i := 0; i < k; i++ {
			<-q.sem
		}
	}
	now := q.Clock()
	var due bool
	if err := q.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) (err error) {
		due, err = tx.HasDueQueueJobs(now, kinds)
		return err
	}); err != nil || !due {
		free(n)
		return err
	}
	var claimed []*store.QueueJob
	err := q.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		var dead []*store.QueueJob
		var err error
		claimed, dead, err = tx.ClaimQueueJobs(now, q.Owner, q.Lease, kinds, n)
		if err != nil {
			return err
		}
		for _, j := range dead {
			if err := auditDead(tx, now, j); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		free(n)
		return err
	}
	free(n - len(claimed))
	for _, j := range claimed {
		q.wg.Add(1)
		go q.run(t, j)
	}
	return nil
}

func auditDead(tx *store.TenantTx, now time.Time, j *store.QueueJob) error {
	return tx.Audit(now, "queue.worker", "queue.job_dead", ojson.Object{{Key: "job_id", Value: j.ID},
		{Key: "kind", Value: j.Kind}, {Key: "attempts", Value: j.Attempts}, {Key: "error", Value: j.LastError}})
}

// run executes one claimed job: heartbeat while the handler runs, then
// complete, reschedule, bury or release it.
func (q *Queue) run(t tenancy.ID, sj *store.QueueJob) {
	defer q.wg.Done()
	defer func() { <-q.sem }()
	q.mu.Lock()
	k := q.kinds[sj.Kind]
	q.mu.Unlock()
	job := Job{ID: sj.ID, Tenant: t, Kind: sj.Kind, Payload: sj.Payload, Attempt: sj.Attempts, MaxAttempts: sj.MaxAttempts}
	if sj.ScheduleID != nil {
		job.ScheduleID = *sj.ScheduleID
	}
	bg := context.WithoutCancel(q.workCtx) // bookkeeping must outlive a cancelled shutdown
	hctx, cancel := context.WithCancel(q.workCtx)
	defer cancel()

	var lost bool
	var lostMu sync.Mutex
	stop := make(chan struct{})
	hbDone := make(chan struct{})
	go func() {
		defer close(hbDone)
		tk := time.NewTicker(q.Lease / 3)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				err := q.DB.InTenant(bg, t, func(tx *store.TenantTx) error {
					return tx.HeartbeatQueueJob(job.ID, q.Owner, q.Clock(), q.Lease)
				})
				if errors.Is(err, store.ErrNotFound) {
					lostMu.Lock()
					lost = true
					lostMu.Unlock()
					cancel() // another worker owns the job now
					return
				}
				if err != nil {
					q.Log.Error("queue heartbeat failed", "job", job.ID, "kind", job.Kind, "err", err)
				}
			}
		}
	}()

	started := q.Clock()
	result, err := call(hctx, k.Handler, job)
	close(stop)
	<-hbDone
	finished := q.Clock()
	lostMu.Lock()
	gone := lost
	lostMu.Unlock()
	if gone {
		q.Log.Warn("queue lease lost; leaving the job to its new owner", "job", job.ID, "kind", job.Kind)
		return
	}
	if err != nil && q.workCtx.Err() != nil && errors.Is(err, context.Canceled) {
		// Shutdown interrupted it: hand it back without using the attempt.
		if rerr := q.DB.InTenant(bg, t, func(tx *store.TenantTx) error {
			return tx.ReleaseQueueJob(job.ID, q.Owner, finished)
		}); rerr != nil {
			q.Log.Error("queue release failed", "job", job.ID, "kind", job.Kind, "err", rerr)
		}
		return
	}
	if ferr := q.finish(bg, job, finished, err); ferr != nil {
		q.Log.Error("queue bookkeeping failed", "job", job.ID, "kind", job.Kind, "err", ferr)
	}
	if err != nil || result != nil {
		trigger := "schedule"
		if job.Attempt > 1 {
			trigger = "retry"
		}
		st := jobs.Start{Kind: job.Kind, Trigger: trigger, Method: k.Method, Route: k.Route, Path: k.Route, Actor: k.Actor}
		if st.Actor == "" {
			st.Actor = "queue.worker"
		}
		if rerr := jobs.Record(bg, q.DB, t, st, started, finished, result, err); rerr != nil {
			q.Log.Error("queue: record job run", "job", job.ID, "kind", job.Kind, "err", rerr)
		}
	}
}

// call runs a handler; a panic is an error, not a dead worker.
func call(ctx context.Context, h Handler, j Job) (result any, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("handler panicked: %v", p)
		}
	}()
	return h(ctx, j)
}

// finish records the handler's outcome on the job.
func (q *Queue) finish(ctx context.Context, j Job, now time.Time, runErr error) error {
	return q.DB.InTenant(ctx, j.Tenant, func(tx *store.TenantTx) error {
		if runErr == nil {
			return ignoreLost(tx.CompleteQueueJob(j.ID, q.Owner, now))
		}
		msg := jobs.ErrorSummary(runErr)
		var retryAt *time.Time
		var perm permanent
		if j.Attempt < j.MaxAttempts && !errors.As(runErr, &perm) {
			at := now.Add(q.Backoff.Delay(j.Attempt))
			retryAt = &at
		}
		if err := tx.FailQueueJob(j.ID, q.Owner, now, msg, retryAt); err != nil {
			return ignoreLost(err)
		}
		if retryAt == nil {
			return auditDead(tx, now, &store.QueueJob{ID: j.ID, Kind: j.Kind, Attempts: j.Attempt, LastError: msg})
		}
		return nil
	})
}

// ignoreLost: the lease moved to another worker between the handler's end and
// this write; that worker's outcome stands.
func ignoreLost(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// Retry puts a dead job back in the queue with a fresh attempt budget and
// audits it, in the caller's transaction (the operator retry).
// store.ErrNotFound: no such dead job.
func (q *Queue) Retry(tx *store.TenantTx, id, actor string) error {
	q.init()
	j, err := tx.QueueJob(id)
	if err != nil {
		return err
	}
	now := q.Clock()
	if err := tx.RetryDeadQueueJob(id, now); err != nil {
		return err
	}
	return tx.Audit(now, actor, "queue.job_retried", ojson.Object{{Key: "job_id", Value: id}, {Key: "kind", Value: j.Kind},
		{Key: "attempts", Value: j.Attempts}, {Key: "error", Value: j.LastError}})
}

// Prune deletes the tenant's succeeded jobs older than Retention.
func (q *Queue) Prune(tx *store.TenantTx) (int64, error) {
	q.init()
	return tx.PruneQueueJobs(q.Clock().Add(-q.Retention))
}
