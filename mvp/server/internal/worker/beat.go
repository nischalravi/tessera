package worker

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Worker health. A worker beats every BeatEvery; one that has not beaten for
// StaleAfter is shown as stale (it crashed, is stuck, or lost the database),
// and its jobs come back when their leases expire (queue.Lease).
const (
	BeatEvery  = 10 * time.Second
	StaleAfter = 3 * BeatEvery
	// forgetAfter: a worker that stopped without saying so (a crash) is
	// forgotten after this long.
	forgetAfter = 24 * time.Hour
)

// Beater records the health of one queue worker, in every active tenant (a
// worker serves them all, and the health table is tenant-owned). A worker
// that stops cleanly removes its rows.
type Beater struct {
	DB      *store.DB
	Queue   *queue.Queue
	Mode    string // store.WorkerModeWorker or store.WorkerModeAPI
	Version string
	Every   time.Duration // BeatEvery
	Clock   func() time.Time
	Log     *slog.Logger

	started time.Time
}

func (b *Beater) now() time.Time {
	if b.Clock != nil {
		return b.Clock()
	}
	return time.Now().UTC()
}

func (b *Beater) log() *slog.Logger {
	if b.Log != nil {
		return b.Log
	}
	return slog.Default()
}

// Beat writes one heartbeat row per active tenant and forgets long-silent
// workers. A tenant that fails does not stop the others.
func (b *Beater) Beat(ctx context.Context) error {
	id := b.Queue.WorkerID()
	if b.started.IsZero() {
		b.started = b.now()
	}
	host, _ := os.Hostname()
	w := &store.QueueWorker{WorkerID: id, Mode: b.Mode, Hostname: host, PID: os.Getpid(), Version: b.Version,
		Kinds: strings.Join(b.Queue.Kinds(), ","), Concurrency: b.Queue.Concurrency, Running: b.Queue.Running(),
		StartedAt: b.started}
	tenants, err := b.DB.ActiveTenants(ctx)
	if err != nil {
		return err
	}
	var first error
	now := b.now()
	for _, t := range tenants {
		if err := b.DB.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			if err := tx.BeatQueueWorker(w, now); err != nil {
				return err
			}
			_, err := tx.PruneQueueWorkers(now.Add(-forgetAfter))
			return err
		}); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Run beats until ctx ends, then removes the worker's rows (so a clean stop
// does not look like a crash). Call it after the queue has shut down so the
// last beat's running count is not stale; it uses its own short context for
// the removal.
func (b *Beater) Run(ctx context.Context) {
	every := b.Every
	if every <= 0 {
		every = BeatEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := b.Beat(ctx); err != nil && ctx.Err() == nil {
			b.log().Warn("worker heartbeat failed", "err", err)
		}
		select {
		case <-ctx.Done():
			b.Forget()
			return
		case <-t.C:
		}
	}
}

// Serve works the queue and beats until ctx ends. The queue stops first: it
// stops claiming, lets running jobs finish for its ShutdownGrace and releases
// the leases of those it had to cancel (so another worker takes them at once).
// The heartbeat goes on meanwhile and is withdrawn last.
func Serve(ctx context.Context, q *queue.Queue, b *Beater) {
	beatCtx, stop := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})
	go func() { defer close(done); b.Run(beatCtx) }()
	q.Run(ctx)
	stop()
	<-done
}

// Forget removes the worker's rows in every tenant.
func (b *Beater) Forget() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id := b.Queue.WorkerID()
	tenants, err := b.DB.ActiveTenants(ctx)
	if err != nil {
		return
	}
	for _, t := range tenants {
		if err := b.DB.InTenant(ctx, t.ID, func(tx *store.TenantTx) error { return tx.DeleteQueueWorker(id) }); err != nil {
			b.log().Warn("worker: removing the health row failed", "err", err)
		}
	}
}
