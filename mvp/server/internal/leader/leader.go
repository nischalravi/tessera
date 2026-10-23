// Package leader runs each background loop on exactly one replica.
//
// On Postgres every loop has a named leader lease: a session-level advisory
// lock (store.DB.LeaderLocker). The replica holding the lock runs the loop;
// the others wait and retry, so they take over within Retry when the leader
// stops or its database session dies (Postgres drops the lock with the
// session). On SQLite there is one process and no election: Run just runs the
// loop. Queue jobs are not elected: they are leased per job (internal/queue).
package leader

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/obs"
)

// Lease is a held leader lease.
type Lease interface {
	// Lost is closed when the lease may no longer be held (the database
	// session failed). The holder must stop at once.
	Lost() <-chan struct{}
	// Release gives the lease up (idempotent).
	Release()
}

// Locker acquires leases by name. TryLock returns (nil, nil) when another
// holder has the lease; it never blocks waiting for it.
type Locker interface {
	TryLock(ctx context.Context, name string) (Lease, error)
}

// DefaultRetry is how often a standby replica tries to take a lease.
const DefaultRetry = 5 * time.Second

// Elector runs loops under leases. The zero Locker means a single process:
// every loop runs, every loop is its own leader.
type Elector struct {
	Locker Locker
	Log    *slog.Logger
	Retry  time.Duration // default DefaultRetry
	Loops  *obs.Loops    // default obs.DefaultLoops; tracked loops are dropped when leadership is lost

	mu     sync.Mutex
	status map[string]bool // loop -> this replica leads it
}

// Enabled reports whether leases are used (Postgres).
func (e *Elector) Enabled() bool { return e != nil && e.Locker != nil }

// Run runs fn as the loop `name`. With a Locker it waits for the lease, runs
// fn with a context that ends when the lease is lost or ctx ends, and goes
// back to waiting if fn returned because the lease was lost. tracked are the
// names fn registers in the loop tracker; they are dropped while this replica
// does not lead, so a standby never reports a stale loop as lagging. Run
// returns when ctx ends or fn returns with the lease still held.
func (e *Elector) Run(ctx context.Context, name string, tracked []string, fn func(ctx context.Context)) {
	if !e.Enabled() {
		e.set(name, true)
		fn(ctx)
		return
	}
	retry := e.Retry
	if retry <= 0 {
		retry = DefaultRetry
	}
	loops := e.Loops
	if loops == nil {
		loops = obs.DefaultLoops
	}
	for ctx.Err() == nil {
		lease, err := e.Locker.TryLock(ctx, name)
		if err != nil && ctx.Err() == nil {
			e.log().Warn("leader lease: cannot try", "loop", name, "err", err)
		}
		if lease == nil {
			e.set(name, false)
			select {
			case <-ctx.Done():
			case <-time.After(retry):
			}
			continue
		}
		e.set(name, true)
		e.log().Info("leader lease acquired", "loop", name)
		lctx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(ctx, cancel)
		go func() {
			select {
			case <-lease.Lost():
				cancel()
			case <-lctx.Done():
			}
		}()
		fn(lctx)
		lost := false
		select {
		case <-lease.Lost():
			lost = true
		default:
		}
		stop()
		cancel()
		lease.Release()
		e.set(name, false)
		loops.Unregister(tracked...)
		if !lost && ctx.Err() == nil {
			return // the loop ended by itself (nothing to run); do not spin
		}
		if lost {
			e.log().Warn("leader lease lost", "loop", name)
		}
	}
	e.set(name, false)
}

func (e *Elector) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

func (e *Elector) set(name string, leads bool) {
	e.mu.Lock()
	if e.status == nil {
		e.status = map[string]bool{}
	}
	e.status[name] = leads
	e.mu.Unlock()
	v := 0.0
	if leads {
		v = 1
	}
	obs.LoopLeader.Set(v, name)
}

// Status lists the loops and whether this replica leads each, sorted by name.
func (e *Elector) Status() []Status {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Status, 0, len(e.status))
	for n, l := range e.status {
		out = append(out, Status{Loop: n, Leader: l})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Loop < out[j].Loop })
	return out
}

// Status is one loop's leadership on this replica.
type Status struct {
	Loop   string `json:"loop"`
	Leader bool   `json:"leader"`
}
