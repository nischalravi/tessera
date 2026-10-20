package provisioning

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Runner is the background job of provisioning, started next to the engine's
// and the history's runners in cmd/tessera. For every provisioner of every
// active tenant it starts
//
//   - a full sync when one was asked for (a changed mark, config or mode, an
//     admin's request), or at the provisioner's daily time;
//   - an incremental sync of the group events after the provisioner's cursor
//     when it is active and has had a full sync: events are coalesced for
//     Coalesce, so a burst of changes becomes one pass, but a pass is never
//     delayed more than MaxWait after the oldest event.
//
// A run that fails for a reason outside the data (the target is down) is tried
// again after FailBackoff (incremental) or FailedFullRetry (full).
type Runner struct {
	Svc   *Service
	Clock timeutil.Clock
	Log   *slog.Logger

	Tick            time.Duration // how often Loop wakes (default 5s)
	Coalesce        time.Duration // quiet time before an incremental pass (default 2s)
	MaxWait         time.Duration // the longest an event waits (default 10s)
	FailBackoff     time.Duration // wait after a failed incremental run (default 30s)
	FailedFullRetry time.Duration // wait after a failed full run (default 5m)
	// RunTimeout bounds one run (default 30m).
	RunTimeout time.Duration

	lastFail map[string]time.Time
}

func (r *Runner) defaults() {
	if r.Tick <= 0 {
		r.Tick = 5 * time.Second
	}
	if r.Coalesce <= 0 {
		r.Coalesce = 2 * time.Second
	}
	if r.MaxWait <= 0 {
		r.MaxWait = 10 * time.Second
	}
	if r.FailBackoff <= 0 {
		r.FailBackoff = 30 * time.Second
	}
	if r.FailedFullRetry <= 0 {
		r.FailedFullRetry = 5 * time.Minute
	}
	if r.RunTimeout <= 0 {
		r.RunTimeout = 30 * time.Minute
	}
	if r.Log == nil {
		r.Log = slog.Default()
	}
	if r.Clock == nil {
		r.Clock = timeutil.System
	}
	if r.lastFail == nil {
		r.lastFail = map[string]time.Time{}
	}
}

// Once runs one pass over every active tenant. An error in one tenant does not
// stop the others; the first is returned.
func (r *Runner) Once(ctx context.Context) error {
	r.defaults()
	ctx = audit.WithSystemActor(ctx, "groups.provisioning")
	tenants, err := r.Svc.DB.ActiveTenants(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, t := range tenants {
		if err := r.tenant(ctx, t); err != nil {
			r.Log.Error("group provisioning pass failed", "tenant", t.Slug, "err", err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

type work struct {
	id   string
	kind string
}

func (r *Runner) tenant(ctx context.Context, t store.Tenant) error {
	now := r.Clock()
	var todo []work
	if err := r.Svc.DB.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) error {
		provs, err := tx.Provisioners()
		if err != nil {
			return err
		}
		for _, p := range provs {
			kind, err := r.decide(tx, p, now)
			if err != nil {
				return err
			}
			if kind != "" {
				todo = append(todo, work{p.ID, kind})
			}
		}
		return nil
	}); err != nil {
		return err
	}
	var first error
	for _, w := range todo {
		key := t.ID.String() + "|" + w.id
		runCtx, cancel := context.WithTimeout(ctx, r.RunTimeout)
		cause := store.CauseEngine
		rep, err := r.Svc.Run(runCtx, t.ID, w.id, RunOptions{Kind: w.kind, Cause: cause})
		cancel()
		switch {
		case errors.Is(err, ErrBusy), errors.Is(err, ErrPaused), errors.Is(err, ErrNotActive), errors.Is(err, store.ErrNotFound):
			continue
		case err != nil:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			r.lastFail[key] = now
			r.Log.Error("group provisioning run failed", "tenant", t.Slug, "provisioner", w.id, "kind", w.kind, "err", err)
			if first == nil {
				first = err
			}
			continue
		}
		delete(r.lastFail, key)
		if !rep.Idle {
			r.Log.Info("group provisioning run", "tenant", t.Slug, "provisioner", w.id, "kind", w.kind, "status", rep.Run.Status,
				"verified", rep.Summary.Verified, "drift", rep.Summary.Drift, "failed", rep.Summary.Failed)
		}
	}
	return first
}

// decide says which run, if any, a provisioner is due for.
func (r *Runner) decide(tx *store.TenantTx, p *store.Provisioner, now time.Time) (string, error) {
	if p.Mode == store.ProvModePaused {
		return "", nil
	}
	key := tx.Tenant().String() + "|" + p.ID
	if at, failed := r.lastFail[key]; failed && now.Sub(at) < r.FailBackoff {
		return "", nil
	}
	last, err := tx.LastSyncRun(p.ID, store.RunFull)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	if errors.Is(err, store.ErrNotFound) {
		last = nil
	}
	if p.NeedsFull {
		if last == nil || last.Status != store.RunFailed || now.Sub(last.StartedAt) >= r.FailedFullRetry {
			return store.RunFull, nil
		}
		return "", nil
	}
	if fullDue(p.FullSchedule, last, now) {
		return store.RunFull, nil
	}
	if p.Mode != store.ProvModeActive || last == nil || last.Status != store.RunDone || last.Mode != store.ProvModeActive {
		return "", nil
	}
	batch, err := events.Poll(tx, Consumer(p.ID), events.MaxBatch)
	if err != nil {
		return "", err
	}
	if len(batch) == 0 {
		due, err := tx.SyncGroupsRetryDue(p.ID, now.Add(-RetryAfter), 1)
		if err != nil || len(due) == 0 {
			return "", err
		}
		return store.RunIncremental, nil
	}
	// only events of groups and folders matter for the wait; the rest (our own
	// provisioning events) is acknowledged at once
	var newest, oldest time.Time
	for _, e := range batch {
		if e.ObjectType != store.EventObjGroup && e.ObjectType != store.EventObjFolder {
			continue
		}
		if oldest.IsZero() {
			oldest = e.OccurredAt
		}
		newest = e.OccurredAt
	}
	if !oldest.IsZero() && len(batch) < events.MaxBatch && now.Sub(newest) < r.Coalesce && now.Sub(oldest) < r.MaxWait {
		return "", nil // wait for the burst to end
	}
	return store.RunIncremental, nil
}

// fullDue reports whether the daily full sync is due: the provisioner's UTC
// time has passed since the last full run started.
func fullDue(schedule string, last *store.SyncRun, now time.Time) bool {
	minute, hour, ok := ParseSchedule(schedule)
	if !ok {
		return false
	}
	now = now.UTC()
	due := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, time.UTC)
	if due.After(now) {
		due = due.AddDate(0, 0, -1)
	}
	return last == nil || last.StartedAt.Before(due)
}

// Loop runs Once every Tick until ctx is done.
func (r *Runner) Loop(ctx context.Context) {
	r.defaults()
	tick := time.NewTicker(r.Tick)
	defer tick.Stop()
	for {
		if err := r.Once(ctx); err != nil && ctx.Err() == nil {
			r.Log.Error("group provisioning failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
