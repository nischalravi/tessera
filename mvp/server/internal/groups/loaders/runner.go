package loaders

import (
	"context"
	"errors"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Runner is the scheduler of loaders (Admin > Jobs), started next to the
// engine's and the history's runners in cmd/tessera. Every Tick it visits the
// active tenants and runs each enabled loader that is due:
//
//   - a full run when its cron schedule has fired since the later of its last
//     full load, its last full attempt and its creation (a failed run waits for
//     the next firing: there is no retry storm);
//   - an incremental run every incremental_secs after the later of its last
//     incremental run and its last full load, once the loader has had a full load.
//
// A held loader is not run until its held run is decided. An error in one
// loader or tenant does not stop the others.
type Runner struct {
	Svc *Service
	// Tick is how often Loop wakes (default 30 seconds).
	Tick time.Duration
}

// JobStatus is the state of a loader as Admin > Jobs shows it.
type JobStatus struct {
	// State is idle, held or disabled.
	State string
	// NextFull is when the schedule fires next, zero if it never does or the
	// loader is not enabled. NextIncremental likewise.
	NextFull, NextIncremental time.Time
	// LastRun is the newest full or incremental run, nil if there is none.
	LastRun *store.GrpLoaderRun
	// LagSeconds is how long since the loader last applied a full or
	// incremental run, -1 if it never has.
	LagSeconds int64
}

// attempts are the last runs of a loader by kind (nil: none).
type attempts struct{ latest, full, incr *store.GrpLoaderRun }

func lastAttempts(tx *store.TenantTx, id string) (attempts, error) {
	var a attempts
	for kind, dst := range map[string]**store.GrpLoaderRun{"": &a.latest, store.RunFull: &a.full, store.RunIncremental: &a.incr} {
		r, err := tx.GrpLoaderLastRun(id, kind)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return a, err
		}
		*dst = r
	}
	return a, nil
}

func later(t time.Time, others ...*time.Time) time.Time {
	for _, o := range others {
		if o != nil && o.After(t) {
			t = *o
		}
	}
	return t
}

func startOf(r *store.GrpLoaderRun) *time.Time {
	if r == nil {
		return nil
	}
	return &r.StartedAt
}

// fullAfter is the time the schedule's next firing is counted from.
func fullAfter(l *store.GrpLoader, a attempts) time.Time {
	return later(l.CreatedAt, l.LastFullAt, startOf(a.full))
}

// incrementalDue is when the next incremental run is due (zero if the loader
// has none or has not had a full load).
func incrementalDue(l *store.GrpLoader, a attempts) time.Time {
	if l.IncrementalSecs == nil || l.LastFullAt == nil {
		return time.Time{}
	}
	base := later(*l.LastFullAt, l.LastIncrAt, startOf(a.incr))
	return base.Add(time.Duration(*l.IncrementalSecs) * time.Second)
}

// StatusOf computes the job status of a loader.
func StatusOf(tx *store.TenantTx, l *store.GrpLoader, now time.Time) (*JobStatus, error) {
	st := &JobStatus{State: "idle", LagSeconds: -1}
	switch l.Status {
	case store.LoaderHeld:
		st.State = "held"
	case store.LoaderDisabled:
		st.State = "disabled"
	}
	a, err := lastAttempts(tx, l.ID)
	if err != nil {
		return nil, err
	}
	st.LastRun = a.latest
	if applied := later(time.Time{}, l.LastFullAt, l.LastIncrAt); !applied.IsZero() {
		st.LagSeconds = int64(now.Sub(applied).Seconds())
	}
	if l.Status != store.LoaderEnabled {
		return st, nil
	}
	if sc, err := ParseSchedule(l.Schedule); err == nil {
		st.NextFull = sc.Next(fullAfter(l, a))
	}
	st.NextIncremental = incrementalDue(l, a)
	return st, nil
}

// Once runs one pass over every active tenant. It returns the first error.
func (r *Runner) Once(ctx context.Context) error {
	ctx = audit.WithSystemActor(ctx, "groups.loaders")
	tenants, err := r.Svc.DB.ActiveTenants(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, t := range tenants {
		if err := r.tenant(ctx, t); err != nil {
			r.Svc.log().Error("group loaders pass failed", "tenant", t.Slug, "err", err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

type due struct{ id, kind string }

func (r *Runner) tenant(ctx context.Context, t store.Tenant) error {
	now := r.Svc.now()
	var work []due
	err := r.Svc.DB.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) error {
		ls, err := tx.GrpLoaders()
		if err != nil {
			return err
		}
		for _, l := range ls {
			if l.Status != store.LoaderEnabled {
				continue
			}
			a, err := lastAttempts(tx, l.ID)
			if err != nil {
				return err
			}
			if sc, perr := ParseSchedule(l.Schedule); perr == nil && sc.Due(fullAfter(l, a), now) {
				work = append(work, due{l.ID, store.RunFull})
			} else if at := incrementalDue(l, a); !at.IsZero() && !now.Before(at) {
				work = append(work, due{l.ID, store.RunIncremental})
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	var first error
	for _, w := range work {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		run, err := r.Svc.Run(ctx, t.ID, w.id, w.kind, Actor{})
		switch {
		case err != nil:
			r.Svc.log().Error("group loader run failed", "tenant", t.Slug, "loader", w.id, "kind", w.kind, "err", err)
			if first == nil {
				first = err
			}
		case run != nil && run.Status != store.RunApplied:
			r.Svc.log().Warn("group loader run did not apply", "tenant", t.Slug, "loader", w.id, "kind", w.kind, "status", run.Status)
		}
	}
	return first
}

// Loop runs Once every Tick until ctx is done.
func (r *Runner) Loop(ctx context.Context) {
	tick := r.Tick
	if tick <= 0 {
		tick = 30 * time.Second
	}
	tk := time.NewTicker(tick)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			if err := r.Once(ctx); err != nil && ctx.Err() == nil {
				r.Svc.log().Error("group loaders pass failed", "err", err)
			}
		}
	}
}
