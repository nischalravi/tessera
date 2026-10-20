package engine

import (
	"context"
	"log/slog"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Runner is the engine's background job: for every active tenant it drains the
// engine queue (one chunk per transaction, so API writers interleave), runs
// the time wheel every WheelEvery or at the next date boundary, and verifies
// the tenant once every VerifyEvery. It is started next to the other
// background jobs in cmd/tessera.
type Runner struct {
	DB     *store.DB
	Engine *Engine
	Clock  timeutil.Clock
	Log    *slog.Logger

	// Tick is how often Loop wakes to look for queued work (default 5s).
	Tick time.Duration
	// WheelEvery is the time wheel's cadence (default 30s: dates take effect
	// within 60 seconds).
	WheelEvery time.Duration
	// VerifyEvery is how often a tenant is fully verified (default 24h).
	VerifyEvery time.Duration
	// MaxChunks bounds the queue chunks drained per tenant per pass (default 500).
	MaxChunks int

	lastWheel map[tenancy.ID]time.Time
}

func (r *Runner) defaults() {
	if r.Tick <= 0 {
		r.Tick = 5 * time.Second
	}
	if r.WheelEvery <= 0 {
		r.WheelEvery = 30 * time.Second
	}
	if r.VerifyEvery <= 0 {
		r.VerifyEvery = 24 * time.Hour
	}
	if r.MaxChunks <= 0 {
		r.MaxChunks = 500
	}
	if r.Log == nil {
		r.Log = slog.Default()
	}
	if r.Clock == nil {
		r.Clock = timeutil.System
	}
	if r.lastWheel == nil {
		r.lastWheel = map[tenancy.ID]time.Time{}
	}
}

// probe is what a pass reads before deciding whether to write.
type probe struct {
	queued   int
	st       *store.EngineState
	boundary *time.Time
}

// Once runs one pass over every active tenant and returns the earliest date
// boundary any tenant is waiting for (nil if none). An error in one tenant
// does not stop the others.
func (r *Runner) Once(ctx context.Context) (*time.Time, error) {
	r.defaults()
	ctx = audit.WithSystemActor(ctx, "groups.engine")
	tenants, err := r.DB.ActiveTenants(ctx)
	if err != nil {
		return nil, err
	}
	var next *time.Time
	var firstErr error
	for _, t := range tenants {
		b, err := r.tenant(ctx, t.ID)
		if err != nil {
			r.Log.Error("groups engine pass failed", "tenant", t.Slug, "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
		if b != nil && (next == nil || b.Before(*next)) {
			next = b
		}
	}
	return next, firstErr
}

func (r *Runner) tenant(ctx context.Context, id tenancy.ID) (*time.Time, error) {
	now := r.Clock()
	var p probe
	if err := r.DB.ReadTenant(ctx, id, func(tx *store.TenantTx) error {
		var err error
		if p.queued, err = tx.GrpQueueLen(); err != nil {
			return err
		}
		if p.st, err = tx.GrpEngineState(); err != nil {
			return err
		}
		if p.st.WheelAt != nil {
			p.boundary, err = tx.GrpNextBoundary(*p.st.WheelAt)
		}
		return err
	}); err != nil {
		return nil, err
	}
	if p.queued > 0 {
		for i := 0; i < r.MaxChunks; i++ {
			var did bool
			if err := r.DB.InTenant(ctx, id, func(tx *store.TenantTx) error {
				var err error
				did, err = r.Engine.Drain(tx, r.Clock())
				return err
			}); err != nil {
				return nil, err
			}
			if !did {
				break
			}
		}
	}
	if p.st.WheelAt == nil {
		return nil, nil // this tenant has never used groups
	}
	last := r.lastWheel[id]
	due := last.IsZero() || now.Sub(last) >= r.WheelEvery || (p.boundary != nil && !p.boundary.After(now))
	if due {
		if err := r.DB.InTenant(ctx, id, func(tx *store.TenantTx) error {
			_, err := r.Engine.Tick(tx, r.Clock())
			return err
		}); err != nil {
			return nil, err
		}
		r.lastWheel[id] = now
	}
	if p.st.VerifiedAt == nil {
		if err := r.DB.InTenant(ctx, id, func(tx *store.TenantTx) error { return tx.SetGrpVerifiedAt(now) }); err != nil {
			return nil, err
		}
	} else if now.Sub(*p.st.VerifiedAt) >= r.VerifyEvery {
		if err := r.DB.InTenant(ctx, id, func(tx *store.TenantTx) error {
			_, err := r.Engine.Verify(tx, r.Clock())
			return err
		}); err != nil {
			return nil, err
		}
	}
	return p.boundary, nil
}

// Loop runs Once until ctx is done, sleeping Tick, or until the next date
// boundary if that is sooner.
func (r *Runner) Loop(ctx context.Context) {
	r.defaults()
	for {
		next, err := r.Once(ctx)
		if err != nil && ctx.Err() == nil {
			r.Log.Error("groups engine failed", "err", err)
		}
		wait := r.Tick
		if next != nil {
			if d := next.Sub(r.Clock()) + time.Millisecond; d > 0 && d < wait {
				wait = d
			}
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
