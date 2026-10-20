package rules

import (
	"context"
	"log/slog"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Runner is the rules' background job: for every active tenant with events the
// "rules" cursor has not read, it fires the rules that react to them, a batch
// per transaction so API writers interleave. It is started next to the other
// groups jobs in cmd/tessera.
type Runner struct {
	DB      *store.DB
	Runtime *Runtime
	Clock   timeutil.Clock
	Log     *slog.Logger

	// Tick is how often Loop looks for new events (default 5s).
	Tick time.Duration
	// Batch is how many events one transaction reads (default 200).
	Batch int
	// MaxBatches bounds the batches per tenant per pass (default 50).
	MaxBatches int
}

func (r *Runner) defaults() {
	if r.Tick <= 0 {
		r.Tick = 5 * time.Second
	}
	if r.Batch <= 0 || r.Batch > events.MaxBatch {
		r.Batch = 200
	}
	if r.MaxBatches <= 0 {
		r.MaxBatches = 50
	}
	if r.Log == nil {
		r.Log = slog.Default()
	}
	if r.Clock == nil {
		r.Clock = timeutil.System
	}
}

// Once runs one pass over every active tenant. An error in one tenant does
// not stop the others; the first is returned.
func (r *Runner) Once(ctx context.Context) error {
	r.defaults()
	ctx = audit.WithSystemActor(ctx, "groups.rules")
	tenants, err := r.DB.ActiveTenants(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, t := range tenants {
		for i := 0; i < r.MaxBatches; i++ {
			var lag int64
			if err := r.DB.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) (err error) {
				lag, err = events.Lag(tx, Consumer)
				return err
			}); err != nil {
				r.Log.Error("group rules probe failed", "tenant", t.Slug, "err", err)
				if first == nil {
					first = err
				}
				break
			}
			if lag <= 0 {
				break
			}
			if err := r.DB.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
				_, err := r.Runtime.Process(tx, r.Clock(), r.Batch)
				return err
			}); err != nil {
				r.Log.Error("group rules pass failed", "tenant", t.Slug, "err", err)
				if first == nil {
					first = err
				}
				break
			}
		}
	}
	return first
}

// Loop runs Once until ctx is done, sleeping Tick between passes.
func (r *Runner) Loop(ctx context.Context) {
	r.defaults()
	for {
		if err := r.Once(ctx); err != nil && ctx.Err() == nil {
			r.Log.Error("group rules failed", "err", err)
		}
		t := time.NewTimer(r.Tick)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
