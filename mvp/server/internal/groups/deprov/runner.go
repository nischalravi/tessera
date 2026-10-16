package deprov

import (
	"context"
	"log/slog"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Runner is deprovisioning's background job: for every active tenant that has
// affiliations it reads the group events after the "deprov" cursor, looks for
// leavers, and removes what the open items' delays allow. It is started next to
// the other groups jobs in cmd/tessera.
type Runner struct {
	DB     *store.DB
	Engine *engine.Engine
	Clock  timeutil.Clock
	Log    *slog.Logger
	// Tick is how often Loop passes (default 10s).
	Tick time.Duration
	// Batch is how many events one transaction reads (default 200).
	Batch int
}

func (r *Runner) defaults() {
	if r.Tick <= 0 {
		r.Tick = 10 * time.Second
	}
	if r.Batch <= 0 || r.Batch > events.MaxBatch {
		r.Batch = 200
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
	ctx = audit.WithSystemActor(ctx, "groups.deprovisioning")
	tenants, err := r.DB.ActiveTenants(ctx)
	if err != nil {
		return err
	}
	var first error
	note := func(slug string, err error) {
		r.Log.Error("group deprovisioning pass failed", "tenant", slug, "err", err)
		if first == nil {
			first = err
		}
	}
	for _, t := range tenants {
		busy := false
		if err := r.DB.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			s, err := LoadSettings(tx)
			busy = len(s.Affiliations) > 0
			return err
		}); err != nil {
			note(t.Slug, err)
			continue
		}
		if !busy {
			continue
		}
		if err := r.DB.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			e := Env{Tx: tx, Now: r.Clock(), Engine: r.Engine}
			if _, err := Process(e, r.Batch); err != nil {
				return err
			}
			if _, err := ScanLeavers(e); err != nil {
				return err
			}
			_, err := Sweep(e)
			return err
		}); err != nil {
			note(t.Slug, err)
		}
	}
	return first
}

// Loop runs Once until ctx is done, sleeping Tick between passes.
func (r *Runner) Loop(ctx context.Context) {
	r.defaults()
	for {
		if err := r.Once(ctx); err != nil && ctx.Err() == nil {
			r.Log.Error("group deprovisioning failed", "err", err)
		}
		t := time.NewTimer(r.Tick)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
