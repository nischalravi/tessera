package attest

import (
	"context"
	"log/slog"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Runner is attestation's background job: for every active tenant that has
// attestation settings or an open campaign, it starts the campaigns that have
// come due and sweeps the open ones (reminders, overdue actions). It is started
// next to the other groups jobs in cmd/tessera.
type Runner struct {
	DB     *store.DB
	Engine *engine.Engine
	Clock  timeutil.Clock
	Log    *slog.Logger
	// Tick is how often Loop passes (default 1 minute).
	Tick time.Duration
}

func (r *Runner) defaults() {
	if r.Tick <= 0 {
		r.Tick = time.Minute
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
	ctx = audit.WithSystemActor(ctx, "groups.attestation")
	tenants, err := r.DB.ActiveTenants(ctx)
	if err != nil {
		return err
	}
	var first error
	note := func(slug string, err error) {
		r.Log.Error("group attestation pass failed", "tenant", slug, "err", err)
		if first == nil {
			first = err
		}
	}
	for _, t := range tenants {
		busy := false
		if err := r.DB.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			s, err := tx.GrpAttestSettingsEnabled()
			if err != nil {
				return err
			}
			open, err := tx.GrpAttestCampaigns(store.GrpAttestFilter{Status: store.AttestOpen, Limit: 1})
			busy = len(s) > 0 || len(open) > 0
			return err
		}); err != nil {
			note(t.Slug, err)
			continue
		}
		if !busy {
			continue
		}
		if err := r.DB.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			_, err := Pass(tx, r.Clock(), r.Engine, r.Log)
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
			r.Log.Error("group attestation failed", "err", err)
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
