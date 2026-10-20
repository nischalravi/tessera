package pit

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Runner is the background job of group history, started next to the engine's
// Runner in cmd/tessera. For every active tenant it
//
//   - writes the digest of every finished UTC day that has events and none yet,
//     from DigestDelay (00:05) after midnight; a server that was down catches up
//     on the days it missed, one transaction each;
//   - once a UTC day prunes events and intervals older than RetentionDays;
//   - every SampleEvery rebuilds the PIT rows of a sample of groups from their
//     events and compares them with what was stored (a difference is repaired
//     and recorded as groups.pit.mismatch).
//
// Digests are idempotent and retention is harmless to repeat; the sample
// schedule is kept in memory, so a restart postpones it by a week.
type Runner struct {
	DB    *store.DB
	Clock timeutil.Clock
	Log   *slog.Logger

	// RetentionDays is groups.retention_days (default DefaultRetentionDays).
	RetentionDays int
	// Tick is how often Loop wakes (default 1 minute).
	Tick time.Duration
	// DigestDelay is how long after midnight UTC a day is digested (default 5 minutes).
	DigestDelay time.Duration
	// SampleEvery is the cadence of the rebuild comparison (default 7 days).
	SampleEvery time.Duration
	// SampleSize is how many groups one comparison covers (default 20).
	SampleSize int

	retained    map[tenancy.ID]string
	lastSample  map[tenancy.ID]time.Time
	sampleAfter map[tenancy.ID]string
}

func (r *Runner) defaults() {
	if r.RetentionDays <= 0 {
		r.RetentionDays = DefaultRetentionDays
	}
	if r.Tick <= 0 {
		r.Tick = time.Minute
	}
	if r.DigestDelay <= 0 {
		r.DigestDelay = 5 * time.Minute
	}
	if r.SampleEvery <= 0 {
		r.SampleEvery = 7 * 24 * time.Hour
	}
	if r.SampleSize <= 0 {
		r.SampleSize = 20
	}
	if r.Log == nil {
		r.Log = slog.Default()
	}
	if r.Clock == nil {
		r.Clock = timeutil.System
	}
	if r.retained == nil {
		r.retained, r.lastSample, r.sampleAfter = map[tenancy.ID]string{}, map[tenancy.ID]time.Time{}, map[tenancy.ID]string{}
	}
}

// Once runs one pass over every active tenant. An error in one tenant does not
// stop the others; the first is returned.
func (r *Runner) Once(ctx context.Context) error {
	r.defaults()
	ctx = audit.WithSystemActor(ctx, "groups.pit")
	tenants, err := r.DB.ActiveTenants(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, t := range tenants {
		if err := r.tenant(ctx, t); err != nil {
			r.Log.Error("groups history pass failed", "tenant", t.Slug, "err", err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

func (r *Runner) tenant(ctx context.Context, t store.Tenant) error {
	now := r.Clock()
	var head store.GrpEventHead
	var days []string
	if err := r.DB.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) error {
		var err error
		if head, err = tx.GrpEventHead(); err != nil || head.LastSeq == 0 {
			return err
		}
		from := time.Unix(0, 0).UTC()
		if ds, err := tx.GrpDigests(1); err != nil {
			return err
		} else if len(ds) > 0 {
			last, _, err := ParseDay(ds[0].Day)
			if err != nil {
				return err
			}
			from = last.AddDate(0, 0, 1)
		}
		to := now.Add(-r.DigestDelay).UTC().Truncate(24 * time.Hour)
		if !from.Before(to) {
			return nil
		}
		days, err = tx.GrpEventDays(from, to)
		return err
	}); err != nil {
		return err
	}
	if head.LastSeq == 0 {
		return nil // this tenant has never used groups
	}
	for _, day := range days {
		var created bool
		if err := r.DB.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			var err error
			_, created, err = WriteDigest(tx, day, now)
			return err
		}); err != nil && !errors.Is(err, ErrNoEvents) {
			return err
		}
		if created {
			r.Log.Info("groups history digest written", "tenant", t.Slug, "day", day)
		}
	}
	if today := Day(now); r.retained[t.ID] != today {
		if err := r.DB.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			_, err := Prune(tx, now, r.RetentionDays)
			return err
		}); err != nil {
			return err
		}
		r.retained[t.ID] = today
	}
	return r.sample(ctx, t, now)
}

// sample rebuilds the PIT rows of the next SampleSize groups (in id order,
// wrapping round) and compares them with the stored rows.
func (r *Runner) sample(ctx context.Context, t store.Tenant, now time.Time) error {
	last, seen := r.lastSample[t.ID]
	if !seen {
		r.lastSample[t.ID] = now // the first sample is one SampleEvery after the process starts
		return nil
	}
	if now.Sub(last) < r.SampleEvery {
		return nil
	}
	var ids []string
	if err := r.DB.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) error {
		var err error
		ids, err = tx.GrpEventGroupIDs(r.sampleAfter[t.ID], r.SampleSize)
		return err
	}); err != nil {
		return err
	}
	if len(ids) < r.SampleSize {
		r.sampleAfter[t.ID] = "" // the end of the groups: start again next time
	} else {
		r.sampleAfter[t.ID] = ids[len(ids)-1]
	}
	r.lastSample[t.ID] = now
	for _, id := range ids {
		var cmp *Comparison
		err := r.DB.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			var err error
			if cmp, err = CompareRebuild(tx, id); err != nil || cmp.Equal {
				return err
			}
			_, err = tx.RecordAudit(store.AuditRecord{At: now, Action: ActionMismatch, LegacyActor: "groups.pit",
				TargetType: "group", TargetID: id, Detail: ojson.Object{{Key: "group_id", Value: id},
					{Key: "intervals_before", Value: cmp.Before.Effective + cmp.Before.Direct + cmp.Before.Objects},
					{Key: "intervals_after", Value: cmp.After.Effective + cmp.After.Direct + cmp.After.Objects}}})
			return err
		})
		switch {
		case errors.Is(err, ErrHistoryPruned):
			continue // retention removed what a rebuild would need; nothing to compare
		case err != nil:
			return err
		case !cmp.Equal:
			r.Log.Error("groups PIT rows differed from their events and were rebuilt", "tenant", t.Slug, "group", id)
		}
	}
	return nil
}

// Loop runs Once every Tick until ctx is done.
func (r *Runner) Loop(ctx context.Context) {
	r.defaults()
	tick := time.NewTicker(r.Tick)
	defer tick.Stop()
	for {
		if err := r.Once(ctx); err != nil && ctx.Err() == nil {
			r.Log.Error("groups history failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
