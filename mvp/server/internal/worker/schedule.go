package worker

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A tenant schedules its own connector syncs (issue #498): a delta sync (incremental: each connector resumes from its
// checkpoint) every few minutes and a full sync (checkpoints ignored) every few hours. Each is a row of the tenant's
// queue_schedules, so the queue fires it like any other schedule and the sync runs as the connector_sync job.

// Names of the two schedules.
const (
	DeltaScheduleName = "connector_sync.delta"
	FullScheduleName  = "connector_sync.full"
)

// Bounds of a schedule.
const (
	MinDeltaMinutes = 5
	MaxDeltaMinutes = 24 * 60
	MinFullHours    = 1
	MaxFullHours    = 30 * 24
)

// SyncSchedule is a tenant's sync schedule; 0 is off.
type SyncSchedule struct {
	DeltaMinutes int
	FullHours    int
	// NextDelta, NextFull and LastDelta, LastFull are when each is due next and was last queued (nil: never or off).
	NextDelta, NextFull, LastDelta, LastFull *time.Time
}

// ErrScheduleBounds is a schedule outside the allowed bounds.
var ErrScheduleBounds = errors.New("schedule out of bounds")

// CheckSyncSchedule refuses an interval outside the bounds (0 turns a schedule off).
func CheckSyncSchedule(deltaMinutes, fullHours int) error {
	if deltaMinutes != 0 && (deltaMinutes < MinDeltaMinutes || deltaMinutes > MaxDeltaMinutes) {
		return fmt.Errorf("%w: a delta sync runs every %d to %d minutes, or never", ErrScheduleBounds, MinDeltaMinutes, MaxDeltaMinutes)
	}
	if fullHours != 0 && (fullHours < MinFullHours || fullHours > MaxFullHours) {
		return fmt.Errorf("%w: a full sync runs every %d to %d hours, or never", ErrScheduleBounds, MinFullHours, MaxFullHours)
	}
	return nil
}

// SetSyncSchedule stores the tenant's schedule. A schedule that is turned on (or changed) is first due one interval
// from now; one turned off is kept disabled. The caller audits the change in the same transaction.
func SetSyncSchedule(tx *store.TenantTx, now time.Time, deltaMinutes, fullHours int) error {
	if err := CheckSyncSchedule(deltaMinutes, fullHours); err != nil {
		return err
	}
	for _, s := range []struct {
		name, mode string
		every      time.Duration
	}{
		{DeltaScheduleName, "incremental", time.Duration(deltaMinutes) * time.Minute},
		{FullScheduleName, "full", time.Duration(fullHours) * time.Hour},
	} {
		cur, err := tx.QueueSchedule(s.name)
		if errors.Is(err, store.ErrNotFound) {
			cur, err = nil, nil
		}
		if err != nil {
			return err
		}
		if s.every == 0 && cur == nil {
			continue
		}
		spec := "@every " + s.every.String()
		next := now.Add(s.every)
		if s.every == 0 { // off: keep the spec it had
			spec, next = cur.Spec, cur.NextRunAt
		} else if cur != nil && cur.Enabled && cur.Spec == spec {
			continue // unchanged: keep its place in the cycle
		}
		if err := tx.SetQueueSchedule(&store.QueueSchedule{Name: s.name, Kind: jobs.ConnectorSync, Payload: `{"mode":"` + s.mode + `"}`,
			Spec: spec, Enabled: s.every > 0, MaxAttempts: maxAttempts, NextRunAt: next}, now); err != nil {
			return err
		}
	}
	return nil
}

// GetSyncSchedule reads the tenant's schedule (zero values when none is set).
func GetSyncSchedule(tx *store.TenantTx) (SyncSchedule, error) {
	var out SyncSchedule
	for _, s := range []struct {
		name string
		unit time.Duration
		n    *int
		next **time.Time
		last **time.Time
	}{
		{DeltaScheduleName, time.Minute, &out.DeltaMinutes, &out.NextDelta, &out.LastDelta},
		{FullScheduleName, time.Hour, &out.FullHours, &out.NextFull, &out.LastFull},
	} {
		cur, err := tx.QueueSchedule(s.name)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return out, err
		}
		if !cur.Enabled {
			continue
		}
		d, err := time.ParseDuration(strings.TrimPrefix(cur.Spec, "@every "))
		if err != nil {
			return out, fmt.Errorf("worker: schedule %s has spec %q: %w", s.name, cur.Spec, err)
		}
		*s.n = int(d / s.unit)
		next := cur.NextRunAt
		*s.next, *s.last = &next, cur.LastEnqueuedAt
	}
	return out, nil
}
