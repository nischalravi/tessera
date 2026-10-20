package pit

import (
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// MaxWindow bounds a between query: a window longer than this is refused, so
// one request cannot ask for every interval ever recorded.
const MaxWindow = 366 * 24 * time.Hour

// ErrWindow is returned for a malformed or too long time window.
var ErrWindow = errors.New("pit: invalid time window")

// MembersAt returns the intervals that make identities members of a group's
// list at an instant, in identity order, with the number of distinct members.
// An identity has at most one interval at an instant.
func MembersAt(tx *store.TenantTx, group store.GroupID, list store.ListID, at time.Time, limit, offset int) ([]*store.PitEffective, int, error) {
	return tx.GrpPitEffectiveIn(string(group), string(list), at, at, limit, offset)
}

// MembersBetween returns the intervals that made identities members of a
// group's list at any time in [from, to]: an interval is returned when it
// overlaps the window. The total counts distinct identities.
func MembersBetween(tx *store.TenantTx, group store.GroupID, list store.ListID, from, to time.Time, limit, offset int) ([]*store.PitEffective, int, error) {
	if err := CheckWindow(from, to); err != nil {
		return nil, 0, err
	}
	return tx.GrpPitEffectiveIn(string(group), string(list), from, to, limit, offset)
}

// DirectAt returns the direct membership rows that existed at an instant. A
// row existing is not the same as counting: its own dates (EnabledFrom,
// DisabledAt) say whether it was active.
func DirectAt(tx *store.TenantTx, group store.GroupID, list store.ListID, at time.Time, limit, offset int) ([]*store.PitDirect, int, error) {
	return tx.GrpPitDirectIn(string(group), string(list), at, at, limit, offset)
}

// DirectBetween returns the direct membership rows that existed at any time in [from, to].
func DirectBetween(tx *store.TenantTx, group store.GroupID, list store.ListID, from, to time.Time, limit, offset int) ([]*store.PitDirect, int, error) {
	if err := CheckWindow(from, to); err != nil {
		return nil, 0, err
	}
	return tx.GrpPitDirectIn(string(group), string(list), from, to, limit, offset)
}

// ObjectAt returns the snapshot of a folder or group at an instant, or
// store.ErrNotFound if it did not exist then.
func ObjectAt(tx *store.TenantTx, objectType, objectID string, at time.Time) (*store.PitObject, error) {
	return tx.GrpPitObjectAt(objectType, objectID, at)
}

// CheckWindow validates a between window: from <= to and at most MaxWindow long.
func CheckWindow(from, to time.Time) error {
	if to.Before(from) {
		return fmt.Errorf("%w: the end is before the start", ErrWindow)
	}
	if to.Sub(from) > MaxWindow {
		return fmt.Errorf("%w: at most %d days", ErrWindow, int(MaxWindow.Hours()/24))
	}
	return nil
}
