package pit

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// ErrHistoryPruned is returned by Rebuild when retention has removed events
// that the PIT rows in scope were built from: replaying what is left would
// lose history, so the tables are left as they are.
var ErrHistoryPruned = errors.New("pit: events of this history were pruned, so it cannot be rebuilt from them")

// Snapshot is every PIT row of a scope, in key order: what Dump returns and
// what two builds of the same history must agree on.
type Snapshot struct {
	Objects    []*store.PitObject    `json:"objects"`
	Direct     []*store.PitDirect    `json:"direct"`
	Effective  []*store.PitEffective `json:"effective"`
	Privileges []*store.PitPrivilege `json:"privileges,omitempty"`
}

// Totals counts the rows of a snapshot.
func (s *Snapshot) Totals() store.PitTotals {
	return store.PitTotals{Objects: int64(len(s.Objects)), Direct: int64(len(s.Direct)), Effective: int64(len(s.Effective)),
		Privileges: int64(len(s.Privileges))}
}

// Dump reads the PIT rows of one group (its object intervals, direct and
// effective memberships), or of the whole tenant when group is "".
func Dump(tx *store.TenantTx, group string) (*Snapshot, error) {
	var s Snapshot
	var err error
	if s.Objects, err = tx.GrpPitObjects(group); err != nil {
		return nil, err
	}
	if s.Direct, err = tx.GrpPitDirects(group); err != nil {
		return nil, err
	}
	if s.Effective, err = tx.GrpPitEffectives(group); err != nil {
		return nil, err
	}
	if group == "" {
		if s.Privileges, err = tx.GrpPitPrivileges(); err != nil {
			return nil, err
		}
	}
	return &s, nil
}

// Equal reports whether two snapshots hold the same rows.
func (s *Snapshot) Equal(o *Snapshot) bool {
	a, err1 := json.Marshal(s)
	b, err2 := json.Marshal(o)
	return err1 == nil && err2 == nil && string(a) == string(b)
}

// Rebuild recreates the PIT rows of a group, or of the whole tenant when
// group is "", by replaying grp_events in seq order. It returns the number of
// events replayed. The PIT tables hold derived data only, so this is always
// safe, unless retention has pruned the events behind them
// (ErrHistoryPruned).
func Rebuild(tx *store.TenantTx, group string) (int64, error) {
	head, err := tx.GrpEventHead()
	if err != nil {
		return 0, err
	}
	if head.PrunedSeq > 0 {
		old, err := tx.GrpPitStartedBefore(group, head.PrunedSeq)
		if err != nil {
			return 0, err
		}
		if old != (store.PitTotals{}) {
			return 0, ErrHistoryPruned
		}
	}
	if err := tx.DeleteGrpPit(group); err != nil {
		return 0, err
	}
	var n int64
	var last *events.Event
	for after := int64(0); ; {
		var page []*events.Event
		if group == "" {
			page, err = tx.GrpEventsAfter(after, head.LastSeq, pageSize)
		} else {
			page, err = tx.GrpEventsOfObject(store.EventObjGroup, group, after, pageSize)
		}
		if err != nil {
			return n, err
		}
		for _, e := range page {
			if err := Apply(tx, e); err != nil {
				return n, fmt.Errorf("pit: rebuild: %s (seq %d): %w", e.Type, e.Seq, err)
			}
			n++
			last = e
		}
		if len(page) < pageSize {
			break
		}
		after = page[len(page)-1].Seq
	}
	if group == "" && last != nil {
		if err := tx.SetGrpCursor(Consumer, last.Seq, last.OccurredAt); err != nil {
			return n, err
		}
	}
	return n, nil
}

// Comparison is the result of CompareRebuild.
type Comparison struct {
	Group  string          `json:"group_id"`
	Equal  bool            `json:"equal"`
	Before store.PitTotals `json:"before"`
	After  store.PitTotals `json:"after"`
	Events int64           `json:"events"`
}

// CompareRebuild rebuilds a group's PIT rows from its events and compares the
// result with what was there. The rebuilt rows replace the old ones, so a
// difference is also repaired; the caller records it (the weekly job writes
// groups.pit.mismatch to the audit ledger).
func CompareRebuild(tx *store.TenantTx, group string) (*Comparison, error) {
	before, err := Dump(tx, group)
	if err != nil {
		return nil, err
	}
	n, err := Rebuild(tx, group)
	if err != nil {
		return nil, err
	}
	after, err := Dump(tx, group)
	if err != nil {
		return nil, err
	}
	return &Comparison{Group: group, Equal: before.Equal(after), Before: before.Totals(), After: after.Totals(), Events: n}, nil
}

// RecordRebuild writes the audit event of an on-demand rebuild.
func RecordRebuild(tx *store.TenantTx, now time.Time, group string, replayed int64) error {
	_, err := tx.RecordAudit(store.AuditRecord{At: now, Action: ActionRebuild, LegacyActor: "groups.pit",
		TargetType: "group_events", TargetID: group, Detail: ojson.Object{{Key: "group_id", Value: group}, {Key: "events", Value: replayed}}})
	return err
}
