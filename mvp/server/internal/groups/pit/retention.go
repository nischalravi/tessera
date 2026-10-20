package pit

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// DefaultRetentionDays is how long events and PIT rows are kept (design
// §10.2: 7 years, `groups.retention_days`).
const DefaultRetentionDays = 7 * 365

// PruneResult says what a retention pass removed.
type PruneResult struct {
	Cutoff    time.Time       `json:"cutoff"`
	Events    int64           `json:"events"`
	PrunedSeq int64           `json:"pruned_seq"`
	Intervals store.PitTotals `json:"intervals"`
}

// Prune is the delete-old-records job (G-94) for group history: it removes
// events older than the retention window and PIT intervals that ended before
// it, and records what it removed in the audit ledger. Events leave as a
// prefix of the sequence, never past the last digested event, so every
// removed event was covered by a digest first. The digests stay.
func Prune(tx *store.TenantTx, now time.Time, retentionDays int) (*PruneResult, error) {
	res := &PruneResult{Cutoff: now.AddDate(0, 0, -retentionDays)}
	if retentionDays < 1 {
		return res, nil
	}
	var digested int64
	ds, err := tx.GrpDigests(1)
	if err != nil {
		return nil, err
	}
	if len(ds) > 0 {
		digested = ds[0].LastSeq
	}
	if res.Events, err = tx.PruneGrpEvents(res.Cutoff, digested); err != nil {
		return nil, err
	}
	if res.Intervals, err = tx.PruneGrpPit(res.Cutoff, digested); err != nil {
		return nil, err
	}
	head, err := tx.GrpEventHead()
	if err != nil {
		return nil, err
	}
	res.PrunedSeq = head.PrunedSeq
	i := res.Intervals
	if res.Events+i.Objects+i.Direct+i.Effective+i.Privileges == 0 {
		return res, nil
	}
	_, err = tx.RecordAudit(store.AuditRecord{At: now, Action: ActionRetention, LegacyActor: "groups.pit",
		TargetType: "group_events", TargetID: Day(res.Cutoff), Detail: ojson.Object{{Key: "cutoff", Value: res.Cutoff},
			{Key: "retention_days", Value: int64(retentionDays)}, {Key: "events", Value: res.Events}, {Key: "pruned_seq", Value: res.PrunedSeq},
			{Key: "pit_objects", Value: i.Objects}, {Key: "pit_direct", Value: i.Direct}, {Key: "pit_effective", Value: i.Effective},
			{Key: "pit_privileges", Value: i.Privileges}}})
	return res, err
}
