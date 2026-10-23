// Package pit is the point-in-time history of native groups (design
// docs/design/groups-grouper-parity.md §10.2, K9).
//
// The PIT tables grp_pit_* are derived data: the writer applies each group
// event to them as it is appended, in the same transaction, closing and
// opening half-open intervals [start_at, end_at) with the event's seq as
// start_seq / end_seq. Because Apply depends only on the event, Rebuild can
// recreate the tables by replaying grp_events, and a weekly job compares a
// sample of groups with their rebuilt form.
//
// Tamper evidence is separate: once a day a Merkle root over the previous
// day's events is appended to the audit ledger (digest.go), and Verify
// recomputes it.
package pit

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Consumer is the PIT writer's cursor name in grp_event_cursors.
const Consumer = "pit"

// Emit appends e to the outbox and applies it to the PIT tables, in tx. This is
// the one call the groups code makes for a change; it sets e.Seq.
func Emit(tx *store.TenantTx, e *events.Event) error {
	if err := events.Append(tx, e); err != nil {
		return err
	}
	if err := Apply(tx, e); err != nil {
		return fmt.Errorf("pit: apply %s (seq %d): %w", e.Type, e.Seq, err)
	}
	return tx.SetGrpCursor(Consumer, e.Seq, e.OccurredAt)
}

// objectData is the data of an event that changes a folder, group or privilege.
type objectData struct {
	Snapshot    json.RawMessage `json:"snapshot"`
	PrivilegeID string          `json:"privilege_id"`
}

// directData is the data of a direct membership event.
// assignData is the part of an attribute event the PIT table indexes (the whole
// event data is kept as the snapshot).
type assignData struct {
	DefID     string `json:"def_id"`
	OwnerType string `json:"owner_type"`
	OwnerID   string `json:"owner_id"`
}

type directData struct {
	MemberType  string  `json:"member_type"`
	Source      string  `json:"source"`
	EnabledFrom *string `json:"enabled_from"`
	DisabledAt  *string `json:"disabled_at"`
}

// Apply updates the PIT tables for one event. It is idempotent per event: an
// interval it would open is preceded by closing any open one for the same key,
// so replaying an event after a crash cannot leave two open intervals. Event
// types without history (attributes, loader runs, ...) change nothing.
func Apply(tx *store.TenantTx, e *events.Event) error {
	at, seq := e.OccurredAt, e.Seq
	switch e.Type {
	case events.FolderCreated, events.FolderUpdated, events.FolderRenamed, events.FolderMoved,
		events.GroupCreated, events.GroupUpdated, events.GroupRenamed, events.GroupMoved, events.GroupDeleted,
		events.GroupRestored, events.GroupDisabled, events.GroupEnabled, events.GroupDefinitionChanged:
		var d objectData
		if err := json.Unmarshal(e.Data, &d); err != nil || len(d.Snapshot) == 0 {
			return fmt.Errorf("%s carries no snapshot", e.Type)
		}
		if err := tx.ClosePitObject(e.ObjectType, e.ObjectID, at, seq); err != nil {
			return err
		}
		return tx.OpenPitObject(e.ObjectType, e.ObjectID, d.Snapshot, at, seq)

	case events.FolderDeleted, events.GroupPurged:
		return tx.ClosePitObject(e.ObjectType, e.ObjectID, at, seq)

	case events.MembershipDirectAdded, events.MembershipDirectDatesChanged:
		row, err := directRow(e)
		if err != nil {
			return err
		}
		if err := tx.ClosePitDirect(row.Group, row.List, row.MemberType, row.MemberKey, at, seq); err != nil {
			return err
		}
		return tx.OpenPitDirect(row)

	case events.MembershipDirectRemoved:
		row, err := directRow(e)
		if err != nil {
			return err
		}
		return tx.ClosePitDirect(row.Group, row.List, row.MemberType, row.MemberKey, at, seq)

	case events.MembershipEffectiveAdded:
		if e.Identity == nil || e.List == "" {
			return fmt.Errorf("%s names no identity or list", e.Type)
		}
		if err := tx.ClosePitEffective(e.ObjectID, e.List, *e.Identity, at, seq); err != nil {
			return err
		}
		return tx.OpenPitEffective(e.ObjectID, e.List, *e.Identity, at, seq)

	case events.MembershipEffectiveRemoved:
		if e.Identity == nil || e.List == "" {
			return fmt.Errorf("%s names no identity or list", e.Type)
		}
		return tx.ClosePitEffective(e.ObjectID, e.List, *e.Identity, at, seq)

	case events.PrivilegeGranted:
		var d objectData
		if err := json.Unmarshal(e.Data, &d); err != nil || len(d.Snapshot) == 0 {
			return fmt.Errorf("%s carries no snapshot", e.Type)
		}
		if err := tx.ClosePitPrivilege(e.ObjectID, at, seq); err != nil {
			return err
		}
		return tx.OpenPitPrivilege(e.ObjectID, d.Snapshot, at, seq)

	case events.PrivilegeRevoked:
		return tx.ClosePitPrivilege(e.ObjectID, at, seq)

	case events.AttributeAssigned, events.AttributeValueChanged:
		var d assignData
		if err := json.Unmarshal(e.Data, &d); err != nil || d.DefID == "" || d.OwnerType == "" {
			return fmt.Errorf("%s carries no assignment", e.Type)
		}
		if err := tx.ClosePitAssign(e.ObjectID, at, seq); err != nil {
			return err
		}
		return tx.OpenPitAssign(e.ObjectID, d.DefID, d.OwnerType, d.OwnerID, e.Data, at, seq)

	case events.AttributeRemoved:
		return tx.ClosePitAssign(e.ObjectID, at, seq)
	}
	return nil
}

func directRow(e *events.Event) (store.PitDirect, error) {
	var d directData
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return store.PitDirect{}, fmt.Errorf("%s: %w", e.Type, err)
	}
	if e.List == "" {
		return store.PitDirect{}, fmt.Errorf("%s names no list", e.Type)
	}
	row := store.PitDirect{Group: e.ObjectID, List: e.List, MemberType: store.MemberType(d.MemberType), Source: d.Source,
		StartAt: e.OccurredAt, StartSeq: e.Seq}
	switch row.MemberType {
	case store.MemberIdentity:
		if e.Identity == nil {
			return row, fmt.Errorf("%s names no identity", e.Type)
		}
		row.Identity, row.MemberKey = e.Identity, strconv.FormatInt(*e.Identity, 10)
	case store.MemberGroup:
		if e.MemberGroup == "" {
			return row, fmt.Errorf("%s names no member group", e.Type)
		}
		row.MemberGroup, row.MemberKey = e.MemberGroup, e.MemberGroup
	default:
		return row, fmt.Errorf("%s: member_type %q", e.Type, d.MemberType)
	}
	var err error
	if row.EnabledFrom, err = parseTime(d.EnabledFrom); err != nil {
		return row, err
	}
	row.DisabledAt, err = parseTime(d.DisabledAt)
	return row, err
}

func parseTime(s *string) (*time.Time, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	t, err := store.ParseRT(*s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
