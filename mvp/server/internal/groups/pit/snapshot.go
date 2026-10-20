package pit

import (
	"encoding/json"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The snapshots and event payloads the groups code writes. They are built from
// the stored rows at the moment of the change, so replaying the events needs
// nothing but the events.

func rtp(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := store.RT(*t)
	return &s
}

// FolderSnapshot is what the PIT keeps of a folder: its name and place.
func FolderSnapshot(f *store.Folder) json.RawMessage {
	var parent *string
	if f.ParentID != nil {
		p := string(*f.ParentID)
		parent = &p
	}
	return events.Data(map[string]any{"id": string(f.ID), "name": f.Name, "display_name": f.DisplayName, "parent_id": parent,
		"managed_by": string(f.ManagedBy)})
}

// GroupSnapshot is what the PIT keeps of a group: names, folder, definition
// (operator and factors, for a composite) and status. factors is the
// composite's factor list in order.
func GroupSnapshot(g *store.NativeGroup, factors []store.GroupID) json.RawMessage {
	fs := make([]string, len(factors))
	for i, f := range factors {
		fs[i] = string(f)
	}
	var op *string
	if g.CompositeOp != nil {
		o := string(*g.CompositeOp)
		op = &o
	}
	return events.Data(map[string]any{"id": string(g.ID), "name": g.Name, "display_name": g.DisplayName, "folder_id": string(g.FolderID),
		"kind": string(g.Kind), "definition": string(g.Definition), "composite_op": op, "factors": fs, "status": g.Status,
		"enabled_from": rtp(g.EnabledFrom), "disabled_at": rtp(g.DisabledAt), "managed_by": string(g.ManagedBy)})
}

// ObjectData is the data of an event that replaces an object's snapshot; extra
// adds fields that describe the change (old names, counts).
func ObjectData(snapshot json.RawMessage, extra map[string]any) json.RawMessage {
	m := map[string]any{"snapshot": snapshot}
	for k, v := range extra {
		if k != "snapshot" {
			m[k] = v
		}
	}
	return events.Data(m)
}

// DirectData is the data of a direct membership event: what the row says.
func DirectData(m *store.DirectMembership) json.RawMessage {
	return events.Data(directData{MemberType: string(m.MemberType), Source: m.Source, EnabledFrom: rtp(m.EnabledFrom),
		DisabledAt: rtp(m.DisabledAt)})
}

// DirectEvent builds the event of a direct membership change of type typ.
func DirectEvent(typ string, m *store.DirectMembership, now time.Time, cause string) *events.Event {
	e := events.New(typ, string(m.GroupID), now, cause)
	e.List = string(m.ListID)
	e.Identity = m.MemberIdentity
	if m.MemberGroup != nil {
		e.MemberGroup = string(*m.MemberGroup)
	}
	e.Data = DirectData(m)
	return e
}

// EffectiveEvent builds the event of an identity entering or leaving a
// group's list. repair marks a change made by verification.
func EffectiveEvent(group store.GroupID, list store.ListID, identity int64, member bool, now time.Time, cause string, repair bool) *events.Event {
	typ := events.MembershipEffectiveRemoved
	if member {
		typ = events.MembershipEffectiveAdded
	}
	e := events.New(typ, string(group), now, cause)
	e.List, e.Identity = string(list), &identity
	if repair {
		e.Data = events.Data(map[string]any{"repair": true})
	}
	return e
}
