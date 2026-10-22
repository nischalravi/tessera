package model

import (
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Change events (issue #46, GR-3; design §10.1). Every change the service
// makes writes its event, with a snapshot of the object after the change, in
// the same transaction as the change and its audit event. The PIT writer
// (internal/groups/pit) applies the event as it is appended, so history is
// never behind the data.

// stamp sets the event's cause from the operation (the API unless a rule made it).
func (e Env) stamp(ev *events.Event) *events.Event {
	ev.CauseType, ev.CauseRef = e.cause(), e.CauseRef
	return ev
}

// emitFolder writes a folder event whose snapshot is f as it now is. extra
// adds descriptive fields (the old name).
func (e Env) emitFolder(typ string, f *store.Folder, extra map[string]any) error {
	ev := e.stamp(events.New(typ, string(f.ID), e.Now, store.CauseAPI))
	if typ == events.FolderDeleted {
		if extra == nil {
			extra = map[string]any{}
		}
		ev.Data = events.Data(extra)
	} else {
		ev.Data = pit.ObjectData(pit.FolderSnapshot(f), extra)
	}
	return pit.Emit(e.Tx, ev)
}

// emitGroup writes a group event whose snapshot is g as it now is, with its
// factors if it is a composite.
func (e Env) emitGroup(typ string, g *store.NativeGroup, extra map[string]any) error {
	var factors []store.GroupID
	if g.Definition != store.DefinitionBasic {
		var err error
		if factors, err = e.Tx.GrpFactors(g.ID); err != nil {
			return err
		}
	}
	ev := e.stamp(events.New(typ, string(g.ID), e.Now, store.CauseAPI))
	ev.Data = pit.ObjectData(pit.GroupSnapshot(g, factors), extra)
	return pit.Emit(e.Tx, ev)
}

// emitGroupPurged writes the group.purged event of a group whose row is about
// to go: it carries the name, no snapshot, and ends the group's history object.
func (e Env) emitGroupPurged(g *store.NativeGroup) error {
	ev := e.stamp(events.New(events.GroupPurged, string(g.ID), e.Now, store.CauseAPI))
	ev.Data = events.Data(map[string]any{"name": g.Name, "folder_id": string(g.FolderID), "deleted_by": g.DeletedBy, "reason": e.Reason})
	return pit.Emit(e.Tx, ev)
}

// emitDirect writes the event of a direct membership row.
func (e Env) emitDirect(typ string, m *store.DirectMembership) error {
	return pit.Emit(e.Tx, e.stamp(pit.DirectEvent(typ, m, e.Now, store.CauseAPI)))
}
