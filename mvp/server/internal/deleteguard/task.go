package deleteguard

import (
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/inbox"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The Inbox task of a hold: approvers see a held deletion in the groups Inbox (kind deletion_held,
// about the hold) as well as on Admin → Held deletions. The task opens with the hold and closes when
// the hold is released (done), discarded or expires (dismissed). A hold made before the task existed
// has none, and closing it is a no-op.

func taskKey(holdID string) string { return "deletion_hold:" + holdID }

func openTask(tx *store.TenantTx, now time.Time, h *store.DeletionHold, d *Decision) error {
	from := h.Source
	if h.SourceID != "" {
		from += " " + h.SourceID
	}
	title := fmt.Sprintf("%d %s deletion(s) held for approval (%s)", len(d.Held), h.Category, from)
	if len(title) > inbox.MaxTitle {
		title = title[:inbox.MaxTitle]
	}
	due := h.ExpiresAt
	_, _, err := inbox.Open(tx, now, inbox.Input{Kind: store.TaskDeletionHeld, Title: title, ObjectType: inbox.ObjectDeletionHold,
		ObjectID: h.ID, DedupeKey: taskKey(h.ID), DueAt: &due,
		Detail: map[string]any{"hold_id": h.ID, "category": h.Category, "source": h.Source, "source_id": h.SourceID, "held": len(d.Held)}})
	return err
}

// closeTask closes the hold's task; status is done (released) or dismissed (discarded, expired).
func closeTask(tx *store.TenantTx, now time.Time, holdID, status, by string) error {
	t, err := tx.GrpOpenTaskByKey(taskKey(holdID))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return inbox.CloseSystem(tx, now, t.ID, status, by)
}
