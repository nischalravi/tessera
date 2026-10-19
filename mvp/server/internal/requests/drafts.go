package requests

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Request access drafts: the cart of Access > Request access, saved
// server-side for the person who made it. A draft is only a note to self. It
// is checked for shape and for existence of what it names, never against
// policy, and nothing here submits it: the client submits through the usual
// calls and then deletes the draft.

// MaxDrafts is how many drafts one user keeps.
const MaxDrafts = 50

// DraftItem is one thing a draft asks for: a group (Kind "group", GroupID) or
// a business role (Kind "role", RoleID).
type DraftItem struct {
	Kind    string `json:"kind"`
	GroupID int64  `json:"group_id,omitempty"`
	RoleID  string `json:"role_id,omitempty"`
}

// DraftSpec is what a user saves.
type DraftSpec struct {
	BeneficiaryIDs []int64
	Items          []DraftItem
	DurationHours  *float64
	Justification  string
}

func (s *DraftSpec) check(tx *store.TenantTx) error {
	switch {
	case len(s.BeneficiaryIDs) > MaxLines || len(s.Items) > MaxLines:
		return refuse(422, "too_many", "a draft names at most %d people and %d items", MaxLines, MaxLines)
	case len(strings.TrimSpace(s.Justification)) > MaxJustification:
		return refuse(422, "justification_too_long", "a justification is at most %d characters", MaxJustification)
	case !hoursOK(s.DurationHours):
		return refuse(422, "invalid_duration", "a duration is more than 0 and at most %d hours", MaxHours)
	case len(s.BeneficiaryIDs) == 0 && len(s.Items) == 0 && strings.TrimSpace(s.Justification) == "":
		return refuse(422, "empty_draft", "there is nothing to save: name a person, an item or a justification")
	}
	seen := map[int64]bool{}
	for _, id := range s.BeneficiaryIDs {
		if seen[id] {
			return refuse(422, "duplicate_person", "a person appears once")
		}
		seen[id] = true
		if _, err := tx.Identity(id); errors.Is(err, store.ErrNotFound) {
			return refuse(404, "beneficiary_not_found", "person not found")
		} else if err != nil {
			return err
		}
	}
	items := map[string]bool{}
	for _, it := range s.Items {
		var key string
		switch it.Kind {
		case "group":
			if it.GroupID <= 0 || it.RoleID != "" {
				return refuse(422, "invalid_item", "a group item names group_id only")
			}
			if _, err := tx.Group(it.GroupID); errors.Is(err, store.ErrNotFound) {
				return refuse(404, "item_not_found", "group not found")
			} else if err != nil {
				return err
			}
			key = "g" + strconv.FormatInt(it.GroupID, 10)
		case "role":
			if it.RoleID == "" || it.GroupID != 0 || len(it.RoleID) > 64 {
				return refuse(422, "invalid_item", "a role item names role_id only")
			}
			if _, err := tx.BusinessRole(it.RoleID); errors.Is(err, store.ErrNotFound) {
				return refuse(404, "item_not_found", "role not found")
			} else if err != nil {
				return err
			}
			key = "r" + it.RoleID
		default:
			return refuse(422, "invalid_item", "an item is a group or a role")
		}
		if items[key] {
			return refuse(422, "duplicate_item", "an item appears once")
		}
		items[key] = true
	}
	return nil
}

func draftDetail(d *store.RequestDraft) ojson.Object {
	return ojson.Object{{Key: "draft_id", Value: d.ID}, {Key: "people", Value: len(d.BeneficiaryIDs)}}
}

// SaveDraft creates a draft (id "") or replaces the user's draft id. Another
// user's draft looks missing.
func SaveDraft(tx *store.TenantTx, id string, s DraftSpec, by Actor, now time.Time) (*store.RequestDraft, error) {
	if err := s.check(tx); err != nil {
		return nil, err
	}
	items, err := json.Marshal(s.Items)
	if err != nil {
		return nil, err
	}
	if s.BeneficiaryIDs == nil {
		s.BeneficiaryIDs = []int64{}
	}
	d := &store.RequestDraft{ID: id, UserID: by.id(), BeneficiaryIDs: s.BeneficiaryIDs, Items: items,
		DurationHours: s.DurationHours, Justification: strings.TrimSpace(s.Justification)}
	action := "request.draft.save"
	if id == "" {
		if n, err := tx.CountRequestDrafts(by.id()); err != nil {
			return nil, err
		} else if n >= MaxDrafts {
			return nil, refuse(409, "too_many_drafts", "you can keep %d drafts; delete one first", MaxDrafts)
		}
		if err := tx.InsertRequestDraft(d, now); err != nil {
			return nil, err
		}
	} else {
		prev, err := tx.RequestDraft(id, by.id())
		if errors.Is(err, store.ErrNotFound) {
			return nil, refuse(404, "draft_not_found", "draft not found")
		} else if err != nil {
			return nil, err
		}
		if err := tx.UpdateRequestDraft(d, now); err != nil {
			return nil, err
		}
		d.CreatedAt = prev.CreatedAt
	}
	return d, tx.Audit(now, by.Display, action, draftDetail(d))
}

// DeleteDraft deletes the user's draft id. Another user's draft looks missing.
func DeleteDraft(tx *store.TenantTx, id string, by Actor, now time.Time) error {
	if err := tx.DeleteRequestDraft(id, by.id()); errors.Is(err, store.ErrNotFound) {
		return refuse(404, "draft_not_found", "draft not found")
	} else if err != nil {
		return err
	}
	return tx.Audit(now, by.Display, "request.draft.delete", ojson.Object{{Key: "draft_id", Value: id}})
}
