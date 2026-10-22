package deleteguard

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Item outcomes of a release.
const (
	ItemReleased  = "released"
	ItemGone      = "gone"   // the item no longer exists or no longer needs deleting
	ItemFailed    = "failed" // the deletion is refused now (named in the note)
	ItemDiscarded = "discarded"
)

// Applier deletes one held item again, in the release's transaction, outside the threshold
// (the release is an approved override and is not counted). It re-checks that the item still
// exists and still should be deleted: ItemGone says it does not; ItemFailed (with a note)
// says the deletion is refused now. An error is for what is not an answer about the item.
type Applier func(tx *store.TenantTx, now time.Time, it *store.DeletionHoldItem) (outcome, note string, err error)

// Appliers maps an item kind to the code that applies it. The API assembles them (the guard
// itself cannot import the packages that own the deletions).
type Appliers map[string]Applier

// Errors of a decision on a hold. Code is the API's error code.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Hold is a hold with its items.
type Hold struct {
	*store.DeletionHold
	Items []*store.DeletionHoldItem
}

// Load returns a hold and its items, expiring it first when it is overdue.
func Load(tx *store.TenantTx, now time.Time, id string) (*Hold, error) {
	h, err := tx.DeletionHoldByID(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "not_found", "no such held deletion")
	}
	if err != nil {
		return nil, err
	}
	return withItems(tx, h)
}

func withItems(tx *store.TenantTx, h *store.DeletionHold) (*Hold, error) {
	items, err := tx.DeletionHoldItems(h.ID)
	return &Hold{DeletionHold: h, Items: items}, err
}

func open(tx *store.TenantTx, now time.Time, id string) (*Hold, error) {
	h, err := Load(tx, now, id)
	if err != nil {
		return nil, err
	}
	if h.Status != "held" {
		return nil, refuse(409, "hold_resolved", "this held deletion is already %s", h.Status)
	}
	if !h.ExpiresAt.After(now) {
		if err := expire(tx, now, h); err != nil {
			return nil, err
		}
		return nil, refuse(409, "hold_expired", "this held deletion expired and was discarded")
	}
	return h, nil
}

// SelectOrds checks a partial selection of item positions against the hold's still-held items.
func (h *Hold) selected(ords []int) (sel, rest []*store.DeletionHoldItem, err error) {
	for _, it := range h.Items {
		if it.Status != "held" {
			continue
		}
		if ords == nil || slices.Contains(ords, it.Ord) {
			sel = append(sel, it)
		} else {
			rest = append(rest, it)
		}
	}
	for _, o := range ords {
		if !slices.ContainsFunc(sel, func(i *store.DeletionHoldItem) bool { return i.Ord == o }) {
			return nil, nil, refuse(422, "invalid_items", "item %d is not held", o)
		}
	}
	if len(sel) == 0 {
		return nil, nil, refuse(422, "invalid_items", "name at least one held item")
	}
	return sel, rest, nil
}

// ReleaseResult is what a release did.
type ReleaseResult struct {
	HoldID   string `json:"hold_id"`
	Status   string `json:"status"`
	Released int    `json:"released"`
	Gone     int    `json:"gone"`
	Failed   int    `json:"failed"`
	Discards int    `json:"discarded"`
}

// Release applies the held items (ords nil: all of them; otherwise only those, and the rest
// of the hold is discarded: "approve partially"). by is the approving platform user, who must
// not be the one whose request was held. The deletions are applied by appliers in this
// transaction, each re-checking the item; they are an approved override and do not count
// against the window again. Audited.
func Release(tx *store.TenantTx, now time.Time, id, by string, ords []int, ap Appliers) (*ReleaseResult, error) {
	h, err := open(tx, now, id)
	if err != nil {
		return nil, err
	}
	if h.Actor != "" {
		same, err := tx.SameActor(h.Actor, by)
		if err != nil {
			return nil, err
		}
		if same {
			return nil, refuse(403, "same_actor", "a held deletion must be released by a different admin than the one whose request was held")
		}
	}
	sel, rest, err := h.selected(ords)
	if err != nil {
		return nil, err
	}
	res := &ReleaseResult{HoldID: h.ID}
	// what the appliers delete is an approved override: Admit lets it through and does not count it
	overrides.Store(tx, struct{}{})
	defer overrides.Delete(tx)
	for _, it := range sel {
		fn := ap[it.Kind]
		if fn == nil {
			return nil, fmt.Errorf("deleteguard: no applier for item kind %q", it.Kind)
		}
		out, note, err := fn(tx, now, it)
		if err != nil {
			return nil, err
		}
		switch out {
		case ItemReleased:
			res.Released++
		case ItemGone:
			res.Gone++
		case ItemFailed:
			res.Failed++
		default:
			return nil, fmt.Errorf("deleteguard: applier of %q answered %q", it.Kind, out)
		}
		if err := tx.SetDeletionHoldItem(h.ID, it.Ord, out, note); err != nil {
			return nil, err
		}
	}
	for _, it := range rest {
		if err := tx.SetDeletionHoldItem(h.ID, it.Ord, ItemDiscarded, "not approved"); err != nil {
			return nil, err
		}
		res.Discards++
	}
	res.Status = "released"
	if len(rest) > 0 {
		res.Status = "partially_released"
	}
	if err := tx.ResolveDeletionHold(h.ID, res.Status, by, "", now); err != nil {
		return nil, err
	}
	if err := closeTask(tx, now, h.ID, store.TaskDone, by); err != nil {
		return nil, err
	}
	// the override is audited in the transaction that applies it
	return res, audit(tx, now, "deletion_guard.released", h.DeletionHold, ojson.Object{{Key: "hold_id", Value: h.ID},
		{Key: "category", Value: h.Category}, {Key: "approved_by", Value: by}, {Key: "requested_by", Value: h.Actor},
		{Key: "approved_override", Value: true}, {Key: "counted_against_window", Value: false}, {Key: "status", Value: res.Status},
		{Key: "released", Value: res.Released}, {Key: "gone", Value: res.Gone}, {Key: "failed", Value: res.Failed},
		{Key: "discarded", Value: res.Discards}})
}

// Discard drops every still-held item without deleting it. Anyone who may decide on holds may
// discard, including the actor: discarding keeps things as they are.
func Discard(tx *store.TenantTx, now time.Time, id, by, note string) (*ReleaseResult, error) {
	h, err := open(tx, now, id)
	if err != nil {
		return nil, err
	}
	res := &ReleaseResult{HoldID: h.ID, Status: "discarded"}
	for _, it := range h.Items {
		if it.Status != "held" {
			continue
		}
		if err := tx.SetDeletionHoldItem(h.ID, it.Ord, ItemDiscarded, note); err != nil {
			return nil, err
		}
		res.Discards++
	}
	if err := tx.ResolveDeletionHold(h.ID, "discarded", by, note, now); err != nil {
		return nil, err
	}
	if err := closeTask(tx, now, h.ID, store.TaskDismissed, by); err != nil {
		return nil, err
	}
	return res, audit(tx, now, "deletion_guard.discarded", h.DeletionHold, ojson.Object{{Key: "hold_id", Value: h.ID},
		{Key: "category", Value: h.Category}, {Key: "discarded_by", Value: by}, {Key: "discarded", Value: res.Discards}})
}

func expire(tx *store.TenantTx, now time.Time, h *Hold) error {
	n := 0
	for _, it := range h.Items {
		if it.Status != "held" {
			continue
		}
		if err := tx.SetDeletionHoldItem(h.ID, it.Ord, ItemDiscarded, "expired"); err != nil {
			return err
		}
		n++
	}
	if err := tx.ResolveDeletionHold(h.ID, "expired", "", "expired without a decision", now); err != nil {
		return err
	}
	if err := closeTask(tx, now, h.ID, store.TaskDismissed, ""); err != nil {
		return err
	}
	return audit(tx, now, "deletion_guard.expired", h.DeletionHold, ojson.Object{{Key: "hold_id", Value: h.ID},
		{Key: "category", Value: h.Category}, {Key: "discarded", Value: n}})
}

// ExpireDue discards the holds that waited past their expiry and returns how many.
func ExpireDue(tx *store.TenantTx, now time.Time) (int, error) {
	due, err := tx.DeletionHoldsDue(now)
	if err != nil {
		return 0, err
	}
	for _, d := range due {
		h, err := withItems(tx, d)
		if err != nil {
			return 0, err
		}
		if err := expire(tx, now, h); err != nil {
			return 0, err
		}
	}
	return len(due), nil
}
