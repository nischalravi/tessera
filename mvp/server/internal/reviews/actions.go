package reviews

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Certification actions (issue #588), beyond keep and revoke:
//
//   - Consult: the reviewer of an open item asks another person for advice. The person answers
//     from their own page; the answer informs the reviewer and decides nothing.
//   - Reassign: the item moves to another reviewer.
//   - Lock and unlock: a lock pauses decisions on a campaign (and its schedule's deadline); unlock
//     resumes it.
//   - Close: ends a campaign for good. Items nobody decided stay undecided and nothing is revoked;
//     the audit event counts them.
//
// The reviewer of an item (or someone holding reviews.manage) consults and reassigns; the person
// asked must be an active person who can sign in and is neither the item's subject nor the asker.
// Every action is audited in the caller's transaction, and the consult, answer and reassignment
// events are kept in review_item_events.

// ActionError is a refused action; Code is stable for API clients.
type ActionError struct {
	Status int
	Code   string
	Msg    string
}

func (e *ActionError) Error() string { return e.Code + ": " + e.Msg }

func refuse(status int, code, format string, args ...any) error {
	return &ActionError{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Limits.
const (
	MaxActionNote    = 1000
	MaxReason        = 500
	MaxOpenConsults  = 5
	ErrCodeLocked    = "campaign_locked"
	ErrCodeClosed    = "campaign_closed"
	ErrCodeNotFound  = "item_not_found"
	ErrCodeDecided   = "item_decided"
	ErrCodeNotYours  = "not_the_reviewer"
	ErrCodeBadPerson = "invalid_person"
)

// Actor is who acts: the platform user, the person they are (nil: not linked) and whether they hold
// reviews.manage.
type Actor struct {
	User       store.UserRef
	IdentityID *int64
	Manager    bool
}

// MaxLock is how long a lock holds: after it the campaign unlocks by itself and its deadline logic resumes.
const MaxLock = 14 * 24 * time.Hour

// ExpireLock unlocks a locked campaign whose lock ran out (a lock with no record counts as run out), in the
// caller's transaction, and reports whether it did.
func ExpireLock(c *store.TenantTx, now time.Time, cmp *store.ReviewCampaign) (bool, error) {
	if cmp.Status != store.CampaignLocked {
		return false, nil
	}
	l, err := c.CampaignLock(cmp.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	if l != nil && now.Before(l.ExpiresAt) {
		return false, nil
	}
	if ok, err := c.TransitionCampaign(cmp.ID, store.CampaignLocked, store.CampaignLocked, store.CampaignOpen); err != nil || !ok {
		return false, err
	}
	if err := c.DeleteCampaignLock(cmp.ID); err != nil {
		return false, err
	}
	cmp.Status = store.CampaignOpen
	_, err = c.RecordAudit(store.AuditRecord{At: now, Action: "review.unlock", LegacyActor: Scheduler, TargetType: "review_campaign",
		TargetID: strconv.FormatInt(cmp.ID, 10), Detail: ojson.Object{{Key: "campaign_id", Value: cmp.ID}, {Key: "from", Value: store.CampaignLocked},
			{Key: "to", Value: store.CampaignOpen}, {Key: "reason", Value: "the lock ran out"}}})
	return true, err
}

// refuseHeld refuses a decision on an item of a locked or closed campaign. A lock that ran out is lifted first.
func refuseHeld(c *store.TenantTx, now time.Time, item *store.ReviewItem) error {
	cmp, err := c.Campaign(item.CampaignID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	if _, err := ExpireLock(c, now, cmp); err != nil {
		return err
	}
	switch cmp.Status {
	case store.CampaignLocked:
		return refuse(409, ErrCodeLocked, "this review is locked; unlock it to decide")
	case store.CampaignClosed:
		return refuse(409, ErrCodeClosed, "this review is closed")
	}
	return nil
}

// refuseHeldUndecided is refuseHeld for a decision: an item already decided is answered by the
// idempotence rules, not by the lock.
func refuseHeldUndecided(c *store.TenantTx, now time.Time, item *store.ReviewItem) error {
	if item.Decision != nil && *item.Decision != "" {
		return nil
	}
	return refuseHeld(c, now, item)
}

func note(s string, max int, code string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > max || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return "", refuse(422, code, "enter 1 to %d characters", max)
	}
	return s, nil
}

// openItem loads an undecided item of an open campaign.
func openItem(c *store.TenantTx, now time.Time, id int64) (*store.ReviewItem, error) {
	item, err := c.Item(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, ErrCodeNotFound, "review item not found")
	} else if err != nil {
		return nil, err
	}
	if item.Decision != nil && *item.Decision != "" {
		return nil, refuse(409, ErrCodeDecided, "this item is already decided")
	}
	if err := refuseHeld(c, now, item); err != nil {
		return nil, err
	}
	return item, nil
}

func mayAct(item *store.ReviewItem, by Actor) bool {
	return by.Manager || (by.IdentityID != nil && item.ReviewerID != nil && *item.ReviewerID == *by.IdentityID)
}

// person checks someone an action names: active, able to sign in, not the item's subject.
func person(c *store.TenantTx, item *store.ReviewItem, id int64) (*store.Identity, error) {
	p, err := c.Identity(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(422, ErrCodeBadPerson, "that person was not found")
	} else if err != nil {
		return nil, err
	}
	users, err := c.UsersLinkedTo(p.ID)
	if err != nil {
		return nil, err
	}
	if p.Status != "active" || len(users) == 0 {
		return nil, refuse(422, ErrCodeBadPerson, "choose an active person who can sign in")
	}
	if p.ID == item.IdentityID {
		return nil, refuse(422, ErrCodeBadPerson, "the person the access belongs to cannot review it")
	}
	// two accounts of one person are one person (SameActor): none of the new person's accounts is the subject's
	subjectUsers, err := c.PlatformUserIDsForIdentity(item.IdentityID)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		for _, su := range subjectUsers {
			if same, err := c.SameActor(u, su.String()); err != nil {
				return nil, err
			} else if same {
				return nil, refuse(422, ErrCodeBadPerson, "the person the access belongs to cannot review it")
			}
		}
	}
	return p, nil
}

func (a Actor) event(item int64, kind, text string, now time.Time) *store.ReviewItemEvent {
	return &store.ReviewItemEvent{ItemID: item, Kind: kind, ActorUserID: a.User.ID.String(), Actor: a.User.Display, Note: text, At: now}
}

// Consult asks another person for advice on an open item.
func Consult(c *store.TenantTx, now time.Time, itemID int64, by Actor, target int64, question string) (*store.ReviewItemEvent, error) {
	item, err := openItem(c, now, itemID)
	if err != nil {
		return nil, err
	}
	if !mayAct(item, by) {
		return nil, refuse(403, ErrCodeNotYours, "only the reviewer of this item can ask for advice")
	}
	q, err := note(question, MaxActionNote, "invalid_question")
	if err != nil {
		return nil, err
	}
	p, err := person(c, item, target)
	if err != nil {
		return nil, err
	}
	if by.IdentityID != nil && p.ID == *by.IdentityID {
		return nil, refuse(422, ErrCodeBadPerson, "choose someone other than yourself")
	}
	evs, err := c.ReviewItemEvents(item.ID)
	if err != nil {
		return nil, err
	}
	answered := map[int64]bool{}
	for _, e := range evs {
		if e.Kind == store.ReviewEventAnswer && e.RefID != nil {
			answered[*e.RefID] = true
		}
	}
	open := 0
	for _, e := range evs {
		if e.Kind == store.ReviewEventConsult && !answered[e.ID] {
			open++
			if e.TargetIdentityID != nil && *e.TargetIdentityID == p.ID {
				return nil, refuse(409, "already_asked", "that person has an open question on this item")
			}
		}
	}
	if open >= MaxOpenConsults {
		return nil, refuse(422, "too_many_consultations", "at most %d questions can be open on one item", MaxOpenConsults)
	}
	ev := by.event(item.ID, store.ReviewEventConsult, q, now)
	ev.TargetIdentityID = &p.ID
	if ev.ID, err = c.InsertReviewItemEvent(ev); err != nil {
		return nil, err
	}
	return ev, c.Audit(now, by.User.Display, "review.consult", ojson.Object{{Key: "item_id", Value: item.ID},
		{Key: "campaign_id", Value: item.CampaignID}, {Key: "consultant_identity_id", Value: p.ID}, {Key: "event_id", Value: ev.ID}})
}

// Answer replies to a consultation; only the person asked can.
func Answer(c *store.TenantTx, now time.Time, consultID int64, by Actor, text string) (*store.ReviewItemEvent, error) {
	ask, err := c.ReviewItemEvent(consultID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && ask.Kind != store.ReviewEventConsult) {
		return nil, refuse(404, "consultation_not_found", "consultation not found")
	} else if err != nil {
		return nil, err
	}
	if by.IdentityID == nil || ask.TargetIdentityID == nil || *by.IdentityID != *ask.TargetIdentityID {
		return nil, refuse(404, "consultation_not_found", "consultation not found")
	}
	a, err := note(text, MaxActionNote, "invalid_answer")
	if err != nil {
		return nil, err
	}
	item, err := openItem(c, now, ask.ItemID)
	if err != nil {
		return nil, err
	}
	evs, err := c.ReviewItemEvents(ask.ItemID)
	if err != nil {
		return nil, err
	}
	for _, e := range evs {
		if e.Kind == store.ReviewEventAnswer && e.RefID != nil && *e.RefID == ask.ID {
			return nil, refuse(409, "already_answered", "this question is already answered")
		}
	}
	ev := by.event(item.ID, store.ReviewEventAnswer, a, now)
	ev.RefID = &ask.ID
	if ev.ID, err = c.InsertReviewItemEvent(ev); err != nil {
		return nil, err
	}
	return ev, c.Audit(now, by.User.Display, "review.consult.answer", ojson.Object{{Key: "item_id", Value: item.ID},
		{Key: "campaign_id", Value: item.CampaignID}, {Key: "consultation_id", Value: ask.ID}, {Key: "event_id", Value: ev.ID}})
}

// Reassign moves an open item to another reviewer.
func Reassign(c *store.TenantTx, now time.Time, itemID int64, by Actor, to int64, reason string) (*store.ReviewItem, error) {
	item, err := openItem(c, now, itemID)
	if err != nil {
		return nil, err
	}
	if !mayAct(item, by) {
		return nil, refuse(403, ErrCodeNotYours, "only the reviewer of this item can reassign it")
	}
	why, err := note(reason, MaxActionNote, "invalid_reason")
	if err != nil {
		return nil, err
	}
	p, err := person(c, item, to)
	if err != nil {
		return nil, err
	}
	if ok, err := canDecide(c, now, p.ID); err != nil {
		return nil, err
	} else if !ok {
		return nil, refuse(422, ErrCodeBadPerson, "a reviewer must be able to decide reviews")
	}
	if item.ReviewerID != nil && *item.ReviewerID == p.ID {
		return nil, refuse(409, "same_reviewer", "that person already reviews this item")
	}
	if err := c.SetItemReviewer(item.ID, p.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, refuse(409, ErrCodeDecided, "this item is already decided")
		}
		return nil, err
	}
	ev := by.event(item.ID, store.ReviewEventReassign, why, now)
	ev.TargetIdentityID = &p.ID
	if ev.ID, err = c.InsertReviewItemEvent(ev); err != nil {
		return nil, err
	}
	from := any(nil)
	if item.ReviewerID != nil {
		from = *item.ReviewerID
	}
	item.ReviewerID = &p.ID
	return item, c.Audit(now, by.User.Display, "review.reassign", ojson.Object{{Key: "item_id", Value: item.ID},
		{Key: "campaign_id", Value: item.CampaignID}, {Key: "from_identity_id", Value: from}, {Key: "to_identity_id", Value: p.ID}})
}

// Campaign actions.
const (
	ActionLock   = "lock"
	ActionUnlock = "unlock"
	ActionClose  = "close"
)

// ChangeCampaign locks, unlocks or closes a campaign. A lock and a close need a reason.
func ChangeCampaign(c *store.TenantTx, now time.Time, campaignID int64, action string, by store.UserRef, reason string) (*store.ReviewCampaign, error) {
	cmp, err := c.Campaign(campaignID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "campaign_not_found", "campaign not found")
	} else if err != nil {
		return nil, err
	}
	var from1, from2, to string
	switch action {
	case ActionLock:
		from1, from2, to = store.CampaignOpen, store.CampaignOpen, store.CampaignLocked
	case ActionUnlock:
		from1, from2, to = store.CampaignLocked, store.CampaignLocked, store.CampaignOpen
	case ActionClose:
		from1, from2, to = store.CampaignOpen, store.CampaignLocked, store.CampaignClosed
	default:
		return nil, refuse(422, "invalid_action", "the action is lock, unlock or close")
	}
	why := strings.TrimSpace(reason)
	if action != ActionUnlock {
		if why, err = note(reason, MaxReason, "reason_required"); err != nil {
			return nil, err
		}
	} else if utf8.RuneCountInString(why) > MaxReason {
		return nil, refuse(422, "invalid_reason", "the reason is at most %d characters", MaxReason)
	}
	if action == ActionClose {
		if err := refuseCloseUnderPolicy(c, campaignID); err != nil {
			return nil, err
		}
	}
	ok, err := c.TransitionCampaign(campaignID, from1, from2, to)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, refuse(409, "invalid_state", "the review is %s, so it cannot be %s", cmp.Status, map[string]string{ActionLock: "locked", ActionUnlock: "unlocked", ActionClose: "closed"}[action])
	}
	open, err := c.CountOpenItems(campaignID)
	if err != nil {
		return nil, err
	}
	var expires time.Time
	if action == ActionLock {
		expires = now.Add(MaxLock)
		if err := c.PutCampaignLock(&store.CampaignLock{CampaignID: campaignID, LockedBy: by.Display, Reason: why, LockedAt: now, ExpiresAt: expires}); err != nil {
			return nil, err
		}
	} else if err := c.DeleteCampaignLock(campaignID); err != nil {
		return nil, err
	}
	detail := ojson.Object{{Key: "campaign_id", Value: campaignID}, {Key: "from", Value: cmp.Status}, {Key: "to", Value: to},
		{Key: "open_items", Value: open}}
	if why != "" {
		detail = append(detail, ojson.KV{Key: "reason", Value: why})
	}
	if !expires.IsZero() {
		detail = append(detail, ojson.KV{Key: "lock_expires_at", Value: expires.UTC().Format(time.RFC3339)})
	}
	if _, err := c.RecordAudit(store.AuditRecord{At: now, Action: "review." + action, LegacyActor: by.Display, Detail: detail,
		TargetType: "review_campaign", TargetID: strconv.FormatInt(campaignID, 10)}); err != nil {
		return nil, err
	}
	cmp.Status = to
	return cmp, nil
}

// canDecide reports whether one of the person's accounts holds reviews.decide through an active role.
func canDecide(c *store.TenantTx, now time.Time, identity int64) (bool, error) {
	users, err := c.UsersLinkedTo(identity)
	if err != nil {
		return false, err
	}
	roles, err := c.ActiveUserRoles(now)
	if err != nil {
		return false, err
	}
	for _, ur := range roles {
		if !slices.Contains(users, ur.UserID) {
			continue
		}
		if slices.Contains(auth.RolePermissions(auth.Role(ur.Role)), auth.PermReviewsDecide) {
			return true, nil
		}
	}
	return false, nil
}

// refuseCloseUnderPolicy refuses to close a scheduled campaign that still has undecided items while its
// review type's close-out is revoke or escalate: those items owe a revocation (or an escalation first), which
// a hand-closed campaign would skip. Decide them, or let the deadline close the campaign by its policy.
func refuseCloseUnderPolicy(c *store.TenantTx, campaignID int64) error {
	open, err := c.CountOpenItems(campaignID)
	if err != nil || open == 0 {
		return err
	}
	ls, err := c.ReviewLaunches("")
	if err != nil {
		return err
	}
	for _, l := range ls {
		if l.CampaignID != campaignID || l.ClosedAt != nil {
			continue
		}
		t, err := c.ReviewTemplate(l.TemplateID)
		if err != nil {
			return err
		}
		co, err := closeOutOf(c, t)
		if err != nil {
			return err
		}
		if co.How != IncompleteKeep {
			return refuse(409, "open_items_need_decision", "%d items are undecided and this review revokes what is not reviewed: decide them or let the deadline close it", open)
		}
	}
	return nil
}
