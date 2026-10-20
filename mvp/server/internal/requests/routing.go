package requests

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Approval routing (issue #165).
//
// A catalog item's policy lists stages in order: "manager" (the
// beneficiary's manager), "owner" (the item's owner) and "decider" (anyone
// holding requests.decide). A line copies the stages when it is filed and
// resolves each assignee then. The first stage waits; each approval starts
// the next; the last one grants the access. Any stage's approver can deny.
//
// Who may act on the waiting stage:
//   - a manager or owner stage: the platform users who are the assignee, or
//     users the assignee's users delegated their approvals to (in force now);
//   - a decider stage, or any stage past its due time (escalated): holders
//     of requests.decide. A stage with no assignee (no manager, no owner, or
//     nobody signs in as them) is due at once.
//
// Never: the requester, the beneficiary, a delegate acting for either of
// them, or someone who already decided an earlier stage of the same line
// (four eyes across stages).

// MaxStages caps a policy.
const MaxStages = 4

// DefaultEscalateHours is how long a stage waits before deciders may act.
const DefaultEscalateHours = 48.0

// MaxDelegationDays caps a delegation's window.
const MaxDelegationDays = 90

// StageKinds are the stage kinds a policy may use.
var StageKinds = []string{store.StageManager, store.StageOwner, store.StageDecider}

// Policy returns an item's stages and escalation hours (the default: one
// decider stage, 48 hours).
func Policy(tx *store.TenantTx, itemID string) ([]string, float64, error) {
	p, err := tx.ApprovalPolicy(itemID)
	if errors.Is(err, store.ErrNotFound) {
		return []string{store.StageDecider}, DefaultEscalateHours, nil
	} else if err != nil {
		return nil, 0, err
	}
	return p.Stages, p.EscalateAfterHours, nil
}

// SetPolicy replaces an item's approval stages.
func SetPolicy(tx *store.TenantTx, itemID string, stages []string, hours float64, by Actor, now time.Time) error {
	if _, err := tx.CatalogItem(itemID); errors.Is(err, store.ErrNotFound) {
		return refuse(404, "item_not_found", "catalog item not found")
	} else if err != nil {
		return err
	}
	switch {
	case len(stages) == 0 || len(stages) > MaxStages:
		return refuse(422, "invalid_stages", "a policy has 1 to %d stages", MaxStages)
	case !(hours > 0 && hours <= 24*30):
		return refuse(422, "invalid_escalation", "escalation is after 0 to 720 hours")
	}
	seen := map[string]bool{}
	for _, k := range stages {
		if !slices.Contains(StageKinds, k) {
			return refuse(422, "invalid_stages", "stages are manager, owner or decider")
		}
		if seen[k] {
			return refuse(422, "invalid_stages", "each kind of stage appears once")
		}
		seen[k] = true
	}
	uid := by.id()
	if err := tx.PutApprovalPolicy(&store.ApprovalPolicy{CatalogItemID: itemID, Stages: stages, EscalateAfterHours: hours,
		UpdatedBy: &uid, UpdatedAt: now}); err != nil {
		return err
	}
	return tx.Audit(now, by.Display, "approval.policy.put", ojson.Object{{Key: "catalog_item_id", Value: itemID},
		{Key: "stages", Value: stages}, {Key: "escalate_after_hours", Value: strconv.FormatFloat(hours, 'f', -1, 64)}})
}

// startStages files a new line's stages from its item's policy.
func startStages(tx *store.TenantTx, l *store.RequestLine, ben *store.Identity, now time.Time) error {
	it, err := tx.CatalogItem(l.CatalogItemID)
	if err != nil {
		return err
	}
	kinds, hours, err := Policy(tx, it.ID)
	if err != nil {
		return err
	}
	// a guest's request goes to their sponsor first (guest access, issue #75)
	var sponsor *int64
	if pops, err := GuestPopulationsOf(tx, ben.ID); err != nil {
		return err
	} else if len(pops) > 0 {
		if id, ok, err := sponsorOf(tx, ben.ID); err != nil {
			return err
		} else if ok {
			sponsor = &id
		}
		kinds = guestKinds(kinds, it)
	}
	for i, k := range kinds {
		st := &store.RequestStage{LineID: l.ID, Idx: i, Kind: k, Status: store.StageQueued}
		switch k {
		case store.StageSponsor:
			st.AssigneeID = sponsor
		case store.StageManager:
			st.AssigneeID = ben.ManagerID
		case store.StageOwner:
			st.AssigneeID = it.OwnerIdentityID
		}
		if i == 0 {
			if err := begin(tx, st, hours, now); err != nil {
				return err
			}
		}
		if err := tx.InsertRequestStage(st); err != nil {
			return err
		}
	}
	return nil
}

// notifyWaiting tells the approvers of a line's waiting stage that it needs
// them (issue #189), in the caller's transaction.
func notifyWaiting(tx *store.TenantTx, l *store.RequestLine, now time.Time) error {
	stages, err := tx.RequestStages(l.ID)
	if err != nil {
		return err
	}
	for _, st := range stages {
		if st.Status == store.StageWaiting {
			return notify.ApprovalNeeded(tx, now, l, st, len(stages))
		}
	}
	return nil
}

// begin makes st the waiting stage, due after hours, or at once when nobody
// can act as its assignee.
func begin(tx *store.TenantTx, st *store.RequestStage, hours float64, now time.Time) error {
	due := now.Add(timeutil.Delta(hours, timeutil.MicrosPerHour))
	if st.Kind != store.StageDecider {
		reachable := false
		if st.AssigneeID != nil {
			if i, err := tx.Identity(*st.AssigneeID); err == nil && i.Status == "active" {
				users, err := tx.UsersLinkedTo(i.ID)
				if err != nil {
					return err
				}
				reachable = len(users) > 0
			} else if err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		if !reachable {
			due = now // escalated at once: deciders act
		}
	}
	st.Status, st.StartedAt, st.DueAt = store.StageWaiting, &now, &due
	return nil
}

// Authority says whether a user may act on a line's waiting stage, and on
// whose behalf.
type Authority struct {
	Stage      *store.RequestStage // nil: a line filed before routing (one decider stage)
	OnBehalfOf *string             // the delegating user
	Escalated  bool
}

// authorize finds the waiting stage and checks by may decide it.
func authorize(tx *store.TenantTx, l *store.RequestLine, by Actor, now time.Time) (*Authority, error) {
	if l.Status != store.RequestPending {
		return nil, refuse(409, "not_pending", "the request is %s", l.Status)
	}
	if l.RequestedBy == by.id() {
		return nil, refuse(403, "self_approval", "you cannot decide a request you made")
	}
	if by.IdentityID != nil && *by.IdentityID == l.BeneficiaryID {
		return nil, refuse(403, "self_approval", "you cannot decide access for yourself")
	}
	stages, err := tx.RequestStages(l.ID)
	if err != nil {
		return nil, err
	}
	if len(stages) == 0 {
		if !by.Decider {
			return nil, refuse(403, "not_an_approver", "you are not an approver of this request")
		}
		return &Authority{}, nil
	}
	var waiting *store.RequestStage
	for _, s := range stages {
		if s.Status == store.StageApproved && (eq(s.DecidedBy, by.id()) || eq(s.OnBehalfOf, by.id())) {
			return nil, refuse(403, "already_decided_a_stage", "you approved an earlier stage; another person decides this one")
		}
		if s.Status == store.StageWaiting && waiting == nil {
			waiting = s
		}
	}
	if waiting == nil {
		return nil, refuse(409, "not_pending", "the request has no stage waiting")
	}
	escalated := waiting.DueAt != nil && !now.Before(*waiting.DueAt)
	a := &Authority{Stage: waiting, Escalated: escalated}
	if waiting.Kind == store.StageDecider || escalated {
		if by.Decider {
			return a, nil
		}
	}
	if waiting.Kind != store.StageDecider && waiting.AssigneeID != nil {
		if by.IdentityID != nil && *by.IdentityID == *waiting.AssigneeID {
			return a, nil
		}
		assignees, err := tx.UsersLinkedTo(*waiting.AssigneeID)
		if err != nil {
			return nil, err
		}
		dels, err := tx.ActiveApprovalDelegationsTo(by.id(), now)
		if err != nil {
			return nil, err
		}
		for _, d := range dels {
			if d.FromUser == l.RequestedBy || !slices.Contains(assignees, d.FromUser) {
				continue // a delegation never covers the delegator's own requests
			}
			from := d.FromUser
			// nor access for the delegator themselves
			fid, err := uuid.Parse(from)
			if err != nil {
				continue
			}
			if u, err := tx.PlatformUser(fid); err != nil {
				return nil, err
			} else if u.IdentityID != nil && *u.IdentityID == l.BeneficiaryID {
				continue
			}
			a.OnBehalfOf = &from
			return a, nil
		}
	}
	return nil, refuse(403, "not_an_approver", "you are not an approver of the current stage")
}

func eq(p *string, v string) bool { return p != nil && *p == v }

// approveStage records an approval of the waiting stage and starts the next
// one; it reports whether the line has more stages to go.
func approveStage(tx *store.TenantTx, l *store.RequestLine, a *Authority, by Actor, reason *string, now time.Time) (bool, error) {
	st := a.Stage
	uid := by.id()
	st.Status, st.DecidedBy, st.OnBehalfOf, st.DecidedAt, st.Reason = store.StageApproved, &uid, a.OnBehalfOf, &now, reason
	if err := tx.SaveRequestStage(st, store.StageWaiting); err != nil {
		return false, err
	}
	stages, err := tx.RequestStages(l.ID)
	if err != nil {
		return false, err
	}
	for _, next := range stages {
		if next.Idx > st.Idx && next.Status == store.StageQueued {
			_, hours, err := Policy(tx, l.CatalogItemID)
			if err != nil {
				return false, err
			}
			if err := begin(tx, next, hours, now); err != nil {
				return false, err
			}
			return true, tx.SaveRequestStage(next, store.StageQueued)
		}
	}
	return false, nil
}

func stageNote(a *Authority, total int, reason *string) *string {
	if a == nil || a.Stage == nil {
		return reason
	}
	var b strings.Builder
	b.WriteString(a.Stage.Kind + " stage")
	if total > 1 {
		b.WriteString(" (" + strconv.Itoa(a.Stage.Idx+1) + " of " + strconv.Itoa(total) + ")")
	}
	if a.Escalated && a.Stage.Kind != store.StageDecider {
		b.WriteString(", escalated")
	}
	if a.OnBehalfOf != nil {
		b.WriteString(", as a delegate")
	}
	if reason != nil {
		b.WriteString(": " + *reason)
	}
	s := b.String()
	return &s
}

// Pending is a line waiting on the signed-in user.
type Pending struct {
	Line      *store.RequestLine
	Authority *Authority
}

// Inbox lists the pending lines by may decide now, oldest first.
func Inbox(tx *store.TenantTx, by Actor, now time.Time) ([]Pending, error) {
	lines, err := tx.RequestLines(store.RequestFilter{Status: store.RequestPending})
	if err != nil {
		return nil, err
	}
	var out []Pending
	for i := len(lines) - 1; i >= 0; i-- {
		l := lines[i]
		a, err := authorize(tx, l, by, now)
		var re *Error
		if errors.As(err, &re) {
			continue
		} else if err != nil {
			return nil, err
		}
		out = append(out, Pending{Line: l, Authority: a})
	}
	return out, nil
}

// CanDecide reports whether by may decide the line now (for views).
func CanDecide(tx *store.TenantTx, l *store.RequestLine, by Actor, now time.Time) (bool, error) {
	_, err := authorize(tx, l, by, now)
	var re *Error
	if errors.As(err, &re) {
		return false, nil
	}
	return err == nil, err
}

// ---------------------------------------------------------------- delegations

// Delegate hands by's approvals to another user for a window.
func Delegate(tx *store.TenantTx, by Actor, to string, starts, ends time.Time, reason string, now time.Time) (*store.ApprovalDelegationRow, error) {
	r := strings.TrimSpace(reason)
	switch {
	case r == "" || len(r) > MaxReason:
		return nil, refuse(422, "reason_required", "a reason of 1 to %d characters is required", MaxReason)
	case !ends.After(starts) || !ends.After(now):
		return nil, refuse(422, "invalid_window", "the delegation must end after it starts, in the future")
	case ends.Sub(starts) > MaxDelegationDays*24*time.Hour:
		return nil, refuse(422, "invalid_window", "a delegation lasts at most %d days", MaxDelegationDays)
	case to == by.id():
		return nil, refuse(422, "self_delegation", "delegate to someone else")
	}
	tid, err := uuid.Parse(to)
	if err != nil {
		return nil, refuse(404, "user_not_found", "user not found")
	}
	u, err := tx.PlatformUser(tid)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "user_not_found", "user not found")
	} else if err != nil {
		return nil, err
	}
	if u.Status != "active" {
		return nil, refuse(409, "user_not_active", "%s is not an active user", u.DisplayName)
	}
	d := &store.ApprovalDelegationRow{ID: uuid.NewString(), FromUser: by.id(), ToUser: to, StartsAt: starts.UTC(), EndsAt: ends.UTC(),
		Reason: r, CreatedAt: now}
	if err := tx.InsertApprovalDelegation(d); err != nil {
		return nil, err
	}
	if err := notify.ApprovalDelegated(tx, now, d); err != nil {
		return nil, err
	}
	return d, tx.Audit(now, by.Display, "approval.delegate", ojson.Object{{Key: "delegation_id", Value: d.ID},
		{Key: "to_user_id", Value: to}, {Key: "starts_at", Value: timeutil.ISO(d.StartsAt)},
		{Key: "ends_at", Value: timeutil.ISO(d.EndsAt)}, {Key: "reason", Value: r}})
}

// RevokeDelegation ends a delegation early; its giver or a decider may.
func RevokeDelegation(tx *store.TenantTx, id string, by Actor, now time.Time) (*store.ApprovalDelegationRow, error) {
	d, err := tx.ApprovalDelegation(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "delegation_not_found", "delegation not found")
	} else if err != nil {
		return nil, err
	}
	if d.FromUser != by.id() && d.ToUser != by.id() && !by.Decider {
		return nil, refuse(404, "delegation_not_found", "delegation not found")
	}
	if d.RevokedAt != nil || !d.EndsAt.After(now) {
		return nil, refuse(409, "delegation_ended", "the delegation has already ended")
	}
	if err := tx.RevokeApprovalDelegation(d.ID, by.id(), now); err != nil {
		return nil, err
	}
	uid := by.id()
	d.RevokedAt, d.RevokedBy = &now, &uid
	return d, tx.Audit(now, by.Display, "approval.delegation.revoke", ojson.Object{{Key: "delegation_id", Value: d.ID}})
}
