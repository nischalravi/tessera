package requests

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Removal requests (My access > Request removal). A person asks for a grant
// they hold to be removed; their manager (or a delegate of the manager, or a
// holder of requests.decide) approves or denies. Approval removes the grant:
// through Remove when an approved access request granted it, otherwise as a
// revoked grant with a tombstone so a connector sync does not bring it back.
// What Tessera removes is the grant in its graph, as with every revoke in
// Tessera; it does not write back to the source system.

// Removal outcomes recorded on an approved request.
const (
	OutcomeRevoked        = "revoked"
	OutcomeRequestRemoved = "request_removed"
	OutcomeAlreadyRemoved = "already_removed"
)

// grantNode parses a node key such as "account:12".
func grantNode(key, kind string) (int64, bool) {
	rest, ok := strings.CutPrefix(key, kind+":")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	return n, err == nil && n > 0
}

// SubmitRemoval files a pending removal request for the grant edgeID.
// forOthers allows grants of people other than the actor's own identity.
func SubmitRemoval(tx *store.TenantTx, edgeID int64, justification string, by Actor, forOthers bool, now time.Time) (*store.RemovalRequest, error) {
	just := strings.TrimSpace(justification)
	if just == "" || len(just) > MaxJustification {
		return nil, refuse(422, "justification_required", "a justification of 1 to %d characters is required", MaxJustification)
	}
	notFound := refuse(404, "grant_not_found", "grant not found")
	e, err := tx.Edge(edgeID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound
	} else if err != nil {
		return nil, err
	}
	acctID, ok1 := grantNode(e.Src, "account")
	groupID, ok2 := grantNode(e.Dst, "group")
	if !ok1 || !ok2 {
		return nil, refuse(409, "not_removable", "only a group membership can be removed here")
	}
	a, err := tx.Account(acctID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && a.IdentityID == nil) {
		return nil, notFound
	} else if err != nil {
		return nil, err
	}
	ben := *a.IdentityID
	switch {
	case (by.IdentityID == nil || *by.IdentityID != ben) && !forOthers:
		return nil, refuse(403, "for_others_not_allowed", "you can request removal only of your own access")
	case e.Source == "jit":
		return nil, refuse(409, "not_removable", "just-in-time access ends by itself; revoke it from Just-in-time")
	case e.Source == "role":
		return nil, refuse(409, "not_removable", "this access comes from a business role; ask for the role to be removed instead")
	}
	g, err := tx.Group(groupID)
	if err != nil {
		return nil, err
	}
	q := &store.RemovalRequest{ID: uuid.NewString(), BeneficiaryID: ben, AccountID: acctID, GroupID: groupID,
		RequestedBy: by.id(), Justification: just, Status: store.RequestPending, RequestedAt: now}
	if err := tx.InsertRemovalRequest(q); errors.Is(err, store.ErrDuplicate) {
		return nil, refuse(409, "already_requested", "removal of %s is already requested", g.Name)
	} else if err != nil {
		return nil, err
	}
	return q, tx.Audit(now, by.Display, "removal.request.submit", removalDetail(q, nil, nil))
}

func removalDetail(q *store.RemovalRequest, reason, outcome *string) ojson.Object {
	d := ojson.Object{{Key: "removal_request_id", Value: q.ID}, {Key: "beneficiary_id", Value: q.BeneficiaryID},
		{Key: "account_id", Value: q.AccountID}, {Key: "group_id", Value: q.GroupID}, {Key: "status", Value: q.Status}}
	if reason != nil {
		d = append(d, ojson.KV{Key: "reason", Value: *reason})
	}
	if outcome != nil {
		d = append(d, ojson.KV{Key: "outcome", Value: *outcome})
	}
	return d
}

// CanDecideRemoval reports whether by may decide q now: not the person who
// asked or the one it is for, and either the beneficiary's manager, a
// delegate of the manager, or a holder of requests.decide.
func CanDecideRemoval(tx *store.TenantTx, q *store.RemovalRequest, by Actor, now time.Time) (bool, error) {
	if q.Status != store.RequestPending || q.RequestedBy == by.id() ||
		(by.IdentityID != nil && *by.IdentityID == q.BeneficiaryID) {
		return false, nil
	}
	if by.Decider {
		return true, nil
	}
	ben, err := tx.Identity(q.BeneficiaryID)
	if err != nil || ben.ManagerID == nil {
		return false, err
	}
	if by.IdentityID != nil && *by.IdentityID == *ben.ManagerID {
		return true, nil
	}
	managers, err := tx.UsersLinkedTo(*ben.ManagerID)
	if err != nil {
		return false, err
	}
	dels, err := tx.ActiveApprovalDelegationsTo(by.id(), now)
	if err != nil {
		return false, err
	}
	for _, d := range dels {
		if d.FromUser == q.RequestedBy || !slices.Contains(managers, d.FromUser) {
			continue // a delegation never covers the delegator's own requests
		}
		fid, err := uuid.Parse(d.FromUser)
		if err != nil {
			continue
		}
		if u, err := tx.PlatformUser(fid); err != nil {
			return false, err
		} else if u.IdentityID != nil && *u.IdentityID == q.BeneficiaryID {
			continue // nor access for the delegator themselves
		}
		return true, nil
	}
	return false, nil
}

func pendingRemoval(tx *store.TenantTx, id string) (*store.RemovalRequest, error) {
	q, err := tx.RemovalRequest(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "request_not_found", "request not found")
	} else if err != nil {
		return nil, err
	}
	if q.Status != store.RequestPending {
		return nil, refuse(409, "not_pending", "the request is %s", q.Status)
	}
	return q, nil
}

func authorizeRemoval(tx *store.TenantTx, q *store.RemovalRequest, by Actor, now time.Time) error {
	switch {
	case q.RequestedBy == by.id():
		return refuse(403, "self_approval", "you cannot decide a request you made")
	case by.IdentityID != nil && *by.IdentityID == q.BeneficiaryID:
		return refuse(403, "self_approval", "you cannot decide access for yourself")
	}
	if ok, err := CanDecideRemoval(tx, q, by, now); err != nil {
		return err
	} else if !ok {
		return refuse(403, "not_an_approver", "you are not an approver of this request")
	}
	return nil
}

// ApproveRemoval removes the grant of a pending request.
func ApproveRemoval(tx *store.TenantTx, id string, by Actor, reason string, now time.Time) (*store.RemovalRequest, error) {
	q, err := pendingRemoval(tx, id)
	if err != nil {
		return nil, err
	}
	rp, err := reasonPtr(reason, false)
	if err != nil {
		return nil, err
	}
	if err := authorizeRemoval(tx, q, by, now); err != nil {
		return nil, err
	}
	outcome := OutcomeAlreadyRemoved
	e, err := tx.EdgeBetween("account:"+strconv.FormatInt(q.AccountID, 10), "group:"+strconv.FormatInt(q.GroupID, 10))
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return nil, err
	case e.Source == "role":
		return nil, refuse(409, "not_removable", "this access now comes from a business role; deny the request and remove the role instead")
	case e.Source == "jit":
		if err := tx.DeleteJITEdge(e.ID); err != nil {
			return nil, err
		}
		outcome = OutcomeRevoked
	default:
		line, err := tx.OpenRequestLine(q.BeneficiaryID, q.GroupID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		if err == nil && line.Status == store.RequestApproved {
			// the access came from an approved request: end that request, which removes its edge
			if _, err := Remove(tx, line.ID, by, true, "", now); err != nil {
				return nil, err
			}
			outcome = OutcomeRequestRemoved
			break
		}
		if err := tx.RevokeEdge(e.ID, now, "removal request "+q.ID); err != nil {
			return nil, err
		}
		outcome = OutcomeRevoked
	}
	uid := by.id()
	q.Status, q.DecidedBy, q.DecidedAt, q.DecisionReason, q.Outcome = store.RequestApproved, &uid, &now, rp, &outcome
	if err := tx.SaveRemovalRequest(q, store.RequestPending); err != nil {
		return nil, err
	}
	return q, tx.Audit(now, by.Display, "removal.request.approve", removalDetail(q, rp, &outcome))
}

// DenyRemoval rejects a pending request; a reason is required.
func DenyRemoval(tx *store.TenantTx, id string, by Actor, reason string, now time.Time) (*store.RemovalRequest, error) {
	q, err := pendingRemoval(tx, id)
	if err != nil {
		return nil, err
	}
	rp, err := reasonPtr(reason, true)
	if err != nil {
		return nil, err
	}
	if err := authorizeRemoval(tx, q, by, now); err != nil {
		return nil, err
	}
	uid := by.id()
	q.Status, q.DecidedBy, q.DecidedAt, q.DecisionReason = store.RequestDenied, &uid, &now, rp
	if err := tx.SaveRemovalRequest(q, store.RequestPending); err != nil {
		return nil, err
	}
	return q, tx.Audit(now, by.Display, "removal.request.deny", removalDetail(q, rp, nil))
}

// CancelRemoval withdraws a pending request; only its requester may (others'
// look missing).
func CancelRemoval(tx *store.TenantTx, id string, by Actor, now time.Time) (*store.RemovalRequest, error) {
	q, err := tx.RemovalRequest(id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && q.RequestedBy != by.id()) {
		return nil, refuse(404, "request_not_found", "request not found")
	} else if err != nil {
		return nil, err
	}
	if q.Status != store.RequestPending {
		return nil, refuse(409, "not_pending", "the request is %s", q.Status)
	}
	q.Status, q.DecidedAt = store.RequestCancelled, &now
	if err := tx.SaveRemovalRequest(q, store.RequestPending); err != nil {
		return nil, err
	}
	return q, tx.Audit(now, by.Display, "removal.request.cancel", removalDetail(q, nil, nil))
}
