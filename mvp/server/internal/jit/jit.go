// Package jit implements just-in-time access: time-bound group/role
// membership with auto-expiry.
package jit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// MaxHours is the longest grant that can be requested.
const MaxHours = 72

// MaxJustification is the longest justification, in characters (runes).
const MaxJustification = 1000

// Kind classifies an Error for the API: invalid input (400), an unknown
// record (404) or a state conflict on an existing record (409).
type Kind int

const (
	KindInvalid Kind = iota
	KindNotFound
	KindConflict
	KindForbidden // 403: the caller may not decide this request (eligibility approvers, issue #651)
)

// Stable codes of the errors that carry one.
const (
	CodeJustificationTooLong = "justification_too_long"
	CodeDuplicatePending     = "duplicate_pending_request"
)

// Error is a refused request. Kind says how the API maps it (400 by default).
type Error struct {
	Msg  string
	Kind Kind
	Code string // stable machine code, empty when the message is all there is
}

func (e *Error) Error() string { return e.Msg }

// ErrSelfApproval refuses an approval by the platform user who made the
// request, or by the platform user linked to the identity that would get the
// access (separation of duties: nobody grants themselves access).
var ErrSelfApproval = errors.New("jit: the requester cannot approve their own request")

// ErrApproverUnlinked refuses an approval by a platform user with no linked
// identity: the self-approval check cannot prove they are not the beneficiary,
// so it fails closed (issue #443, as reviewer_unlinked in #439).
var ErrApproverUnlinked = errors.New("jit: the approver's account is not linked to an identity")

func jitErr(format string, args ...any) error { return &Error{Msg: fmt.Sprintf(format, args...)} }

func notFound(msg string) error { return &Error{Msg: msg, Kind: KindNotFound} }

func conflict(code, msg string) error { return &Error{Msg: msg, Kind: KindConflict, Code: code} }

// Hours is a requested duration. Whole marks a value supplied as an integer
// (the API's default of 4, or the seed's literals): the creation response and
// the audit log render it as 4 rather than 4.0, as the original backend did.
type Hours struct {
	N     float64
	Whole bool
}

// JSON returns the value as the API renders it.
func (h Hours) JSON() any {
	if h.Whole && h.N == float64(int64(h.N)) {
		return int64(h.N)
	}
	return ojson.Float(h.N)
}

// Audit returns the value as the audit ledger records it: a decimal string
// spelled as the API renders it ("4", "2.0", "1.5"). The ledger refuses
// floats so that every JCS implementation reproduces the event hash.
func (h Hours) Audit() string {
	b, err := ojson.Marshal(h.JSON())
	if err != nil {
		return fmt.Sprint(h.N)
	}
	return string(b)
}

// AccountFor picks the account that receives the grant: same system as the
// group, else the IdP (Okta) account.
func AccountFor(c *store.TenantTx, identityID int64, g *store.Group) (*store.Account, error) {
	accts, err := c.IdentityAccounts(identityID)
	if err != nil {
		return nil, err
	}
	for _, system := range []string{g.System, "okta"} {
		for _, a := range accts {
			if a.Status == "active" && a.System == system {
				return a, nil
			}
		}
	}
	return nil, jitErr("identity has no active account that can receive this grant")
}

func getOrNil[T any](v *T, err error) (*T, error) {
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return v, err
}

// CreateRequest files a pending request on behalf of identityID, made by the
// platform user by (zero for seed data).
func CreateRequest(c *store.TenantTx, now time.Time, identityID, groupID int64, hours Hours, justification string,
	by store.UserRef) (*store.AccessRequest, error) {
	ident, err := getOrNil(c.Identity(identityID))
	if err != nil {
		return nil, err
	}
	g, err := getOrNil(c.Group(groupID))
	if err != nil {
		return nil, err
	}
	if ident == nil || g == nil {
		return nil, jitErr("unknown identity or group")
	}
	if ident.Status != "active" {
		return nil, jitErr("identity is not active")
	}
	// Once the tenant applies JIT eligibility rules, they decide (deny by default); until then groups.requestable does.
	enforced, err := Enforced(c)
	if err != nil {
		return nil, err
	}
	if !enforced && !g.Requestable {
		return nil, jitErr("%s is not eligible for just-in-time access", g.Name)
	}
	if !(hours.N > 0 && hours.N <= MaxHours) {
		return nil, jitErr("duration must be between 0 and %d hours", MaxHours)
	}
	justification = strings.TrimSpace(justification)
	if justification == "" {
		return nil, jitErr("justification is required")
	}
	if utf8.RuneCountInString(justification) > MaxJustification {
		return nil, &Error{Msg: fmt.Sprintf("justification must be at most %d characters", MaxJustification),
			Code: CodeJustificationTooLong}
	}
	if enforced {
		if err := checkEligible(c, now, ident, g, hours.N); err != nil {
			return nil, err
		}
	}
	acct, err := AccountFor(c, identityID, g)
	if err != nil {
		return nil, err
	}
	standing, err := c.HasStandingEdge(graph.Key("account", acct.ID), graph.Key("group", g.ID))
	if err != nil {
		return nil, err
	}
	if standing {
		return nil, jitErr("%s already holds %s as a standing grant", ident.Name, g.Name)
	}
	dup, err := c.HasPendingRequest(identityID, g.ID)
	if err != nil {
		return nil, err
	}
	if dup {
		return nil, errDuplicatePending(ident.Name, g.Name)
	}
	id, err := c.InsertRequest(&store.AccessRequest{IdentityID: identityID, AccountID: acct.ID, GroupID: g.ID,
		Justification: justification, DurationHours: hours.N, Status: "pending", RequestedAt: now,
		RequestedByUserID: userID(by)})
	if errors.Is(err, store.ErrDuplicate) { // the partial unique index, should a check ever race
		return nil, errDuplicatePending(ident.Name, g.Name)
	}
	if err != nil {
		return nil, err
	}
	if err := c.Audit(now, ident.Name, "jit.request", ojson.Object{{Key: "request_id", Value: id},
		{Key: "group", Value: g.Name}, {Key: "hours", Value: hours.Audit()}}); err != nil {
		return nil, err
	}
	return c.Request(id)
}

func errDuplicatePending(identity, group string) error {
	return conflict(CodeDuplicatePending, fmt.Sprintf("%s already has a pending request for %s", identity, group))
}

func pending(c *store.TenantTx, id int64) (*store.AccessRequest, error) {
	r, err := getOrNil(c.Request(id))
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, notFound("request not found")
	}
	if r.Status != "pending" {
		return nil, conflict("", "request is not pending")
	}
	return r, nil
}

// Approve grants the access until now + duration. createdAt stamps a newly
// created edge (the wall clock, which differs from now when back-dating).
// by is the approver: its display string is decided_by, its platform user
// decided_by_user_id. The audit actor is the request's principal.
func Approve(c *store.TenantTx, requestID int64, by store.UserRef, now, createdAt time.Time) (*store.AccessRequest, error) {
	req, err := pending(c, requestID)
	if err != nil {
		return nil, err
	}
	if by.ID != uuid.Nil {
		if req.RequestedByUserID != nil {
			if same, err := c.SameActor(req.RequestedByUserID.String(), by.ID.String()); err != nil {
				return nil, err
			} else if same {
				return nil, ErrSelfApproval
			}
		}
		u, err := c.PlatformUser(by.ID)
		if err != nil {
			return nil, err
		}
		if u.IdentityID == nil {
			return nil, ErrApproverUnlinked
		}
		if *u.IdentityID == req.IdentityID {
			return nil, ErrSelfApproval
		}
		if enforced, err := Enforced(c); err != nil {
			return nil, err
		} else if enforced {
			if err := checkApprover(c, now, req, *u.IdentityID); err != nil {
				return nil, err
			}
		}
	}
	src, dst := graph.Key("account", req.AccountID), graph.Key("group", req.GroupID)
	existing, err := getOrNil(c.EdgeBetween(src, dst))
	if err != nil {
		return nil, err
	}
	expires := now.Add(timeutil.Delta(req.DurationHours, timeutil.MicrosPerHour))
	if existing != nil && existing.Source != "jit" {
		return nil, jitErr("identity already holds this access as a standing grant")
	}
	var edgeID int64
	if existing == nil {
		edgeID, err = c.InsertEdge(&store.GrantEdge{Src: src, Dst: dst, Relation: "member_of", Source: "jit",
			ExpiresAt: &expires, CreatedAt: createdAt, Ref: "jit:" + strconv.FormatInt(req.ID, 10)})
	} else {
		edgeID = existing.ID
		err = c.SetEdgeExpiry(edgeID, expires, createdAt)
	}
	if err != nil {
		return nil, err
	}
	approver := by.Display
	req.Status, req.DecidedAt, req.DecidedBy, req.ExpiresAt, req.EdgeID = "approved", &now, &approver, &expires, &edgeID
	req.DecidedByUserID = userID(by)
	if err := c.SaveRequest(req); err != nil {
		return nil, err
	}
	if err := notifyDecided(c, now, req, by); err != nil {
		return nil, err
	}
	if err := c.Audit(createdAt, approver, "jit.approve", ojson.Object{{Key: "request_id", Value: req.ID},
		{Key: "expires_at", Value: timeutil.ISO(expires)}}); err != nil {
		return nil, err
	}
	return req, nil
}

// Deny rejects a pending request.
func Deny(c *store.TenantTx, requestID int64, by store.UserRef, now time.Time) (*store.AccessRequest, error) {
	req, err := pending(c, requestID)
	if err != nil {
		return nil, err
	}
	approver := by.Display
	req.Status, req.DecidedAt, req.DecidedBy, req.DecidedByUserID = "denied", &now, &approver, userID(by)
	if err := c.SaveRequest(req); err != nil {
		return nil, err
	}
	if err := notifyDecided(c, now, req, by); err != nil {
		return nil, err
	}
	return req, c.Audit(now, approver, "jit.deny", ojson.Object{{Key: "request_id", Value: req.ID}})
}

// notifyDecided tells the requester and the person that a request was granted
// or denied (issue #189). Seed data has no signed-in decider and tells no one.
func notifyDecided(c *store.TenantTx, now time.Time, req *store.AccessRequest, by store.UserRef) error {
	if by.ID == uuid.Nil {
		return nil
	}
	return notify.JITDecided(c, now, req, by.ID.String())
}

// Revoke ends an active grant early. When the group's system has a
// connection with write-back on, the removal goes to the target and the
// request stays approved (the grant stays) until a re-read confirms it.
func Revoke(c *store.TenantTx, requestID int64, by store.UserRef, now time.Time) (*store.AccessRequest, error) {
	req, err := getOrNil(c.Request(requestID))
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, notFound("request not found")
	}
	if req.Status != "approved" {
		return nil, conflict("", "request is not active")
	}
	if routed, _, err := routeEnd(c, now, req, "revoked", by.Display, false); err != nil {
		return nil, err
	} else if routed {
		return req, nil
	}
	if err := dropEdge(c, req, now); err != nil {
		return nil, err
	}
	req.Status, req.ExpiresAt = "revoked", &now
	if err := c.SaveRequest(req); err != nil {
		return nil, err
	}
	return req, c.Audit(now, by.Display, "jit.revoke", ojson.Object{{Key: "request_id", Value: req.ID}})
}

func dropEdge(c *store.TenantTx, req *store.AccessRequest, now time.Time) error {
	if req.EdgeID == nil || *req.EdgeID == 0 {
		return nil
	}
	return c.DeleteJITEdge(*req.EdgeID, now)
}

// completeEnd is the provisioning completion that ends a grant once the
// target no longer shows the membership.
const completeEnd = "jit.end"

type endData struct {
	RequestID int64  `json:"request_id"`
	Status    string `json:"status"` // revoked | expired
	By        string `json:"by"`
}

func init() {
	provision.RegisterCompletion(completeEnd, func(c *store.TenantTx, now time.Time, raw json.RawMessage) error {
		var d endData
		if err := json.Unmarshal(raw, &d); err != nil {
			return err
		}
		req, err := getOrNil(c.Request(d.RequestID))
		if err != nil {
			return err
		}
		if req == nil || req.Status != "approved" {
			return nil // ended some other way meanwhile
		}
		if err := dropEdge(c, req, now); err != nil {
			return err
		}
		req.Status, req.ExpiresAt = d.Status, &now
		if err := c.SaveRequest(req); err != nil {
			return err
		}
		action := "jit.revoke"
		if d.Status == "expired" {
			action = "jit.expire"
		}
		return c.Audit(now, d.By, action, ojson.Object{{Key: "request_id", Value: req.ID}})
	})
}

// routeEnd sends the removal of an approved grant to the target. It reports
// whether the system is routed (a system without write-back is not) and
// whether this call queued a new operation. background: the caller is the
// sweeper, which must not retry an operation an operator has to look at.
func routeEnd(c *store.TenantTx, now time.Time, req *store.AccessRequest, status, by string, background bool) (routed, created bool, err error) {
	g, err := getOrNil(c.Group(req.GroupID))
	if err != nil || g == nil {
		return false, false, err
	}
	a, err := getOrNil(c.Account(req.AccountID))
	if err != nil || a == nil {
		return false, false, err
	}
	key := fmt.Sprintf("jit:%d:end", req.ID)
	_, lookup := c.ProvOpByKey(key)
	_, routed, err = provision.Submit(c, now, provision.Change{System: g.System, Kind: target.RemoveEntitlement,
		Account: target.Account{Username: a.Username, ExternalID: a.ExternalID},
		Group:   target.Group{ExternalID: g.ExternalID, Name: g.Name}, Source: provision.SourceJIT,
		Key: key, Completion: completeEnd, Data: endData{RequestID: req.ID, Status: status, By: by}, NoRequeue: background})
	return routed, routed && errors.Is(lookup, store.ErrNotFound), err
}

// NeedsSweep reports whether Sweep would change anything at now.
func NeedsSweep(c *store.TenantTx, now time.Time) (bool, error) {
	n, err := c.JITSweepPending(now)
	return n > 0, err
}

// Sweep expires approved requests past their deadline, removes their grant
// edges and any orphaned expired JIT edges. It returns the number of
// requests expired.
func Sweep(c *store.TenantTx, now time.Time) (int, error) {
	reqs, err := c.ExpiredApprovedRequests(now)
	if err != nil {
		return 0, err
	}
	expired := 0
	for _, r := range reqs {
		if routed, created, err := routeEnd(c, now, r, "expired", "system", true); err != nil {
			return 0, err
		} else if routed {
			if created {
				expired++ // counted when queued; the grant stays until the target confirms the removal
			}
			continue
		}
		if err := dropEdge(c, r, now); err != nil {
			return 0, err
		}
		r.Status = "expired"
		if err := c.SaveRequest(r); err != nil {
			return 0, err
		}
		if err := c.Audit(now, "system", "jit.expire", ojson.Object{{Key: "request_id", Value: r.ID}}); err != nil {
			return 0, err
		}
		expired++
	}
	// orphan JIT edges (e.g. created directly) also expire
	if _, err := c.DeleteExpiredJITEdges(now); err != nil {
		return 0, err
	}
	return expired, nil
}

// SweepAll runs Sweep for every active tenant, each in its own tenant
// transaction (the background sweeper). A tenant with nothing to expire is
// left untouched. An error in one tenant does not stop the others. It returns
// the number of requests expired per tenant.
func SweepAll(ctx context.Context, db *store.DB, now time.Time) (map[tenancy.ID]int, error) {
	out := map[tenancy.ID]int{}
	err := db.ForEachActiveTenant(ctx, func(_ context.Context, tx *store.TenantTx) error {
		need, err := NeedsSweep(tx, now)
		if err != nil || !need {
			return err
		}
		n, err := Sweep(tx, now)
		if err != nil {
			return err
		}
		out[tx.Tenant()] = n
		return nil
	})
	return out, err
}

// userID is the platform user of by, or nil.
func userID(by store.UserRef) *uuid.UUID {
	if by.ID == uuid.Nil {
		return nil
	}
	id := by.ID
	return &id
}
