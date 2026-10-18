package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Removal requests (My access > Request removal):
//
//	POST /api/removal-requests                       {edge_id, justification}: ask for a grant to be removed
//	GET  /api/removal-requests                       ?scope=mine (default) | approvals | pending | all
//	POST /api/removal-requests/{request_id}/approve  {reason?}: removes the grant
//	POST /api/removal-requests/{request_id}/deny     {reason}
//	POST /api/removal-requests/{request_id}/cancel   the requester withdraws a pending request
//
// Everyone but break-glass holds requests.create (for their own access;
// other people's needs requests.create_for_others). The approver is the
// person's manager, a delegate of the manager, or a holder of
// requests.decide; approval also needs a fresh phishing-resistant sign-in.
// scope=approvals lists what the signed-in user may decide now (the Inbox).
// Requests of other people are visible to their requester, beneficiary,
// approvers and graph readers only; to anyone else they look missing.

func (s *Server) registerRemovalRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	create := need(auth.PermRequestsCreate)
	s.handle(P, "/api/removal-requests", write, create, s.submitRemoval)
	s.handle(G, "/api/removal-requests", read, create, s.listRemovals)
	s.handle(P, "/api/removal-requests/{request_id}/approve", write, needStepUp(auth.PermRequestsCreate, auth.StepUpPolicy), s.approveRemoval)
	s.handle(P, "/api/removal-requests/{request_id}/deny", write, create, s.denyRemoval)
	s.handle(P, "/api/removal-requests/{request_id}/cancel", write, create, s.cancelRemoval)
}

type removalView struct {
	ID             string     `json:"id"`
	Group          groupRef   `json:"group"`
	Account        accountRef `json:"account"`
	Beneficiary    personRef  `json:"beneficiary"`
	RequestedBy    userRef    `json:"requested_by"`
	Justification  string     `json:"justification"`
	Status         string     `json:"status"`
	RequestedAt    time.Time  `json:"requested_at"`
	DecidedBy      *userRef   `json:"decided_by"`
	DecidedAt      *time.Time `json:"decided_at"`
	DecisionReason *string    `json:"decision_reason"`
	Outcome        *string    `json:"outcome"`
	CanApprove     bool       `json:"can_approve"`
	CanCancel      bool       `json:"can_cancel"`
}

func (s *Server) removalView(v *viewer, q *store.RemovalRequest, me requests.Actor) (removalView, error) {
	g, err := v.group(q.GroupID)
	if err != nil {
		return removalView{}, err
	}
	b, err := v.person(q.BeneficiaryID)
	if err != nil {
		return removalView{}, err
	}
	a, err := v.tx.Account(q.AccountID)
	if err != nil {
		return removalView{}, err
	}
	out := removalView{ID: q.ID, Group: g, Account: accountRef{a.ID, a.System, a.Username}, Beneficiary: b,
		RequestedBy: v.user(q.RequestedBy), Justification: q.Justification, Status: q.Status, RequestedAt: q.RequestedAt,
		DecidedAt: q.DecidedAt, DecisionReason: q.DecisionReason, Outcome: q.Outcome}
	if q.DecidedBy != nil {
		d := v.user(*q.DecidedBy)
		out.DecidedBy = &d
	}
	if out.CanApprove, err = requests.CanDecideRemoval(v.tx, q, me, s.clock().UTC()); err != nil {
		return out, err
	}
	out.CanCancel = q.Status == store.RequestPending && q.RequestedBy == me.UserID.String()
	return out, nil
}

type removalBody struct {
	EdgeID        int64  `json:"edge_id"`
	Justification string `json:"justification"`
}

func (s *Server) submitRemoval(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	by, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	var b removalBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if b.EdgeID <= 0 {
		return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_edge", Msg: "edge_id is required"}
	}
	tx := store.TxFrom(r.Context())
	q, err := requests.SubmitRemoval(tx, b.EdgeID, b.Justification, by, s.can(r, auth.PermRequestsCreateOthers), s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	out, err := s.removalView(newViewer(tx), q, by)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, out}, nil
}

func (s *Server) listRemovals(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	var f store.RemovalRequestFilter
	scope := qs(p, "scope")
	switch scope {
	case "", "mine":
		f.InvolvingUser = me.UserID.String()
		if me.IdentityID != nil {
			f.InvolvingIdentity = *me.IdentityID
		}
	case "approvals":
		f.Status = store.RequestPending // filtered to what me may decide below
	case "pending", "all":
		if !s.can(r, auth.PermRequestsDecide) && !s.can(r, auth.PermGraphRead) {
			return nil, denial{auth.Check(principal(r), auth.PermRequestsDecide, nil, s.clock())}
		}
		if scope == "pending" {
			f.Status = store.RequestPending
		}
	default:
		return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_scope", Msg: "scope is mine, approvals, pending or all"}
	}
	tx := store.TxFrom(r.Context())
	list, err := tx.RemovalRequests(f)
	if err != nil {
		return nil, err
	}
	v := newViewer(tx)
	out := make([]removalView, 0, len(list))
	for _, q := range list {
		rv, err := s.removalView(v, q, me)
		if err != nil {
			return nil, err
		}
		if scope == "approvals" && !rv.CanApprove {
			continue
		}
		out = append(out, rv)
	}
	return out, nil
}

// removal loads a request the signed-in user may see; others' look missing.
func (s *Server) removal(r *http.Request, p *params) (*store.RemovalRequest, requests.Actor, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, me, err
	}
	tx := store.TxFrom(r.Context())
	q, err := tx.RemovalRequest(strings.TrimSpace(p.path["request_id"]))
	missing := &readiness.Error{Status: http.StatusNotFound, Code: "request_not_found", Msg: "request not found"}
	if errors.Is(err, store.ErrNotFound) {
		return nil, me, missing
	} else if err != nil {
		return nil, me, err
	}
	visible := q.RequestedBy == me.UserID.String() || (me.IdentityID != nil && *me.IdentityID == q.BeneficiaryID) ||
		me.Decider || s.can(r, auth.PermGraphRead)
	if !visible {
		if visible, err = requests.CanDecideRemoval(tx, q, me, s.clock().UTC()); err != nil {
			return nil, me, err
		}
	}
	if !visible {
		return nil, me, missing
	}
	return q, me, nil
}

func (s *Server) decideRemoval(r *http.Request, p *params, allowEmpty bool,
	fn func(tx *store.TenantTx, id string, me requests.Actor, reason string, now time.Time) (*store.RemovalRequest, error)) (any, error) {
	q, me, err := s.removal(r, p)
	if err != nil {
		return nil, err
	}
	var b reasonOnly
	if err := decodeBody(r, &b, allowEmpty); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	out, err := fn(tx, q.ID, me, b.Reason, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return s.removalView(newViewer(tx), out, me)
}

func (s *Server) approveRemoval(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.decideRemoval(r, p, true, func(tx *store.TenantTx, id string, me requests.Actor, reason string, now time.Time) (*store.RemovalRequest, error) {
		return requests.ApproveRemoval(tx, id, me, reason, now)
	})
}

func (s *Server) denyRemoval(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.decideRemoval(r, p, false, func(tx *store.TenantTx, id string, me requests.Actor, reason string, now time.Time) (*store.RemovalRequest, error) {
		return requests.DenyRemoval(tx, id, me, reason, now)
	})
}

func (s *Server) cancelRemoval(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.decideRemoval(r, p, true, func(tx *store.TenantTx, id string, me requests.Actor, _ string, now time.Time) (*store.RemovalRequest, error) {
		return requests.CancelRemoval(tx, id, me, now)
	})
}
