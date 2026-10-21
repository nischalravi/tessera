package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ownership"
	"github.com/nischalravi/tessera/mvp/server/internal/questionnaires"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/svcaccounts"
	"github.com/nischalravi/tessera/mvp/server/internal/workflow"
)

// Service-account requests (issue #298): create, change or transfer a service account, with
// mandatory owners. Approval is the workflow engine's; the last approval makes the change.
//
//	GET  /api/service-accounts                          the service accounts, with their owners (requests.create)
//	POST /api/service-account-requests                  {kind, identity_id, name, system, username, purpose, description,
//	                                                     primary_owner_id, backup_owner_id, justification, answers}
//	GET  /api/service-account-requests                  ?scope=mine (default) | pending | all, &status=
//	GET  /api/service-account-requests/{id}             one, with its stages and the requester's answers
//	POST /api/service-account-requests/{id}/approve     {reason?}
//	POST /api/service-account-requests/{id}/deny        {reason}
//	POST /api/service-account-requests/{id}/cancel      the requester withdraws a pending request
//
// Everyone who may request access may file one. Approvers are the stage's owners, managers,
// groups, delegates and deciders: the handler checks the request's routing, as for access
// requests. Requests of other people are visible to deciders, graph readers (as the tenant's
// history setting allows), the owners involved and the approvers; to anyone else they look missing.

func (s *Server) registerServiceAccountRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	create := need(auth.PermRequestsCreate)
	s.handle(G, "/api/service-accounts", read, create, s.listServiceAccounts)
	s.handle(P, "/api/service-account-requests", write, create, s.fileServiceAccountRequest)
	s.handle(G, "/api/service-account-requests", read, create, s.listServiceAccountRequests)
	s.handle(G, "/api/service-account-requests/{id}", read, create, s.getServiceAccountRequest)
	s.handle(P, "/api/service-account-requests/{id}/approve", write, needStepUp(auth.PermRequestsCreate, auth.StepUpPolicy), s.approveServiceAccountRequest)
	s.handle(P, "/api/service-account-requests/{id}/deny", write, create, s.denyServiceAccountRequest)
	s.handle(P, "/api/service-account-requests/{id}/cancel", write, create, s.cancelServiceAccountRequest)
}

type serviceAccountView struct {
	ID           int64      `json:"id"`
	Name         string     `json:"name"`
	Status       string     `json:"status"`
	Purpose      string     `json:"purpose"`
	PrimaryOwner *personRef `json:"primary_owner"`
	BackupOwner  *personRef `json:"backup_owner"`
	Systems      []string   `json:"systems"`
	OpenRequest  *string    `json:"open_request"`
}

func (s *Server) listServiceAccounts(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	ids, err := tx.Identities()
	if err != nil {
		return nil, err
	}
	open, err := tx.ServiceAccountRequests(store.SARequestFilter{Status: store.SAPending})
	if err != nil {
		return nil, err
	}
	openBy := map[int64]string{}
	for _, q := range open {
		if q.IdentityID != nil {
			openBy[*q.IdentityID] = q.ID
		}
	}
	v := newViewer(tx)
	out := []serviceAccountView{}
	for _, i := range ids {
		if i.Type != "service" {
			continue
		}
		sv := serviceAccountView{ID: i.ID, Name: i.Name, Status: i.Status, Systems: []string{}}
		primary := i.OwnerID
		if o, err := tx.Ownership(store.OwnedIdentity, strconv.FormatInt(i.ID, 10)); err == nil {
			sv.Purpose = o.Purpose
			if o.PrimaryID != nil {
				primary = o.PrimaryID
			}
			if o.BackupID != nil {
				p, err := v.person(*o.BackupID)
				if err != nil {
					return nil, err
				}
				sv.BackupOwner = &p
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		if primary != nil {
			p, err := v.person(*primary)
			if err != nil {
				return nil, err
			}
			sv.PrimaryOwner = &p
		}
		accts, err := tx.IdentityAccounts(i.ID)
		if err != nil {
			return nil, err
		}
		for _, a := range accts {
			if a.Status == "active" {
				sv.Systems = append(sv.Systems, a.System)
			}
		}
		if id, ok := openBy[i.ID]; ok {
			sv.OpenRequest = &id
		}
		out = append(out, sv)
	}
	systems, err := ownership.Systems(tx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"accounts": out, "systems": systems}, nil
}

type workflowRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version int    `json:"version"`
}

type saRequestView struct {
	ID              string                    `json:"id"`
	Kind            string                    `json:"kind"`
	Status          string                    `json:"status"`
	Account         *personRef                `json:"account"`
	Name            string                    `json:"name"`
	System          string                    `json:"system"`
	Username        string                    `json:"username"`
	Purpose         string                    `json:"purpose"`
	Description     string                    `json:"description"`
	PrimaryOwner    personRef                 `json:"primary_owner"`
	BackupOwner     *personRef                `json:"backup_owner"`
	PreviousPrimary *personRef                `json:"previous_primary_owner"`
	PreviousBackup  *personRef                `json:"previous_backup_owner"`
	Justification   string                    `json:"justification"`
	RequestedBy     userRef                   `json:"requested_by"`
	RequestedAt     time.Time                 `json:"requested_at"`
	DecidedBy       *userRef                  `json:"decided_by"`
	DecidedAt       *time.Time                `json:"decided_at"`
	DecisionReason  *string                   `json:"decision_reason"`
	ClosedAt        *time.Time                `json:"closed_at"`
	FulfilledAt     *time.Time                `json:"fulfilled_at"`
	OpID            *string                   `json:"op_id"`
	Workflow        *workflowRef              `json:"workflow"`
	Questionnaires  []questionnaires.Answered `json:"questionnaires,omitempty"`
	Stages          []stageView               `json:"stages"`
	CanApprove      bool                      `json:"can_approve"`
	CanCancel       bool                      `json:"can_cancel"`
}

func (s *Server) saView(v *viewer, q *store.ServiceAccountRequest, me requests.Actor, withAnswers bool) (saRequestView, error) {
	tx := v.tx
	opt := func(id *int64) (*personRef, error) {
		if id == nil {
			return nil, nil
		}
		p, err := v.person(*id)
		return &p, err
	}
	out := saRequestView{ID: q.ID, Kind: q.Kind, Status: q.Status, Name: q.Name, System: q.System, Username: q.Username, Purpose: q.Purpose,
		Description: q.Description, Justification: q.Justification, RequestedBy: v.user(q.RequestedBy), RequestedAt: q.RequestedAt,
		DecidedAt: q.DecidedAt, DecisionReason: q.DecisionReason, ClosedAt: q.ClosedAt, FulfilledAt: q.FulfilledAt, OpID: q.OpID}
	var err error
	if out.Account, err = opt(q.IdentityID); err != nil {
		return out, err
	}
	if out.PrimaryOwner, err = v.person(q.PrimaryOwnerID); err != nil {
		return out, err
	}
	if out.BackupOwner, err = opt(q.BackupOwnerID); err != nil {
		return out, err
	}
	if out.PreviousPrimary, err = opt(q.PreviousPrimaryID); err != nil {
		return out, err
	}
	if out.PreviousBackup, err = opt(q.PreviousBackupID); err != nil {
		return out, err
	}
	if q.DecidedBy != nil {
		d := v.user(*q.DecidedBy)
		out.DecidedBy = &d
	}
	now := s.clock().UTC()
	if out.CanApprove, err = svcaccounts.CanDecide(tx, q, me, now); err != nil {
		return out, err
	}
	out.CanCancel = q.Status == store.SAPending && q.RequestedBy == me.UserID.String()
	if run, err := tx.WorkflowRunFor(store.WFSubjectServiceAccount, q.ID); err == nil {
		name, ver, err := workflow.Names(tx, store.WFSubjectServiceAccount, q.ID)
		if err != nil {
			return out, err
		}
		out.Workflow = &workflowRef{run.WorkflowID, name, ver}
	} else if !errors.Is(err, store.ErrNotFound) {
		return out, err
	}
	stages, err := tx.WorkflowStages(q.ID)
	if err != nil {
		return out, err
	}
	out.Stages = make([]stageView, 0, len(stages))
	for _, st := range stages {
		label, err := svcaccounts.StageLabel(tx, q, st.Idx)
		if err != nil {
			return out, err
		}
		sv := stageView{Index: st.Idx, Kind: st.Kind, Label: label, Status: st.Status, StartedAt: st.StartedAt, DueAt: st.DueAt,
			DecidedAt: st.DecidedAt, Reason: st.Reason,
			Escalated: st.Status == store.StageWaiting && st.DueAt != nil && !now.Before(*st.DueAt)}
		if st.AssigneeID != nil {
			p, err := v.person(*st.AssigneeID)
			if err != nil {
				return out, err
			}
			sv.Assignee = &p
		}
		if st.DecidedBy != nil {
			u := v.user(*st.DecidedBy)
			sv.DecidedBy = &u
		}
		if st.OnBehalfOf != nil {
			u := v.user(*st.OnBehalfOf)
			sv.OnBehalfOf = &u
		}
		out.Stages = append(out.Stages, sv)
	}
	if withAnswers {
		out.Questionnaires, err = questionnaires.AnswersFor(tx, store.QSubjectRequestLine, q.ID)
	}
	return out, err
}

// saVisible reports whether the signed-in user may see a request.
func (s *Server) saVisible(r *http.Request, q *store.ServiceAccountRequest, me requests.Actor) (bool, error) {
	if q.RequestedBy == me.UserID.String() || me.Decider {
		return true, nil
	}
	if involves(q, me) {
		return true, nil
	}
	if ok, err := s.readsRequestHistory(r); err != nil || ok {
		return ok, err
	}
	return svcaccounts.CanDecide(store.TxFrom(r.Context()), q, me, s.clock().UTC())
}

type saBody struct {
	Kind           string                    `json:"kind"`
	IdentityID     *int64                    `json:"identity_id"`
	Name           string                    `json:"name"`
	System         string                    `json:"system"`
	Username       string                    `json:"username"`
	Purpose        string                    `json:"purpose"`
	Description    string                    `json:"description"`
	PrimaryOwnerID *int64                    `json:"primary_owner_id"`
	BackupOwnerID  *int64                    `json:"backup_owner_id"`
	Justification  string                    `json:"justification"`
	Answers        map[string]map[string]any `json:"answers"`
}

func (s *Server) fileServiceAccountRequest(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	var b saBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	q, err := svcaccounts.File(tx, svcaccounts.Input{Kind: b.Kind, IdentityID: b.IdentityID, Name: b.Name, System: b.System,
		Username: b.Username, Purpose: b.Purpose, Description: b.Description, PrimaryOwnerID: b.PrimaryOwnerID,
		BackupOwnerID: b.BackupOwnerID, Justification: b.Justification, Answers: b.Answers}, me, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	v, err := s.saView(newViewer(tx), q, me, true)
	return statusBody{http.StatusCreated, v}, err
}

func (s *Server) listServiceAccountRequests(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	status := qs(p, "status")
	switch status {
	case "", store.SAPending, store.SAApproved, store.SAFulfilled, store.SADenied, store.SACancelled:
	default:
		return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_status", Msg: "unknown status"}
	}
	tx := store.TxFrom(r.Context())
	now := s.clock().UTC()
	var rows []*store.ServiceAccountRequest
	switch scope := qs(p, "scope"); scope {
	case "", "mine":
		all, err := tx.ServiceAccountRequests(store.SARequestFilter{Status: status})
		if err != nil {
			return nil, err
		}
		for _, q := range all {
			if ok, err := s.saVisible(r, q, me); err != nil {
				return nil, err
			} else if ok && (q.RequestedBy == me.UserID.String() || involves(q, me)) {
				rows = append(rows, q)
			}
		}
	case "pending":
		if rows, err = svcaccounts.Pending(tx, me, now); err != nil {
			return nil, err
		}
	case "all":
		reads, err := s.readsRequestHistory(r)
		if err != nil {
			return nil, err
		}
		if !s.can(r, auth.PermRequestsDecide) && !reads {
			return nil, denial{auth.Check(principal(r), auth.PermRequestsDecide, nil, s.clock())}
		}
		if rows, err = tx.ServiceAccountRequests(store.SARequestFilter{Status: status}); err != nil {
			return nil, err
		}
	default:
		return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_scope", Msg: "scope is mine, pending or all"}
	}
	v := newViewer(tx)
	out := make([]saRequestView, 0, len(rows))
	for _, q := range rows {
		sv, err := s.saView(v, q, me, false)
		if err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	return out, nil
}

// involves reports whether the user is one of the owners a request names.
func involves(q *store.ServiceAccountRequest, me requests.Actor) bool {
	if me.IdentityID == nil {
		return false
	}
	for _, id := range []*int64{&q.PrimaryOwnerID, q.BackupOwnerID, q.PreviousPrimaryID, q.PreviousBackupID} {
		if id != nil && *id == *me.IdentityID {
			return true
		}
	}
	return false
}

// saRequest loads a request the signed-in user may see; others' look missing.
func (s *Server) saRequest(r *http.Request, p *params) (*store.ServiceAccountRequest, requests.Actor, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, me, err
	}
	missing := &readiness.Error{Status: http.StatusNotFound, Code: "request_not_found", Msg: "request not found"}
	id := strings.TrimSpace(p.path["id"])
	if !idRE.MatchString(id) {
		return nil, me, missing
	}
	q, err := store.TxFrom(r.Context()).ServiceAccountRequest(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, me, missing
	} else if err != nil {
		return nil, me, err
	}
	if ok, err := s.saVisible(r, q, me); err != nil {
		return nil, me, err
	} else if !ok {
		return nil, me, missing
	}
	return q, me, nil
}

func (s *Server) getServiceAccountRequest(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	q, me, err := s.saRequest(r, p)
	if err != nil {
		return nil, err
	}
	return s.saView(newViewer(store.TxFrom(r.Context())), q, me, true)
}

func (s *Server) decideServiceAccountRequest(r *http.Request, p *params, allowEmpty bool,
	fn func(tx *store.TenantTx, id string, me requests.Actor, reason string, now time.Time) (*store.ServiceAccountRequest, error)) (any, error) {
	q, me, err := s.saRequest(r, p)
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
	return s.saView(newViewer(tx), out, me, true)
}

func (s *Server) approveServiceAccountRequest(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.decideServiceAccountRequest(r, p, true, svcaccounts.Approve)
}

func (s *Server) denyServiceAccountRequest(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.decideServiceAccountRequest(r, p, false, svcaccounts.Deny)
}

func (s *Server) cancelServiceAccountRequest(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.decideServiceAccountRequest(r, p, true, func(tx *store.TenantTx, id string, me requests.Actor, _ string, now time.Time) (*store.ServiceAccountRequest, error) {
		return svcaccounts.Cancel(tx, id, me, now)
	})
}
