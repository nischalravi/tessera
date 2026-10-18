package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The access request service (issue #164):
//
//	GET  /api/catalog                          {me, can_*, items}: requestable items (?all=1: every group, catalog.manage)
//	PUT  /api/catalog/items/{group_id}         a group's catalog item
//	POST /api/requests                         {beneficiary_ids, catalog_item_ids, justification, duration_hours}
//	GET  /api/requests                         ?scope=mine (default) | pending | all, &status=
//	GET  /api/requests/{request_id}            one line with its history
//	POST /api/requests/{request_id}/approve    {reason?}
//	POST /api/requests/{request_id}/deny       {reason}
//	POST /api/requests/{request_id}/cancel     the requester withdraws a pending line
//	POST /api/requests/{request_id}/remove     {reason?}: end approved access early
//
// Everyone but break-glass holds requests.create (for themselves).
// Requesting for others needs requests.create_for_others; deciding needs
// requests.decide (approval also a fresh phishing-resistant sign-in); the
// catalog needs catalog.manage. Lines of other people are visible to
// deciders and graph readers only; to anyone else they look missing.

func (s *Server) registerRequestRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	create := need(auth.PermRequestsCreate)
	s.handle(G, "/api/catalog", read, create, s.catalog)
	s.handle(http.MethodPut, "/api/catalog/items/{group_id}", write, needStepUp(auth.PermCatalogManage, auth.StepUpPolicy), s.putCatalogItem)
	s.handle(P, "/api/requests", write, create, s.submitRequest)
	s.handle(G, "/api/requests", read, create, s.listRequestLines)
	s.handle(G, "/api/requests/{request_id}", read, create, s.getRequestLine)
	// approvers are managers, owners, their delegates and deciders: the handler
	// checks the line's routing (issue #165)
	s.handle(P, "/api/requests/{request_id}/approve", write, needStepUp(auth.PermRequestsCreate, auth.StepUpPolicy), s.approveRequestLine)
	s.handle(P, "/api/requests/{request_id}/deny", write, create, s.denyRequestLine)
	s.handle(P, "/api/requests/{request_id}/cancel", write, create, s.cancelRequestLine)
	s.handle(P, "/api/requests/{request_id}/remove", write, create, s.removeRequestLine)
	s.handle(G, "/api/approvals/inbox", read, create, s.approvalInbox)
	s.handle(G, "/api/approvals/delegates", read, create, s.approvalDelegates)
	s.handle(G, "/api/approvals/delegations", read, create, s.listDelegations)
	s.handle(P, "/api/approvals/delegations", write, create, s.createDelegation)
	s.handle(P, "/api/approvals/delegations/{delegation_id}/revoke", write, create, s.revokeDelegation)
}

func (s *Server) can(r *http.Request, p auth.Permission) bool {
	return auth.Check(principal(r), p, nil, s.clock()) == nil
}

// requestActor is the signed-in user, with the person they are and whether
// they hold requests.decide.
func (s *Server) requestActor(r *http.Request) (requests.Actor, error) {
	pr := principal(r)
	if pr == nil || pr.UserID == nil {
		return requests.Actor{}, &readiness.Error{Status: http.StatusForbidden, Code: "user_required",
			Msg: "requests are made and decided by a signed-in user"}
	}
	a := requests.Actor{UserID: *pr.UserID, Display: pr.Display, Decider: s.can(r, auth.PermRequestsDecide)}
	if pr.Authn != nil {
		a.AAL = pr.Authn.AAL
	}
	u, err := store.TxFrom(r.Context()).PlatformUser(*pr.UserID)
	if err != nil {
		return a, err
	}
	a.IdentityID, a.Display = u.IdentityID, u.DisplayName // the name people see in request history
	return a, nil
}

func reqErr(err error) error {
	var re *requests.Error
	if errors.As(err, &re) {
		return &readiness.Error{Status: re.Status, Code: re.Code, Msg: re.Msg}
	}
	return err
}

// ---------------------------------------------------------------- views

type groupRef struct {
	ID         int64  `json:"id"`
	System     string `json:"system"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Privileged bool   `json:"privileged"`
}

type personRef struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

type userRef struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}

type catalogEntry struct {
	ID                  *string      `json:"id"`
	Group               groupRef     `json:"group"`
	Requestable         bool         `json:"requestable"`
	Description         string       `json:"description"`
	Owner               *personRef   `json:"owner"`
	Risk                string       `json:"risk"`
	EligibleTypes       []string     `json:"eligible_types"`
	EligibleDepartments []string     `json:"eligible_departments"`
	DefaultHours        *float64     `json:"default_hours"`
	MaxHours            *float64     `json:"max_hours"`
	UpdatedAt           *time.Time   `json:"updated_at"`
	Approval            approvalView `json:"approval"`
}

type approvalView struct {
	Stages             []string `json:"stages"`
	EscalateAfterHours float64  `json:"escalate_after_hours"`
}

type lineEvent struct {
	Event string    `json:"event"`
	Actor string    `json:"actor"`
	Note  *string   `json:"note"`
	At    time.Time `json:"at"`
}

type lineView struct {
	ID             string      `json:"id"`
	BatchID        string      `json:"batch_id"`
	Status         string      `json:"status"`
	CatalogItemID  string      `json:"catalog_item_id"`
	Group          groupRef    `json:"group"`
	Beneficiary    personRef   `json:"beneficiary"`
	Account        accountRef  `json:"account"`
	RequestedBy    userRef     `json:"requested_by"`
	Justification  string      `json:"justification"`
	DurationHours  *float64    `json:"duration_hours"`
	RequestedAt    time.Time   `json:"requested_at"`
	DecidedBy      *userRef    `json:"decided_by"`
	DecidedAt      *time.Time  `json:"decided_at"`
	DecisionReason *string     `json:"decision_reason"`
	ExpiresAt      *time.Time  `json:"expires_at"`
	ClosedAt       *time.Time  `json:"closed_at"`
	Events         []lineEvent `json:"events,omitempty"`
	Stages         []stageView `json:"stages"`
	// What the signed-in user may do with the line (the API checks again).
	CanApprove bool `json:"can_approve"`
	CanCancel  bool `json:"can_cancel"`
	CanRemove  bool `json:"can_remove"`
}

type stageView struct {
	Index      int        `json:"index"`
	Kind       string     `json:"kind"`
	Status     string     `json:"status"`
	Assignee   *personRef `json:"assignee"`
	DueAt      *time.Time `json:"due_at"`
	Escalated  bool       `json:"escalated"`
	DecidedBy  *userRef   `json:"decided_by"`
	OnBehalfOf *userRef   `json:"on_behalf_of"`
	DecidedAt  *time.Time `json:"decided_at"`
	Reason     *string    `json:"reason"`
}

type accountRef struct {
	ID       int64  `json:"id"`
	System   string `json:"system"`
	Username string `json:"username"`
}

// viewer resolves names for views, caching within one request.
type viewer struct {
	tx     *store.TenantTx
	people map[int64]*store.Identity
	groups map[int64]*store.Group
	users  map[string]string
}

func newViewer(tx *store.TenantTx) *viewer {
	return &viewer{tx: tx, people: map[int64]*store.Identity{}, groups: map[int64]*store.Group{}, users: map[string]string{}}
}

func (v *viewer) person(id int64) (personRef, error) {
	i, ok := v.people[id]
	if !ok {
		var err error
		if i, err = v.tx.Identity(id); err != nil {
			return personRef{}, err
		}
		v.people[id] = i
	}
	return personRef{i.ID, i.Name, i.Type, i.Status}, nil
}

func (v *viewer) group(id int64) (groupRef, error) {
	g, ok := v.groups[id]
	if !ok {
		var err error
		if g, err = v.tx.Group(id); err != nil {
			return groupRef{}, err
		}
		v.groups[id] = g
	}
	return groupRef{g.ID, g.System, g.Name, g.Kind, g.Privileged}, nil
}

func (v *viewer) user(id string) userRef {
	if n, ok := v.users[id]; ok {
		return userRef{id, n}
	}
	n := "unknown user"
	if uid, err := uuid.Parse(id); err == nil {
		if u, err := v.tx.PlatformUser(uid); err == nil {
			n = u.DisplayName
		}
	}
	v.users[id] = n
	return userRef{id, n}
}

func (v *viewer) entry(e requests.Entry) (catalogEntry, error) {
	g := e.Group
	out := catalogEntry{Group: groupRef{g.ID, g.System, g.Name, g.Kind, g.Privileged}, Risk: "low",
		EligibleTypes: []string{}, EligibleDepartments: []string{}}
	if g.Description != nil {
		out.Description = *g.Description
	}
	out.Approval = approvalView{Stages: []string{store.StageDecider}, EscalateAfterHours: requests.DefaultEscalateHours}
	if it := e.Item; it != nil {
		stages, hours, err := requests.Policy(v.tx, it.ID)
		if err != nil {
			return out, err
		}
		out.Approval = approvalView{Stages: stages, EscalateAfterHours: hours}
		out.ID, out.Requestable, out.Risk, out.DefaultHours, out.MaxHours = &it.ID, it.Requestable, it.Risk, it.DefaultHours, it.MaxHours
		out.EligibleTypes, out.EligibleDepartments, out.UpdatedAt = it.EligibleTypes, it.EligibleDepartments, &it.UpdatedAt
		if it.Description != "" {
			out.Description = it.Description
		}
		if it.OwnerIdentityID != nil {
			o, err := v.person(*it.OwnerIdentityID)
			if err != nil {
				return out, err
			}
			out.Owner = &o
		}
	}
	return out, nil
}

func (s *Server) lineView(r *http.Request, v *viewer, l *store.RequestLine, me requests.Actor, withEvents bool) (lineView, error) {
	g, err := v.group(l.GroupID)
	if err != nil {
		return lineView{}, err
	}
	b, err := v.person(l.BeneficiaryID)
	if err != nil {
		return lineView{}, err
	}
	a, err := v.tx.Account(l.AccountID)
	if err != nil {
		return lineView{}, err
	}
	out := lineView{ID: l.ID, BatchID: l.BatchID, Status: l.Status, CatalogItemID: l.CatalogItemID, Group: g, Beneficiary: b,
		Account: accountRef{a.ID, a.System, a.Username}, RequestedBy: v.user(l.RequestedBy), Justification: l.Justification,
		DurationHours: l.DurationHours, RequestedAt: l.RequestedAt, DecidedAt: l.DecidedAt, DecisionReason: l.DecisionReason,
		ExpiresAt: l.ExpiresAt, ClosedAt: l.ClosedAt}
	if l.DecidedBy != nil {
		d := v.user(*l.DecidedBy)
		out.DecidedBy = &d
	}
	decider := me.Decider
	mine := me.IdentityID != nil && *me.IdentityID == l.BeneficiaryID
	if out.CanApprove, err = requests.CanDecide(v.tx, l, me, s.clock().UTC()); err != nil {
		return out, err
	}
	stages, err := v.tx.RequestStages(l.ID)
	if err != nil {
		return out, err
	}
	out.Stages = make([]stageView, 0, len(stages))
	for _, st := range stages {
		sv := stageView{Index: st.Idx, Kind: st.Kind, Status: st.Status, DueAt: st.DueAt, DecidedAt: st.DecidedAt, Reason: st.Reason,
			Escalated: st.Status == store.StageWaiting && st.DueAt != nil && !s.clock().Before(*st.DueAt)}
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
	out.CanCancel = l.Status == store.RequestPending && l.RequestedBy == me.UserID.String()
	out.CanRemove = l.Status == store.RequestApproved && (decider || mine)
	if withEvents {
		evs, err := v.tx.RequestEvents(l.ID)
		if err != nil {
			return out, err
		}
		out.Events = make([]lineEvent, len(evs))
		for i, e := range evs {
			out.Events[i] = lineEvent{e.Event, e.Actor, e.Note, e.At}
		}
	}
	return out, nil
}

// visible reports whether the signed-in user may see a line.
func (s *Server) visible(r *http.Request, l *store.RequestLine, me requests.Actor) (bool, error) {
	if l.RequestedBy == me.UserID.String() || (me.IdentityID != nil && *me.IdentityID == l.BeneficiaryID) ||
		me.Decider || s.can(r, auth.PermGraphRead) {
		return true, nil
	}
	// an approver of the line (a manager, an owner or a delegate)
	return requests.CanDecide(store.TxFrom(r.Context()), l, me, s.clock().UTC())
}

// ---------------------------------------------------------------- catalog

func (s *Server) catalog(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	all := qs(p, "all") == "1"
	if all && !s.can(r, auth.PermCatalogManage) {
		return nil, denial{auth.Check(principal(r), auth.PermCatalogManage, nil, s.clock())}
	}
	tx := store.TxFrom(r.Context())
	entries, err := requests.Catalog(tx, !all)
	if err != nil {
		return nil, err
	}
	v := newViewer(tx)
	out := catalogView{Items: make([]catalogEntry, 0, len(entries)), CanRequestForOthers: s.can(r, auth.PermRequestsCreateOthers),
		CanDecide: s.can(r, auth.PermRequestsDecide), CanManage: s.can(r, auth.PermCatalogManage)}
	for _, e := range entries {
		ce, err := v.entry(e)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, ce)
	}
	if me, err := s.requestActor(r); err == nil && me.IdentityID != nil {
		p, err := v.person(*me.IdentityID)
		if err != nil {
			return nil, err
		}
		out.Me = &p
	}
	return out, nil
}

// catalogView is the catalog with what the signed-in user may do: Me is
// the person they are (nil: not linked, so they request for others only).
type catalogView struct {
	Me                  *personRef     `json:"me"`
	CanRequestForOthers bool           `json:"can_request_for_others"`
	CanDecide           bool           `json:"can_decide"`
	CanManage           bool           `json:"can_manage"`
	Items               []catalogEntry `json:"items"`
}

type catalogItemBody struct {
	Requestable         bool     `json:"requestable"`
	Description         string   `json:"description"`
	OwnerIdentityID     *int64   `json:"owner_identity_id"`
	Risk                string   `json:"risk"`
	EligibleTypes       []string `json:"eligible_types"`
	EligibleDepartments []string `json:"eligible_departments"`
	DefaultHours        *float64 `json:"default_hours"`
	MaxHours            *float64 `json:"max_hours"`
	// optional: the approval stages (manager, owner, decider) and escalation hours
	ApprovalStages     []string `json:"approval_stages"`
	EscalateAfterHours *float64 `json:"escalate_after_hours"`
}

func (s *Server) putCatalogItem(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	gid := p.pathInt("group_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	var b catalogItemBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	it, err := requests.PutItem(tx, gid, requests.ItemSpec{Requestable: b.Requestable, Description: b.Description,
		OwnerIdentityID: b.OwnerIdentityID, Risk: b.Risk, EligibleTypes: b.EligibleTypes,
		EligibleDepartments: b.EligibleDepartments, DefaultHours: b.DefaultHours, MaxHours: b.MaxHours}, by, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	if b.ApprovalStages != nil || b.EscalateAfterHours != nil {
		stages, hours, err := requests.Policy(tx, it.ID)
		if err != nil {
			return nil, err
		}
		if b.ApprovalStages != nil {
			stages = b.ApprovalStages
		}
		if b.EscalateAfterHours != nil {
			hours = *b.EscalateAfterHours
		}
		if err := requests.SetPolicy(tx, it.ID, stages, hours, by, s.clock().UTC()); err != nil {
			return nil, reqErr(err)
		}
	}
	g, err := tx.Group(it.GroupID)
	if err != nil {
		return nil, err
	}
	return newViewer(tx).entry(requests.Entry{Group: g, Item: it})
}

// ---------------------------------------------------------------- requests

type submitBody struct {
	BeneficiaryIDs []int64  `json:"beneficiary_ids"`
	CatalogItemIDs []string `json:"catalog_item_ids"`
	Justification  string   `json:"justification"`
	DurationHours  *float64 `json:"duration_hours"`
}

func (s *Server) submitRequest(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	by, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	var b submitBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	batch, lines, err := requests.Submit(tx, requests.Submission{Beneficiaries: b.BeneficiaryIDs, Items: b.CatalogItemIDs,
		Justification: b.Justification, DurationHours: b.DurationHours}, by, s.can(r, auth.PermRequestsCreateOthers), s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	v := newViewer(tx)
	views := make([]lineView, 0, len(lines))
	for _, l := range lines {
		lv, err := s.lineView(r, v, l, by, false)
		if err != nil {
			return nil, err
		}
		views = append(views, lv)
	}
	return statusBody{http.StatusCreated, map[string]any{"batch_id": batch, "lines": views}}, nil
}

func (s *Server) listRequestLines(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	f := store.RequestFilter{Status: qs(p, "status"), Limit: 500}
	switch scope := qs(p, "scope"); scope {
	case "", "mine":
		f.InvolvingUser = me.UserID.String()
		if me.IdentityID != nil {
			f.InvolvingIdentity = *me.IdentityID
		}
	case "pending", "all":
		if !s.can(r, auth.PermRequestsDecide) && !s.can(r, auth.PermGraphRead) {
			return nil, denial{auth.Check(principal(r), auth.PermRequestsDecide, nil, s.clock())}
		}
		if scope == "pending" {
			f.Status = store.RequestPending
		}
	default:
		return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_scope", Msg: "scope is mine, pending or all"}
	}
	if f.Status != "" && !validStatus(f.Status) {
		return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_status", Msg: "unknown status"}
	}
	tx := store.TxFrom(r.Context())
	lines, err := tx.RequestLines(f)
	if err != nil {
		return nil, err
	}
	v := newViewer(tx)
	out := make([]lineView, 0, len(lines))
	for _, l := range lines {
		lv, err := s.lineView(r, v, l, me, false)
		if err != nil {
			return nil, err
		}
		out = append(out, lv)
	}
	return out, nil
}

// qs is an optional query parameter ("" when absent).
func qs(p *params, name string) string {
	if v := p.queryOptStr(name); v != nil {
		return *v
	}
	return ""
}

func validStatus(st string) bool {
	switch st {
	case store.RequestPending, store.RequestApproved, store.RequestDenied, store.RequestCancelled, store.RequestExpired, store.RequestRemoved:
		return true
	}
	return false
}

// line loads a line the signed-in user may see; others' look missing.
func (s *Server) line(r *http.Request, p *params) (*store.RequestLine, requests.Actor, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, me, err
	}
	missing := &readiness.Error{Status: http.StatusNotFound, Code: "request_not_found", Msg: "request not found"}
	l, err := store.TxFrom(r.Context()).RequestLine(strings.TrimSpace(p.path["request_id"]))
	if errors.Is(err, store.ErrNotFound) {
		return nil, me, missing
	} else if err != nil {
		return nil, me, err
	}
	if ok, err := s.visible(r, l, me); err != nil {
		return nil, me, err
	} else if !ok {
		return nil, me, missing
	}
	return l, me, nil
}

func (s *Server) getRequestLine(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	l, me, err := s.line(r, p)
	if err != nil {
		return nil, err
	}
	return s.lineView(r, newViewer(store.TxFrom(r.Context())), l, me, true)
}

type reasonOnly struct {
	Reason string `json:"reason"`
}

func (s *Server) decideLine(r *http.Request, p *params, allowEmpty bool,
	fn func(tx *store.TenantTx, id string, me requests.Actor, reason string, now time.Time) (*store.RequestLine, error)) (any, error) {
	l, me, err := s.line(r, p)
	if err != nil {
		return nil, err
	}
	var b reasonOnly
	if err := decodeBody(r, &b, allowEmpty); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	out, err := fn(tx, l.ID, me, b.Reason, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return s.lineView(r, newViewer(tx), out, me, true)
}

func (s *Server) approveRequestLine(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.decideLine(r, p, true, requests.Approve)
}

func (s *Server) denyRequestLine(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.decideLine(r, p, false, requests.Deny)
}

func (s *Server) cancelRequestLine(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.decideLine(r, p, true, func(tx *store.TenantTx, id string, me requests.Actor, _ string, now time.Time) (*store.RequestLine, error) {
		return requests.Cancel(tx, id, me, now)
	})
}

func (s *Server) removeRequestLine(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.decideLine(r, p, true, func(tx *store.TenantTx, id string, me requests.Actor, reason string, now time.Time) (*store.RequestLine, error) {
		return requests.Remove(tx, id, me, me.Decider, reason, now)
	})
}

// ---------------------------------------------------------------- approvals

type inboxItem struct {
	Line       lineView `json:"line"`
	Stage      *int     `json:"stage"`
	Kind       string   `json:"kind"`
	Escalated  bool     `json:"escalated"`
	OnBehalfOf *userRef `json:"on_behalf_of"`
}

func (s *Server) approvalInbox(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	pend, err := requests.Inbox(tx, me, s.clock().UTC())
	if err != nil {
		return nil, err
	}
	v := newViewer(tx)
	out := make([]inboxItem, 0, len(pend))
	for _, p := range pend {
		lv, err := s.lineView(r, v, p.Line, me, false)
		if err != nil {
			return nil, err
		}
		it := inboxItem{Line: lv, Kind: store.StageDecider, Escalated: p.Authority.Escalated}
		if st := p.Authority.Stage; st != nil {
			idx := st.Idx
			it.Stage, it.Kind = &idx, st.Kind
		}
		if p.Authority.OnBehalfOf != nil {
			u := v.user(*p.Authority.OnBehalfOf)
			it.OnBehalfOf = &u
		}
		out = append(out, it)
	}
	return out, nil
}

func (s *Server) approvalDelegates(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	users, err := store.TxFrom(r.Context()).PlatformUsers()
	if err != nil {
		return nil, err
	}
	out := []userRef{}
	for _, u := range users {
		if u.Status == "active" && u.ID != me.UserID && !u.IsBreakGlass {
			out = append(out, userRef{u.ID.String(), u.DisplayName})
		}
	}
	return out, nil
}

type delegationView struct {
	ID        string     `json:"id"`
	From      userRef    `json:"from"`
	To        userRef    `json:"to"`
	StartsAt  time.Time  `json:"starts_at"`
	EndsAt    time.Time  `json:"ends_at"`
	Reason    string     `json:"reason"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at"`
	Active    bool       `json:"active"`
}

func (s *Server) delegationView(v *viewer, d *store.ApprovalDelegationRow) delegationView {
	now := s.clock()
	return delegationView{ID: d.ID, From: v.user(d.FromUser), To: v.user(d.ToUser), StartsAt: d.StartsAt, EndsAt: d.EndsAt,
		Reason: d.Reason, CreatedAt: d.CreatedAt, RevokedAt: d.RevokedAt,
		Active: d.RevokedAt == nil && !now.Before(d.StartsAt) && now.Before(d.EndsAt)}
}

func (s *Server) listDelegations(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	user := me.UserID.String()
	if qs(p, "all") == "1" {
		if !me.Decider {
			return nil, denial{auth.Check(principal(r), auth.PermRequestsDecide, nil, s.clock())}
		}
		user = ""
	}
	tx := store.TxFrom(r.Context())
	ds, err := tx.ApprovalDelegations(user)
	if err != nil {
		return nil, err
	}
	v := newViewer(tx)
	out := make([]delegationView, 0, len(ds))
	for _, d := range ds {
		out = append(out, s.delegationView(v, d))
	}
	return out, nil
}

type delegationBody struct {
	ToUserID string    `json:"to_user_id"`
	StartsAt time.Time `json:"starts_at"`
	EndsAt   time.Time `json:"ends_at"`
	Reason   string    `json:"reason"`
}

func (s *Server) createDelegation(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	var b delegationBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	d, err := requests.Delegate(tx, me, b.ToUserID, b.StartsAt, b.EndsAt, b.Reason, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return statusBody{http.StatusCreated, s.delegationView(newViewer(tx), d)}, nil
}

func (s *Server) revokeDelegation(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	d, err := requests.RevokeDelegation(tx, strings.TrimSpace(p.path["delegation_id"]), me, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return s.delegationView(newViewer(tx), d), nil
}
