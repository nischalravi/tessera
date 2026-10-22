package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/questionnaires"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Business roles (issue #161):
//
//	GET  /api/roles                                  every role (summary) with what the user may do
//	POST /api/roles                                  {spec}: create (?dry_run=1: the plan only)
//	GET  /api/roles/{role_id}                        a role with its members
//	PUT  /api/roles/{role_id}                        {version, spec}: update (?dry_run=1)
//	GET  /api/roles/{role_id}/versions               saved versions, newest first
//	GET  /api/roles/{role_id}/drift                  members missing entitlements; holders without the role
//	POST /api/roles/{role_id}/retire                 {reason} (?dry_run=1)
//	POST /api/roles/{role_id}/reconcile              rule members and grants in step (?dry_run=1)
//	POST /api/roles/{role_id}/members                {identity_id, reason?} (?dry_run=1)
//	POST /api/roles/{role_id}/members/{identity_id}/remove   {reason} (?dry_run=1)
//	POST /api/role-requests                          {role_id, beneficiary_id, justification}
//	GET  /api/role-requests                          ?scope=mine (default) | pending | all
//	POST /api/role-requests/{request_id}/approve     {reason?}
//	POST /api/role-requests/{request_id}/deny        {reason}
//	POST /api/role-requests/{request_id}/cancel
//
// Listing roles needs requests.create (everyone requests from it); a role's
// members, versions and drift need graph.read; changing roles needs
// roles.manage and a fresh phishing-resistant sign-in. Role requests follow
// the request service: requests.create, requests.create_for_others and
// requests.decide (approval with step-up).

func (s *Server) registerRoleRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	create, graph := need(auth.PermRequestsCreate), need(auth.PermGraphRead)
	manage := needStepUp(auth.PermRolesManage, auth.StepUpPolicy)
	s.handle(G, "/api/roles", read, create, s.listRoles)
	s.handle(P, "/api/roles", write, manage, s.createRole)
	s.handle(G, "/api/roles/{role_id}", read, graph, s.getRole)
	s.handle(http.MethodPut, "/api/roles/{role_id}", write, manage, s.updateRole)
	s.handle(G, "/api/roles/{role_id}/versions", read, graph, s.roleVersions)
	s.handle(G, "/api/roles/{role_id}/drift", read, graph, s.roleDrift)
	s.handle(P, "/api/roles/{role_id}/retire", write, manage, s.retireRole)
	s.handle(P, "/api/roles/{role_id}/reconcile", write, manage, s.reconcileRole)
	s.handle(P, "/api/roles/{role_id}/members", write, manage, s.assignRole)
	s.handle(P, "/api/roles/{role_id}/members/{identity_id}/remove", write, manage, s.unassignRole)
	s.handle(P, "/api/role-requests", write, create, s.submitRoleRequest)
	s.handle(G, "/api/role-requests", read, create, s.listRoleRequests)
	s.handle(P, "/api/role-requests/{request_id}/approve", write, needStepUp(auth.PermRequestsDecide, auth.StepUpPolicy), s.approveRoleRequest)
	s.handle(P, "/api/role-requests/{request_id}/deny", write, need(auth.PermRequestsDecide), s.denyRoleRequest)
	s.handle(P, "/api/role-requests/{request_id}/cancel", write, create, s.cancelRoleRequest)
}

// ---------------------------------------------------------------- views

type ruleView struct {
	Department []string `json:"department"`
	Type       []string `json:"type"`
	Title      []string `json:"title"`
	Policy     string   `json:"policy"` // id of the attribute policy ("" : none)
}

type roleView struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Owner        *personRef `json:"owner"`
	Risk         string     `json:"risk"`
	Requestable  bool       `json:"requestable"`
	Birthright   *ruleView  `json:"birthright"`
	Status       string     `json:"status"`
	Version      int        `json:"version"`
	Entitlements []groupRef `json:"entitlements"`
	MemberCount  int        `json:"member_count"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedBy    *userRef   `json:"updated_by"`
	UpdatedAt    time.Time  `json:"updated_at"`
	Members      []memberV  `json:"members,omitempty"`
	// for the signed-in user: they hold it, or have a pending request for it
	Held    bool `json:"held"`
	Pending bool `json:"pending"`
}

type memberV struct {
	Person     personRef `json:"person"`
	Source     string    `json:"source"`
	AssignedBy *userRef  `json:"assigned_by"`
	AssignedAt time.Time `json:"assigned_at"`
	RequestID  *string   `json:"request_id"`
}

type rolesList struct {
	Me                  *personRef `json:"me"`
	CanManage           bool       `json:"can_manage"`
	CanDecide           bool       `json:"can_decide"`
	CanRequestForOthers bool       `json:"can_request_for_others"`
	CanReadMembers      bool       `json:"can_read_members"`
	Roles               []roleView `json:"roles"`
}

func (v *viewer) roleView(r *store.BusinessRole, ents []int64, members int) (roleView, error) {
	out := roleView{ID: r.ID, Name: r.Name, Description: r.Description, Risk: r.Risk, Requestable: r.Requestable,
		Status: r.Status, Version: r.Version, Entitlements: make([]groupRef, 0, len(ents)), MemberCount: members,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
	if r.OwnerIdentityID != nil {
		o, err := v.person(*r.OwnerIdentityID)
		if err != nil {
			return out, err
		}
		out.Owner = &o
	}
	if r.UpdatedBy != nil {
		u := v.user(*r.UpdatedBy)
		out.UpdatedBy = &u
	}
	rule, err := roles.ParseRule(r.Birthright)
	if err != nil {
		return out, err
	}
	if rule != nil {
		out.Birthright = &ruleView{nonNilS(rule.Department), nonNilS(rule.Type), nonNilS(rule.Title), rule.Policy}
	}
	for _, g := range ents {
		gr, err := v.group(g)
		if err != nil {
			return out, err
		}
		out.Entitlements = append(out.Entitlements, gr)
	}
	return out, nil
}

func nonNilS(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func roleErr(err error) error { return reqErr(err) }

func roleID(p *params) string { return strings.TrimSpace(p.path["role_id"]) }

func dryRun(p *params) bool {
	b := p.queryOptBool("dry_run")
	return b != nil && *b
}

// ---------------------------------------------------------------- reads

func (s *Server) listRoles(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	rs, err := tx.BusinessRoles()
	if err != nil {
		return nil, err
	}
	ents, err := tx.AllRoleEntitlements()
	if err != nil {
		return nil, err
	}
	members, err := tx.AllRoleMembers()
	if err != nil {
		return nil, err
	}
	byRole, counts := map[string][]int64{}, map[string]int{}
	for _, e := range ents {
		byRole[e.RoleID] = append(byRole[e.RoleID], e.GroupID)
	}
	me, _ := s.requestActor(r)
	held := map[string]bool{}
	for _, m := range members {
		counts[m.RoleID]++
		if me.IdentityID != nil && m.IdentityID == *me.IdentityID {
			held[m.RoleID] = true
		}
	}
	pend := map[string]bool{}
	if me.IdentityID != nil {
		qs, err := tx.RoleRequests(store.RoleRequestFilter{Status: store.RequestPending, InvolvingIdentity: *me.IdentityID})
		if err != nil {
			return nil, err
		}
		for _, q := range qs {
			if q.BeneficiaryID == *me.IdentityID {
				pend[q.RoleID] = true
			}
		}
	}
	v := newViewer(tx)
	out := rolesList{CanManage: s.can(r, auth.PermRolesManage), CanDecide: s.can(r, auth.PermRequestsDecide),
		CanRequestForOthers: s.can(r, auth.PermRequestsCreateOthers), CanReadMembers: s.can(r, auth.PermGraphRead),
		Roles: make([]roleView, 0, len(rs))}
	for _, ro := range rs {
		rv, err := v.roleView(ro, byRole[ro.ID], counts[ro.ID])
		if err != nil {
			return nil, err
		}
		rv.Held, rv.Pending = held[ro.ID], pend[ro.ID]
		out.Roles = append(out.Roles, rv)
	}
	if me.IdentityID != nil {
		p, err := v.person(*me.IdentityID)
		if err != nil {
			return nil, err
		}
		out.Me = &p
	}
	return out, nil
}

func (s *Server) loadRole(r *http.Request, p *params) (*store.BusinessRole, error) {
	ro, err := store.TxFrom(r.Context()).BusinessRole(roleID(p))
	if errors.Is(err, store.ErrNotFound) {
		return nil, &readiness.Error{Status: http.StatusNotFound, Code: "role_not_found", Msg: "role not found"}
	}
	return ro, err
}

func (s *Server) roleDetail(r *http.Request, ro *store.BusinessRole) (roleView, error) {
	tx := store.TxFrom(r.Context())
	ents, err := tx.RoleEntitlements(ro.ID)
	if err != nil {
		return roleView{}, err
	}
	ms, err := tx.RoleMembers(ro.ID)
	if err != nil {
		return roleView{}, err
	}
	v := newViewer(tx)
	out, err := v.roleView(ro, ents, len(ms))
	if err != nil {
		return out, err
	}
	out.Members = make([]memberV, 0, len(ms))
	for _, m := range ms {
		pr, err := v.person(m.IdentityID)
		if err != nil {
			return out, err
		}
		mv := memberV{Person: pr, Source: m.Source, AssignedAt: m.AssignedAt, RequestID: m.RequestID}
		if m.AssignedBy != nil {
			u := v.user(*m.AssignedBy)
			mv.AssignedBy = &u
		}
		out.Members = append(out.Members, mv)
	}
	return out, nil
}

func (s *Server) getRole(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ro, err := s.loadRole(r, p)
	if err != nil {
		return nil, err
	}
	return s.roleDetail(r, ro)
}

type versionView struct {
	Version   int             `json:"version"`
	Snapshot  json.RawMessage `json:"snapshot"`
	Note      *string         `json:"note"`
	Actor     string          `json:"actor"`
	ChangedAt time.Time       `json:"changed_at"`
}

func (s *Server) roleVersions(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ro, err := s.loadRole(r, p)
	if err != nil {
		return nil, err
	}
	vs, err := store.TxFrom(r.Context()).RoleVersions(ro.ID)
	if err != nil {
		return nil, err
	}
	out := make([]versionView, len(vs))
	for i, x := range vs {
		out[i] = versionView{x.Version, json.RawMessage(x.Snapshot), x.Note, x.Actor, x.ChangedAt}
	}
	return out, nil
}

type gapView struct {
	Person  personRef  `json:"person"`
	Missing []groupRef `json:"missing"`
}

type holderView struct {
	Person personRef  `json:"person"`
	Held   []groupRef `json:"held"`
	All    bool       `json:"holds_all"`
}

func (s *Server) roleDrift(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ro, err := s.loadRole(r, p)
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	d, err := roles.RoleDrift(tx, ro.ID, s.clock().UTC())
	if err != nil {
		return nil, roleErr(err)
	}
	v := newViewer(tx)
	groups := func(ids []int64) ([]groupRef, error) {
		out := make([]groupRef, 0, len(ids))
		for _, g := range ids {
			gr, err := v.group(g)
			if err != nil {
				return nil, err
			}
			out = append(out, gr)
		}
		return out, nil
	}
	out := struct {
		Missing []gapView    `json:"missing"`
		Holders []holderView `json:"holders"`
	}{[]gapView{}, []holderView{}}
	for _, g := range d.Missing {
		pr, err := v.person(g.IdentityID)
		if err != nil {
			return nil, err
		}
		gs, err := groups(g.Missing)
		if err != nil {
			return nil, err
		}
		out.Missing = append(out.Missing, gapView{pr, gs})
	}
	for _, h := range d.Holders {
		pr, err := v.person(h.IdentityID)
		if err != nil {
			return nil, err
		}
		gs, err := groups(h.Held)
		if err != nil {
			return nil, err
		}
		out.Holders = append(out.Holders, holderView{pr, gs, len(h.Held) == len(d.Entitlements)})
	}
	return out, nil
}

// ---------------------------------------------------------------- changes

type roleBody struct {
	Version         int       `json:"version"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	OwnerIdentityID *int64    `json:"owner_identity_id"`
	Risk            string    `json:"risk"`
	Requestable     bool      `json:"requestable"`
	Birthright      *ruleView `json:"birthright"`
	Entitlements    []int64   `json:"entitlement_group_ids"`
	Note            string    `json:"note"`
}

func (b roleBody) spec() roles.Spec {
	s := roles.Spec{Name: b.Name, Description: b.Description, OwnerIdentityID: b.OwnerIdentityID, Risk: b.Risk,
		Requestable: b.Requestable, Entitlements: b.Entitlements, Note: b.Note}
	if b.Birthright != nil {
		s.Birthright = &roles.Rule{Department: b.Birthright.Department, Type: b.Birthright.Type, Title: b.Birthright.Title, Policy: b.Birthright.Policy}
	}
	return s
}

// changeView is a role after a change, with the plan.
type changeView struct {
	Role roleView    `json:"role"`
	Plan *roles.Plan `json:"plan"`
}

func (s *Server) changed(r *http.Request, res *roles.Result) (any, error) {
	tx := store.TxFrom(r.Context())
	var rv roleView
	var err error
	if res.Plan.DryRun {
		// the role as it would be; nothing was saved
		rv, err = newViewer(tx).roleView(res.Role, res.Entitlements, 0)
	} else {
		rv, err = s.roleDetail(r, res.Role)
	}
	if err != nil {
		return nil, err
	}
	return changeView{rv, res.Plan}, nil
}

func (s *Server) createRole(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	dry := dryRun(p)
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	var b roleBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	res, err := roles.Create(store.TxFrom(r.Context()), b.spec(), by, dry, s.clock().UTC())
	if err != nil {
		return nil, roleErr(err)
	}
	out, err := s.changed(r, res)
	if err != nil || dry {
		return out, err
	}
	return statusBody{http.StatusCreated, out}, nil
}

func (s *Server) updateRole(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	dry := dryRun(p)
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	ro, err := s.loadRole(r, p)
	if err != nil {
		return nil, err
	}
	var b roleBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	res, err := roles.Update(store.TxFrom(r.Context()), ro.ID, b.Version, b.spec(), by, dry, s.clock().UTC())
	if err != nil {
		return nil, roleErr(err)
	}
	return s.changed(r, res)
}

func (s *Server) roleChange(r *http.Request, p *params, allowEmpty bool, fn func(tx *store.TenantTx, id string, by roles.Actor,
	body *roleChangeBody, dry bool, now time.Time) (*roles.Result, error)) (any, error) {
	dry := dryRun(p)
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	ro, err := s.loadRole(r, p)
	if err != nil {
		return nil, err
	}
	var b roleChangeBody
	if err := decodeBody(r, &b, allowEmpty); err != nil {
		return nil, err
	}
	res, err := fn(store.TxFrom(r.Context()), ro.ID, by, &b, dry, s.clock().UTC())
	if err != nil {
		return nil, roleErr(err)
	}
	return s.changed(r, res)
}

type roleChangeBody struct {
	IdentityID int64  `json:"identity_id"`
	Reason     string `json:"reason"`
}

func (s *Server) retireRole(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.roleChange(r, p, false, func(tx *store.TenantTx, id string, by roles.Actor, b *roleChangeBody, dry bool, now time.Time) (*roles.Result, error) {
		return roles.Retire(tx, id, b.Reason, by, dry, now)
	})
}

func (s *Server) reconcileRole(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.roleChange(r, p, true, func(tx *store.TenantTx, id string, by roles.Actor, _ *roleChangeBody, dry bool, now time.Time) (*roles.Result, error) {
		return roles.Reconcile(tx, id, by, dry, now)
	})
}

func (s *Server) assignRole(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.roleChange(r, p, false, func(tx *store.TenantTx, id string, by roles.Actor, b *roleChangeBody, dry bool, now time.Time) (*roles.Result, error) {
		return roles.Assign(tx, id, b.IdentityID, b.Reason, by, dry, now)
	})
}

func (s *Server) unassignRole(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ident := p.pathInt("identity_id")
	return s.roleChange(r, p, false, func(tx *store.TenantTx, id string, by roles.Actor, b *roleChangeBody, dry bool, now time.Time) (*roles.Result, error) {
		if b.IdentityID != 0 && b.IdentityID != ident {
			return nil, &roles.Error{Status: 422, Code: "identity_mismatch", Msg: "identity_id differs from the path"}
		}
		return roles.Unassign(tx, id, ident, b.Reason, by, dry, now)
	})
}

// ---------------------------------------------------------------- requests

type roleRequestView struct {
	ID             string     `json:"id"`
	Role           roleRef    `json:"role"`
	Beneficiary    personRef  `json:"beneficiary"`
	RequestedBy    userRef    `json:"requested_by"`
	Justification  string     `json:"justification"`
	Status         string     `json:"status"`
	RequestedAt    time.Time  `json:"requested_at"`
	DecidedBy      *userRef   `json:"decided_by"`
	DecidedAt      *time.Time `json:"decided_at"`
	DecisionReason *string    `json:"decision_reason"`
	CanApprove     bool       `json:"can_approve"`
	CanCancel      bool       `json:"can_cancel"`
	// Questionnaires are the requester's answers (issue #298), with the questions as asked.
	Questionnaires []questionnaires.Answered `json:"questionnaires,omitempty"`
}

type roleRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Risk string `json:"risk"`
}

func (s *Server) roleRequestView(r *http.Request, v *viewer, q *store.RoleRequest, me roles.Actor) (roleRequestView, error) {
	ro, err := v.tx.BusinessRole(q.RoleID)
	if err != nil {
		return roleRequestView{}, err
	}
	b, err := v.person(q.BeneficiaryID)
	if err != nil {
		return roleRequestView{}, err
	}
	out := roleRequestView{ID: q.ID, Role: roleRef{ro.ID, ro.Name, ro.Risk}, Beneficiary: b, RequestedBy: v.user(q.RequestedBy),
		Justification: q.Justification, Status: q.Status, RequestedAt: q.RequestedAt, DecidedAt: q.DecidedAt,
		DecisionReason: q.DecisionReason}
	if q.DecidedBy != nil {
		d := v.user(*q.DecidedBy)
		out.DecidedBy = &d
	}
	mine := me.IdentityID != nil && *me.IdentityID == q.BeneficiaryID
	// CanApprove is a UI hint and compares raw ids on purpose; the server enforces the rule with
	// SameActor when the decision is made (roles/roles.go), so a linked second user sees the button
	// and is refused there.
	out.CanApprove = s.can(r, auth.PermRequestsDecide) && q.Status == store.RequestPending && q.RequestedBy != me.UserID.String() && !mine
	out.CanCancel = q.Status == store.RequestPending && q.RequestedBy == me.UserID.String()
	var qerr error
	out.Questionnaires, qerr = questionnaires.AnswersFor(v.tx, store.QSubjectRoleRequest, q.ID)
	return out, qerr
}

type roleRequestBody struct {
	RoleID        string `json:"role_id"`
	BeneficiaryID int64  `json:"beneficiary_id"`
	Justification string `json:"justification"`
	// answers to the questionnaires the role asks: questionnaire id -> question id -> value (issue #298)
	Answers map[string]map[string]any `json:"answers"`
}

func (s *Server) submitRoleRequest(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	by, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	var b roleRequestBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if b.BeneficiaryID == 0 && by.IdentityID != nil {
		b.BeneficiaryID = *by.IdentityID
	}
	tx := store.TxFrom(r.Context())
	q, err := roles.RequestAnswered(tx, b.RoleID, b.BeneficiaryID, b.Justification, by, s.can(r, auth.PermRequestsCreateOthers), s.clock().UTC(), b.Answers)
	if err != nil {
		return nil, roleErr(err)
	}
	out, err := s.roleRequestView(r, newViewer(tx), q, by)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, out}, nil
}

func (s *Server) listRoleRequests(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	var f store.RoleRequestFilter
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
	tx := store.TxFrom(r.Context())
	list, err := tx.RoleRequests(f)
	if err != nil {
		return nil, err
	}
	v := newViewer(tx)
	out := make([]roleRequestView, 0, len(list))
	for _, q := range list {
		rv, err := s.roleRequestView(r, v, q, me)
		if err != nil {
			return nil, err
		}
		out = append(out, rv)
	}
	return out, nil
}

// roleRequest loads a request the signed-in user may see; others' look missing.
func (s *Server) roleRequest(r *http.Request, p *params) (*store.RoleRequest, roles.Actor, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, me, err
	}
	q, err := store.TxFrom(r.Context()).RoleRequest(strings.TrimSpace(p.path["request_id"]))
	visible := err == nil && (q.RequestedBy == me.UserID.String() || (me.IdentityID != nil && *me.IdentityID == q.BeneficiaryID) ||
		s.can(r, auth.PermRequestsDecide) || s.can(r, auth.PermGraphRead))
	if errors.Is(err, store.ErrNotFound) || (err == nil && !visible) {
		return nil, me, &readiness.Error{Status: http.StatusNotFound, Code: "request_not_found", Msg: "request not found"}
	}
	return q, me, err
}

func (s *Server) decideRoleRequest(r *http.Request, p *params, allowEmpty bool,
	fn func(tx *store.TenantTx, id, reason string, me roles.Actor, now time.Time) (*store.RoleRequest, error)) (any, error) {
	q, me, err := s.roleRequest(r, p)
	if err != nil {
		return nil, err
	}
	var b reasonOnly
	if err := decodeBody(r, &b, allowEmpty); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	out, err := fn(tx, q.ID, b.Reason, me, s.clock().UTC())
	if err != nil {
		return nil, roleErr(err)
	}
	return s.roleRequestView(r, newViewer(tx), out, me)
}

func (s *Server) approveRoleRequest(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.decideRoleRequest(r, p, true, func(tx *store.TenantTx, id, reason string, me roles.Actor, now time.Time) (*store.RoleRequest, error) {
		q, _, err := roles.Approve(tx, id, reason, me, now)
		return q, err
	})
}

func (s *Server) denyRoleRequest(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.decideRoleRequest(r, p, false, roles.Deny)
}

func (s *Server) cancelRoleRequest(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.decideRoleRequest(r, p, true, func(tx *store.TenantTx, id, _ string, me roles.Actor, now time.Time) (*store.RoleRequest, error) {
		return roles.Cancel(tx, id, me, now)
	})
}
