package api

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Native groups, memberships and composites (issue #45, GR-2; design
// docs/design/groups-grouper-parity.md §6, §10.11). A member read needs the
// group's read privilege; adding or removing a member needs update (and read on
// a nested group), or optin / optout when the caller is the member; changing a
// composite needs admin (and read on its factors). The engine routes are
// tenant-wide maintenance: groups.admin.
//
//	GET    /api/groups/{id}/members?filter=direct|indirect|effective|composite&list=&enabled=&q=&sort=&page=&limit=&offset=
//	POST   /api/groups/{id}/members              {identity | group, enabled_from, disabled_at, reason}
//	GET    /api/groups/{id}/members/{identity}   hasMember; trace=true adds every path
//	DELETE /api/groups/{id}/members/{member}     an identity id or a group id
//	POST   /api/groups/{id}/convert-to-composite {op, factors, discard_members}
//	PUT    /api/groups/{id}/composite            {op, factors}
//	POST   /api/groups/engine/verify             full recompute and repair
//	GET    /api/groups/engine/ops/{seq}          progress of a queued operation
//
// A change whose engine work fits TESSERA_GROUPS_SYNC_BUDGET is answered 200 or
// 201 with the effective memberships already updated. A bigger one commits the
// direct change, queues the recompute and answers 202 with "op", the operation
// id; the group's recompute_state is "pending" until it finishes and reads of
// it say "stale": true. A cycle is 409 {"error":"cycle","path":[names...]}; a
// composite refuses direct members with 409 composite_no_members. The two
// membership writes accept an Idempotency-Key (groups_api.go), as does the batch.
func (s *Server) registerGroupsMemberRoutes() {
	G, P, PU, D := http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete
	canRead, canWrite, admin := need(auth.PermGroupsRead), need(auth.PermGroupsWrite), need(auth.PermGroupsAdmin)
	s.handle(G, "/api/groups/{id}/members", read, canRead, s.rd(s.listGrpMembers))
	s.handle(P, "/api/groups/{id}/members", write, canWrite, s.idem(s.addGrpMember))
	s.handle(G, "/api/groups/{id}/members/{member}", read, canRead, s.rd(s.hasGrpMember))
	s.handle(D, "/api/groups/{id}/members/{member}", write, canWrite, s.idem(s.removeGrpMember))
	s.handle(P, "/api/groups/{id}/convert-to-composite", write, canWrite, s.rd(s.convertGrpComposite))
	s.handle(PU, "/api/groups/{id}/composite", write, canWrite, s.rd(s.setGrpComposite))
	s.handle(P, "/api/groups/engine/verify", write, admin, s.rd(s.verifyGrpEngine))
	s.handle(G, "/api/groups/engine/ops/{seq}", read, admin, s.rd(s.grpEngineOp))
}

// requireReadOn requires the read privilege on each of the groups that exist
// (an unknown one is the model's answer to give).
func (s *Server) requireReadOn(r *http.Request, ck *privs.Checker, ids []store.GroupID) error {
	tx := store.TxFrom(r.Context())
	for _, id := range ids {
		if _, err := tx.GrpGroup(id); errors.Is(err, store.ErrNotFound) {
			continue
		} else if err != nil {
			return err
		}
		if err := ck.Require(privs.GroupObject(id), privs.Read); err != nil {
			return grpErr(err)
		}
	}
	return nil
}

type memberView struct {
	ID          string  `json:"id"`
	Type        string  `json:"type"`
	IdentityID  *int64  `json:"identity_id"`
	GroupID     *string `json:"group_id"`
	Name        string  `json:"name"`
	EnabledFrom *string `json:"enabled_from"`
	DisabledAt  *string `json:"disabled_at"`
	// Active says the row counts at this moment (its own dates).
	Active    bool    `json:"active"`
	Source    string  `json:"source"`
	Reason    *string `json:"reason"`
	CreatedAt string  `json:"created_at"`
}

func viewMember(m *store.DirectMembership, name string, active bool) memberView {
	v := memberView{ID: m.ID, Type: string(m.MemberType), IdentityID: m.MemberIdentity, Name: name, Active: active,
		Source: m.Source, Reason: m.Reason, CreatedAt: store.RT(m.CreatedAt)}
	if m.MemberGroup != nil {
		g := string(*m.MemberGroup)
		v.GroupID = &g
	}
	if m.EnabledFrom != nil {
		s := store.RT(*m.EnabledFrom)
		v.EnabledFrom = &s
	}
	if m.DisabledAt != nil {
		s := store.RT(*m.DisabledAt)
		v.DisabledAt = &s
	}
	return v
}

type effectiveView struct {
	IdentityID int64  `json:"identity_id"`
	Name       string `json:"name"`
	Support    int32  `json:"support"`
	Since      string `json:"since"`
}

type memberList struct {
	Items  any    `json:"items"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
	Total  int    `json:"total"`
	Filter string `json:"filter"`
	// Stale says a queued recompute of the group has not finished.
	Stale bool `json:"stale"`
}

func (s *Server) listGrpMembers(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	if _, err := s.grpGroupFor(r, s.grpChecker(r), id, privs.Read); err != nil { // history reads too
		return 0, nil, err
	}
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	if err := listParam(p, store.MembersListID(store.TxFrom(r.Context()).Tenant())); err != nil {
		return 0, nil, err
	}
	if from, to, asOf, ok, err := pitWindow(p, s.clock()); err != nil {
		return 0, nil, err
	} else if ok {
		for _, name := range []string{"q", "sort", "enabled", "page"} {
			if _, has := p.query(name); has {
				return 0, nil, badRequest("invalid_"+name, name+" does not apply to as_of or between")
			}
		}
		return s.pitMembers(r, p, id, from, to, asOf)
	}
	limit, offset, err = pagePair(p, limit, offset)
	if err != nil {
		return 0, nil, err
	}
	filter, _ := p.query("filter")
	if filter == "" {
		filter = "direct"
	}
	if !slices.Contains([]string{"direct", "indirect", "effective", "composite"}, filter) {
		return 0, nil, badRequest("invalid_filter", "filter is direct, indirect, effective or composite")
	}
	search, err := searchParams(p, filter)
	if err != nil {
		return 0, nil, err
	}
	e := s.grpRead(r)
	search.Limit, search.Offset = limit, offset
	q := search
	body := memberList{Limit: limit, Offset: offset, Filter: filter}
	if filter == "composite" {
		// the members a composite definition gives: those of a composite group, none for others
		g, err := e.Group(store.GroupID(id))
		if err != nil {
			return 0, nil, grpErr(err)
		}
		if g.Definition != store.DefinitionComposite {
			body.Items, body.Stale = []effectiveView{}, g.RecomputeState != "clean"
			return http.StatusOK, body, nil
		}
	}
	if filter == "direct" {
		rows, total, err := e.DirectMembers(store.GroupID(id), q)
		if err != nil {
			return 0, nil, grpErr(err)
		}
		items := make([]memberView, len(rows))
		for i, m := range rows {
			items[i] = viewMember(m.DirectMembership, m.Name, m.Active)
		}
		body.Items, body.Total = items, total
		g, err := e.Group(store.GroupID(id))
		if err != nil {
			return 0, nil, grpErr(err)
		}
		body.Stale = g.RecomputeState != "clean"
		return http.StatusOK, body, nil
	}
	rows, total, stale, err := e.EffectiveMembers(store.GroupID(id), q)
	if err != nil {
		return 0, nil, grpErr(err)
	}
	items := make([]effectiveView, len(rows))
	for i, m := range rows {
		items[i] = effectiveView{IdentityID: m.Identity, Name: m.Name, Support: m.Support, Since: store.RT(m.Since)}
	}
	body.Items, body.Total, body.Stale = items, total, stale
	return http.StatusOK, body, nil
}

// grpTimeBody parses an optional RFC 3339 body field (null or absent: none).
func grpTimeBody(field string, v *string) (*time.Time, error) {
	t, _, err := grpTime(field, v)
	return t, err
}

type memberAnswer struct {
	Member *memberView `json:"member,omitempty"`
	// Effective is "applied" when the effective memberships already reflect the
	// change, "pending" when a queued recompute will (see Op).
	Effective string `json:"effective"`
	Op        *int64 `json:"op"`
}

func answerOutcome(out model.Outcome) (string, *int64) {
	if out.Queued {
		return "pending", &out.Op
	}
	return "applied", nil
}

func (s *Server) addGrpMember(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Identity    *int64  `json:"identity"`
		Group       string  `json:"group"`
		EnabledFrom *string `json:"enabled_from"`
		DisabledAt  *string `json:"disabled_at"`
		Reason      string  `json:"reason"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.Group != "" {
		if err := grpBodyID("group", in.Group); err != nil {
			return 0, nil, err
		}
	}
	if in.Identity != nil && *in.Identity < 1 {
		return 0, nil, badRequest("invalid_identity", "identity must be an identity id")
	}
	from, err := grpTimeBody("enabled_from", in.EnabledFrom)
	if err != nil {
		return 0, nil, err
	}
	to, err := grpTimeBody("disabled_at", in.DisabledAt)
	if err != nil {
		return 0, nil, err
	}
	ck := s.grpChecker(r)
	if err := s.requireMemberChange(r, ck, id, privs.Optin, in.Identity != nil && isSelf(ck, *in.Identity)); err != nil {
		return 0, nil, err
	}
	if in.Group != "" { // a nested group's members become this group's: the caller must be able to read it
		if err := s.requireReadOn(r, ck, []store.GroupID{store.GroupID(in.Group)}); err != nil {
			return 0, nil, err
		}
	}
	var res *model.AddResult
	var view memberView
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		res, err = e.AddMember(store.GroupID(id), model.MemberInput{Identity: in.Identity, Group: store.GroupID(in.Group),
			EnabledFrom: from, DisabledAt: to, Reason: in.Reason})
		if err != nil {
			return err
		}
		name := ""
		if res.Member.MemberIdentity != nil {
			if ident, err := e.Tx.Identity(*res.Member.MemberIdentity); err == nil {
				name = ident.Name
			}
		} else if g, err := e.Tx.GrpGroup(*res.Member.MemberGroup); err == nil {
			name = g.Name
		}
		view = viewMember(res.Member, name, (from == nil || !from.After(e.Now)) && (to == nil || e.Now.Before(*to)))
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	state, op := answerOutcome(res.Outcome)
	status := http.StatusOK
	switch {
	case res.Outcome.Queued:
		status = http.StatusAccepted
	case res.Created:
		status = http.StatusCreated
	}
	return status, memberAnswer{Member: &view, Effective: state, Op: op}, nil
}

func (s *Server) removeGrpMember(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	ck := s.grpChecker(r)
	typ, key, _ := model.ParseMember(p.path["member"])
	self := false
	if n, perr := strconv.ParseInt(key, 10, 64); typ == store.MemberIdentity && perr == nil {
		self = isSelf(ck, n)
	}
	if err := s.requireMemberChange(r, ck, id, privs.Optout, self); err != nil {
		return 0, nil, err
	}
	var out model.Outcome
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = e.RemoveMember(store.GroupID(id), p.path["member"])
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	state, op := answerOutcome(out)
	status := http.StatusOK
	if out.Queued {
		status = http.StatusAccepted
	}
	return status, memberAnswer{Effective: state, Op: op}, nil
}

// isSelf reports whether the identity is the caller's own.
func isSelf(ck *privs.Checker, identity int64) bool {
	me := ck.Subject().Identity
	return me != nil && *me == identity
}

// requireMemberChange requires update on the group, or self (the caller is the
// member) with the opt privilege: a member may add or remove themselves with
// optin or optout. A group that does not exist is 404.
func (s *Server) requireMemberChange(r *http.Request, ck *privs.Checker, id string, opt privs.Privilege, self bool) error {
	g, err := s.grpRead(r).Group(store.GroupID(id))
	if err != nil {
		return grpErr(err)
	}
	want := []privs.Privilege{privs.Update}
	if self {
		want = []privs.Privilege{opt, privs.Update} // the refusal names the weaker privilege
	}
	return grpErr(ck.RequireAny(privs.GroupObject(g.ID), want...))
}

func (s *Server) hasGrpMember(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	if _, err := s.grpGroupFor(r, s.grpChecker(r), id, privs.Read); err != nil {
		return 0, nil, err
	}
	typ, key, ok := model.ParseMember(p.path["member"])
	if !ok || typ != store.MemberIdentity {
		return 0, nil, badRequest("invalid_member", "member is an identity id")
	}
	ident, err := strconv.ParseInt(key, 10, 64)
	if err != nil {
		return 0, nil, badRequest("invalid_member", "member is an identity id")
	}
	trace, err := boolParam(p, "trace")
	if err != nil {
		return 0, nil, err
	}
	e := s.grpRead(r)
	member, err := e.IsMember(store.GroupID(id), ident)
	if err != nil {
		return 0, nil, grpErr(err)
	}
	g, err := e.Group(store.GroupID(id))
	if err != nil {
		return 0, nil, grpErr(err)
	}
	body := map[string]any{"group_id": id, "identity_id": ident, "member": member, "stale": g.RecomputeState != "clean"}
	if trace {
		t, err := e.TraceMember(store.GroupID(id), ident)
		if err != nil {
			return 0, nil, grpErr(err)
		}
		body["paths"], body["truncated"] = viewTrace(t), t.Truncated
	}
	return http.StatusOK, body, nil
}

type compositeBody struct {
	Op             string   `json:"op"`
	Factors        []string `json:"factors"`
	DiscardMembers bool     `json:"discard_members"`
}

type compositeAnswer struct {
	groupView
	Effective string `json:"effective"`
	Op        *int64 `json:"op"`
}

func (s *Server) compositeCall(r *http.Request, p *params, convert bool) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	var in compositeBody
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	factors, err := grpFactorIDs(in.Factors)
	if err != nil {
		return 0, nil, err
	}
	ck := s.grpChecker(r)
	if _, err := s.grpGroupFor(r, ck, id, privs.Admin); err != nil {
		return 0, nil, err
	}
	if err := s.requireReadOn(r, ck, factors); err != nil {
		return 0, nil, err
	}
	var out compositeAnswer
	var queued bool
	err = s.grpWrite(r, func(e model.Env) error {
		def := model.CompositeInput{Op: store.CompositeOp(in.Op), Factors: factors, DiscardMembers: in.DiscardMembers}
		var g *store.NativeGroup
		var res model.Outcome
		var err error
		if convert {
			g, res, err = e.ConvertToComposite(store.GroupID(id), def)
		} else {
			g, res, err = e.SetComposite(store.GroupID(id), def)
		}
		if err != nil {
			return err
		}
		if out.groupView, err = viewGroupFull(e, g); err != nil {
			return err
		}
		out.Effective, out.Op = answerOutcome(res)
		queued = res.Queued
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	if queued {
		return http.StatusAccepted, out, nil
	}
	return http.StatusOK, out, nil
}

func (s *Server) convertGrpComposite(r *http.Request, p *params) (int, any, error) {
	return s.compositeCall(r, p, true)
}

func (s *Server) setGrpComposite(r *http.Request, p *params) (int, any, error) {
	return s.compositeCall(r, p, false)
}

// verifyGrpEngine recomputes the tenant's closure, levels and effective
// memberships and repairs any difference (the nightly job, on demand).
func (s *Server) verifyGrpEngine(r *http.Request, _ *params) (int, any, error) {
	var rep *engine.VerifyReport
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		var err error
		rep, err = s.cfg.GroupsEngine.Verify(c, now)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	type repair struct {
		Kind     string `json:"kind"`
		GroupID  string `json:"group_id"`
		Identity int64  `json:"identity_id,omitempty"`
		Had      int64  `json:"had"`
		Want     int64  `json:"want"`
	}
	reps := make([]repair, len(rep.Repairs))
	for i, x := range rep.Repairs {
		reps[i] = repair{Kind: x.Kind, GroupID: string(x.Group), Identity: x.Identity, Had: x.Had, Want: x.Want}
	}
	return http.StatusOK, map[string]any{"groups": rep.Groups, "checked": rep.Checked, "repair_count": rep.RepairCount,
		"repairs": reps}, nil
}

// grpEngineOp reports an operation id returned with 202.
func (s *Server) grpEngineOp(r *http.Request, p *params) (int, any, error) {
	seq, err := strconv.ParseInt(p.path["seq"], 10, 64)
	if err != nil || seq < 1 {
		return 0, nil, &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such operation"}
	}
	pr, err := engine.OpProgress(store.TxFrom(r.Context()), seq)
	if err != nil {
		return 0, nil, err
	}
	if pr.State == store.OpUnknown {
		return 0, nil, &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such operation"}
	}
	return http.StatusOK, map[string]any{"op": seq, "state": pr.State, "done": pr.Done, "total": pr.Total}, nil
}
