package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Native groups, memberships and composites (issue #45, GR-2; design
// docs/design/groups-grouper-parity.md §6, §10.11). Every route needs
// groups.admin, which only tenant_admin holds until GR-4.
//
//	GET    /api/groups/{id}/members?filter=direct|effective&limit=&offset=
//	POST   /api/groups/{id}/members              {identity | group, enabled_from, disabled_at, reason}
//	GET    /api/groups/{id}/members/{identity}   hasMember
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
// composite refuses direct members with 409 composite_no_members.
func (s *Server) registerGroupsMemberRoutes() {
	G, P, PU, D := http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete
	perm := need(auth.PermGroupsAdmin)
	s.handle(G, "/api/groups/{id}/members", read, perm, s.rd(s.listGrpMembers))
	s.handle(P, "/api/groups/{id}/members", write, perm, s.rd(s.addGrpMember))
	s.handle(G, "/api/groups/{id}/members/{member}", read, perm, s.rd(s.hasGrpMember))
	s.handle(D, "/api/groups/{id}/members/{member}", write, perm, s.rd(s.removeGrpMember))
	s.handle(P, "/api/groups/{id}/convert-to-composite", write, perm, s.rd(s.convertGrpComposite))
	s.handle(PU, "/api/groups/{id}/composite", write, perm, s.rd(s.setGrpComposite))
	s.handle(P, "/api/groups/engine/verify", write, perm, s.rd(s.verifyGrpEngine))
	s.handle(G, "/api/groups/engine/ops/{seq}", read, perm, s.rd(s.grpEngineOp))
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
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	if from, to, asOf, ok, err := pitWindow(p, s.clock()); err != nil {
		return 0, nil, err
	} else if ok {
		return s.pitMembers(r, p, id, from, to, asOf)
	}
	filter, _ := p.query("filter")
	if filter == "" {
		filter = "direct"
	}
	if filter != "direct" && filter != "effective" {
		return 0, nil, badRequest("invalid_filter", "filter is direct or effective")
	}
	e := s.grpRead(r)
	q := model.MemberQuery{Limit: limit, Offset: offset}
	body := memberList{Limit: limit, Offset: offset, Filter: filter}
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

func (s *Server) hasGrpMember(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
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
	e := s.grpRead(r)
	member, err := e.IsMember(store.GroupID(id), ident)
	if err != nil {
		return 0, nil, grpErr(err)
	}
	g, err := e.Group(store.GroupID(id))
	if err != nil {
		return 0, nil, grpErr(err)
	}
	return http.StatusOK, map[string]any{"group_id": id, "identity_id": ident, "member": member,
		"stale": g.RecomputeState != "clean"}, nil
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
