package api

import (
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/rules"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Group rules and membership constraints (issue #56, GR-13; design
// docs/design/groups-grouper-parity.md §10.3). A rule is owned by a folder or a
// group, has a trigger, conditions and one action from a closed vocabulary (no
// code), and acts with the privileges of the user who last saved it: saving
// needs the route's permission and admin on the owner (stem_admin on a folder)
// and on every object the action touches, and the rule is checked again every
// time it fires. The built-in constraints (membership require, one group only,
// no self-add) are rules with those actions.
//
//	GET    /api/groups/folders/{id}/rules                list the folder's rules (stem_admin)
//	POST   /api/groups/folders/{id}/rules                save a rule (stem_admin)
//	PUT    /api/groups/folders/{id}/rules/{rule_id}      replace a rule (stem_admin)
//	DELETE /api/groups/folders/{id}/rules/{rule_id}      delete a rule (stem_admin)
//	GET|POST /api/groups/{id}/rules, PUT|DELETE .../rules/{rule_id}   the same on a group (admin)
//	GET|PUT /api/groups/rules/settings                   {email_enabled}: rule actions that send email are off until a tenant admin turns them on (groups.admin)
//
// A rule is {name, scope (folder rules: one|sub), trigger, conditions, action,
// params, enabled, rotate_secret (PUT)}. A webhook rule's signing secret is in
// the answer to the save that made or rotated it (signing_secret), once.
// A veto answers the request that was refused: 409 {"error":"vetoed","rule":id}.
func (s *Server) registerGroupsRuleRoutes() {
	G, P, PU, D := http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete
	canRead, canWrite, admin := need(auth.PermGroupsRead), need(auth.PermGroupsWrite), need(auth.PermGroupsAdmin)
	s.handle(G, "/api/groups/rules/settings", read, admin, s.rd(s.getGrpRuleSettings))
	s.handle(PU, "/api/groups/rules/settings", write, admin, s.rd(s.putGrpRuleSettings))
	for _, typ := range []privs.ObjectType{privs.Folder, privs.Group} {
		base := "/api/groups/{id}/rules"
		if typ == privs.Folder {
			base = "/api/groups/folders/{id}/rules"
		}
		h := ruleHandlers{s, s.privHandlers(typ)}
		s.handle(G, base, read, canRead, s.rd(h.list))
		s.handle(P, base, write, canWrite, s.rd(h.create))
		s.handle(PU, base+"/{rule_id}", write, canWrite, s.rd(h.update))
		s.handle(D, base+"/{rule_id}", write, canWrite, s.rd(h.remove))
	}
}

type ruleHandlers struct {
	s *Server
	p privHandlers
}

// rulesEnv is the save context of the request: its transaction, clock, the
// signed-in user (a machine client has none) and the caller's checker.
func (s *Server) rulesEnv(r *http.Request, c *store.TenantTx, now time.Time, ck *privs.Checker) rules.Env {
	e := rules.Env{Tx: c, Now: now, Checker: ck, RT: s.cfg.GroupsRules}
	if pr := principal(r); pr.UserID != nil {
		e.By = pr.UserID.String()
	}
	return e
}

type ruleBody struct {
	Name         string            `json:"name"`
	Scope        string            `json:"scope"`
	Trigger      string            `json:"trigger"`
	Conditions   []rules.Condition `json:"conditions"`
	Action       string            `json:"action"`
	Params       rules.Params      `json:"params"`
	Enabled      *bool             `json:"enabled"`
	RotateSecret bool              `json:"rotate_secret"`
}

func (b ruleBody) spec(o privs.Object) rules.Spec {
	return rules.Spec{OwnerType: string(o.Type), OwnerID: o.ID, Scope: b.Scope, Name: b.Name, Trigger: b.Trigger, Conditions: b.Conditions,
		Action: b.Action, Params: b.Params, Enabled: b.Enabled == nil || *b.Enabled}
}

type ruleAnswer struct {
	*rules.View
	SigningSecret string `json:"signing_secret,omitempty"`
}

type ruleList struct {
	ObjectType string        `json:"object_type"`
	ObjectID   string        `json:"object_id"`
	Items      []*rules.View `json:"items"`
}

func (h ruleHandlers) list(r *http.Request, p *params) (int, any, error) {
	ck := h.s.grpChecker(r)
	o, err := h.p.object(r, p, ck, h.p.admin())
	if err != nil {
		return 0, nil, err
	}
	items, err := rules.List(store.TxFrom(r.Context()), string(o.Type), o.ID)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, ruleList{ObjectType: string(o.Type), ObjectID: o.ID, Items: items}, nil
}

func (h ruleHandlers) create(r *http.Request, p *params) (int, any, error) {
	ck := h.s.grpChecker(r)
	o, err := h.p.object(r, p, ck, h.p.admin())
	if err != nil {
		return 0, nil, err
	}
	var in ruleBody
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out ruleAnswer
	err = grpErr(h.s.write(r, func(c *store.TenantTx, now time.Time) error {
		v, secret, err := rules.Create(h.s.rulesEnv(r, c, now, ck), in.spec(o))
		out = ruleAnswer{v, secret}
		return err
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, out, nil
}

// ownRule loads a rule of the path's owner (another owner's rule is not found).
func (h ruleHandlers) ownRule(r *http.Request, p *params, o privs.Object) (*store.GrpRule, error) {
	id := p.path["rule_id"]
	if !idRE.MatchString(id) {
		return nil, grpNotFound("rule")
	}
	rule, err := rules.Get(store.TxFrom(r.Context()), id)
	if err != nil {
		return nil, grpErr(err)
	}
	if rule.OwnerType != string(o.Type) || rule.OwnerID != o.ID {
		return nil, grpNotFound("rule")
	}
	return rule, nil
}

func (h ruleHandlers) update(r *http.Request, p *params) (int, any, error) {
	ck := h.s.grpChecker(r)
	o, err := h.p.object(r, p, ck, h.p.admin())
	if err != nil {
		return 0, nil, err
	}
	rule, err := h.ownRule(r, p, o)
	if err != nil {
		return 0, nil, err
	}
	var in ruleBody
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out ruleAnswer
	err = grpErr(h.s.write(r, func(c *store.TenantTx, now time.Time) error {
		v, secret, err := rules.Update(h.s.rulesEnv(r, c, now, ck), rule.ID, in.spec(o), in.RotateSecret)
		out = ruleAnswer{v, secret}
		return err
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

func (h ruleHandlers) remove(r *http.Request, p *params) (int, any, error) {
	ck := h.s.grpChecker(r)
	o, err := h.p.object(r, p, ck, h.p.admin())
	if err != nil {
		return 0, nil, err
	}
	rule, err := h.ownRule(r, p, o)
	if err != nil {
		return 0, nil, err
	}
	err = grpErr(h.s.write(r, func(c *store.TenantTx, now time.Time) error {
		return rules.Delete(h.s.rulesEnv(r, c, now, ck), rule.ID)
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"id": rule.ID, "deleted": true}, nil
}

// ---------------------------------------------------------------- settings

func (s *Server) getGrpRuleSettings(r *http.Request, _ *params) (int, any, error) {
	set, err := rules.LoadSettings(store.TxFrom(r.Context()))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, set, nil
}

func (s *Server) putGrpRuleSettings(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		EmailEnabled bool `json:"email_enabled"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out rules.Settings
	err := grpErr(s.write(r, func(c *store.TenantTx, now time.Time) (err error) {
		out, err = rules.SaveSettings(s.rulesEnv(r, c, now, s.grpChecker(r)), rules.Settings{EmailEnabled: in.EmailEnabled})
		return err
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}
