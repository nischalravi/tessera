package api

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/perms"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Permissions and limits (issue #62, GR-19; design
// docs/design/groups-grouper-parity.md §10.10). A permission is an attribute
// assignment of a definition of type perm on a role or on a role's membership;
// it is made through /api/groups/attr-assignments (groups_attrs.go). These routes
// read what such assignments add up to, and import and export them in
// Grouper's shape. The tenant-wide routes need groups.admin (tenant_admin); the
// per-role read needs groups.read and the role's read privilege.
//
//	GET  /api/groups/permissions/effective?identity=&as_of=T      what an identity can do (as_of: from the history)
//	GET  /api/groups/permissions/check?identity=&resource=&action=&as_of=T&ctx.<name>=<value>
//	                                                             the decision for one resource and action, limits evaluated
//	GET  /api/groups/permissions/cedar                            the assignments as Cedar policy text
//	GET  /api/groups/permissions/export                           the Grouper-shaped document
//	POST /api/groups/permissions/import                           {permissions: [...]}: applies it, audited; 422 with every problem and nothing applied
//	GET  /api/groups/{id}/permissions                             the assignments on a role and on its memberships
//
// resource is a full name ("folder:definition:name"); action is an action name
// (default "assign"). A context value is an integer when it reads as one, else
// text; hour (UTC) is the clock's when not given. A request that cannot be
// decided because the resource or action does not exist is 404; a name that is
// not a permission is 422.
func (s *Server) registerGroupsPermRoutes() {
	G, P := http.MethodGet, http.MethodPost
	admin, canRead := need(auth.PermGroupsAdmin), need(auth.PermGroupsRead)
	// literal paths: /api/groups/{id}/... would also match "permissions"
	s.handle(G, "/api/groups/permissions/effective", read, admin, s.rd(s.permsEffective))
	s.handle(G, "/api/groups/permissions/check", read, admin, s.rd(s.permsCheck))
	s.handle(G, "/api/groups/permissions/cedar", read, admin, s.rd(s.permsCedar))
	s.handle(G, "/api/groups/permissions/export", read, admin, s.rd(s.permsExport))
	s.handle(P, "/api/groups/permissions/import", write, admin, s.rd(s.permsImport))
	s.handle(G, "/api/groups/{id}/permissions", read, canRead, s.rd(s.rolePerms))
}

func permsErr(err error) error {
	var pe *perms.Error
	var le *perms.LimitError
	switch {
	case errors.As(err, &pe):
		return &readiness.Error{Status: pe.Kind, Code: pe.Code, Msg: pe.Msg}
	case errors.As(err, &le):
		return &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_limit", Msg: le.Msg}
	}
	return grpErr(err)
}

type permAssignView struct {
	ID         string        `json:"id"`
	RoleID     string        `json:"role_id"`
	Role       string        `json:"role"`
	Subject    *int64        `json:"subject,omitempty"`
	Resource   string        `json:"resource"`
	Action     string        `json:"action"`
	Disallowed bool          `json:"disallowed"`
	EnabledAt  *string       `json:"enabled_at"`
	DisabledAt *string       `json:"disabled_at"`
	Limits     []perms.Limit `json:"limits"`
}

func viewPermAssign(a *perms.Assignment) permAssignView {
	v := permAssignView{ID: a.ID, RoleID: string(a.Role), Role: a.RoleName, Subject: a.Subject, Resource: a.Resource,
		Action: a.Action, Disallowed: a.Disallowed, Limits: a.Limits}
	if v.Limits == nil {
		v.Limits = []perms.Limit{}
	}
	if a.EnabledFrom != nil {
		t := store.RT(*a.EnabledFrom)
		v.EnabledAt = &t
	}
	if a.DisabledAt != nil {
		t := store.RT(*a.DisabledAt)
		v.DisabledAt = &t
	}
	return v
}

func viewAll(as []*perms.Assignment) []permAssignView {
	out := make([]permAssignView, len(as))
	for i, a := range as {
		out[i] = viewPermAssign(a)
	}
	return out
}

// permsInstant reads as_of: the instant to answer for and whether it is a past
// one (the history is used then).
func permsInstant(p *params, now time.Time) (at time.Time, past bool, err error) {
	raw, ok := p.query("as_of")
	if !ok {
		return now, false, nil
	}
	t, perr := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	if perr != nil {
		return now, false, badRequest("invalid_as_of", "as_of must be an RFC 3339 time")
	}
	t = t.UTC()
	if t.After(now) {
		return now, false, badRequest("invalid_as_of", "as_of must not be in the future")
	}
	return t, true, nil
}

func permsIdentity(r *http.Request, p *params) (int64, error) {
	raw, _ := p.query("identity")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id < 1 {
		return 0, badRequest("invalid_identity", "identity is the identity's numeric id")
	}
	if _, err := store.TxFrom(r.Context()).Identity(id); errors.Is(err, store.ErrNotFound) {
		return 0, grpNotFound("identity")
	} else if err != nil {
		return 0, err
	}
	return id, nil
}

// permsSet loads the assignments and the subject for now or, for a past instant, from the history.
func permsSet(tx *store.TenantTx, identity int64, at time.Time, past bool) (*perms.Set, perms.Subject, error) {
	if past {
		s, err := perms.LoadAt(tx, at)
		if err != nil {
			return nil, perms.Subject{}, err
		}
		sub, err := perms.SubjectAt(tx, identity, at)
		return s, sub, err
	}
	s, err := perms.Load(tx)
	if err != nil {
		return nil, perms.Subject{}, err
	}
	sub, err := perms.SubjectOf(tx, identity, at)
	return s, sub, err
}

func (s *Server) permsEffective(r *http.Request, p *params) (int, any, error) {
	identity, err := permsIdentity(r, p)
	if err != nil {
		return 0, nil, err
	}
	at, past, err := permsInstant(p, s.clock())
	if err != nil {
		return 0, nil, err
	}
	set, sub, err := permsSet(store.TxFrom(r.Context()), identity, at, past)
	if err != nil {
		return 0, nil, permsErr(err)
	}
	eff, truncated, err := set.Effective(sub, at)
	if err != nil {
		return 0, nil, permsErr(err)
	}
	type item struct {
		Resource    string           `json:"resource"`
		Action      string           `json:"action"`
		Allowed     bool             `json:"allowed"`
		Conditional bool             `json:"conditional"`
		Via         []permAssignView `json:"via"`
		Note        string           `json:"note,omitempty"`
	}
	items := make([]item, len(eff))
	for i, e := range eff {
		items[i] = item{Resource: e.Resource, Action: e.Action, Allowed: e.Allowed, Conditional: e.Conditional, Via: viewAll(e.Via)}
		if e.Conditional && !e.Allowed {
			items[i].Note = "denies unless its limit is evaluated and false; denies when a context value is missing"
		}
	}
	return http.StatusOK, map[string]any{"identity": identity, "as_of": store.RT(at), "truncated": truncated, "permissions": items}, nil
}

var ctxNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// maxCtx bounds the context values of a check.
const maxCtx = 20

func permsContext(p *params, at time.Time) (perms.Context, error) {
	ctx := perms.Context{}
	for k, vs := range p.r.URL.Query() {
		name, ok := strings.CutPrefix(k, "ctx.")
		if !ok || len(vs) == 0 {
			continue
		}
		if len(ctx) >= maxCtx || len(name) == 0 || len(name) > 32 || !ctxNameRE.MatchString(name) || len(vs[len(vs)-1]) > 256 {
			return nil, badRequest("invalid_context", "at most 20 context values ctx.<name>=<value>, names of letters, digits and _, values up to 256 characters")
		}
		v := vs[len(vs)-1]
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			ctx[name] = n
		} else {
			ctx[name] = v
		}
	}
	if _, ok := ctx["hour"]; !ok {
		ctx["hour"] = int64(at.Hour())
	}
	return ctx, nil
}

func (s *Server) permsCheck(r *http.Request, p *params) (int, any, error) {
	identity, err := permsIdentity(r, p)
	if err != nil {
		return 0, nil, err
	}
	resource, _ := p.query("resource")
	action, _ := p.query("action")
	if resource == "" || len(resource) > 600 || len(action) > 64 {
		return 0, nil, badRequest("invalid_resource", "resource is a permission name (folder:definition:name); action is an action name")
	}
	at, past, err := permsInstant(p, s.clock())
	if err != nil {
		return 0, nil, err
	}
	ctx, err := permsContext(p, at.UTC())
	if err != nil {
		return 0, nil, err
	}
	set, sub, err := permsSet(store.TxFrom(r.Context()), identity, at, past)
	if err != nil {
		return 0, nil, permsErr(err)
	}
	q, err := set.Resolve(resource, action)
	if err != nil {
		return 0, nil, permsErr(err)
	}
	d, err := set.Decide(sub, q, ctx, at)
	if err != nil {
		return 0, nil, permsErr(err)
	}
	failed := d.LimitsFailed
	if failed == nil {
		failed = []string{}
	}
	missing := d.ContextMissing
	if missing == nil {
		missing = []string{}
	}
	return http.StatusOK, map[string]any{"identity": identity, "resource": q.Resource, "action": q.Action, "as_of": store.RT(at),
		"allowed": d.Allowed, "reason": d.Reason, "via": viewAll(d.Via), "limits_failed": failed, "context_missing": missing, "context": ctx}, nil
}

func (s *Server) permsCedar(r *http.Request, _ *params) (int, any, error) {
	set, err := perms.Load(store.TxFrom(r.Context()))
	if err != nil {
		return 0, nil, permsErr(err)
	}
	return http.StatusOK, map[string]any{"policy": set.Policy(s.clock())}, nil
}

func (s *Server) permsExport(r *http.Request, _ *params) (int, any, error) {
	doc, err := perms.Export(store.TxFrom(r.Context()))
	if err != nil {
		return 0, nil, permsErr(err)
	}
	return http.StatusOK, doc, nil
}

func (s *Server) permsImport(r *http.Request, _ *params) (int, any, error) {
	var in perms.Doc
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var res *perms.ImportResult
	err := s.grpWrite(r, func(e model.Env) error {
		if !e.TenantAdmin {
			return &readiness.Error{Status: http.StatusForbidden, Code: "privilege_required", Msg: "importing permissions needs the tenant_admin role"}
		}
		var err error
		res, err = perms.Import(e.Attrs(), &in)
		return err
	})
	if err != nil {
		return 0, nil, permsErr(err)
	}
	if len(res.Errors) > 0 {
		return http.StatusUnprocessableEntity, map[string]any{"error": "invalid_import", "detail": "nothing was applied", "errors": res.Errors}, nil
	}
	return http.StatusOK, res, nil
}

func (s *Server) rolePerms(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "role")
	if err != nil {
		return 0, nil, err
	}
	tx := store.TxFrom(r.Context())
	if err := grpErr(s.grpChecker(r).Require(privs.GroupObject(store.GroupID(id)), privs.Read)); err != nil {
		return 0, nil, err
	}
	if _, err := tx.GrpGroup(store.GroupID(id)); errors.Is(err, store.ErrNotFound) {
		return 0, nil, grpNotFound("role")
	} else if err != nil {
		return 0, nil, err
	}
	set, err := perms.Load(tx)
	if err != nil {
		return 0, nil, permsErr(err)
	}
	var mine []*perms.Assignment
	for _, a := range set.Assignments {
		if string(a.Role) == id {
			mine = append(mine, a)
		}
	}
	return http.StatusOK, map[string]any{"role_id": id, "permissions": viewAll(mine)}, nil
}
