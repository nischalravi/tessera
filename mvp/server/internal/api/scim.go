package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	grpapi "github.com/nischalravi/tessera/mvp/server/internal/groups/api"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Read-only SCIM 2.0 server (issue #48, GR-5; design §10.11 "G-98"; RFC 7643 and
// RFC 7644): the native groups and the tenant's identities, for the applications
// and provisioning tools that pull them. Resources: grpapi.User (an identity)
// and grpapi.Group (a native group with its effective members).
//
//	GET /scim/v2/Groups, /scim/v2/Groups/{id}
//	GET /scim/v2/Users, /scim/v2/Users/{id}
//	GET /scim/v2/ServiceProviderConfig, /scim/v2/ResourceTypes
//
// Authentication is the API's own, never anything weaker: the request must carry a
// signed-in principal (today a session cookie; Principal already has the api_client
// kind for the token principals that come with the machine-client work) whose roles
// hold groups.read, and the tenant is the principal's, never a header or a path.
// Groups are filtered by the object privilege like every group route: a group is
// listed, and its members are read, only if the caller holds read on it (a Group
// carries its members, so view alone is not enough); a User's groups are those the
// caller may read. Users are all the tenant's identities, as GET /api/identities.
// There are no write routes: other methods are 405. Answers are
// application/scim+json, errors follow RFC 7644 §3.12. filter supports eq ne co sw
// ew gt ge lt le pr with and, or, not and parentheses on id and displayName
// (Groups) or id, userName, displayName, externalId, emails.value, active,
// userType and title (Users); startIndex and count page; attributes and
// excludedAttributes select. sortBy is ignored (ServiceProviderConfig says so).
func (s *Server) registerSCIMRoutes() {
	G := http.MethodGet
	canRead := need(auth.PermGroupsRead)
	s.handle(G, "/scim/v2/ServiceProviderConfig", noTenant, canRead, s.scimConfig)
	s.handle(G, "/scim/v2/ResourceTypes", noTenant, canRead, s.scimResourceTypes)
	s.handle(G, "/scim/v2/Groups", read, canRead, s.scimGroups)
	s.handle(G, "/scim/v2/Groups/{id}", read, canRead, s.scimGroup)
	s.handle(G, "/scim/v2/Users", read, canRead, s.scimUsers)
	s.handle(G, "/scim/v2/Users/{id}", read, canRead, s.scimUser)
}

// scim builds an answer.
func scim(status int, body any) (any, error) { return scimResponse{status, body}, nil }

func scimError(status int, scimType, detail string) (any, error) {
	return scim(status, grpapi.NewError(status, scimType, detail))
}

func (s *Server) scimConfig(_ http.ResponseWriter, _ *http.Request, _ *params) (any, error) {
	return scim(http.StatusOK, grpapi.ServiceProviderConfig(s.cfg.PublicOrigin))
}

func (s *Server) scimResourceTypes(_ http.ResponseWriter, _ *http.Request, _ *params) (any, error) {
	rts := grpapi.ResourceTypes(s.cfg.PublicOrigin)
	return scim(http.StatusOK, grpapi.NewList(len(rts), 1, rts))
}

// scimPaging reads startIndex (1-based, at least 1) and count (0 to MaxCount).
func scimPaging(p *params) (start, count int, ok bool) {
	start, count = 1, grpapi.DefaultCount
	if v, has := p.query("startIndex"); has {
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, 0, false
		}
		start = max(n, 1)
	}
	if v, has := p.query("count"); has {
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, 0, false
		}
		count = min(max(n, 0), grpapi.MaxCount)
	}
	return start, count, true
}

var (
	scimUserAttrs  = []string{"id", "username", "displayname", "externalid", "emails.value", "active", "usertype", "title"}
	scimGroupAttrs = []string{"id", "displayname"}
)

func userAttr(i *store.Identity) func(string) []string {
	return func(a string) []string {
		switch a {
		case "id":
			return []string{strconv.FormatInt(i.ID, 10)}
		case "username":
			return []string{grpapi.UserName(i)}
		case "displayname":
			return []string{i.Name}
		case "externalid":
			return []string{i.ExternalID}
		case "emails.value":
			if i.Email != nil {
				return []string{*i.Email}
			}
		case "active":
			return []string{strconv.FormatBool(i.Status == "active")}
		case "usertype":
			return []string{i.Type}
		case "title":
			if i.Title != nil {
				return []string{*i.Title}
			}
		}
		return nil
	}
}

func groupAttr(g *store.NativeGroup) func(string) []string {
	return func(a string) []string {
		switch a {
		case "id":
			return []string{string(g.ID)}
		case "displayname":
			return []string{g.Name}
		}
		return nil
	}
}

// scimQuery is the parsed paging, filter and attribute selection of a list request.
type scimQuery struct {
	start, count int
	filter       *grpapi.Filter
	attributes   string
	excluded     string
}

// scimParse reads the query of a list request; on a bad one it returns the SCIM error to send.
func scimParse(p *params, attrs []string) (q scimQuery, bad any) {
	var ok bool
	if q.start, q.count, ok = scimPaging(p); !ok {
		r, _ := scimError(http.StatusBadRequest, "invalidValue", "startIndex and count are numbers")
		return q, r
	}
	raw, _ := p.query("filter")
	var err error
	if q.filter, err = grpapi.ParseFilter(raw, attrs); err != nil {
		detail := err.Error()
		if fe, isF := grpapi.IsFilterError(err); isF {
			detail = fe.Detail
		}
		r, _ := scimError(http.StatusBadRequest, "invalidFilter", detail)
		return q, r
	}
	q.attributes, _ = p.query("attributes")
	q.excluded, _ = p.query("excludedAttributes")
	return q, nil
}

// scimScan walks fetch's pages of rows in order and returns the rows after the
// first start-1 matches (at most count of them) and the number of matches.
func scimScan[T any](q scimQuery, fetch func(limit, offset int) ([]T, error), match func(T) (bool, error)) ([]T, int, error) {
	const chunk = 500
	var out []T
	matched := 0
	for off := 0; ; off += chunk {
		rows, err := fetch(chunk, off)
		if err != nil {
			return nil, 0, err
		}
		for _, row := range rows {
			ok, err := match(row)
			if err != nil {
				return nil, 0, err
			}
			if !ok {
				continue
			}
			if matched++; matched > q.start-1 && len(out) < q.count {
				out = append(out, row)
			}
		}
		if len(rows) < chunk {
			return out, matched, nil
		}
	}
}

func (s *Server) scimUsers(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	q, bad := scimParse(p, scimUserAttrs)
	if bad != nil {
		return bad, nil
	}
	tx := store.TxFrom(r.Context())
	var items []*store.Identity
	var total int
	var err error
	switch attr, op, val, single := q.filter.Single(); {
	case q.filter == nil:
		if total, err = tx.IdentityCount(); err == nil && q.count > 0 {
			items, err = tx.IdentitiesPage(q.count, q.start-1)
		}
	case single && attr == "id" && op == "eq":
		if n, perr := strconv.ParseInt(val, 10, 64); perr == nil {
			if i, ierr := tx.Identity(n); ierr == nil {
				total = 1
				if q.start == 1 && q.count > 0 {
					items = []*store.Identity{i}
				}
			} else if !errors.Is(ierr, store.ErrNotFound) {
				err = ierr
			}
		}
	default:
		items, total, err = scimScan(q, func(l, o int) ([]*store.Identity, error) { return tx.IdentitiesPage(l, o) },
			func(i *store.Identity) (bool, error) { return q.filter.Eval(userAttr(i)), nil })
	}
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(items))
	for _, i := range items {
		v, err := grpapi.Select(grpapi.NewUser(i, s.cfg.PublicOrigin), q.attributes, q.excluded)
		if err != nil {
			return nil, err
		}
		res = append(res, v)
	}
	return scim(http.StatusOK, grpapi.NewList(total, q.start, res))
}

func (s *Server) scimUser(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	tx := store.TxFrom(r.Context())
	n, perr := strconv.ParseInt(p.path["id"], 10, 64)
	if perr != nil || n < 1 {
		return scimError(http.StatusNotFound, "", "no such user")
	}
	i, err := tx.Identity(n)
	if errors.Is(err, store.ErrNotFound) {
		return scimError(http.StatusNotFound, "", "no such user")
	}
	if err != nil {
		return nil, err
	}
	u := grpapi.NewUser(i, s.cfg.PublicOrigin)
	// the groups the caller may read
	now := s.clock()
	groups, err := visible(s.grpChecker(r), privs.Group, 500, 0, func(l, o int) ([]*store.NativeGroup, error) {
		return tx.GrpGroupsOfIdentity(i.ID, store.MembersListID(tx.Tenant()), "effective", now, l, o)
	}, func(g *store.NativeGroup) privs.Object { return privs.GroupObject(g.ID) }, privs.Read)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		u.Groups = append(u.Groups, grpapi.GroupRef(g, s.cfg.PublicOrigin))
	}
	attributes, _ := p.query("attributes")
	excluded, _ := p.query("excludedAttributes")
	v, err := grpapi.Select(u, attributes, excluded)
	if err != nil {
		return nil, err
	}
	return scim(http.StatusOK, v)
}

// scimGroupResource builds the Group of a native group with up to maxMembers members.
func (s *Server) scimGroupResource(e model.Env, g *store.NativeGroup, maxMembers int) (grpapi.Group, error) {
	rows, total, _, err := e.EffectiveMembers(g.ID, model.MemberQuery{Limit: maxMembers})
	if err != nil {
		return grpapi.Group{}, err
	}
	refs := make([]grpapi.Ref, len(rows))
	for i, m := range rows {
		refs[i] = grpapi.MemberRef(m.Identity, m.Name, s.cfg.PublicOrigin)
	}
	return grpapi.NewGroup(g, refs, total, s.cfg.PublicOrigin), nil
}

// scimListMembers is how many members each Group of a list carries (a single Group has more).
const scimListMembers = 100

func (s *Server) scimGroups(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	q, bad := scimParse(p, scimGroupAttrs)
	if bad != nil {
		return bad, nil
	}
	e, ck := s.grpRead(r), s.grpChecker(r)
	search := ""
	if attr, op, val, single := q.filter.Single(); single && attr == "displayname" && (op == "eq" || op == "co" || op == "sw") {
		search = val // a substring of the name narrows the scan; the filter decides
	}
	items, total, err := scimScan(q, func(l, o int) ([]*store.NativeGroup, error) {
		return e.ListGroups(model.GroupQuery{Q: search, Limit: l, Offset: o})
	}, func(g *store.NativeGroup) (bool, error) {
		if !q.filter.Eval(groupAttr(g)) {
			return false, nil
		}
		return ck.Has(privs.GroupObject(g.ID), privs.Read)
	})
	if err != nil {
		return nil, grpErr(err)
	}
	res := make([]any, 0, len(items))
	for _, g := range items {
		gr, err := s.scimGroupResource(e, g, scimListMembers)
		if err != nil {
			return nil, grpErr(err)
		}
		v, err := grpapi.Select(gr, q.attributes, q.excluded)
		if err != nil {
			return nil, err
		}
		res = append(res, v)
	}
	return scim(http.StatusOK, grpapi.NewList(total, q.start, res))
}

func (s *Server) scimGroup(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.path["id"]
	if !idRE.MatchString(id) {
		return scimError(http.StatusNotFound, "", "no such group")
	}
	e := s.grpRead(r)
	g, err := e.Group(store.GroupID(id))
	if err != nil {
		if me := (*model.Error)(nil); errors.As(err, &me) && me.Kind == model.NotFound {
			return scimError(http.StatusNotFound, "", "no such group")
		}
		return nil, grpErr(err)
	}
	if g.Status == store.GroupDeleted {
		return scimError(http.StatusNotFound, "", "no such group")
	}
	if err := s.grpChecker(r).Require(privs.GroupObject(g.ID), privs.Read); err != nil {
		var d *privs.DeniedError
		if errors.As(err, &d) {
			return scimError(http.StatusForbidden, "", "the read privilege is required on this group")
		}
		return nil, grpErr(err)
	}
	gr, err := s.scimGroupResource(e, g, grpapi.MaxMembers)
	if err != nil {
		return nil, grpErr(err)
	}
	attributes, _ := p.query("attributes")
	excluded, _ := p.query("excludedAttributes")
	v, err := grpapi.Select(gr, attributes, excluded)
	if err != nil {
		return nil, err
	}
	return scim(http.StatusOK, v)
}
