package api

import (
	"net/http"
	"regexp"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/orgs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Organizations (Directory > Organizations), derived from the identity data
// Tessera ingests (see internal/orgs): a root for the tenant and one organization
// per department, with the assigned owners and hierarchy source of issue #298
// applied (org_settings.go holds the routes that set them).
//
//	GET /api/orgs                the root, then the departments by name, with member counts and owners
//	GET /api/orgs/{org_id}       one organization: owners, child organizations and members
//
// graph.read, like the identity lists the numbers come from. An id that names
// no organization of the tenant, including another tenant's, is 404.

var orgIDRE = regexp.MustCompile(`^(root|dept-none|dept-[0-9a-f]{10})$`)

func (s *Server) registerOrgRoutes() {
	s.handle(http.MethodGet, "/api/orgs", read, need(auth.PermGraphRead), s.listOrgs)
	s.handle(http.MethodGet, "/api/orgs/{org_id}", read, need(auth.PermGraphRead), s.getOrg)
}

func orgInputs(r *http.Request) (string, []*store.Identity, orgs.Options, error) {
	c := store.TxFrom(r.Context())
	t, err := c.TenantRecord()
	if err != nil {
		return "", nil, orgs.Options{}, err
	}
	idents, err := c.Identities()
	if err != nil {
		return "", nil, orgs.Options{}, err
	}
	opts, err := orgs.Load(c) // assigned owners and the hierarchy source (issue #298)
	return t.Name, idents, opts, err
}

func (s *Server) listOrgs(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	name, idents, opts, err := orgInputs(r)
	if err != nil {
		return nil, err
	}
	return orgs.TreeWith(name, idents, opts), nil
}

func (s *Server) getOrg(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.path["org_id"]
	if !orgIDRE.MatchString(id) {
		return nil, errStatus(http.StatusNotFound, "organization not found")
	}
	name, idents, opts, err := orgInputs(r)
	if err != nil {
		return nil, err
	}
	d, ok := orgs.GetWith(name, idents, id, opts)
	if !ok {
		return nil, errStatus(http.StatusNotFound, "organization not found")
	}
	return d, nil
}
