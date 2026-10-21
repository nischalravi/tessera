package api

import (
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/orgs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Organization settings (issue #298; the tree itself is derived, see orgs.go):
//
//	GET /api/orgs/{org_id}/settings     assigned owners and policies, with the version
//	PUT /api/orgs/{org_id}/settings     {version, owner_ids, policies}: replaces them
//	GET /api/org-hierarchy-source       where the hierarchy comes from, and the sources to choose from
//	PUT /api/org-hierarchy-source       {version, source, system}: replaces it
//
// Reading needs graph.read. Changing needs catalog.manage (the policies it sets
// are request and approval policies) and a fresh phishing-resistant sign-in, and
// is audited in the same transaction. An id that names no organization of the
// tenant, including another tenant's, is 404.

func (s *Server) registerOrgSettingsRoutes() {
	manage := needStepUp(auth.PermCatalogManage, auth.StepUpPolicy)
	s.handle(http.MethodGet, "/api/orgs/{org_id}/settings", read, need(auth.PermGraphRead), s.getOrgSettings)
	s.handle(http.MethodPut, "/api/orgs/{org_id}/settings", write, manage, s.putOrgSettings)
	s.handle(http.MethodGet, "/api/org-hierarchy-source", read, need(auth.PermGraphRead), s.getOrgSource)
	s.handle(http.MethodPut, "/api/org-hierarchy-source", write, manage, s.putOrgSource)
}

type orgSettingsView struct {
	OrgID     string        `json:"org_id"`
	OwnerIDs  []int64       `json:"owner_ids"`
	Owners    []orgs.Person `json:"owners"`
	Policies  orgs.Policies `json:"policies"`
	Version   int           `json:"version"`
	CanManage bool          `json:"can_manage"`
}

func (s *Server) orgFromPath(r *http.Request, p *params) (string, error) {
	id := p.path["org_id"]
	if !orgIDRE.MatchString(id) {
		return "", errStatus(http.StatusNotFound, "organization not found")
	}
	tx := store.TxFrom(r.Context())
	t, err := tx.TenantRecord()
	if err != nil {
		return "", err
	}
	ok, err := orgs.Exists(tx, t.Name, id)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errStatus(http.StatusNotFound, "organization not found")
	}
	return id, nil
}

func (s *Server) orgSettingsView(r *http.Request, id string) (orgSettingsView, error) {
	tx := store.TxFrom(r.Context())
	pol, ver, err := orgs.LoadPolicies(tx, id)
	if err != nil {
		return orgSettingsView{}, err
	}
	opts, err := orgs.Load(tx)
	if err != nil {
		return orgSettingsView{}, err
	}
	v := orgSettingsView{OrgID: id, OwnerIDs: []int64{}, Owners: []orgs.Person{}, Policies: pol, Version: ver, CanManage: s.can(r, auth.PermCatalogManage)}
	for _, oid := range opts.Owners[id] {
		i, err := tx.Identity(oid)
		if err != nil {
			return v, err
		}
		v.OwnerIDs = append(v.OwnerIDs, oid)
		v.Owners = append(v.Owners, orgs.Person{ID: i.ID, Name: i.Name, Title: i.Title, Status: i.Status})
	}
	return v, nil
}

func (s *Server) getOrgSettings(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := s.orgFromPath(r, p)
	if err != nil {
		return nil, err
	}
	return s.orgSettingsView(r, id)
}

type orgSettingsBody struct {
	Version  int           `json:"version"`
	OwnerIDs []int64       `json:"owner_ids"`
	Policies orgs.Policies `json:"policies"`
}

func (s *Server) putOrgSettings(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	id, err := s.orgFromPath(r, p)
	if err != nil {
		return nil, err
	}
	var b orgSettingsBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if _, _, err := orgs.SaveSettings(store.TxFrom(r.Context()), orgs.Settings{OrgID: id, Owners: b.OwnerIDs, Policies: b.Policies},
		b.Version, principal(r).Display, s.clock().UTC()); err != nil {
		return nil, cfgErr(err)
	}
	return s.orgSettingsView(r, id)
}

type orgSourceView struct {
	orgs.HierarchySource
	Version   int      `json:"version"`
	Sources   []string `json:"sources"`
	Available []string `json:"available"`
	CanManage bool     `json:"can_manage"`
}

func (s *Server) orgSourceView(r *http.Request, src orgs.HierarchySource, ver int) (orgSourceView, error) {
	known, err := orgs.Sources(store.TxFrom(r.Context()))
	if err != nil {
		return orgSourceView{}, err
	}
	return orgSourceView{HierarchySource: src, Version: ver, Sources: known, Available: []string{orgs.SourceHRDepartment},
		CanManage: s.can(r, auth.PermCatalogManage)}, nil
}

func (s *Server) getOrgSource(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	src, ver, err := orgs.LoadSource(store.TxFrom(r.Context()))
	if err != nil {
		return nil, err
	}
	return s.orgSourceView(r, src, ver)
}

type orgSourceBody struct {
	Version int `json:"version"`
	orgs.HierarchySource
}

func (s *Server) putOrgSource(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b orgSourceBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	src, ver, err := orgs.SaveSource(store.TxFrom(r.Context()), b.HierarchySource, b.Version, principal(r).Display, s.clock().UTC())
	if err != nil {
		return nil, cfgErr(err)
	}
	return s.orgSourceView(r, src, ver)
}
