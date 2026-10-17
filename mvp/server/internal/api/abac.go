package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/abac"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Attribute conditions (issue #162):
//
//	GET  /api/abac/policies                     every policy, with where it is used, and the attributes available
//	POST /api/abac/policies                     {name, description, condition, note}: create
//	GET  /api/abac/policies/{policy_id}         a policy with its versions
//	PUT  /api/abac/policies/{policy_id}         {version, name, description, condition, note}: next version
//	POST /api/abac/policies/{policy_id}/retire  {reason}: only when nothing uses it
//	POST /api/abac/simulate                     {policy_id?, condition, resource?, context?}: who gains and loses
//	GET  /api/abac/bindings                     the policy bound to each catalog item
//	PUT  /api/catalog/items/{group_id}/policy   {policy_id | null}: bind or unbind a catalog item's eligibility policy
//
// Reading needs graph.read; changing a policy needs roles.manage and a fresh
// phishing-resistant sign-in; binding a catalog item needs catalog.manage
// (also step-up). Simulating changes nothing but is audited like a read
// that returns computed data. Birthright rules name their policy in the
// role's rule (PUT /api/roles/{id}); SoD policies carry a subjects.condition
// in their YAML.

func (s *Server) registerAbacRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	graph := need(auth.PermGraphRead)
	manage := needStepUp(auth.PermRolesManage, auth.StepUpPolicy)
	s.handle(G, "/api/abac/policies", read, graph, s.listAbacPolicies)
	s.handle(P, "/api/abac/policies", write, manage, s.createAbacPolicy)
	s.handle(G, "/api/abac/policies/{policy_id}", read, graph, s.getAbacPolicy)
	s.handle(http.MethodPut, "/api/abac/policies/{policy_id}", write, manage, s.updateAbacPolicy)
	s.handle(P, "/api/abac/policies/{policy_id}/retire", write, manage, s.retireAbacPolicy)
	s.handle(P, "/api/abac/simulate", write, graph, s.simulateAbac).answersRead = true
	s.handle(G, "/api/abac/bindings", read, graph, s.listAbacBindings)
	s.handle(http.MethodPut, "/api/catalog/items/{group_id}/policy", write, needStepUp(auth.PermCatalogManage, auth.StepUpPolicy),
		s.bindCatalogPolicy)
}

// ---------------------------------------------------------------- views

type abacUsage struct {
	Roles        []string `json:"roles"`
	CatalogItems []string `json:"catalog_items"`
}

type abacPolicyView struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Condition   json.RawMessage `json:"condition"`
	Status      string          `json:"status"`
	Version     int             `json:"version"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedBy   *userRef        `json:"updated_by"`
	UpdatedAt   time.Time       `json:"updated_at"`
	UsedBy      abacUsage       `json:"used_by"`
	Versions    []versionView   `json:"versions,omitempty"`
}

func (v *viewer) abacPolicy(p *store.AbacPolicy, use *abac.Usage) abacPolicyView {
	out := abacPolicyView{ID: p.ID, Name: p.Name, Description: p.Description, Condition: json.RawMessage(p.Condition),
		Status: p.Status, Version: p.Version, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
		UsedBy: abacUsage{Roles: []string{}, CatalogItems: []string{}}}
	if p.UpdatedBy != nil {
		u := v.user(*p.UpdatedBy)
		out.UpdatedBy = &u
	}
	if use != nil {
		out.UsedBy.Roles = append(out.UsedBy.Roles, use.Roles...)
		for _, id := range use.CatalogItems {
			out.UsedBy.CatalogItems = append(out.UsedBy.CatalogItems, v.itemLabel(id))
		}
	}
	return out
}

// itemLabel names a catalog item by its group (system:name).
func (v *viewer) itemLabel(itemID string) string {
	it, err := v.tx.CatalogItem(itemID)
	if err != nil {
		return itemID
	}
	g, err := v.group(it.GroupID)
	if err != nil {
		return itemID
	}
	return g.System + ":" + g.Name
}

func abacErr(err error) error {
	var rf *abac.Refusal
	if errors.As(err, &rf) {
		return &readiness.Error{Status: rf.Status, Code: rf.Code, Msg: rf.Msg}
	}
	var ae *abac.Error
	if errors.As(err, &ae) {
		return &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_condition", Msg: ae.Msg}
	}
	return err
}

func (s *Server) loadAbacPolicy(r *http.Request, p *params) (*store.AbacPolicy, error) {
	ap, err := store.TxFrom(r.Context()).AbacPolicy(strings.TrimSpace(p.path["policy_id"]))
	if errors.Is(err, store.ErrNotFound) {
		return nil, &readiness.Error{Status: http.StatusNotFound, Code: "policy_not_found", Msg: "policy not found"}
	}
	return ap, err
}

// ---------------------------------------------------------------- reads

func (s *Server) listAbacPolicies(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	ps, err := tx.AbacPolicies()
	if err != nil {
		return nil, err
	}
	use, err := abac.UsageOf(tx)
	if err != nil {
		return nil, err
	}
	v := newViewer(tx)
	out := struct {
		CanManage  bool             `json:"can_manage"`
		Attributes []abac.Attribute `json:"attributes"`
		Policies   []abacPolicyView `json:"policies"`
	}{s.can(r, auth.PermRolesManage), abac.Catalog, make([]abacPolicyView, 0, len(ps))}
	for _, p := range ps {
		out.Policies = append(out.Policies, v.abacPolicy(p, use[p.ID]))
	}
	return out, nil
}

func (s *Server) abacDetail(r *http.Request, ap *store.AbacPolicy) (abacPolicyView, error) {
	tx := store.TxFrom(r.Context())
	use, err := abac.UsageOf(tx)
	if err != nil {
		return abacPolicyView{}, err
	}
	vs, err := tx.AbacPolicyVersions(ap.ID)
	if err != nil {
		return abacPolicyView{}, err
	}
	out := newViewer(tx).abacPolicy(ap, use[ap.ID])
	out.Versions = make([]versionView, len(vs))
	for i, x := range vs {
		out.Versions[i] = versionView{x.Version, json.RawMessage(x.Snapshot), x.Note, x.Actor, x.ChangedAt}
	}
	return out, nil
}

func (s *Server) getAbacPolicy(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ap, err := s.loadAbacPolicy(r, p)
	if err != nil {
		return nil, err
	}
	return s.abacDetail(r, ap)
}

type abacBindingView struct {
	Kind     string `json:"kind"`
	TargetID string `json:"target_id"`
	Target   string `json:"target"`
	PolicyID string `json:"policy_id"`
}

func (s *Server) listAbacBindings(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	bs, err := tx.AbacBindings()
	if err != nil {
		return nil, err
	}
	v := newViewer(tx)
	out := make([]abacBindingView, 0, len(bs))
	for _, b := range bs {
		out = append(out, abacBindingView{b.Kind, b.TargetID, v.itemLabel(b.TargetID), b.PolicyID})
	}
	return out, nil
}

// ---------------------------------------------------------------- changes

type abacBody struct {
	Version     int             `json:"version"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Condition   json.RawMessage `json:"condition"`
	Note        string          `json:"note"`
}

func (b abacBody) spec() (abac.Spec, error) {
	s := abac.Spec{Name: b.Name, Description: b.Description, Note: b.Note}
	if len(b.Condition) == 0 {
		return s, nil
	}
	n, err := abac.Parse(b.Condition)
	if err != nil {
		return s, abacErr(err)
	}
	s.Condition = n
	return s, nil
}

func (s *Server) abacActor(r *http.Request) (abac.Actor, error) {
	a, err := s.requestActor(r)
	return abac.Actor{UserID: a.UserID, Display: a.Display}, err
}

func (s *Server) createAbacPolicy(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.abacActor(r)
	if err != nil {
		return nil, err
	}
	var b abacBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	spec, err := b.spec()
	if err != nil {
		return nil, err
	}
	ap, err := abac.Create(store.TxFrom(r.Context()), spec, by, s.clock().UTC())
	if err != nil {
		return nil, abacErr(err)
	}
	out, err := s.abacDetail(r, ap)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, out}, nil
}

func (s *Server) updateAbacPolicy(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.abacActor(r)
	if err != nil {
		return nil, err
	}
	old, err := s.loadAbacPolicy(r, p)
	if err != nil {
		return nil, err
	}
	var b abacBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	spec, err := b.spec()
	if err != nil {
		return nil, err
	}
	ap, err := abac.Update(store.TxFrom(r.Context()), old.ID, b.Version, spec, by, s.clock().UTC())
	if err != nil {
		return nil, abacErr(err)
	}
	return s.abacDetail(r, ap)
}

func (s *Server) retireAbacPolicy(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.abacActor(r)
	if err != nil {
		return nil, err
	}
	old, err := s.loadAbacPolicy(r, p)
	if err != nil {
		return nil, err
	}
	var b struct {
		Reason string `json:"reason"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	ap, err := abac.Retire(store.TxFrom(r.Context()), old.ID, b.Reason, by, s.clock().UTC())
	if err != nil {
		return nil, abacErr(err)
	}
	return s.abacDetail(r, ap)
}

type simPerson struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	Department string `json:"department"`
	Title      string `json:"title"`
}

func simPeople(ps []abac.Person) []simPerson {
	out := make([]simPerson, len(ps))
	for i, p := range ps {
		out[i] = simPerson{p.ID, p.Name, p.Type, p.Status, p.Department, p.Title}
	}
	return out
}

const maxSimAttrs = 20

// simAttrs validates caller-supplied resource.* / context.* values.
func simAttrs(in map[string]any, ns string) (abac.Attrs, error) {
	if len(in) > maxSimAttrs {
		return nil, badRequest("invalid_attributes", "at most 20 attributes")
	}
	out := abac.Attrs{}
	for k, v := range in {
		if !strings.HasPrefix(k, ns+".") {
			return nil, badRequest("invalid_attributes", "attributes under "+ns+" are named "+ns+".<name>")
		}
		switch x := v.(type) {
		case string:
			if len(x) > abac.MaxStringLen {
				return nil, badRequest("invalid_attributes", "a value is too long")
			}
		case float64, bool:
		default:
			return nil, badRequest("invalid_attributes", "a value is a string, number or boolean")
		}
		out[k] = v
	}
	return out, nil
}

func (s *Server) simulateAbac(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b struct {
		PolicyID  string          `json:"policy_id"`
		Condition json.RawMessage `json:"condition"`
		Resource  map[string]any  `json:"resource"`
		Context   map[string]any  `json:"context"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if len(b.Condition) == 0 {
		return nil, badRequest("invalid_condition", "a condition is required")
	}
	draft, err := abac.Parse(b.Condition)
	if err != nil {
		return nil, abacErr(err)
	}
	res, err := simAttrs(b.Resource, "resource")
	if err != nil {
		return nil, err
	}
	ctx, err := simAttrs(b.Context, "context")
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	var cur *store.AbacPolicy
	if b.PolicyID != "" {
		if cur, err = tx.AbacPolicy(strings.TrimSpace(b.PolicyID)); errors.Is(err, store.ErrNotFound) {
			return nil, &readiness.Error{Status: http.StatusNotFound, Code: "policy_not_found", Msg: "policy not found"}
		} else if err != nil {
			return nil, err
		}
	}
	sim, err := abac.Simulate(tx, draft, cur, abac.Merge(res, ctx), s.clock().UTC())
	if err != nil {
		return nil, abacErr(err)
	}
	return struct {
		Evaluated      int         `json:"evaluated"`
		Matching       int         `json:"matching"`
		Before         int         `json:"before"`
		Unchanged      int         `json:"unchanged"`
		MissingAttrs   int         `json:"missing_attributes"`
		CurrentVersion int         `json:"current_version"`
		GainCount      int         `json:"gain_count"`
		LoseCount      int         `json:"lose_count"`
		Gains          []simPerson `json:"gains"`
		Loses          []simPerson `json:"loses"`
		ListsTruncated bool        `json:"lists_truncated"`
	}{sim.Evaluated, sim.Matching, sim.Before, sim.Unchanged, sim.NoAttrs, sim.CurrentVer, sim.GainCount, sim.LoseCount,
		simPeople(sim.Gains), simPeople(sim.Loses), sim.Truncated}, nil
}

func (s *Server) bindCatalogPolicy(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	gid := p.pathInt("group_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.abacActor(r)
	if err != nil {
		return nil, err
	}
	var b struct {
		PolicyID *string `json:"policy_id"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	it, err := tx.CatalogItemForGroup(gid)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &readiness.Error{Status: http.StatusNotFound, Code: "item_not_found", Msg: "catalog item not found"}
	} else if err != nil {
		return nil, err
	}
	pid := ""
	if b.PolicyID != nil {
		pid = strings.TrimSpace(*b.PolicyID)
	}
	if err := abac.Bind(tx, store.BindCatalogItem, it.ID, pid, by, s.clock().UTC()); err != nil {
		return nil, abacErr(err)
	}
	out := struct {
		CatalogItemID string  `json:"catalog_item_id"`
		PolicyID      *string `json:"policy_id"`
	}{it.ID, nil}
	if pid != "" {
		out.PolicyID = &pid
	}
	return out, nil
}
