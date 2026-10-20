package api

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/reconcile"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Access drift and its remediation policy (issue #301). Drift is the
// difference between intended access (approvals, roles, JIT, review keeps,
// admin grants) and observed access (what connectors reported); the engine in
// internal/reconcile finds it after each sync and on the sweeper schedule.
// These routes list it, run the engine on demand, accept or remediate a row,
// and manage the policy that says what the engine does about each class.

func (s *Server) registerDriftRoutes() {
	G, P := http.MethodGet, http.MethodPost
	s.handle(G, "/api/access-drift", read, need(auth.PermDriftRead), s.rd(s.listDrift))
	s.handle(P, "/api/access-drift/run", write, need(auth.PermDriftRemediate), s.rd(s.runDrift))
	// Accepting a risk and acting on it change access: a fresh phishing-resistant sign-in.
	s.handle(P, "/api/access-drift/{drift_id}/accept", write, needStepUp(auth.PermDriftRemediate, auth.StepUpPolicy), s.rd(s.acceptDrift))
	s.handle(P, "/api/access-drift/{drift_id}/remediate", write, needStepUp(auth.PermDriftRemediate, auth.StepUpPolicy), s.rd(s.remediateDrift))
	s.handle(G, "/api/remediation-policies", read, need(auth.PermDriftRead), s.rd(s.listRemediationPolicies))
	s.handle(http.MethodPut, "/api/remediation-policies", write, needStepUp(auth.PermDriftPolicy, auth.StepUpPolicy), s.rd(s.putRemediationPolicy))
	s.handle(http.MethodDelete, "/api/remediation-policies/{policy_id}", write, needStepUp(auth.PermDriftPolicy, auth.StepUpPolicy), s.rd(s.deleteRemediationPolicy))
}

func driftErr(err error) error {
	if e, ok := err.(*reconcile.Error); ok {
		return &readiness.Error{Status: e.Status, Code: e.Code, Msg: e.Msg}
	}
	return err
}

type nameRef struct {
	ID   *int64 `json:"id"`
	Name string `json:"name"`
}

type driftView struct {
	ID          string   `json:"id"`
	Class       string   `json:"class"`
	Status      string   `json:"status"`
	System      string   `json:"system"`
	Entitlement string   `json:"entitlement"`
	Name        string   `json:"entitlement_name"`
	AccountRef  string   `json:"account_ref"`
	Account     string   `json:"account"`
	Identity    *nameRef `json:"identity"`
	Owner       *nameRef `json:"owner"`
	IntendedID  *string  `json:"intended_id"`
	ObservedID  *int64   `json:"observed_id"`
	Action      string   `json:"action"`
	RemRef      *string  `json:"remediation_ref"`
	RemNote     *string  `json:"remediation_note"`
	RemAt       *string  `json:"remediation_at"`
	DetectedAt  string   `json:"detected_at"`
	UpdatedAt   string   `json:"updated_at"`
	ResolvedAt  *string  `json:"resolved_at"`
	AcceptedBy  *string  `json:"accepted_by"`
	AcceptedWhy *string  `json:"accepted_reason"`
	CanAct      bool     `json:"can_remediate"`
	CanAccept   bool     `json:"can_accept"`
}

type driftNames struct {
	idents map[int64]string
	groups map[string]string // system|external id -> name
	accts  map[int64]string
}

func loadDriftNames(c *store.TenantTx) (*driftNames, error) {
	n := &driftNames{idents: map[int64]string{}, groups: map[string]string{}, accts: map[int64]string{}}
	is, err := c.Identities()
	if err != nil {
		return nil, err
	}
	for _, i := range is {
		n.idents[i.ID] = i.Name
	}
	gs, err := c.Groups()
	if err != nil {
		return nil, err
	}
	for _, g := range gs {
		n.groups[g.System+"|"+g.ExternalID] = g.Name
	}
	as, err := c.Accounts()
	if err != nil {
		return nil, err
	}
	for _, a := range as {
		n.accts[a.ID] = a.Username
	}
	return n, nil
}

func (n *driftNames) ref(id *int64) *nameRef {
	if id == nil {
		return nil
	}
	return &nameRef{ID: id, Name: n.idents[*id]}
}

func (n *driftNames) view(d *store.AccessDrift) driftView {
	v := driftView{ID: d.ID, Class: d.Class, Status: d.Status, System: d.System, Entitlement: d.EntitlementRef,
		Name: n.groups[d.System+"|"+d.EntitlementRef], AccountRef: d.AccountRef, Identity: n.ref(d.IdentityID),
		Owner: n.ref(d.OwnerIdentityID), IntendedID: d.IntendedID, ObservedID: d.ObservedID, Action: d.Action,
		RemRef: d.RemediationRef, RemNote: d.RemediationNote, RemAt: timeutil.ISOPtr(d.RemediationAt),
		DetectedAt: timeutil.ISO(d.DetectedAt), UpdatedAt: timeutil.ISO(d.UpdatedAt), ResolvedAt: timeutil.ISOPtr(d.ResolvedAt),
		AcceptedBy: d.AcceptedBy, AcceptedWhy: d.AcceptedReason,
		CanAct:    d.Status == store.DriftOpen,
		CanAccept: d.Status == store.DriftOpen || d.Status == store.DriftRemediating}
	if d.AccountID != nil {
		v.Account = n.accts[*d.AccountID]
	}
	return v
}

func (s *Server) listDrift(r *http.Request, _ *params) (int, any, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return 0, nil, badRequest("invalid_query", "the query string is not valid")
	}
	f := store.DriftFilter{Class: q.Get("class"), Status: q.Get("status"), System: q.Get("system"), Limit: 200}
	if f.Class != "" && !slices.Contains(store.DriftClasses, f.Class) {
		return 0, nil, badRequest("invalid_class", "class must be one of "+strings.Join(store.DriftClasses, ", "))
	}
	if f.Status != "" && !slices.Contains(store.DriftStatuses, f.Status) {
		return 0, nil, badRequest("invalid_status", "status must be one of "+strings.Join(store.DriftStatuses, ", "))
	}
	if len(f.System) > 100 {
		return 0, nil, badRequest("invalid_system", "system is too long")
	}
	if v := q.Get("identity_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			return 0, nil, badRequest("invalid_identity", "identity_id must be a positive integer")
		}
		f.IdentityID = n
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			return 0, nil, badRequest("invalid_limit", "limit must be 1 to 500")
		}
		f.Limit = n
	}
	c := store.TxFrom(r.Context())
	rows, err := c.AccessDrifts(f)
	if err != nil {
		return 0, nil, err
	}
	counts, err := c.AccessDriftCounts()
	if err != nil {
		return 0, nil, err
	}
	names, err := loadDriftNames(c)
	if err != nil {
		return 0, nil, err
	}
	items := make([]driftView, 0, len(rows))
	for _, d := range rows {
		items = append(items, names.view(d))
	}
	byClass, byStatus := map[string]int{}, map[string]int{}
	for _, k := range counts {
		byClass[k.Class] += k.N
		byStatus[k.Status] += k.N
	}
	return http.StatusOK, map[string]any{"items": items, "counts": map[string]any{"by_class": byClass, "by_status": byStatus}}, nil
}

func (s *Server) runDrift(r *http.Request, _ *params) (int, any, error) {
	c, now := store.TxFrom(r.Context()), s.clock()
	res, err := reconcile.RunDrift(c, now, actor(r))
	if err != nil {
		return 0, nil, driftErr(err)
	}
	if err := c.Audit(now, actor(r), "drift.run", ojson.Object{{Key: "opened", Value: res.Opened},
		{Key: "reopened", Value: res.Reopened}, {Key: "updated", Value: res.Updated}, {Key: "resolved", Value: res.Resolved},
		{Key: "actions", Value: res.Actions}}); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]int{"opened": res.Opened, "reopened": res.Reopened, "updated": res.Updated,
		"resolved": res.Resolved, "actions": res.Actions}, nil
}

func driftID(p *params) (string, error) {
	id := p.path["drift_id"]
	if !idRE.MatchString(id) {
		return "", notFoundErr("drift")
	}
	return id, nil
}

func (s *Server) acceptDrift(r *http.Request, p *params) (int, any, error) {
	id, err := driftID(p)
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Reason string `json:"reason"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	c := store.TxFrom(r.Context())
	d, err := reconcile.Accept(c, s.clock(), actor(r), id, in.Reason)
	if err != nil {
		return 0, nil, driftErr(err)
	}
	return s.driftResponse(c, d)
}

func (s *Server) remediateDrift(r *http.Request, p *params) (int, any, error) {
	id, err := driftID(p)
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Action string `json:"action"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if !slices.Contains(store.PolicyActions, in.Action) {
		return 0, nil, badRequest("invalid_action", "action must be one of "+strings.Join(store.PolicyActions, ", "))
	}
	c := store.TxFrom(r.Context())
	d, err := reconcile.Remediate(c, s.clock(), actor(r), id, in.Action)
	if err != nil {
		return 0, nil, driftErr(err)
	}
	return s.driftResponse(c, d)
}

func (s *Server) driftResponse(c *store.TenantTx, d *store.AccessDrift) (int, any, error) {
	names, err := loadDriftNames(c)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, names.view(d), nil
}

// ---------------------------------------------------------------- policies

type policyView struct {
	ID             string `json:"id"`
	System         string `json:"system"`
	EntitlementRef string `json:"entitlement_ref"`
	DriftClass     string `json:"drift_class"`
	Action         string `json:"action"`
	CreatedBy      string `json:"created_by"`
	UpdatedAt      string `json:"updated_at"`
}

func viewPolicy(p *store.RemediationPolicy) policyView {
	return policyView{ID: p.ID, System: p.System, EntitlementRef: p.EntitlementRef, DriftClass: p.DriftClass, Action: p.Action,
		CreatedBy: p.CreatedBy, UpdatedAt: timeutil.ISO(p.UpdatedAt)}
}

func (s *Server) listRemediationPolicies(r *http.Request, _ *params) (int, any, error) {
	ps, err := store.TxFrom(r.Context()).RemediationPolicies()
	if err != nil {
		return 0, nil, err
	}
	out := make([]policyView, 0, len(ps))
	for _, p := range ps {
		out = append(out, viewPolicy(p))
	}
	return http.StatusOK, out, nil
}

func (s *Server) putRemediationPolicy(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		System         string `json:"system"`
		EntitlementRef string `json:"entitlement_ref"`
		DriftClass     string `json:"drift_class"`
		Action         string `json:"action"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	in.System, in.EntitlementRef = strings.TrimSpace(in.System), strings.TrimSpace(in.EntitlementRef)
	switch {
	case in.System == "" || len(in.System) > 100:
		return 0, nil, badRequest("invalid_system", "system is required (at most 100 characters)")
	case len(in.EntitlementRef) > 300:
		return 0, nil, badRequest("invalid_entitlement", "entitlement_ref is at most 300 characters")
	case !slices.Contains(store.DriftClasses, in.DriftClass):
		return 0, nil, badRequest("invalid_class", "drift_class must be one of "+strings.Join(store.DriftClasses, ", "))
	case !slices.Contains(store.PolicyActions, in.Action):
		return 0, nil, badRequest("invalid_action", "action must be one of "+strings.Join(store.PolicyActions, ", "))
	case !reconcile.ValidAction(in.DriftClass, in.Action):
		return 0, nil, badRequest("invalid_action", in.Action+" does not apply to "+in.DriftClass+" drift")
	}
	c, now := store.TxFrom(r.Context()), s.clock()
	if err := c.UpsertRemediationPolicy(&store.RemediationPolicy{System: in.System, EntitlementRef: in.EntitlementRef,
		DriftClass: in.DriftClass, Action: in.Action, CreatedBy: actor(r), UpdatedAt: now}); err != nil {
		return 0, nil, err
	}
	if err := c.Audit(now, actor(r), "drift.policy_set", ojson.Object{{Key: "system", Value: in.System},
		{Key: "entitlement", Value: in.EntitlementRef}, {Key: "class", Value: in.DriftClass}, {Key: "action", Value: in.Action}}); err != nil {
		return 0, nil, err
	}
	ps, err := c.RemediationPolicies()
	if err != nil {
		return 0, nil, err
	}
	for _, p := range ps {
		if p.System == in.System && p.EntitlementRef == in.EntitlementRef && p.DriftClass == in.DriftClass {
			return http.StatusOK, viewPolicy(p), nil
		}
	}
	return 0, nil, store.ErrNotFound
}

func (s *Server) deleteRemediationPolicy(r *http.Request, p *params) (int, any, error) {
	id := p.path["policy_id"]
	if !idRE.MatchString(id) {
		return 0, nil, notFoundErr("policy")
	}
	c := store.TxFrom(r.Context())
	pol, err := c.RemediationPolicy(id)
	if err == store.ErrNotFound {
		return 0, nil, notFoundErr("policy")
	} else if err != nil {
		return 0, nil, err
	}
	if err := c.DeleteRemediationPolicy(id); err != nil {
		return 0, nil, err
	}
	if err := c.Audit(s.clock(), actor(r), "drift.policy_removed", ojson.Object{{Key: "system", Value: pol.System},
		{Key: "entitlement", Value: pol.EntitlementRef}, {Key: "class", Value: pol.DriftClass}}); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"removed": true}, nil
}
