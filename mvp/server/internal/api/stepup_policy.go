package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/stepup"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Tenant step-up policy per action (issue #298):
//
//	GET /api/stepup-policy   the actions, what the code requires of each, the tenant's entries and the effective result
//	PUT /api/stepup-policy   {version, entries: {permission: {acr, max_age_s}}}: replaces the entries
//
// An action is a permission; the policy covers its state-changing routes. What
// the code requires today is the floor: an entry can add step-up or make it
// stricter, never weaker (422 weaker_than_required). Reading needs admin.read.
// Changing needs admin.change.request and a fresh phishing-resistant sign-in
// within five minutes, and is audited in the same transaction. The two routes
// are exempt from the policy itself, so it cannot lock its admins out.
// Production refuses TESSERA_STEPUP_ALLOW_WEAKER, the only way below the floor.

func (s *Server) registerStepUpPolicyRoutes() {
	s.handle(http.MethodGet, "/api/stepup-policy", read, need(auth.PermAdminRead), s.getStepUpPolicy)
	put := needStepUp(auth.PermAdminChangeReq, auth.StepUpAdmin)
	put.NoTenantStepUp = true
	s.handle(http.MethodPut, "/api/stepup-policy", write, put, s.putStepUpPolicy)
}

// allowWeaker is whether this deployment lets a tenant policy go below the
// floor: only outside production, and only when configured.
func (s *Server) allowWeaker() bool { return s.cfg.StepUpAllowWeaker && s.cfg.Env != "prod" }

// stepUpBypass is whether step-up is off for this deployment
// (TESSERA_STEPUP_BYPASS): only outside production, and only when configured.
func (s *Server) stepUpBypass() bool { return s.cfg.StepUpBypass && s.cfg.Env != "prod" }

// stepUpCatalog is the catalog of actions, built from the routes on first use.
func (s *Server) stepUpCatalog() stepup.Catalog {
	s.stepUpsOnce.Do(func() {
		decls := make([]stepup.RouteDecl, 0, len(s.routes))
		for _, rt := range s.routes {
			if rt.spec.Public || rt.tenant == noTenant {
				continue
			}
			decls = append(decls, stepup.RouteDecl{Method: rt.method, Perm: rt.spec.Perm, Authn: rt.spec.Authn,
				Exempt: rt.spec.NoTenantStepUp || rt.answersRead})
		}
		s.stepUps = stepup.BuildCatalog(decls)
	})
	return s.stepUps
}

// tenantStepUp is the requirement the request's route is held to under the
// tenant's policy: the route's own (floor) when the tenant has no entry for the
// action, else the stricter of the two. It returns floor itself when nothing
// changes.
func (s *Server) tenantStepUp(ctx context.Context, p *auth.Principal, perm auth.Permission, floor *auth.AuthnRequirement) (*auth.AuthnRequirement, error) {
	var pol stepup.Policy
	err := s.store.ReadTenant(ctx, p.TenantID, func(tx *store.TenantTx) error {
		var err error
		pol, _, err = stepup.Load(tx)
		return err
	})
	if err != nil {
		return nil, err
	}
	return pol.Effective(perm, floor, s.allowWeaker()), nil
}

type stepUpEntryJSON struct {
	ACR     string `json:"acr"`
	MaxAgeS int    `json:"max_age_s"`
}

func entryJSON(r *auth.AuthnRequirement) *stepUpEntryJSON {
	if r == nil {
		return nil
	}
	return &stepUpEntryJSON{ACR: string(r.ACR), MaxAgeS: int(r.MaxAge / time.Second)}
}

type stepUpActionView struct {
	Action string `json:"action"`
	// Floor is what the code requires (the weakest of the action's routes); null: nothing.
	Floor *stepUpEntryJSON `json:"floor"`
	// Unguarded: some route of the action has no step-up in code.
	Unguarded bool `json:"unguarded"`
	Routes    int  `json:"routes"`
	// Policy is the tenant's entry, Effective what the weakest route is held to under it.
	Policy    *stepUpEntryJSON `json:"policy"`
	Effective *stepUpEntryJSON `json:"effective"`
}

type stepUpPolicyView struct {
	Version     int                `json:"version"`
	Actions     []stepUpActionView `json:"actions"`
	ACRs        []string           `json:"acrs"`
	MinMaxAgeS  int                `json:"min_max_age_s"`
	MaxMaxAgeS  int                `json:"max_max_age_s"`
	AllowWeaker bool               `json:"allow_weaker"`
	CanManage   bool               `json:"can_manage"`
}

func (s *Server) stepUpPolicyView(r *http.Request, pol stepup.Policy, ver int) stepUpPolicyView {
	cat := s.stepUpCatalog()
	v := stepUpPolicyView{Version: ver, Actions: []stepUpActionView{}, ACRs: []string{}, MinMaxAgeS: int(stepup.MinMaxAge / time.Second),
		MaxMaxAgeS: int(stepup.MaxMaxAge / time.Second), AllowWeaker: s.allowWeaker(), CanManage: s.can(r, auth.PermAdminChangeReq)}
	for _, a := range stepup.ACRs {
		v.ACRs = append(v.ACRs, string(a))
	}
	for _, perm := range cat.Actions() {
		f := cat[perm]
		av := stepUpActionView{Action: string(perm), Floor: entryJSON(f.Req), Unguarded: f.Unguarded, Routes: f.Routes}
		if e, ok := pol[perm]; ok {
			req := e.Req()
			av.Policy = entryJSON(&req)
		}
		av.Effective = entryJSON(pol.Effective(perm, f.Req, s.allowWeaker()))
		v.Actions = append(v.Actions, av)
	}
	return v
}

func (s *Server) getStepUpPolicy(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	pol, ver, err := stepup.Load(store.TxFrom(r.Context()))
	if err != nil {
		return nil, err
	}
	return s.stepUpPolicyView(r, pol, ver), nil
}

type stepUpPolicyBody struct {
	Version int                        `json:"version"`
	Entries map[string]stepUpEntryJSON `json:"entries"`
}

func (s *Server) putStepUpPolicy(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b stepUpPolicyBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	pol := stepup.Policy{}
	for perm, e := range b.Entries {
		pol[auth.Permission(perm)] = stepup.Entry{ACR: auth.ACR(e.ACR), MaxAge: time.Duration(e.MaxAgeS) * time.Second}
	}
	saved, ver, err := stepup.Save(store.TxFrom(r.Context()), s.stepUpCatalog(), pol, b.Version, s.allowWeaker(),
		principal(r).Display, s.clock().UTC())
	if err != nil {
		return nil, cfgErr(err)
	}
	return s.stepUpPolicyView(r, saved, ver), nil
}

// cfgErr renders a refused tenant-configuration change.
func cfgErr(err error) error {
	var ce *cfgerr.Error
	if errors.As(err, &ce) {
		return &readiness.Error{Status: ce.Status, Code: ce.Code, Msg: ce.Msg}
	}
	return err
}
