package api

import (
	"encoding/json"
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/agentscopeascode"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Agent scopes as code (issue #653, AC-7; design docs/design/access-as-code-repo.md), the same shape as SoD rules
// as code (policy_sod.go):
//
//	GET  /api/policy/agents/export    the active scopes as a bundle: {tenant, files: {path: text}, bundle_sha256}
//	POST /api/policy/agents/validate  {files}: load and resolve the bundle, change nothing; 422 invalid_bundle with
//	                                  a diagnostics list (path, line, code, message) when it is not valid
//	POST /api/policy/agents/plan      {files}: the scopes it would create, update or retire and plan_sha256;
//	                                  413 plan_too_large, 409 deletion_guard when a plan is refused
//	POST /api/policy/agents/apply     {commit, files}: plans the bundle and files an admin change request of type
//	                                  agent_scopes.bundle.apply with the plan's digest; a different admin approves
//	                                  it (every apply takes two people) and the apply plans again, refusing 409
//	                                  stale_plan when the plan moved
//
// files is {"<path>": "<text>"}, the repository's layout (tessera.yaml, agents/<key>.yaml). Planning needs
// agents.manage with step-up like every agents.manage route (it changes nothing); filing the apply needs
// admin.change.request and a fresh STEP_UP_ADMIN like every change request. Once applied, a scope shows up as
// findings of the agent-out-of-scope and agent-exceeds-owner policies on /api/violations.

func (s *Server) registerPolicyAgentRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	s.handle(G, "/api/policy/agents/export", read, need(auth.PermGraphRead), s.policyAgentsExport)
	s.handle(P, "/api/policy/agents/validate", read, needStepUp(auth.PermAgentsManage, auth.StepUpPolicy), s.policyAgentsValidate)
	s.handle(P, "/api/policy/agents/plan", read, needStepUp(auth.PermAgentsManage, auth.StepUpPolicy), s.policyAgentsPlan)
	s.handle(P, "/api/policy/agents/apply", phased, needStepUp(auth.PermAdminChangeReq, auth.StepUpAdmin), s.policyAgentsApply)
}

func (s *Server) policyAgentsOptions(tx *store.TenantTx) (agentscopeascode.Options, error) {
	t, err := tx.TenantRecord()
	if err != nil {
		return agentscopeascode.Options{}, err
	}
	return agentscopeascode.Options{Tenant: t.Slug, MaxSteps: s.admin.PolicyMaxSteps}, nil
}

func (s *Server) policyAgentsExport(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	t, err := tx.TenantRecord()
	if err != nil {
		return nil, err
	}
	files, err := agentscopeascode.Export(tx, t.Slug)
	if err != nil {
		return nil, bundleErr(err)
	}
	out := make(map[string]string, len(files))
	for p, b := range files {
		out[p] = string(b)
	}
	return map[string]any{"tenant": t.Slug, "files": out, "bundle_sha256": agentscopeascode.Digest(files)}, nil
}

func (s *Server) policyAgentsValidate(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b bundleBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	opt, err := s.policyAgentsOptions(tx)
	if err != nil {
		return nil, err
	}
	files := b.bundle()
	if err := agentscopeascode.Validate(tx, files, opt); err != nil {
		return nil, bundleErr(err)
	}
	return map[string]any{"valid": true, "bundle_sha256": agentscopeascode.Digest(files)}, nil
}

func (s *Server) policyAgentsPlan(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b bundleBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	opt, err := s.policyAgentsOptions(tx)
	if err != nil {
		return nil, err
	}
	plan, err := agentscopeascode.Build(tx, b.bundle(), opt)
	if err != nil {
		return nil, bundleErr(err)
	}
	return plan, nil
}

// policyAgentsApply plans the bundle (so a bundle that cannot be applied never becomes a request) and files the
// change request with the digests the server computed: a client cannot name a plan it did not get.
func (s *Server) policyAgentsApply(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b bundleBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	p := principal(r)
	var plan *agentscopeascode.Plan
	files := b.bundle()
	err := s.store.ReadTenant(r.Context(), p.TenantID, func(tx *store.TenantTx) error {
		opt, err := s.policyAgentsOptions(tx)
		if err != nil {
			return err
		}
		plan, err = agentscopeascode.Build(tx, files, opt)
		return err
	})
	if err != nil {
		return nil, bundleErr(err)
	}
	payload, err := json.Marshal(map[string]any{"commit": b.Commit, "files": b.Files,
		"bundle_sha256": plan.BundleSHA256, "plan_sha256": plan.PlanSHA256})
	if err != nil {
		return nil, err
	}
	ch, err := s.admin.Submit(r.Context(), p, admin.SubmitInput{Type: admin.TypeAgentScopesBundleApply, Payload: payload})
	if err != nil {
		return nil, err
	}
	out, err := s.changeResponse(r, ch)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, map[string]any{"change_request": out, "plan": plan}}, nil
}
