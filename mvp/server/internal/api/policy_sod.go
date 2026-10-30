package api

import (
	"encoding/json"
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/sodascode"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// SoD rulesets as code (issue #652, AC-6; design docs/design/access-as-code-repo.md), the same shape as roles as
// code (policy_roles.go):
//
//	GET  /api/policy/sod/export    the active rulesets as a bundle: {tenant, files: {path: text}, bundle_sha256}
//	POST /api/policy/sod/validate  {files}: load and resolve the bundle, change nothing; 422 invalid_bundle with a
//	                               diagnostics list (path, line, code, message) when it is not valid
//	POST /api/policy/sod/plan      {files}: the rulesets, functions and risks it would create, update or retire
//	                               and plan_sha256; 413 plan_too_large, 409 deletion_guard
//	                               when a plan is refused
//	POST /api/policy/sod/apply     {commit, files}: plans the bundle and files an admin change request of type
//	                               sod.bundle.apply with the plan's digest; a different admin approves it (every
//	                               apply takes two people) and the apply plans again, refusing 409 stale_plan when
//	                               the plan moved
//
// files is {"<path>": "<text>"}, the repository's layout (tessera.yaml, sod/<ruleset-key>.yaml). Planning needs
// sod.manage with step-up like every sod.manage route (it changes nothing); filing the apply needs admin.change.request and a fresh
// STEP_UP_ADMIN like every change request.

func (s *Server) registerPolicySodRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	s.handle(G, "/api/policy/sod/export", read, need(auth.PermGraphRead), s.policySodExport)
	s.handle(P, "/api/policy/sod/validate", read, needStepUp(auth.PermSoDManage, auth.StepUpPolicy), s.policySodValidate)
	s.handle(P, "/api/policy/sod/plan", read, needStepUp(auth.PermSoDManage, auth.StepUpPolicy), s.policySodPlan)
	s.handle(P, "/api/policy/sod/apply", phased, needStepUp(auth.PermAdminChangeReq, auth.StepUpAdmin), s.policySodApply)
}

func (s *Server) policySodOptions(tx *store.TenantTx) (sodascode.Options, error) {
	t, err := tx.TenantRecord()
	if err != nil {
		return sodascode.Options{}, err
	}
	return sodascode.Options{Tenant: t.Slug, MaxSteps: s.admin.PolicyMaxSteps}, nil
}

func (s *Server) policySodExport(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	t, err := tx.TenantRecord()
	if err != nil {
		return nil, err
	}
	files, err := sodascode.Export(tx, t.Slug)
	if err != nil {
		return nil, bundleErr(err)
	}
	out := make(map[string]string, len(files))
	for p, b := range files {
		out[p] = string(b)
	}
	return map[string]any{"tenant": t.Slug, "files": out, "bundle_sha256": sodascode.Digest(files)}, nil
}

func (s *Server) policySodValidate(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b bundleBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	opt, err := s.policySodOptions(tx)
	if err != nil {
		return nil, err
	}
	files := b.bundle()
	if err := sodascode.Validate(tx, files, opt); err != nil {
		return nil, bundleErr(err)
	}
	return map[string]any{"valid": true, "bundle_sha256": sodascode.Digest(files)}, nil
}

func (s *Server) policySodPlan(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b bundleBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	opt, err := s.policySodOptions(tx)
	if err != nil {
		return nil, err
	}
	plan, err := sodascode.Build(tx, b.bundle(), opt)
	if err != nil {
		return nil, bundleErr(err)
	}
	return plan, nil
}

// policySodApply plans the bundle (so a bundle that cannot be applied never becomes a request) and files the change
// request with the digests the server computed: a client cannot name a plan it did not get.
func (s *Server) policySodApply(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b bundleBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	p := principal(r)
	var plan *sodascode.Plan
	files := b.bundle()
	err := s.store.ReadTenant(r.Context(), p.TenantID, func(tx *store.TenantTx) error {
		opt, err := s.policySodOptions(tx)
		if err != nil {
			return err
		}
		plan, err = sodascode.Build(tx, files, opt)
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
	ch, err := s.admin.Submit(r.Context(), p, admin.SubmitInput{Type: admin.TypeSodBundleApply, Payload: payload})
	if err != nil {
		return nil, err
	}
	out, err := s.changeResponse(r, ch)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, map[string]any{"change_request": out, "plan": plan}}, nil
}
