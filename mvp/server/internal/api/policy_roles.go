package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/rolesascode"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Roles and birthright rules as code (issue #650, AC-4; design docs/design/access-as-code-repo.md):
//
//	GET  /api/policy/roles/export    the active roles as a bundle: {tenant, files: {path: text}, bundle_sha256}
//	POST /api/policy/roles/validate  {files}: load and resolve the bundle, change nothing; 422 invalid_bundle
//	                                 with a diagnostics list (path, line, code, message) when it is not valid
//	POST /api/policy/roles/plan      {files}: the roles it would create, update or leave, each with the member
//	                                 and grant steps roles.Plan lists, and plan_sha256; 413 plan_too_large, 409
//	                                 deletion_guard when a plan is refused
//	POST /api/policy/roles/apply     {commit, files}: plans the bundle and files an admin change request of type
//	                                 roles.bundle.apply with the plan's digest; a different admin approves it
//	                                 (every apply takes two people) and the apply plans again, refusing 409
//	                                 stale_plan when the plan moved
//
// files is {"<path>": "<text>"}, the repository's layout (tessera.yaml, roles/<key>.yaml, birthright/<key>.cedar).
// Planning needs roles.manage and no step-up (it changes nothing); filing the apply needs admin.change.request
// and a fresh STEP_UP_ADMIN like every change request.

func (s *Server) registerPolicyRoleRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	s.handle(G, "/api/policy/roles/export", read, need(auth.PermGraphRead), s.policyRolesExport)
	s.handle(P, "/api/policy/roles/validate", read, need(auth.PermRolesManage), s.policyRolesValidate)
	s.handle(P, "/api/policy/roles/plan", read, need(auth.PermRolesManage), s.policyRolesPlan)
	s.handle(P, "/api/policy/roles/apply", phased, needStepUp(auth.PermAdminChangeReq, auth.StepUpAdmin), s.policyRolesApply)
}

type bundleBody struct {
	Commit string            `json:"commit"`
	Files  map[string]string `json:"files"`
}

func (b *bundleBody) bundle() policybundle.Files {
	f := make(policybundle.Files, len(b.Files))
	for p, s := range b.Files {
		f[p] = []byte(s)
	}
	return f
}

// bundleErr turns a bundle finding into a 422 with the diagnostics, and a roles refusal into its own status.
func bundleErr(err error) error {
	var inv *rolesascode.InvalidError
	if errors.As(err, &inv) {
		return &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_bundle", Msg: inv.Error(),
			Extra: map[string]any{"diagnostics": inv.Diags}}
	}
	return reqErr(err)
}

func (s *Server) policyRolesOptions(tx *store.TenantTx) (rolesascode.Options, error) {
	t, err := tx.TenantRecord()
	if err != nil {
		return rolesascode.Options{}, err
	}
	return rolesascode.Options{Tenant: t.Slug, MaxSteps: s.admin.PolicyMaxSteps}, nil
}

func (s *Server) policyRolesExport(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	t, err := tx.TenantRecord()
	if err != nil {
		return nil, err
	}
	files, err := rolesascode.Export(tx, t.Slug)
	if err != nil {
		return nil, bundleErr(err)
	}
	out := make(map[string]string, len(files))
	for p, b := range files {
		out[p] = string(b)
	}
	return map[string]any{"tenant": t.Slug, "files": out, "bundle_sha256": rolesascode.Digest(files)}, nil
}

func (s *Server) policyRolesValidate(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b bundleBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	opt, err := s.policyRolesOptions(tx)
	if err != nil {
		return nil, err
	}
	files := b.bundle()
	if err := rolesascode.Validate(tx, files, opt); err != nil {
		return nil, bundleErr(err)
	}
	return map[string]any{"valid": true, "bundle_sha256": rolesascode.Digest(files)}, nil
}

func (s *Server) policyRolesPlan(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b bundleBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	opt, err := s.policyRolesOptions(tx)
	if err != nil {
		return nil, err
	}
	plan, err := rolesascode.Build(tx, b.bundle(), opt, s.clock().UTC())
	if err != nil {
		return nil, bundleErr(err)
	}
	return plan, nil
}

// policyRolesApply plans the bundle (so a bundle that cannot be applied never becomes a request) and files the
// change request with the digests the server computed: a client cannot name a plan it did not get.
func (s *Server) policyRolesApply(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b bundleBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	p := principal(r)
	var plan *rolesascode.Plan
	files := b.bundle()
	err := s.store.ReadTenant(r.Context(), p.TenantID, func(tx *store.TenantTx) error {
		opt, err := s.policyRolesOptions(tx)
		if err != nil {
			return err
		}
		plan, err = rolesascode.Build(tx, files, opt, s.clock().UTC())
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
	ch, err := s.admin.Submit(r.Context(), p, admin.SubmitInput{Type: admin.TypeRolesBundleApply, Payload: payload})
	if err != nil {
		return nil, err
	}
	out, err := s.changeResponse(r, ch)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, map[string]any{"change_request": out, "plan": plan}}, nil
}
