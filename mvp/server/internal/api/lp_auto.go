package api

import (
	"encoding/json"
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/lp"
	"github.com/nischalravi/tessera/mvp/server/internal/lpauto"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/rolesascode"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Automatic least-privilege mode as code (issue #664, LP-8; design docs/design/least-privilege-loop.md sections 3,
// 10 and 11). The policy is lp/auto.yaml of the access-as-code repository; auto mode is off by default.
//
//	GET  /api/lp/auto-policy           the applied policy (null when none), the mode, whether auto is running and
//	                                   whether the calibration asks for a review (which pauses auto by itself)
//	POST /api/lp/auto-policy/validate  {files}: parse lp/auto.yaml, change nothing; 422 invalid_auto_policy
//	POST /api/lp/auto-policy/apply     {commit, files}: files an admin change request of type lp.auto_policy.apply
//	                                   with the policy digest; a different admin approves it (two people always) and
//	                                   the apply parses again, refusing 409 stale_plan when the policy moved
//
// Applying a policy does not turn auto mode on. That is lp.settings.update to mode auto, which needs two people and
// is refused (422 auto_policy_missing) until a policy was applied and (409 calibration_review) while the
// false-positive rate of high confidence is over 1 percent.

func (s *Server) registerLPAutoRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	s.handle(G, "/api/lp/auto-policy", read, need(auth.PermGraphRead), s.lpAutoGet)
	s.handle(P, "/api/lp/auto-policy/validate", read, need(auth.PermLPManage), s.lpAutoValidate)
	s.handle(P, "/api/lp/auto-policy/apply", phased, needStepUp(auth.PermAdminChangeReq, auth.StepUpAdmin), s.lpAutoApply)
}

type lpAutoView struct {
	Applied bool `json:"applied"`
	// Policy is the applied policy; null when none was applied.
	Policy       *lpauto.Policy `json:"policy"`
	PolicySHA256 string         `json:"policy_sha256,omitempty"`
	Commit       string         `json:"commit,omitempty"`
	AppliedBy    string         `json:"applied_by,omitempty"`
	ApprovedBy   string         `json:"approved_by,omitempty"`
	AppliedAt    string         `json:"applied_at,omitempty"`
	Mode         string         `json:"mode"`
	// Running: auto mode is on, not paused and not disabled by the operator.
	Running bool `json:"running"`
	// CalibrationReview is why the calibration asks for a review ("" when it does not); auto pauses itself then.
	CalibrationReview string `json:"calibration_review,omitempty"`
}

func (s *Server) lpAutoGet(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	st, err := tx.LPSettings()
	if err != nil {
		return nil, err
	}
	pol, row, err := lp.AutoPolicy(tx)
	if err != nil {
		return nil, lpErr(err)
	}
	review, err := lp.CalibrationReview(tx, s.clock())
	if err != nil {
		return nil, err
	}
	v := lpAutoView{Mode: st.Mode, Running: st.Mode == store.LPModeAuto && lp.Active(st) && !s.cfg.LPDisabled, CalibrationReview: review}
	if pol != nil {
		v.Applied, v.Policy, v.PolicySHA256, v.Commit, v.AppliedBy, v.ApprovedBy = true, pol, row.PolicySHA256, row.Commit, row.AppliedBy, row.ApprovedBy
		v.AppliedAt = store.RT(row.AppliedAt)
	}
	return v, nil
}

type lpAutoBody struct {
	Commit string            `json:"commit"`
	Files  map[string]string `json:"files"`
}

func (b *lpAutoBody) bundle() policybundle.Files {
	f := make(policybundle.Files, len(b.Files))
	for p, s := range b.Files {
		f[p] = []byte(s)
	}
	return f
}

func (s *Server) lpAutoValidate(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b lpAutoBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	files := b.bundle()
	p, err := admin.LPAutoParse(files)
	if err != nil {
		return nil, reqErr(err)
	}
	return map[string]any{"valid": true, "policy": p, "policy_sha256": p.Digest(), "bundle_sha256": rolesascode.Digest(files)}, nil
}

// lpAutoApply parses the policy (so one that cannot be applied never becomes a request) and files the change
// request with the digests the server computed: a client cannot name a policy it did not get.
func (s *Server) lpAutoApply(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b lpAutoBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	files := b.bundle()
	pol, err := admin.LPAutoParse(files)
	if err != nil {
		return nil, reqErr(err)
	}
	payload, err := json.Marshal(map[string]any{"commit": b.Commit, "files": b.Files,
		"bundle_sha256": rolesascode.Digest(files), "policy_sha256": pol.Digest()})
	if err != nil {
		return nil, err
	}
	p := principal(r)
	ch, err := s.admin.Submit(r.Context(), p, admin.SubmitInput{Type: admin.TypeLPAutoPolicyApply, Payload: payload})
	if err != nil {
		return nil, err
	}
	out, err := s.changeResponse(r, ch)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, map[string]any{"change_request": out, "policy": pol, "policy_sha256": pol.Digest()}}, nil
}
