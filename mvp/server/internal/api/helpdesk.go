package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/helpdesk"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Verified help-desk resets (issue #108):
//
//	GET  /api/helpdesk/cases                                  list cases with their policy decision
//	POST /api/helpdesk/cases                                  {identity_id, kind, system, reason}: start a case
//	GET  /api/helpdesk/cases/{case_id}                        one case
//	POST /api/helpdesk/cases/{case_id}/verifications          {method, evidence, number_source, session_ref}
//	POST /api/helpdesk/cases/{case_id}/manager-approval       {evidence}: the subject's manager approves (step-up)
//	POST /api/helpdesk/cases/{case_id}/second-approval        the second approver of a privileged case (step-up)
//	POST /api/helpdesk/cases/{case_id}/execute                run the reset through the IdP (step-up)
//	POST /api/helpdesk/cases/{case_id}/cancel                 close the case
//	GET  /api/helpdesk/findings                               post-reset takeover findings
//	POST /api/helpdesk/signals                                {identity_id, kind, location, device, occurred_at}
//
// Execute is a phased route like containment: it claims the case (policy
// checked inside that transaction), then calls the IdP with no transaction
// open, then records the outcome. The signals route simulates the IdP log
// feed and exists only outside production.

// resetTimeout bounds the IdP calls of one execute (the handler timeout is 30s).
const resetTimeout = 20 * time.Second

func (s *Server) registerHelpdeskRoutes() {
	s.handle(http.MethodGet, "/api/helpdesk/cases", read, need(auth.PermGraphRead), s.listHelpdeskCases)
	s.handle(http.MethodPost, "/api/helpdesk/cases", write, need(auth.PermHelpdeskReset), s.startHelpdeskCase)
	s.handle(http.MethodGet, "/api/helpdesk/cases/{case_id}", read, need(auth.PermGraphRead), s.getHelpdeskCase)
	s.handle(http.MethodPost, "/api/helpdesk/cases/{case_id}/verifications", phased, need(auth.PermHelpdeskReset), s.verifyHelpdeskCase)
	s.handle(http.MethodPost, "/api/helpdesk/cases/{case_id}/manager-approval", phased,
		needStepUp(auth.PermHelpdeskApprove, auth.StepUpPolicy), s.managerApproveHelpdeskCase)
	s.handle(http.MethodPost, "/api/helpdesk/cases/{case_id}/second-approval", write,
		needStepUp(auth.PermHelpdeskApprove, auth.StepUpPolicy), s.secondApproveHelpdeskCase)
	s.handle(http.MethodPost, "/api/helpdesk/cases/{case_id}/execute", phased,
		needStepUp(auth.PermHelpdeskReset, auth.StepUpPolicy), s.executeHelpdeskCase)
	s.handle(http.MethodPost, "/api/helpdesk/cases/{case_id}/cancel", write, need(auth.PermHelpdeskReset), s.cancelHelpdeskCase)
	s.handle(http.MethodGet, "/api/helpdesk/findings", read, need(auth.PermGraphRead), s.listHelpdeskFindings)
	s.handle(http.MethodPost, "/api/helpdesk/signals", write, need(auth.PermHelpdeskApprove), s.ingestHelpdeskSignal)
}

// helpdeskErr renders a workflow refusal.
func helpdeskErr(err error) error {
	var he *helpdesk.Error
	if !errors.As(err, &he) {
		return err
	}
	switch he.Code {
	case helpdesk.CodeNotFound:
		return errStatus(http.StatusNotFound, he.Msg)
	case helpdesk.CodeInvalid:
		return badRequest("invalid_request", he.Msg)
	case helpdesk.CodeConflict:
		return &readiness.Error{Status: http.StatusConflict, Code: "conflict", Msg: he.Msg}
	case helpdesk.CodeForbidden:
		return &readiness.Error{Status: http.StatusForbidden, Code: "forbidden", Msg: he.Msg}
	case helpdesk.CodeNotVerified:
		return &readiness.Error{Status: http.StatusConflict, Code: "verification_required", Msg: he.Msg,
			Extra: map[string]any{"policy": he.Decision}}
	case helpdesk.CodeUnavailable:
		return &readiness.Error{Status: http.StatusServiceUnavailable, Code: "provider_unavailable", Msg: he.Msg}
	case helpdesk.CodeIdPFailed:
		return &readiness.Error{Status: http.StatusBadGateway, Code: "provider_failed", Msg: he.Msg}
	}
	return err
}

func (s *Server) helpdeskCaseID(p *params) (string, error) {
	id := p.path["case_id"]
	if !idRE.MatchString(id) {
		return "", errStatus(http.StatusNotFound, "case not found")
	}
	return id, nil
}

func (s *Server) listHelpdeskCases(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	c := store.TxFrom(r.Context())
	rows, err := c.HelpdeskCases()
	if err != nil {
		return nil, err
	}
	k := helpdesk.NewChecker(c, s.clock()) // one graph build for the whole list
	out := make([]*helpdesk.CaseView, 0, len(rows))
	for _, hc := range rows {
		v, err := helpdesk.View(k, hc)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return ojson.Object{{Key: "cases", Value: out}}, nil
}

func (s *Server) getHelpdeskCase(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := s.helpdeskCaseID(p)
	if err != nil {
		return nil, err
	}
	return s.helpdeskView(store.TxFrom(r.Context()), id)
}

func (s *Server) helpdeskView(c *store.TenantTx, id string) (*helpdesk.CaseView, error) {
	hc, err := c.HelpdeskCase(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errStatus(http.StatusNotFound, "case not found")
	}
	if err != nil {
		return nil, err
	}
	return helpdesk.View(helpdesk.NewChecker(c, s.clock()), hc)
}

func (s *Server) startHelpdeskCase(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b struct {
		IdentityID int64  `json:"identity_id"`
		Kind       string `json:"kind"`
		System     string `json:"system"`
		Reason     string `json:"reason"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	hc, err := s.helpdesk.Start(c, helpdesk.StartInput{IdentityID: b.IdentityID, Kind: b.Kind, System: b.System,
		Reason: b.Reason}, principal(r).User(), s.clock())
	if err != nil {
		return nil, helpdeskErr(err)
	}
	v, err := helpdesk.View(helpdesk.NewChecker(c, s.clock()), hc)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, v}, nil
}

type helpdeskVerifyBody struct {
	Method       string `json:"method"`
	Evidence     string `json:"evidence"`
	NumberSource string `json:"number_source"`
	SessionRef   string `json:"session_ref"`
}

func (s *Server) verifyHelpdeskCase(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b helpdeskVerifyBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if b.Method == helpdesk.MethodManagerApproval {
		return nil, &readiness.Error{Status: http.StatusForbidden, Code: "forbidden",
			Msg: "a manager approval is given by the manager through the manager-approval route"}
	}
	return s.runVerification(r, p, b)
}

func (s *Server) managerApproveHelpdeskCase(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b helpdeskVerifyBody
	if err := decodeBody(r, &b, true); err != nil {
		return nil, err
	}
	b.Method = helpdesk.MethodManagerApproval
	return s.runVerification(r, p, b)
}

// runVerification checks the attempt, makes the provider call with no
// transaction open, then records it.
func (s *Server) runVerification(r *http.Request, p *params, b helpdeskVerifyBody) (any, error) {
	id, err := s.helpdeskCaseID(p)
	if err != nil {
		return nil, err
	}
	ctx, by := r.Context(), principal(r).User()
	in := helpdesk.VerifyInput{Method: b.Method, Evidence: b.Evidence, NumberSource: b.NumberSource, SessionRef: b.SessionRef}
	var plan *helpdesk.VerifyPlan
	if err := p.scope.Read(ctx, func(c *store.TenantTx) error {
		var err error
		plan, err = s.helpdesk.PrepareVerify(c, id, in, by, s.clock())
		return err
	}); err != nil {
		return nil, helpdeskErr(err)
	}
	att, err := s.helpdesk.RunVerify(ctx, plan)
	if err != nil {
		return nil, helpdeskErr(err)
	}
	var out *helpdesk.CaseView
	if err := p.scope.Write(ctx, func(c *store.TenantTx) error {
		if _, err := s.helpdesk.RecordVerify(c, plan, att, by, s.clock()); err != nil {
			return err
		}
		var err error
		out, err = s.helpdeskView(c, id)
		return err
	}); err != nil {
		return nil, helpdeskErr(err)
	}
	return out, nil
}

func (s *Server) secondApproveHelpdeskCase(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := s.helpdeskCaseID(p)
	if err != nil {
		return nil, err
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	if err := s.helpdesk.SecondApprove(c, id, principal(r).User(), s.clock()); err != nil {
		return nil, helpdeskErr(err)
	}
	return s.helpdeskView(c, id)
}

func (s *Server) cancelHelpdeskCase(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := s.helpdeskCaseID(p)
	if err != nil {
		return nil, err
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	if err := s.helpdesk.Cancel(c, id, principal(r).User(), s.clock()); err != nil {
		return nil, helpdeskErr(err)
	}
	return s.helpdeskView(c, id)
}

// executeHelpdeskCase runs the reset. Unverified: 409 verification_required
// and nothing is called. A failed IdP call: 502 provider_failed, and the case
// is failed and can be executed again.
func (s *Server) executeHelpdeskCase(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := s.helpdeskCaseID(p)
	if err != nil {
		return nil, err
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return nil, err
	}
	ctx, by := r.Context(), principal(r).User()
	var plan *helpdesk.ExecPlan
	if err := p.scope.Write(ctx, func(c *store.TenantTx) error {
		var err error
		plan, err = s.helpdesk.Claim(c, id, by, s.clock())
		return err
	}); err != nil {
		return nil, helpdeskErr(err)
	}
	runCtx, cancel := context.WithTimeout(ctx, resetTimeout)
	defer cancel()
	res, runErr := plan.Run(runCtx)
	var out *helpdesk.CaseView
	if err := p.scope.Write(ctx, func(c *store.TenantTx) error {
		if err := s.helpdesk.Finish(c, plan, res, runErr, by, s.clock()); err != nil {
			return err
		}
		var err error
		out, err = s.helpdeskView(c, id)
		return err
	}); err != nil {
		return nil, err
	}
	if runErr != nil {
		return nil, &readiness.Error{Status: http.StatusBadGateway, Code: "provider_failed",
			Msg: "the IdP reset failed; the case can be executed again", Extra: map[string]any{"case": out}}
	}
	body := ojson.Object{{Key: "case", Value: out}}
	if res.TemporaryAccessPass != "" {
		// shown once, never stored, audited or logged
		w.Header().Set("Cache-Control", "no-store")
		body = append(body, ojson.KV{Key: "temporary_access_pass", Value: res.TemporaryAccessPass})
	}
	return body, nil
}

func (s *Server) listHelpdeskFindings(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	rows, err := store.TxFrom(r.Context()).HelpdeskFindings()
	if err != nil {
		return nil, err
	}
	out := make([]helpdesk.FindingView, len(rows))
	for i, f := range rows {
		out[i] = helpdesk.ViewFinding(f)
	}
	return ojson.Object{{Key: "findings", Value: out}}, nil
}

func (s *Server) ingestHelpdeskSignal(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	if !s.helpdesk.Simulated {
		return nil, errStatus(http.StatusNotFound, "the simulated signal feed is not available in this environment")
	}
	var b struct {
		IdentityID int64     `json:"identity_id"`
		Kind       string    `json:"kind"`
		Location   string    `json:"location"`
		Device     string    `json:"device"`
		OccurredAt time.Time `json:"occurred_at"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	fs, err := s.helpdesk.IngestSignal(store.TxFrom(r.Context()), helpdesk.SignalInput{IdentityID: b.IdentityID,
		Kind: b.Kind, Location: b.Location, Device: b.Device, Source: "simulated", OccurredAt: b.OccurredAt},
		principal(r).User(), s.clock())
	if err != nil {
		return nil, helpdeskErr(err)
	}
	out := make([]helpdesk.FindingView, len(fs))
	for i, f := range fs {
		out[i] = helpdesk.ViewFinding(f)
	}
	return statusBody{http.StatusCreated, ojson.Object{{Key: "recorded", Value: true}, {Key: "findings", Value: out}}}, nil
}
