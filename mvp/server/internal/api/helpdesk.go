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
//	GET  /api/helpdesk/settings                               the recent authentication method rule (#477)
//	PUT  /api/helpdesk/settings                               {recent_method_days, recent_method_action} (step-up)
//	POST /api/helpdesk/risk-signals                           {identity_id, source, detail, occurred_at}: an IdP risk signal (helpdesk.risk, step-up)
//	GET  /api/helpdesk/risk-signals                           the tenant's newest risk signals (helpdesk.risk)
//	POST /api/helpdesk/risk-signals/{risk_id}/dismiss         {reason}: a different admin than the poster (helpdesk.risk, step-up)
//
// Recent authentication method rule (#477): when the identity gained an
// authentication method in the last recent_method_days (1-90, default 7), or a
// connected IdP reported a suspiciously added method, the case's policy decision
// carries recent_auth_method and, per recent_method_action, needs the second
// approver (require_approval, the default) or cannot execute (block); off
// disables the rule. A case shows the reasons; settings changes are audited.
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
	s.handle(http.MethodGet, "/api/helpdesk/settings", read, need(auth.PermGraphRead), s.getHelpdeskSettings)
	s.handle(http.MethodPut, "/api/helpdesk/settings", write, needStepUp(auth.PermHelpdeskApprove, auth.StepUpPolicy), s.putHelpdeskSettings)
	// issue #510: a signal can block account recovery for up to the rule's window, so only admins post or dismiss one
	// (operators hold helpdesk.approve, not helpdesk.risk), each with step-up
	s.handle(http.MethodPost, "/api/helpdesk/risk-signals", write, needStepUp(auth.PermHelpdeskRisk, auth.StepUpPolicy), s.ingestHelpdeskRisk)
	s.handle(http.MethodGet, "/api/helpdesk/risk-signals", read, need(auth.PermHelpdeskRisk), s.listHelpdeskRisks)
	s.handle(http.MethodPost, "/api/helpdesk/risk-signals/{risk_id}/dismiss", write,
		needStepUp(auth.PermHelpdeskRisk, auth.StepUpPolicy), s.dismissHelpdeskRisk)
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
		code := "forbidden"
		if he.Reason != "" {
			code = he.Reason
		}
		return &readiness.Error{Status: http.StatusForbidden, Code: code, Msg: he.Msg}
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

type helpdeskSettingsView struct {
	RecentMethodDays   int     `json:"recent_method_days"`
	RecentMethodAction string  `json:"recent_method_action"`
	UpdatedBy          string  `json:"updated_by"`
	UpdatedAt          *string `json:"updated_at"`
}

func viewHelpdeskSettings(h *store.HelpdeskSettings) helpdeskSettingsView {
	return helpdeskSettingsView{h.RecentMethodDays, h.RecentMethodAction, h.UpdatedBy, isoPtr(h.UpdatedAt)}
}

func (s *Server) getHelpdeskSettings(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	h, err := store.TxFrom(r.Context()).HelpdeskSettings()
	if err != nil {
		return nil, err
	}
	return viewHelpdeskSettings(h), nil
}

func (s *Server) putHelpdeskSettings(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b struct {
		Days   int    `json:"recent_method_days"`
		Action string `json:"recent_method_action"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	// Loosening the rule (a weaker action or a shorter window) undoes what risk signals and the rule protect, so it
	// needs helpdesk.risk (admins), not only helpdesk.approve (operators); tightening needs only helpdesk.approve.
	cur, err := store.TxFrom(r.Context()).HelpdeskSettings()
	if err != nil {
		return nil, err
	}
	rank := map[string]int{store.HelpdeskRecentOff: 0, store.HelpdeskRecentRequireApproval: 1, store.HelpdeskRecentBlock: 2}
	na, oa := rank[b.Action], rank[cur.RecentMethodAction]
	if _, known := rank[b.Action]; known && (na < oa || (na > 0 && b.Days > 0 && b.Days < cur.RecentMethodDays)) && !s.can(r, auth.PermHelpdeskRisk) {
		return nil, &readiness.Error{Status: http.StatusForbidden, Code: "forbidden",
			Msg: "weakening the recent method rule (a weaker action or a shorter window) needs an admin with helpdesk.risk"}
	}
	h, err := s.helpdesk.UpdateSettings(store.TxFrom(r.Context()), helpdesk.SettingsInput{Days: b.Days, Action: b.Action},
		principal(r).User(), s.clock())
	if err != nil {
		return nil, helpdeskErr(err)
	}
	return viewHelpdeskSettings(h), nil
}

func (s *Server) ingestHelpdeskRisk(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b struct {
		IdentityID int64     `json:"identity_id"`
		Source     string    `json:"source"`
		Detail     string    `json:"detail"`
		OccurredAt time.Time `json:"occurred_at"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	rk, err := s.helpdesk.IngestRisk(store.TxFrom(r.Context()), helpdesk.RiskInput{IdentityID: b.IdentityID, Source: b.Source,
		Detail: b.Detail, OccurredAt: b.OccurredAt}, principal(r).User(), s.clock())
	if err != nil {
		return nil, helpdeskErr(err)
	}
	return statusBody{http.StatusCreated, ojson.Object{{Key: "recorded", Value: true}, {Key: "id", Value: rk.ID},
		{Key: "reported_by", Value: rk.SubmittedBy}}}, nil
}

type riskView struct {
	ID            string  `json:"id"`
	IdentityID    int64   `json:"identity_id"`
	SourceLabel   string  `json:"source_label"` // typed by the poster: unverified
	Detail        string  `json:"detail"`
	OccurredAt    string  `json:"occurred_at"`
	ReportedBy    string  `json:"reported_by"` // the signed-in admin who posted it
	Dismissed     bool    `json:"dismissed"`
	DismissedAt   *string `json:"dismissed_at"`
	DismissedBy   string  `json:"dismissed_by"`
	DismissReason string  `json:"dismiss_reason"`
}

func viewRisk(r *store.HelpdeskIdPRisk) riskView {
	v := riskView{ID: r.ID, IdentityID: r.IdentityID, SourceLabel: r.Source, Detail: r.Detail, OccurredAt: rt3339(r.OccurredAt),
		ReportedBy: r.SubmittedBy, Dismissed: r.DismissedAt != nil, DismissedBy: r.DismissedBy, DismissReason: r.DismissReason}
	if r.DismissedAt != nil {
		t := rt3339(*r.DismissedAt)
		v.DismissedAt = &t
	}
	return v
}

func (s *Server) listHelpdeskRisks(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	rs, err := store.TxFrom(r.Context()).HelpdeskIdPRiskList(200)
	if err != nil {
		return nil, err
	}
	out := make([]riskView, 0, len(rs))
	for _, x := range rs {
		out = append(out, viewRisk(x))
	}
	return out, nil
}

func (s *Server) dismissHelpdeskRisk(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b struct {
		Reason string `json:"reason"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	id := p.path["risk_id"]
	if len(id) > 64 {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	rk, err := s.helpdesk.DismissRisk(store.TxFrom(r.Context()), id, b.Reason, principal(r).User(), s.clock())
	if err != nil {
		return nil, helpdeskErr(err)
	}
	return viewRisk(rk), nil
}
