package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/breach"
	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Vendor breach response (issue #475): when a vendor is breached, list every
// credential tied to it, rotate and contain them as one tracked plan, verify
// by re-reading, and export the evidence.
//
//	POST /api/breach/inventory                     {vendor}: every credential tied to the vendor (a dry run)
//	GET  /api/breach/plans                         the plans
//	POST /api/breach/plans                         {vendor, reason}: record a plan, one item per credential
//	GET  /api/breach/plans/{id}                    the plan, its items and the completion report
//	POST /api/breach/plans/{id}/run                queue the rotation of the vendor's secrets, revoke its OAuth
//	                                               grants, then re-read everything
//	POST /api/breach/plans/{id}/verify             re-read every open item (completes the plan when none is left)
//	POST /api/breach/plans/{id}/items/{item}/attest {note}: a person did a manual item
//	GET  /api/breach/plans/{id}/evidence           the evidence export (JSON, hashed), as a download
//
// Reading needs graph.read (the export needs audit.read). Everything that
// changes a plan needs secrets.rotate and a fresh phishing-resistant sign-in;
// revoking OAuth grants also needs oauthapps.revoke and keeps its four-eyes
// rule: a plan that revokes grants with a high-risk scope waits for a second
// admin, and the plan stays running until that admin repeats the run.
func (s *Server) registerBreachRoutes() {
	G, P := http.MethodGet, http.MethodPost
	rot := needStepUp(auth.PermSecretsRotate, auth.StepUpPolicy)
	// the inventory is computed data: recorded by its http.request event, fails closed like a read
	s.handle(P, "/api/breach/inventory", read, need(auth.PermGraphRead), s.rd(s.breachInventory)).answersRead = true
	s.handle(G, "/api/breach/plans", read, need(auth.PermGraphRead), s.rd(s.breachPlans))
	s.handle(P, "/api/breach/plans", write, rot, s.rd(s.breachCreate))
	s.handle(G, "/api/breach/plans/{id}", read, need(auth.PermGraphRead), s.rd(s.breachPlan))
	s.handle(P, "/api/breach/plans/{id}/run", phased, rot, s.breachRun)
	s.handle(P, "/api/breach/plans/{id}/verify", write, rot, s.rd(s.breachVerify))
	s.handle(P, "/api/breach/plans/{id}/items/{item}/attest", write, rot, s.rd(s.breachAttest))
	s.handle(G, "/api/breach/plans/{id}/evidence", read, need(auth.PermAuditRead), s.breachEvidence)
}

// breachErr renders a breach or rotation refusal as the readiness error shape.
func breachErr(err error) error {
	var be *breach.Error
	if errors.As(err, &be) {
		return &readiness.Error{Status: be.Status, Code: be.Code, Msg: be.Msg}
	}
	return rotErr(err)
}

func breachID(p *params, name string) (string, error) {
	id := p.path[name]
	if !idRE.MatchString(id) {
		return "", &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such breach plan or item"}
	}
	return id, nil
}

type breachInput struct {
	Vendor string `json:"vendor"`
	Reason string `json:"reason"`
	Note   string `json:"note"`
}

func (s *Server) breachInventory(r *http.Request, _ *params) (int, any, error) {
	var in breachInput
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	v, err := breach.NormalizeVendor(in.Vendor)
	if err != nil {
		return 0, nil, breachErr(err)
	}
	cands, err := s.breach.Inventory(store.TxFrom(r.Context()), v, s.clock())
	if err != nil {
		return 0, nil, breachErr(err)
	}
	return http.StatusOK, map[string]any{"vendor": v, "credentials": cands, "total": len(cands)}, nil
}

func (s *Server) breachPlans(r *http.Request, _ *params) (int, any, error) {
	out, err := s.breach.List(store.TxFrom(r.Context()))
	return http.StatusOK, map[string]any{"plans": out}, breachErr(err)
}

func (s *Server) breachCreate(r *http.Request, _ *params) (int, any, error) {
	var in breachInput
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	out, err := s.breach.Create(store.TxFrom(r.Context()), in.Vendor, in.Reason, actor(r), s.clock())
	return http.StatusCreated, out, breachErr(err)
}

func (s *Server) breachPlan(r *http.Request, p *params) (int, any, error) {
	id, err := breachID(p, "id")
	if err != nil {
		return 0, nil, err
	}
	out, err := s.breach.View(store.TxFrom(r.Context()), id, s.clock())
	return http.StatusOK, out, breachErr(err)
}

func (s *Server) breachVerify(r *http.Request, p *params) (int, any, error) {
	id, err := breachID(p, "id")
	if err != nil {
		return 0, nil, err
	}
	out, err := s.breach.Verify(store.TxFrom(r.Context()), id, actor(r), s.clock())
	return http.StatusOK, out, breachErr(err)
}

func (s *Server) breachAttest(r *http.Request, p *params) (int, any, error) {
	id, err := breachID(p, "id")
	if err != nil {
		return 0, nil, err
	}
	item, err := breachID(p, "item")
	if err != nil {
		return 0, nil, err
	}
	var in breachInput
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	out, err := s.breach.Attest(store.TxFrom(r.Context()), id, item, in.Note, actor(r), s.clock())
	return http.StatusOK, out, breachErr(err)
}

func (s *Server) breachEvidence(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := breachID(p, "id")
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	ev, err := s.breach.Evidence(tx, id, s.clock())
	if err != nil {
		return nil, breachErr(err)
	}
	raw, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return nil, err
	}
	return fileBody{contentType: "application/json", filename: breach.FileName(ev.Body.Plan.Vendor, ev.Body.Plan.ID), body: raw,
		headers: map[string]string{"X-Tessera-Evidence-SHA256": ev.SHA256}}, nil
}

// breachRun is the one tracked run. It commits in phases because revoking
// OAuth grants calls providers, which never happens inside a transaction:
// (1) start the plan and queue the rotation, (2) revoke the grants (four-eyes
// gate, provider revoke and re-read: internal/oauthapps), (3) re-read every
// item. Calling it again repeats steps 2 and 3 (the rotation is queued once).
func (s *Server) breachRun(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := breachID(p, "id")
	if err != nil {
		return nil, err
	}
	ctx, now, who := r.Context(), s.clock(), actor(r)
	var pl *store.BreachPlan
	var hasGrants bool
	if err := p.scope.Read(ctx, func(c *store.TenantTx) error {
		var err error
		if pl, err = c.BreachPlan(id); errors.Is(err, store.ErrNotFound) {
			return &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such breach plan"}
		} else if err != nil {
			return err
		}
		cands, err := s.breach.Inventory(c, pl.Vendor, now)
		for _, cd := range cands {
			hasGrants = hasGrants || cd.Kind == store.BreachKindOAuthGrant
		}
		return err
	}); err != nil {
		return nil, breachErr(err)
	}
	if hasGrants && !s.can(r, auth.PermOAuthAppsRevoke) {
		return nil, &readiness.Error{Status: http.StatusForbidden, Code: "forbidden",
			Msg: "this plan revokes OAuth grants, which needs the oauthapps.revoke permission"}
	}
	if err := p.scope.Write(ctx, func(c *store.TenantTx) error {
		_, err := s.breach.Start(c, id, who, now)
		return err
	}); err != nil {
		return nil, breachErr(err)
	}
	out := map[string]any{"oauth_revoke": "none"}
	if hasGrants {
		status, rep, err := s.breachRevokeGrants(ctx, r, p, pl, who, now)
		if err != nil {
			return nil, err
		}
		out["oauth_revoke"], out["oauth_report"] = status, rep
	}
	err = p.scope.Write(ctx, func(c *store.TenantTx) error {
		v, err := s.breach.Verify(c, id, who, s.clock())
		out["plan"] = v
		return err
	})
	if err != nil {
		return nil, breachErr(err)
	}
	return statusBody{http.StatusOK, out}, nil
}

// breachRevokeGrants revokes the vendor's live OAuth grants through the same
// plan, four-eyes gate and executor as the OAuth app revoke, and records the
// outcome on the plan's items.
func (s *Server) breachRevokeGrants(ctx context.Context, r *http.Request, p *params, pl *store.BreachPlan, who string, now time.Time) (string, *oauthapps.RevokeReport, error) {
	var plan *oauthapps.Plan
	err := p.scope.Read(ctx, func(c *store.TenantTx) error {
		var err error
		plan, err = oauthapps.BuildPlan(c, oauthapps.ScopeVendor, "", pl.Vendor, now)
		return err
	})
	switch {
	case errors.Is(err, oauthapps.ErrNotFound), errors.Is(err, oauthapps.ErrNothingToRevoke):
		return "nothing_to_revoke", nil, nil
	case err != nil:
		return "", nil, err
	}
	by := principal(r).User()
	if plan.FourEyes() && by.ID == uuid.Nil {
		return "", nil, &readiness.Error{Status: http.StatusForbidden, Code: "forbidden",
			Msg: "this revoke needs two admins; a signed-in admin user makes it"}
	}
	reason := "vendor breach response: " + pl.Reason
	var decision string
	if err := p.scope.Write(ctx, func(c *store.TenantTx) error {
		var err error
		decision, _, err = oauthapps.Gate(c, plan, by.ID, who, reason, now)
		return err
	}); err != nil {
		return "", nil, err
	}
	switch decision {
	case oauthapps.GateSameApprover:
		return "", nil, &readiness.Error{Status: http.StatusForbidden, Code: "four_eyes_required",
			Msg: "revoking these grants needs a second admin: another tenant admin must run this plan too"}
	case oauthapps.GatePending:
		return "pending_second_admin", nil, nil
	}
	ectx, cancel := context.WithTimeout(ctx, containTimeout)
	defer cancel()
	rep, err := s.oauthapps.Execute(ectx, s.store, principal(r).TenantID, plan, who, reason)
	if err != nil {
		return "", nil, err
	}
	results := map[string]breach.RevokeResult{}
	for _, it := range rep.Items {
		res := breach.RevokeResult{State: store.BreachInProgress, Detail: "revoked at the provider; awaiting the re-read"}
		switch it.Outcome {
		case oauthapps.OutcomeFailed:
			res = breach.RevokeResult{State: store.BreachFailed, Detail: it.Detail}
		case oauthapps.OutcomeManual:
			res = breach.RevokeResult{State: store.BreachPending, Detail: it.Detail}
		case oauthapps.OutcomeSkipped:
			res = breach.RevokeResult{State: store.BreachPending, Detail: it.Detail}
		}
		results[it.GrantID] = res
	}
	if err := p.scope.Write(ctx, func(c *store.TenantTx) error { return s.breach.RecordRevoke(c, pl.ID, results, s.clock()) }); err != nil {
		return "", nil, err
	}
	rep.Target = echoSafe(rep.Target)
	return "executed", rep, nil
}
