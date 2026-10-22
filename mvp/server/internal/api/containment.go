package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/jml"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Identity containment (issue #106), the kill switch:
//
//	POST /api/identities/{identity_id}/contain       {reason}: revoke_sessions and revoke_grants
//	PUT  /api/connections/{id}/containment-credential {token, base_url, org}
//
// Disable and Enable of a person (the Identity page and bulk actions):
//
//	POST /api/identities/{identity_id}/disable   {reason}: containment, then accounts and status set to disabled
//	POST /api/identities/{identity_id}/enable    {reason}: sets back what Disable disabled; revoked sessions stay revoked
//	GET  /api/identities/{identity_id}/disables  the Disable records, newest first, with what each changed
//
// Both need identities.contain and a fresh phishing-resistant sign-in (the
// kill switch's rules). Disable runs the kill switch's containment steps
// (phased, like contain) and then writes the local decision and its audit
// event in one transaction. A failed provider step does not stop the disable:
// it becomes a retry task and the response says containment is incomplete.
//
// Contain calls the providers, so it is a phased route: it reads, then runs
// with no transaction open, then records the run in the audit ledger (also
// when it failed). It answers 200 with the report, or 502 containment_failed
// with the same report when any step failed. The leaver plan runs the same
// steps (hrisExecute).

// containTimeout bounds the provider calls of one request (the handler
// timeout is 30s).
const containTimeout = 20 * time.Second

func (s *Server) registerContainmentRoutes() {
	s.handle(http.MethodPost, "/api/identities/{identity_id}/contain", phased,
		needStepUp(auth.PermIdentitiesContain, auth.StepUpPolicy), s.containIdentity)
	s.handle(http.MethodPost, "/api/identities/{identity_id}/disable", phased,
		needStepUp(auth.PermIdentitiesContain, auth.StepUpPolicy), s.disableIdentity)
	s.handle(http.MethodPost, "/api/identities/{identity_id}/enable", write,
		needStepUp(auth.PermIdentitiesContain, auth.StepUpPolicy), s.enableIdentity)
	s.handle(http.MethodGet, "/api/identities/{identity_id}/disables", read, need(auth.PermGraphRead), s.listDisables)
	s.handle(http.MethodGet, "/api/identities/{identity_id}/containment", read, need(auth.PermGraphRead), s.listContainment)
	s.handle(http.MethodPost, "/api/containment-retries/{retry_id}/retry-now", phased,
		needStepUp(auth.PermIdentitiesContain, auth.StepUpPolicy), s.retryNow)
	s.handle(http.MethodPut, "/api/connections/{id}/containment-credential", write,
		needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.putContainmentCredential))
}

func containmentFailed(rep *containment.Report, retries []*store.ContainmentRetry) error {
	n := len(rep.Failed())
	msg := fmt.Sprintf("containment failed: %d step(s) failed; the identity may still have live sessions or grants. "+
		"A retry is scheduled.", n)
	sum := containment.Summarize(rep, retries)
	return &readiness.Error{Status: http.StatusBadGateway, Code: "containment_failed", Msg: msg,
		Extra: map[string]any{"report": rep, "status": sum.Status, "retry_id": sum.RetryID, "retry_ids": sum.RetryIDs}}
}

func (s *Server) containIdentity(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b struct {
		Reason string `json:"reason"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	id := p.pathInt("identity_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	if err := checkReason(b.Reason); err != nil {
		return nil, err
	}
	ctx := r.Context()
	var job *containment.Job
	err := p.scope.Read(ctx, func(c *store.TenantTx) error {
		ident, err := c.Identity(id)
		if errors.Is(err, store.ErrNotFound) {
			return errStatus(http.StatusNotFound, "identity not found")
		}
		if err != nil {
			return err
		}
		specs, err := containment.Steps(c, id, false)
		if err != nil {
			return err
		}
		trigger := "manual"
		if ident.Type == "ai_agent" {
			trigger = "agent"
		}
		job, err = s.containment.BuildJob(c, id, trigger, specs)
		return err
	})
	if err != nil {
		return nil, err
	}
	// the kill switch cuts MCP tokens first and on its own: the provider calls
	// below can be slow or fail, and a live agent token must not wait for them
	if err := p.scope.Write(ctx, func(c *store.TenantTx) error {
		_, err := s.mcp.RevokeIdentity(c, id, "kill switch ("+job.Trigger+")")
		return err
	}); err != nil {
		return nil, err
	}
	// then Tessera's own sessions end, before any provider call
	if err := s.revokeLocalSessions(ctx, p, actor(r), id, job.Trigger); err != nil {
		return nil, err
	}
	rep := s.runContainment(ctx, job)
	retries, err := s.recordContainment(ctx, p, actor(r), job, rep)
	if err != nil {
		return nil, err
	}
	if !rep.OK {
		return nil, containmentFailed(rep, retries)
	}
	return rep, nil
}

// revokeLocalSessions ends the identity's Tessera sessions (and audits it) in
// one write transaction: the part of containment that needs no provider.
func (s *Server) revokeLocalSessions(ctx context.Context, p *params, by string, identityID int64, trigger string) error {
	return p.scope.Write(ctx, func(c *store.TenantTx) error {
		_, err := containment.RevokeLocal(c, s.clock(), by, identityID, trigger)
		return err
	})
}

func checkReason(reason string) error {
	if n := len(strings.TrimSpace(reason)); n < 10 || n > 500 {
		return badRequest("invalid_reason", "reason is required: 10 to 500 characters")
	}
	return nil
}

// disableView is the answer of Disable and the rows of GET .../disables.
type disableView struct {
	ID                string                   `json:"id"`
	IdentityID        int64                    `json:"identity_id"`
	Reason            string                   `json:"reason"`
	DisabledBy        string                   `json:"disabled_by"`
	DisabledAt        time.Time                `json:"disabled_at"`
	ContainmentStatus string                   `json:"containment_status"`
	Accounts          []containment.AccountRef `json:"accounts"`
	EnabledBy         *string                  `json:"enabled_by"`
	EnabledAt         *time.Time               `json:"enabled_at"`
	EnableReason      *string                  `json:"enable_reason"`
}

func viewDisable(c *store.TenantTx, d *store.IdentityDisable) (disableView, error) {
	v := disableView{ID: d.ID, IdentityID: d.IdentityID, Reason: d.Reason, DisabledBy: d.DisabledBy, DisabledAt: d.DisabledAt,
		ContainmentStatus: d.ContainmentStatus, Accounts: []containment.AccountRef{}, EnabledBy: d.EnabledBy,
		EnabledAt: d.EnabledAt, EnableReason: d.EnableReason}
	for _, id := range d.AccountIDs {
		a, err := c.Account(id)
		if err != nil {
			return v, err
		}
		v.Accounts = append(v.Accounts, containment.AccountRef{ID: a.ID, System: a.System, Username: a.Username})
	}
	return v, nil
}

// disableIdentity: containment first (no transaction open), then the local
// disable, the run record and any retry tasks in one transaction.
func (s *Server) disableIdentity(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b struct {
		Reason string `json:"reason"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	id := p.pathInt("identity_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	if err := checkReason(b.Reason); err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(b.Reason)
	ctx := r.Context()
	var job *containment.Job
	refusal := ""
	err := p.scope.Read(ctx, func(c *store.TenantTx) error {
		ident, err := c.Identity(id)
		if errors.Is(err, store.ErrNotFound) {
			return errStatus(http.StatusNotFound, "identity not found")
		}
		if err != nil {
			return err
		}
		if pr := principal(r); pr != nil && pr.UserID != nil {
			me, err := c.PlatformUser(*pr.UserID)
			if err != nil {
				return err
			}
			if refusal = containment.DisableRefusal(id, me); refusal != "" {
				return nil
			}
		}
		if ident.Status != "active" {
			return disableRefused(ident.Status)
		}
		specs, err := containment.Steps(c, id, false)
		if err != nil {
			return err
		}
		job, err = s.containment.BuildJob(c, id, "disable", specs)
		return err
	})
	if err != nil {
		return nil, err
	}
	if refusal != "" {
		// nothing changed; the refusal itself is evidence of the control (#335)
		if err := p.scope.Write(ctx, func(c *store.TenantTx) error {
			return c.Audit(s.clock(), actor(r), "identity.disable.refused", ojson.Object{{Key: "identity_id", Value: id},
				{Key: "reason", Value: refusal}})
		}); err != nil {
			return nil, err
		}
		return statusBody{http.StatusForbidden, ojson.Object{{Key: "error", Value: refusal},
			{Key: "detail", Value: "You cannot disable the identity linked to your own Tessera user; another admin must do it."}}}, nil
	}
	rep := s.runContainment(ctx, job)
	// The run is recorded first, in its own transaction, so a provider call that
	// happened is in the ledger whatever the local disable then does.
	retries, err := s.recordContainment(ctx, p, actor(r), job, rep)
	if err != nil {
		return nil, err
	}
	var res *containment.DisableResult
	err = p.scope.Write(ctx, func(c *store.TenantTx) error {
		var err error
		byUser := ""
		if pr := principal(r); pr != nil && pr.UserID != nil {
			byUser = pr.UserID.String()
		}
		res, err = containment.DisableAs(c, id, actor(r), byUser, reason, containment.Summarize(rep, retries).Status, s.clock())
		return err
	})
	switch {
	case errors.Is(err, containment.ErrNotActive), errors.Is(err, store.ErrDuplicate):
		return nil, disableRefused("not active")
	case errors.Is(err, store.ErrNotFound):
		return nil, errStatus(http.StatusNotFound, "identity not found")
	case err != nil:
		return nil, err
	}
	var v disableView
	if err := p.scope.Read(ctx, func(c *store.TenantTx) error {
		var err error
		v, err = viewDisable(c, res.Disable)
		return err
	}); err != nil {
		return nil, err
	}
	return map[string]any{"identity_id": id, "status": "disabled", "disable": v,
		"containment": containment.Summarize(rep, retries)}, nil
}

func disableRefused(status string) error {
	return errStatus(http.StatusConflict, "only an active identity can be disabled (it is "+status+")")
}

func (s *Server) enableIdentity(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b struct {
		Reason string `json:"reason"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	id := p.pathInt("identity_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	if err := checkReason(b.Reason); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	if _, err := c.Identity(id); errors.Is(err, store.ErrNotFound) {
		return nil, errStatus(http.StatusNotFound, "identity not found")
	} else if err != nil {
		return nil, err
	}
	var me *store.PlatformUser
	if pr := principal(r); pr != nil && pr.UserID != nil {
		u, err := c.PlatformUser(*pr.UserID)
		if err != nil {
			return nil, err
		}
		me = u
	}
	refusal, err := containment.EnableRefusal(c, id, me, actor(r))
	if err != nil {
		return nil, err
	}
	if refusal != "" {
		// nothing changed; the refusal itself is evidence of the control
		if err := c.Audit(s.clock(), actor(r), "identity.enable.refused", ojson.Object{{Key: "identity_id", Value: id},
			{Key: "reason", Value: refusal}}); err != nil {
			return nil, err
		}
		msg := "You cannot enable an identity linked to your own Tessera user; another admin must do it."
		if refusal == containment.RefuseFourEyes {
			msg = "This identity is linked to a Tessera user, so a second admin, not the one who disabled it, must enable it."
		}
		return statusBody{http.StatusForbidden, ojson.Object{{Key: "error", Value: refusal}, {Key: "detail", Value: msg}}}, nil
	}
	res, err := containment.Enable(c, id, actor(r), strings.TrimSpace(b.Reason), s.clock())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, errStatus(http.StatusNotFound, "identity not found")
	case errors.Is(err, containment.ErrNotDisabled):
		return nil, errStatus(http.StatusConflict, "the identity was not disabled by Tessera, so there is nothing to enable")
	case err != nil:
		return nil, err
	}
	v, err := viewDisable(c, res.Disable)
	if err != nil {
		return nil, err
	}
	open, err := openRetries(c, id)
	if err != nil {
		return nil, err
	}
	return map[string]any{"identity_id": id, "status": "active", "disable": v, "restored": res.Restored, "skipped": res.Skipped,
		"not_restored":                "Sessions, refresh tokens and OAuth grants revoked at the providers stay revoked; the person signs in and consents again.",
		"pending_containment_retries": open}, nil
}

func openRetries(c *store.TenantTx, id int64) (int, error) {
	rows, err := c.ContainmentRetriesFor(id)
	n := 0
	for _, x := range rows {
		if x.Status == store.RetryPending {
			n++
		}
	}
	return n, err
}

// GET /api/identities/{identity_id}/disables lists the identity's Disable records, newest first.
func (s *Server) listDisables(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("identity_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	if _, err := c.Identity(id); errors.Is(err, store.ErrNotFound) {
		return nil, errStatus(http.StatusNotFound, "identity not found")
	} else if err != nil {
		return nil, err
	}
	rows, err := c.IdentityDisables(id)
	if err != nil {
		return nil, err
	}
	out := make([]disableView, 0, len(rows))
	for _, d := range rows {
		v, err := viewDisable(c, d)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return map[string]any{"identity_id": id, "disables": out}, nil
}

// recordContainment audits the run and queues a retry task for each failed
// step, in one transaction (also when the run failed).
func (s *Server) recordContainment(ctx context.Context, p *params, by string, job *containment.Job, rep *containment.Report) ([]*store.ContainmentRetry, error) {
	var retries []*store.ContainmentRetry
	err := p.scope.Write(ctx, func(c *store.TenantTx) error {
		now := s.clock()
		if err := containment.Record(c, now, by, rep); err != nil {
			return err
		}
		// an agent's (or a user's) MCP tokens die with the containment, also
		// when a provider step failed
		if _, err := s.mcp.RevokeIdentity(c, rep.IdentityID, "identity contained ("+rep.Trigger+")"); err != nil {
			return err
		}
		var err error
		retries, err = containment.EnqueueRetries(c, now, job, rep)
		return err
	})
	return retries, err
}

// runContainment runs job under the containment time budget.
func (s *Server) runContainment(ctx context.Context, job *containment.Job) *containment.Report {
	ctx, cancel := context.WithTimeout(ctx, containTimeout)
	defer cancel()
	return s.containment.Run(ctx, job)
}

func (s *Server) putContainmentCredential(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	var in containment.CredentialInput
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		return s.containment.PutCredential(c, id, in, actor(r), now)
	})
	var ce *containment.Error
	if errors.As(err, &ce) {
		return 0, nil, badRequest("invalid_credential", ce.Msg)
	}
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"configured": true}, nil
}

// executeLeaver executes an HRIS event. A leaver plan's containment steps run
// first, with no transaction open; the run is recorded whatever its result.
// A failed step does not stop the leaver: it becomes a retry task and the
// response says containment is incomplete (containment.status "retrying").
func (s *Server) executeLeaver(r *http.Request, p *params, id int64) (any, error) {
	ctx := r.Context()
	var job *containment.Job
	var leaverID *int64
	err := p.scope.Read(ctx, func(c *store.TenantTx) error {
		pols, err := s.effectivePolicies(c)
		if err != nil {
			return err
		}
		ev, err := c.HrisEvent(id)
		if err != nil || ev.Type != "leaver" || ev.Status == "executed" || ev.IdentityID == nil {
			return nil // ExecuteEvent below answers as it always did
		}
		plan, err := jml.PlanForEvent(c, s.clock(), ev, false, pols)
		if err != nil {
			return nil
		}
		leaverID = ev.IdentityID
		if specs := jml.ContainmentSpecs(plan); len(specs) > 0 {
			job, err = s.containment.BuildJob(c, *ev.IdentityID, "leaver", specs)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if leaverID != nil {
		// the leaver's Tessera sessions end whether or not a provider step exists
		if err := s.revokeLocalSessions(ctx, p, actor(r), *leaverID, "leaver"); err != nil {
			return nil, err
		}
	}
	var rep *containment.Report
	var retries []*store.ContainmentRetry
	if job != nil {
		rep = s.runContainment(ctx, job)
		if retries, err = s.recordContainment(ctx, p, actor(r), job, rep); err != nil {
			return nil, err
		}
	}
	var plan jml.Plan
	var refusal any
	err = p.scope.Write(ctx, func(c *store.TenantTx) error {
		pols, err := s.effectivePolicies(c)
		if err != nil {
			return err
		}
		// read before it runs: a leaver or mover who sponsors guests sets transfer tasks going
		ev, evErr := c.HrisEvent(id)
		plan, err = jml.ExecuteEvent(c, s.clock(), id, principal(r).User(), pols, jml.WithRotator(s.rotation))
		var ex *jml.ExistsError
		if errors.As(err, &ex) {
			// ExecuteEvent wrote nothing before refusing; commit so the refusal is audited.
			refusal, err = s.joinerRefused(c, "execute", &id, ex, principal(r).User())
		} else if err == nil && evErr == nil && ev.IdentityID != nil {
			_, err = s.guestLife.OnEvent(c, ev.Type, *ev.IdentityID, s.clock().UTC())
		}
		return err
	})
	if refusal != nil && err == nil {
		return refusal, nil
	}
	var je *jml.Error
	switch {
	case errors.Is(err, jml.ErrEventNotFound):
		return nil, errStatus(http.StatusNotFound, err.Error())
	case errors.Is(err, jml.ErrEventExecuted):
		return nil, errStatus(http.StatusConflict, err.Error())
	case errors.As(err, &je):
		return nil, errStatus(http.StatusBadRequest, je.Msg)
	}
	if err != nil {
		return nil, err
	}
	out := ojson.Object{{Key: "executed", Value: true}, {Key: "plan", Value: plan}}
	if rep != nil {
		out = append(out, ojson.KV{Key: "containment", Value: containment.Summarize(rep, retries)})
	}
	return out, nil
}

// GET /api/identities/{identity_id}/containment lists the identity's containment
// retry tasks (pending, succeeded, gave_up), oldest first.
func (s *Server) listContainment(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("identity_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	if _, err := c.Identity(id); errors.Is(err, store.ErrNotFound) {
		return nil, errStatus(http.StatusNotFound, "identity not found")
	} else if err != nil {
		return nil, err
	}
	rows, err := c.ContainmentRetriesFor(id)
	if err != nil {
		return nil, err
	}
	out := make([]containment.RetryView, len(rows))
	for i, x := range rows {
		out[i] = containment.ViewRetry(x)
	}
	return ojson.Object{{Key: "identity_id", Value: id}, {Key: "retries", Value: out}}, nil
}

// POST /api/containment-retries/{retry_id}/retry-now runs one pending retry
// task now (provider calls, then re-read) and answers with its new state.
func (s *Server) retryNow(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.path["retry_id"]
	if !idRE.MatchString(id) {
		return nil, errStatus(http.StatusNotFound, "retry not found")
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return nil, err
	}
	rows, err := s.containment.RunRetries(r.Context(), s.store, p.scope.Tenant, actor(r), id)
	var ce *containment.Error
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, errStatus(http.StatusNotFound, "retry not found")
	case errors.As(err, &ce):
		return nil, errStatus(http.StatusConflict, ce.Msg)
	case err != nil:
		return nil, err
	}
	return ojson.Object{{Key: "retry", Value: containment.ViewRetry(rows[0])}}, nil
}
