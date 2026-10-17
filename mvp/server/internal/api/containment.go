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
	if n := len(strings.TrimSpace(b.Reason)); n < 10 || n > 500 {
		return nil, badRequest("invalid_reason", "reason is required: 10 to 500 characters")
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

// recordContainment audits the run and queues a retry task for each failed
// step, in one transaction (also when the run failed).
func (s *Server) recordContainment(ctx context.Context, p *params, by string, job *containment.Job, rep *containment.Report) ([]*store.ContainmentRetry, error) {
	var retries []*store.ContainmentRetry
	err := p.scope.Write(ctx, func(c *store.TenantTx) error {
		now := s.clock()
		if err := containment.Record(c, now, by, rep); err != nil {
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
	pols, err := s.policies()
	if err != nil {
		return nil, err
	}
	var job *containment.Job
	err = p.scope.Read(ctx, func(c *store.TenantTx) error {
		ev, err := c.HrisEvent(id)
		if err != nil || ev.Type != "leaver" || ev.Status == "executed" || ev.IdentityID == nil {
			return nil // ExecuteEvent below answers as it always did
		}
		plan, err := jml.PlanForEvent(c, s.clock(), ev, false, pols)
		if err != nil {
			return nil
		}
		if specs := jml.ContainmentSpecs(plan); len(specs) > 0 {
			job, err = s.containment.BuildJob(c, *ev.IdentityID, "leaver", specs)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
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
		var err error
		plan, err = jml.ExecuteEvent(c, s.clock(), id, principal(r).User(), pols)
		var ex *jml.ExistsError
		if errors.As(err, &ex) {
			// ExecuteEvent wrote nothing before refusing; commit so the refusal is audited.
			refusal, err = s.joinerRefused(c, "execute", &id, ex, principal(r).User())
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
