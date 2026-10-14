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
	s.handle(http.MethodPut, "/api/connections/{id}/containment-credential", write,
		needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.putContainmentCredential))
}

func containmentFailed(rep *containment.Report) error {
	n := len(rep.Failed())
	msg := fmt.Sprintf("containment failed: %d step(s) failed; the identity may still have live sessions or grants", n)
	return &readiness.Error{Status: http.StatusBadGateway, Code: "containment_failed", Msg: msg,
		Extra: map[string]any{"report": rep}}
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
	err = p.scope.Write(ctx, func(c *store.TenantTx) error {
		return containment.Record(c, s.clock(), actor(r), rep)
	})
	if err != nil {
		return nil, err
	}
	if !rep.OK {
		return nil, containmentFailed(rep)
	}
	return rep, nil
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
// first, with no transaction open; the run is recorded whatever its result,
// and the event is executed only when no step failed.
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
	if job != nil {
		rep = s.runContainment(ctx, job)
		if err := p.scope.Write(ctx, func(c *store.TenantTx) error {
			return containment.Record(c, s.clock(), actor(r), rep)
		}); err != nil {
			return nil, err
		}
		if !rep.OK {
			return nil, containmentFailed(rep)
		}
	}
	var plan jml.Plan
	err = p.scope.Write(ctx, func(c *store.TenantTx) error {
		var err error
		plan, err = jml.ExecuteEvent(c, s.clock(), id, principal(r).User(), pols, rep)
		return err
	})
	var je *jml.Error
	if errors.As(err, &je) {
		return nil, errStatus(http.StatusBadRequest, je.Msg)
	}
	if err != nil {
		return nil, err
	}
	out := ojson.Object{{Key: "executed", Value: true}, {Key: "plan", Value: plan}}
	if rep != nil {
		out = append(out, ojson.KV{Key: "containment", Value: rep})
	}
	return out, nil
}
