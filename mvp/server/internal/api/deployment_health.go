package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Deployment health (design §7, §9): the tenant score, per-connection
// scores, needs-attention, skipped items, and on-demand re-runs.

func (s *Server) registerHealthRoutes() {
	s.handle(http.MethodGet, "/api/insights/deployment-health", read, need(auth.PermConnectionsRead), s.rd(s.deploymentHealth))
	s.handle(http.MethodPost, "/api/insights/deployment-health/rerun", phased, need(auth.PermConnectionsManage), s.rd(s.rerunHealth)).asJob(jobs.HealthRerun, "")
	s.handle(http.MethodGet, "/api/connections/{id}/health", read, need(auth.PermConnectionsRead), s.rd(s.connectionHealth))
	// Evidence exports (design §7.6). They are GETs on a write transaction:
	// the readiness.evidence.exported event is appended in the transaction
	// that builds the file. The design asks for connections.read plus
	// audit.export; audit.export does not exist, so the handler also
	// requires audit.read, the permission of the ledger export.
	s.handle(http.MethodGet, "/api/connections/{id}/readiness/evidence", write, need(auth.PermConnectionsRead), s.exportConnectionEvidence)
	s.handle(http.MethodGet, "/api/insights/deployment-health/evidence", write, need(auth.PermConnectionsRead), s.exportTenantEvidence)
}

// requireAuditRead is the second permission of the evidence routes.
func requireAuditRead(r *http.Request) error {
	if p, ok := auth.PrincipalFrom(r.Context()); ok && auth.EffectivePermissions(p).Has(auth.PermAuditRead) {
		return nil
	}
	return &readiness.Error{Status: http.StatusForbidden, Code: "forbidden",
		Msg: "the evidence export needs the " + string(auth.PermAuditRead) + " permission"}
}

func (s *Server) exportConnectionEvidence(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := connID(p)
	if err != nil {
		return nil, err
	}
	if err := requireAuditRead(r); err != nil {
		return nil, err
	}
	ex, err := s.readiness.EvidenceOf(store.TxFrom(r.Context()), id, actor(r), s.clock(), nil)
	if err != nil {
		return nil, err
	}
	return fileBody{contentType: "application/zip", filename: ex.Filename, body: ex.Zip}, nil
}

func (s *Server) exportTenantEvidence(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	if err := requireAuditRead(r); err != nil {
		return nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock()
	d, err := s.dashboard(c, now)
	if err != nil {
		return nil, err
	}
	ex, err := s.readiness.EvidenceOf(c, "", actor(r), now, d)
	if err != nil {
		return nil, err
	}
	return fileBody{contentType: "application/zip", filename: ex.Filename, body: ex.Zip}, nil
}

// legacyHR names an env-configured HR connector that is not governed by a
// connection yet (the demo's Workday feed). It counts as the authoritative
// HR source for the tenant score until it is governed.
func (s *Server) legacyHR(c *store.TenantTx, now time.Time) (string, error) {
	legacy, err := s.cfg.Connectors(now)
	if err != nil {
		return "", err
	}
	conns, err := c.Connections()
	if err != nil {
		return "", err
	}
	for _, l := range legacy {
		if l.System() != "workday" {
			continue
		}
		governed := false
		for _, cn := range conns {
			if cn.System == l.System() && cn.RetiredAt == nil {
				governed = true
			}
		}
		if !governed {
			return l.DisplayName(), nil
		}
	}
	return "", nil
}

func (s *Server) dashboard(c *store.TenantTx, now time.Time) (*readiness.Dashboard, error) {
	hr, err := s.legacyHR(c, now)
	if err != nil {
		return nil, err
	}
	d, err := s.readiness.Dashboard(c, now, hr)
	if err != nil {
		return nil, err
	}
	if d.AWSShadow, err = readiness.ShadowAgreementOf(c, now); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *Server) deploymentHealth(r *http.Request, _ *params) (int, any, error) {
	d, err := s.dashboard(store.TxFrom(r.Context()), s.clock())
	return http.StatusOK, d, err
}

func (s *Server) connectionHealth(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	v, err := s.readiness.Health(store.TxFrom(r.Context()), id, s.clock())
	return http.StatusOK, v, err
}

type rerunResult struct {
	ConnectionID string  `json:"connection_id"`
	Name         string  `json:"name"`
	ValidationID *string `json:"validation_run_id"`
	DryRunID     *string `json:"dry_run_id"`
	Skipped      string  `json:"skipped,omitempty"`
	Error        string  `json:"error,omitempty"`
}

// rerunHealth re-runs the live checks of every connection that is ready to
// validate or later (and, with reconcile, the dry run of those in setup). It
// is a phased route: each run commits in its own transactions of the
// request's tenant (p.scope).
func (s *Server) rerunHealth(r *http.Request, p *params) (int, any, error) {
	var in struct {
		Reconcile bool `json:"reconcile"`
	}
	if err := decodeBody(r, &in, true); err != nil {
		return 0, nil, err
	}
	var conns []*store.Connection
	if err := p.scope.Read(r.Context(), func(c *store.TenantTx) error {
		var err error
		conns, err = c.Connections()
		return err
	}); err != nil {
		return 0, nil, err
	}
	out := []rerunResult{}
	for _, conn := range conns {
		if conn.RetiredAt != nil {
			continue
		}
		res := rerunResult{ConnectionID: conn.ID, Name: conn.Name}
		v, err := s.readiness.Validate(r.Context(), p.scope, conn.ID, actor(r), s.clock)
		var re *readiness.Error
		switch {
		case errors.As(err, &re):
			res.Skipped = re.Code
		case err != nil:
			return 0, nil, err
		default:
			res.ValidationID = &v.ID
		}
		if in.Reconcile && err == nil {
			dr, err := s.readiness.DryRun(r.Context(), p.scope, conn.ID, actor(r), s.clock, stage)
			switch {
			case errors.As(err, &re):
				if res.Skipped == "" {
					res.Skipped = re.Code
				}
			case err != nil:
				return 0, nil, err
			default:
				res.DryRunID = &dr.ID
			}
		}
		out = append(out, res)
	}
	var d *readiness.Dashboard
	err := p.scope.Write(r.Context(), func(c *store.TenantTx) error {
		now := s.clock()
		var err error
		if d, err = s.dashboard(c, now); err != nil {
			return err
		}
		if d.Tenant.Score != nil {
			raw, err := json.Marshal(d.Tenant)
			if err != nil {
				return err
			}
			if err := c.RecordScore(&store.ScoreRow{Scope: "tenant", ComputedAt: now, Score: *d.Tenant.Score,
				Band: d.Tenant.Band, Breakdown: string(raw)}); err != nil {
				return err
			}
		}
		return c.Audit(now, actor(r), "readiness.rerun", ojson.Object{{Key: "connections", Value: len(out)},
			{Key: "reconcile", Value: in.Reconcile}})
	})
	return http.StatusOK, map[string]any{"results": out, "dashboard": d}, err
}

// attachScore adds the connection readiness score to a connection view.
func (s *Server) attachScore(c *store.TenantTx, v *readiness.ConnectionView, now time.Time) error {
	h, err := s.readiness.Health(c, v.ID, now)
	if err != nil {
		var re *readiness.Error
		if errors.As(err, &re) {
			return nil
		}
		return err
	}
	v.Score = &readiness.ScoreSummary{Score: h.Breakdown.Score, Band: h.Breakdown.Band}
	return nil
}

// readinessSummary is the /api/summary?include=readiness block for the Home card.
func (s *Server) readinessSummary(ctx context.Context, now time.Time) (ojson.Object, error) {
	d, err := s.dashboard(store.TxFrom(ctx), now)
	if err != nil {
		return nil, err
	}
	top := d.NeedsAttention
	if len(top) > 3 {
		top = top[:3]
	}
	var score any
	if d.Tenant.Score != nil {
		score = *d.Tenant.Score
	}
	return ojson.Object{{Key: "score", Value: score}, {Key: "band", Value: d.Tenant.Band},
		{Key: "needs_attention", Value: len(d.NeedsAttention)}, {Key: "draft", Value: d.KPIs["connections_in_setup"]},
		{Key: "degraded", Value: d.KPIs["degraded"]}, {Key: "connections", Value: len(d.Connections)},
		{Key: "top", Value: top}}, nil
}
