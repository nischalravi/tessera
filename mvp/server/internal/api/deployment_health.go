package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Deployment health (design §7, §9): the tenant score, per-connection
// scores, needs-attention, skipped items, and on-demand re-runs.

func (s *Server) registerHealthRoutes() {
	s.handle(http.MethodGet, "/api/insights/deployment-health", s.rd(s.deploymentHealth))
	s.handle(http.MethodPost, "/api/insights/deployment-health/rerun", s.rd(s.rerunHealth))
	s.handle(http.MethodGet, "/api/connections/{id}/health", s.rd(s.connectionHealth))
}

// legacyHR names an env-configured HR connector that is not governed by a
// connection yet (the demo's Workday feed). It counts as the authoritative
// HR source for the tenant score until it is governed.
func (s *Server) legacyHR(c *store.Conn, now time.Time) (string, error) {
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

func (s *Server) dashboard(c *store.Conn, now time.Time) (*readiness.Dashboard, error) {
	hr, err := s.legacyHR(c, now)
	if err != nil {
		return nil, err
	}
	return s.readiness.Dashboard(c, now, hr)
}

func (s *Server) deploymentHealth(r *http.Request, _ *params) (int, any, error) {
	d, err := s.dashboard(s.store.Read(r.Context()), s.clock())
	return http.StatusOK, d, err
}

func (s *Server) connectionHealth(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	v, err := s.readiness.Health(s.store.Read(r.Context()), id, s.clock())
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
// validate or later (and, with reconcile, the dry run of those in setup).
func (s *Server) rerunHealth(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		Reconcile bool `json:"reconcile"`
	}
	if err := decodeBody(r, &in, true); err != nil {
		return 0, nil, err
	}
	conns, err := s.store.Read(r.Context()).Connections()
	if err != nil {
		return 0, nil, err
	}
	out := []rerunResult{}
	for _, conn := range conns {
		if conn.RetiredAt != nil {
			continue
		}
		res := rerunResult{ConnectionID: conn.ID, Name: conn.Name}
		v, err := s.readiness.Validate(r.Context(), s.store, conn.ID, actor(r), s.clock)
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
			dr, err := s.readiness.DryRun(r.Context(), s.store, conn.ID, actor(r), s.clock, stage)
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
	err = s.write(r, func(c *store.Conn, now time.Time) error {
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
func (s *Server) attachScore(c *store.Conn, v *readiness.ConnectionView, now time.Time) error {
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
	d, err := s.dashboard(s.store.Read(ctx), now)
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
