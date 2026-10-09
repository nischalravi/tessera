package api

import (
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func (s *Server) registerDryRunRoutes() {
	s.handle(http.MethodPost, "/api/connections/{id}/dry-run", s.rd(s.dryRun))
	s.handle(http.MethodGet, "/api/connections/{id}/dry-runs/{run}", s.rd(s.getDryRun))
	s.handle(http.MethodGet, "/api/connections/{id}/findings", s.rd(s.listFindings))
	s.handle(http.MethodPost, "/api/connections/{id}/findings/{fid}/accept", s.rd(s.acceptFinding))
}

func stage(c *store.Conn, runID, system string, res *connectors.DiscoveryResult) error {
	_, err := ingest.Stage(c, runID, system, res)
	return err
}

// dryRun stages a snapshot and reconciles it; it writes staging tables only.
func (s *Server) dryRun(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return 0, nil, err
	}
	v, err := s.readiness.DryRun(r.Context(), s.store, id, actor(r), s.clock, stage)
	return http.StatusAccepted, v, err
}

func (s *Server) getDryRun(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	run := p.path["run"]
	if !runIDRE.MatchString(run) {
		return 0, nil, badRequest("not_found", "no such dry run")
	}
	v, err := s.readiness.DryRunView(s.store.Read(r.Context()), id, run, s.clock())
	return http.StatusOK, v, err
}

var severityNames = map[string]bool{"": true, "critical": true, "high": true, "medium": true, "low": true, "info": true}
var findingStatuses = map[string]bool{"": true, "open": true, "accepted": true, "resolved": true}

func (s *Server) listFindings(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	q := r.URL.Query()
	f := readiness.FindingFilter{RunID: q.Get("run"), Code: q.Get("code"), Severity: q.Get("severity"), Status: q.Get("status")}
	if (f.RunID != "" && !runIDRE.MatchString(f.RunID)) || !severityNames[f.Severity] || !findingStatuses[f.Status] || len(f.Code) > 8 {
		return 0, nil, badRequest("invalid_filter", "run must be a run id, severity critical|high|medium|low|info, status open|accepted|resolved")
	}
	v, err := s.readiness.Findings(s.store.Read(r.Context()), id, f, s.clock())
	return http.StatusOK, v, err
}

func (s *Server) acceptFinding(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	fid := p.path["fid"]
	if !runIDRE.MatchString(fid) {
		return 0, nil, badRequest("not_found", "no such finding")
	}
	var in struct {
		Reason    string  `json:"reason"`
		ExpiresAt *string `json:"expires_at"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var exp *time.Time
	if in.ExpiresAt != nil {
		t, err := parseDate(*in.ExpiresAt)
		if err != nil {
			return 0, nil, badRequest("invalid_expires_at", "expires_at must be a date (YYYY-MM-DD) or an RFC 3339 time")
		}
		exp = &t
	}
	var out any
	err = s.write(r, func(c *store.Conn, now time.Time) error {
		f, err := s.readiness.AcceptFinding(c, id, fid, in.Reason, exp, actor(r), now)
		if err != nil {
			return err
		}
		out, err = readiness.FindingOf(f)
		return err
	})
	return http.StatusOK, out, err
}

// firstSync runs the normal first sync of a just-activated connection
// inside the activation transaction (§6.1): only an ActiveConnection, which
// only package readiness can construct, reaches the live graph.
func (s *Server) firstSync(_ *http.Request, c *store.Conn, ac readiness.ActiveConnection, now time.Time) error {
	if _, ok := connectors.DemoConnectorFor(ac.ConnectorType(), now); !ok {
		return c.Audit(now, "system", "connection.first_sync_skipped", ojson.Object{{Key: "connection_id", Value: ac.ConnectionID()},
			{Key: "reason", Value: "no live connector for " + ac.ConnectorType() + " yet (DR-12 to DR-18)"}})
	}
	stats, err := ingest.SyncActive(c, now, []readiness.ActiveConnection{ac}, func(a readiness.ActiveConnection) (connectors.Connector, error) {
		cn, _ := connectors.DemoConnectorFor(a.ConnectorType(), now)
		return cn, nil
	})
	if err != nil {
		return err
	}
	return c.Audit(now, "system", "connection.first_sync", ojson.Object{{Key: "connection_id", Value: ac.ConnectionID()},
		{Key: "revision_id", Value: ac.RevisionID()}, {Key: "discovery", Value: stats.Discovery.Object()}})
}
