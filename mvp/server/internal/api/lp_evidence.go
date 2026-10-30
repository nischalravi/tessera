package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/lp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Evidence and metrics of the least-privilege loop (issue #666, LP-10; design docs/design/least-privilege-loop.md
// section 7). The evidence is computed from the loop's own rows (internal/lp, evidence.go) and is also a file of the
// evidence packs (least_privilege_revocations.csv).
//
//	GET /api/lp/evidence?from=&to=&limit=       the evidence records of the revocations carried out in [from, to)
//	                                            (default: the last 60 days; dates or datetimes; a date-only `to` is
//	                                            inclusive); audit.read, as the evidence packs are
//	GET /api/lp/revocations/{id}/evidence       one record
//	GET /api/lp/metrics?days=                   unused permissions removed, restore and false-positive rate per
//	                                            confidence level, median restore latency, auto against staged counts
//	                                            (default 60 days, 1 to 365); graph.read, as the calibration is

func (s *Server) registerLPEvidenceRoutes() {
	G := http.MethodGet
	s.handle(G, "/api/lp/evidence", read, need(auth.PermAuditRead), s.rd(s.lpEvidenceList))
	s.handle(G, "/api/lp/revocations/{id}/evidence", read, need(auth.PermAuditRead), s.rd(s.lpEvidenceGet))
	s.handle(G, "/api/lp/metrics", read, need(auth.PermGraphRead), s.rd(s.lpMetrics))
}

func (s *Server) lpEvidenceList(r *http.Request, _ *params) (int, any, error) {
	q := r.URL.Query()
	now := s.clock()
	to, from := now.Add(time.Microsecond), now.AddDate(0, 0, -lp.CalibrationDays)
	if v := q.Get("to"); v != "" {
		t, dateOnly, err := parseWhen(v)
		if err != nil {
			return 0, nil, badRequest("invalid_to", "to must be a date (YYYY-MM-DD) or an ISO-8601 datetime")
		}
		if dateOnly {
			t = t.AddDate(0, 0, 1)
		}
		to = t
	}
	if v := q.Get("from"); v != "" {
		t, _, err := parseWhen(v)
		if err != nil {
			return 0, nil, badRequest("invalid_from", "from must be a date (YYYY-MM-DD) or an ISO-8601 datetime")
		}
		from = t
	} else if q.Get("to") != "" {
		from = to.AddDate(0, 0, -lp.CalibrationDays)
	}
	if !from.Before(to) {
		return 0, nil, badRequest("invalid_period", "from must be before to")
	}
	if to.Sub(from) > maxPackDays*24*time.Hour {
		return 0, nil, badRequest("period_too_long", "the period is at most "+strconv.Itoa(maxPackDays)+" days")
	}
	limit := store.LPEvidenceMaxRows
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > store.LPEvidenceMaxRows {
			return 0, nil, badRequest("invalid_limit", "limit must be 1 to "+strconv.Itoa(store.LPEvidenceMaxRows))
		}
		limit = n
	}
	items, err := lp.EvidenceBetween(store.TxFrom(r.Context()), from, to, limit)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"schema": lp.EvidenceSchema, "from": store.RT(from), "to": store.RT(to), "items": items}, nil
}

func (s *Server) lpEvidenceGet(r *http.Request, p *params) (int, any, error) {
	tx := store.TxFrom(r.Context())
	x, err := lpLoad(tx, p.path["id"])
	if err != nil {
		return 0, nil, err
	}
	e, err := lp.BuildEvidence(tx, x)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, e, nil
}

func (s *Server) lpMetrics(r *http.Request, _ *params) (int, any, error) {
	days := lp.CalibrationDays
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 365 {
			return 0, nil, badRequest("invalid_days", "days must be 1 to 365")
		}
		days = n
	}
	m, err := lp.MetricsFor(store.TxFrom(r.Context()), s.clock(), days)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"metrics": m, "high_threshold_percent": lp.HighFalsePositivePercent}, nil
}
