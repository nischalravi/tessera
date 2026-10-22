package api

import (
	"errors"
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Per-connection limits of the connector workers (issue #302): how many calls
// may be in flight to the connection's system, how fast, and when the circuit
// breaker opens. Every field is 0 = the worker's default (`tessera worker
// -target-*`). They apply per worker process. The workers re-read them every
// 30 seconds, so a change takes effect without a restart.

func (s *Server) registerConnectionLimitRoutes() {
	// The connection is named in the query (GET, DELETE) or the body (PUT), not the path: these routes
	// belong to the worker pool's queue API, not to a connection's readiness lifecycle.
	s.handle(http.MethodGet, "/api/queue/limits", read, need(auth.PermConnectionsRead), s.rd(s.getConnectionLimits))
	// Step-up like the credential: raising a limit changes the load put on a customer's system.
	s.handle(http.MethodPut, "/api/queue/limits", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.putConnectionLimits))
	s.handle(http.MethodDelete, "/api/queue/limits", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.deleteConnectionLimits))
}

type connectionLimitsView struct {
	ConnectionID        string  `json:"connection_id"`
	Set                 bool    `json:"set"` // false: every limit is the worker's default
	MaxConcurrency      int     `json:"max_concurrency"`
	RatePerMin          int     `json:"rate_per_min"`
	Burst               int     `json:"burst"`
	BreakerThreshold    int     `json:"breaker_threshold"`
	BreakerCooldownSecs int     `json:"breaker_cooldown_seconds"`
	UpdatedBy           *string `json:"updated_by"`
	UpdatedAt           *string `json:"updated_at"`
}

func viewLimits(id string, l *store.ConnectionLimits) connectionLimitsView {
	v := connectionLimitsView{ConnectionID: id}
	if l == nil {
		return v
	}
	v.Set, v.MaxConcurrency, v.RatePerMin, v.Burst = true, l.MaxConcurrency, l.RatePerMin, l.Burst
	v.BreakerThreshold, v.BreakerCooldownSecs = l.BreakerThreshold, l.BreakerCooldownSecs
	by, at := l.UpdatedBy, timeutil.ISO(l.UpdatedAt)
	v.UpdatedBy, v.UpdatedAt = &by, &at
	return v
}

type connectionLimitsInput struct {
	ConnectionID        string `json:"connection_id"`
	MaxConcurrency      int    `json:"max_concurrency"`
	RatePerMin          int    `json:"rate_per_min"`
	Burst               int    `json:"burst"`
	BreakerThreshold    int    `json:"breaker_threshold"`
	BreakerCooldownSecs int    `json:"breaker_cooldown_seconds"`
}

func (in *connectionLimitsInput) validate() error {
	switch {
	case in.MaxConcurrency < 0 || in.MaxConcurrency > 64:
		return badRequest("invalid_limit", "max_concurrency must be 0 (the default) to 64")
	case in.RatePerMin < 0 || in.RatePerMin > 60000:
		return badRequest("invalid_limit", "rate_per_min must be 0 (the default) to 60000")
	case in.Burst < 0 || in.Burst > 1000:
		return badRequest("invalid_limit", "burst must be 0 (the default) to 1000")
	case in.BreakerThreshold < 0 || in.BreakerThreshold > 100:
		return badRequest("invalid_limit", "breaker_threshold must be 0 (the default) to 100")
	case in.BreakerCooldownSecs != 0 && (in.BreakerCooldownSecs < 5 || in.BreakerCooldownSecs > 3600):
		return badRequest("invalid_limit", "breaker_cooldown_seconds must be 0 (the default) or 5 to 3600")
	}
	return nil
}

// liveConnection checks that id names a live (not retired) connection of the
// request's tenant.
func (s *Server) liveConnection(r *http.Request, id string) (string, error) {
	if !idRE.MatchString(id) {
		return "", notFoundErr("connection")
	}
	conn, err := store.TxFrom(r.Context()).Connection(id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && conn.RetiredAt != nil) {
		return "", notFoundErr("connection")
	}
	return id, err
}

func (s *Server) getConnectionLimits(r *http.Request, _ *params) (int, any, error) {
	c := store.TxFrom(r.Context())
	if r.URL.Query().Get("connection_id") == "" { // every connection that has limits set
		ls, err := c.AllConnectionLimits()
		if err != nil {
			return 0, nil, err
		}
		out := make([]connectionLimitsView, 0, len(ls))
		for _, l := range ls {
			out = append(out, viewLimits(l.ConnectionID, l))
		}
		return http.StatusOK, out, nil
	}
	id, err := s.liveConnection(r, r.URL.Query().Get("connection_id"))
	if err != nil {
		return 0, nil, err
	}
	l, err := c.ConnectionLimits(id)
	if errors.Is(err, store.ErrNotFound) {
		l, err = nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, viewLimits(id, l), nil
}

func (s *Server) putConnectionLimits(r *http.Request, _ *params) (int, any, error) {
	var in connectionLimitsInput
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	id, err := s.liveConnection(r, in.ConnectionID)
	if err != nil {
		return 0, nil, err
	}
	if err := in.validate(); err != nil {
		return 0, nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock()
	l := &store.ConnectionLimits{ConnectionID: id, MaxConcurrency: in.MaxConcurrency, RatePerMin: in.RatePerMin, Burst: in.Burst,
		BreakerThreshold: in.BreakerThreshold, BreakerCooldownSecs: in.BreakerCooldownSecs, UpdatedBy: actor(r)}
	if err := c.PutConnectionLimits(l, now); err != nil {
		return 0, nil, err
	}
	if err := c.Audit(now, actor(r), "connection.limits_set", ojson.Object{{Key: "connection_id", Value: id},
		{Key: "max_concurrency", Value: in.MaxConcurrency}, {Key: "rate_per_min", Value: in.RatePerMin},
		{Key: "burst", Value: in.Burst}, {Key: "breaker_threshold", Value: in.BreakerThreshold},
		{Key: "breaker_cooldown_seconds", Value: in.BreakerCooldownSecs}}); err != nil {
		return 0, nil, err
	}
	saved, err := c.ConnectionLimits(id)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, viewLimits(id, saved), nil
}

func (s *Server) deleteConnectionLimits(r *http.Request, _ *params) (int, any, error) {
	id, err := s.liveConnection(r, r.URL.Query().Get("connection_id"))
	if err != nil {
		return 0, nil, err
	}
	c := store.TxFrom(r.Context())
	if err := c.DeleteConnectionLimits(id); errors.Is(err, store.ErrNotFound) {
		return http.StatusOK, viewLimits(id, nil), nil // nothing was set: already the defaults
	} else if err != nil {
		return 0, nil, err
	}
	if err := c.Audit(s.clock(), actor(r), "connection.limits_cleared", ojson.Object{{Key: "connection_id", Value: id}}); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, viewLimits(id, nil), nil
}
