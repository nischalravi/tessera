package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The rate limit of one machine client (issue #587, clientlimit.go).
//
//	GET    /api/admin/api-clients/{client_id}/rate-limit   admin.read: the limit in force and where it comes from
//	PUT    /api/admin/api-clients/{client_id}/rate-limit   {burst, per_minute}: the client's own limit (step-up)
//	DELETE /api/admin/api-clients/{client_id}/rate-limit   back to the tenant default (step-up)
//
// Changing a limit needs admin.change.request and step-up like the other client changes, and writes its audit event
// in the same transaction. A limit takes effect within 30 seconds (the overrides are cached that long per process).
func (s *Server) registerClientLimitRoutes() {
	change := needStepUp(auth.PermAdminChangeReq, auth.StepUpAdmin)
	s.handle(http.MethodGet, "/api/admin/api-clients/{client_id}/rate-limit", read, need(auth.PermAdminRead), s.adminGetClientLimit)
	s.handle(http.MethodPut, "/api/admin/api-clients/{client_id}/rate-limit", write, change, s.adminSetClientLimit)
	s.handle(http.MethodDelete, "/api/admin/api-clients/{client_id}/rate-limit", write, change, s.adminClearClientLimit)
}

const (
	maxClientBurst     = 100000
	maxClientPerMinute = 600000
)

func (s *Server) clientLimitView(clientID string, o *store.APIClientLimit) ojson.Object {
	cfg, source := s.clientLimits.def, "default"
	if o != nil {
		cfg, source = ClientRate{o.Burst, o.PerMinute}, "client"
	}
	return ojson.Object{{Key: "client_id", Value: clientID}, {Key: "burst", Value: cfg.Burst},
		{Key: "per_minute", Value: cfg.PerMinute}, {Key: "source", Value: source}, {Key: "enabled", Value: s.clientLimits.def.PerMinute > 0}}
}

func (s *Server) adminGetClientLimit(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	c, err := machineClientOf(r, p)
	if err != nil {
		return nil, err
	}
	o, err := store.TxFrom(r.Context()).APIClientLimit(c.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return s.clientLimitView(c.ClientID, nil), nil
	}
	if err != nil {
		return nil, err
	}
	return s.clientLimitView(c.ClientID, o), nil
}

type clientLimitBody struct {
	Burst     int `json:"burst"`
	PerMinute int `json:"per_minute"`
}

func (s *Server) adminSetClientLimit(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errBodyTooLarge
		}
		return nil, errBodyUnreadable
	}
	var b clientLimitBody
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || dec.More() {
		return nil, badRequest("invalid_body", "the body must be a JSON object {burst, per_minute} of integers")
	}
	if b.Burst < 1 || b.Burst > maxClientBurst || b.PerMinute < 1 || b.PerMinute > maxClientPerMinute {
		return nil, badRequest("invalid_limit", "burst must be 1 to 100000 and per_minute 1 to 600000")
	}
	c, err := machineClientOf(r, p)
	if err != nil {
		return nil, err
	}
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	if err := tx.SetAPIClientLimit(c.ClientID, b.Burst, b.PerMinute, now); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, actor(r), "oauth.client.rate_limit.set", ojson.Object{{Key: "client_id", Value: c.ClientID},
		{Key: "burst", Value: b.Burst}, {Key: "per_minute", Value: b.PerMinute}}); err != nil {
		return nil, err
	}
	s.clientLimits.forget(bucketKey{principal(r).TenantID, c.ClientID})
	return s.clientLimitView(c.ClientID, &store.APIClientLimit{ClientID: c.ClientID, Burst: b.Burst, PerMinute: b.PerMinute, UpdatedAt: now}), nil
}

func (s *Server) adminClearClientLimit(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	c, err := machineClientOf(r, p)
	if err != nil {
		return nil, err
	}
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	if err := tx.ClearAPIClientLimit(c.ClientID); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, actor(r), "oauth.client.rate_limit.cleared", ojson.Object{{Key: "client_id", Value: c.ClientID}}); err != nil {
		return nil, err
	}
	s.clientLimits.forget(bucketKey{principal(r).TenantID, c.ClientID})
	return s.clientLimitView(c.ClientID, nil), nil
}
