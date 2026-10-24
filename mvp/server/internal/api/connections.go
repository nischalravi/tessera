package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Deployment-readiness routes (design §9). They are new API surface, so
// they use plain JSON errors ({"error": code, "detail": msg}) and, for a
// refused transition, the gate report, instead of the FastAPI-compatible
// shapes the parity-tested routes keep.

// Every route except the OpenAPI document is tenant-scoped: it runs inside a
// transaction of the request's tenant (read or write) and reaches it with
// store.TxFrom, or, for the phased validation and dry-run routes, opens
// transactions of that tenant through p.scope.
func (s *Server) registerReadinessRoutes() {
	G, P := http.MethodGet, http.MethodPost
	s.handle(G, "/api/readiness/templates", read, need(auth.PermConnectionsRead), s.rd(s.listTemplates))
	s.handle(G, "/api/readiness/templates/{type}", read, need(auth.PermConnectionsRead), s.rd(s.getTemplate))
	s.handle(G, "/api/scim/presets", read, need(auth.PermConnectionsRead), s.rd(s.listSCIMPresets))
	s.handle(http.MethodPut, "/api/readiness/overlays/{type}", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.putOverlay))
	s.handle(G, "/api/readiness/openapi.json", noTenant, need(auth.PermAuthenticated), s.readinessOpenAPI)
	s.handle(G, "/api/connections", read, need(auth.PermConnectionsRead), s.rd(s.listConnections))
	s.handle(P, "/api/connections", write, need(auth.PermConnectionsManage), s.rd(s.createConnection))
	s.handle(G, "/api/connections/{id}", read, need(auth.PermConnectionsRead), s.rd(s.getConnection))
	// Step-up like the credential: a config edit can point the revision's
	// credential at another host (host, base_url, org_url, tenant_host, ...)
	// or widen write_mode/write_scope.
	s.handle(http.MethodPatch, "/api/connections/{id}/config", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.patchConfig))
	s.handle(http.MethodPut, "/api/connections/{id}/credential", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.putCredential))
	s.handle(G, "/api/connections/{id}/checklist", read, need(auth.PermConnectionsRead), s.rd(s.getChecklist))
	s.handle(P, "/api/connections/{id}/checklist/{item}/attest", write, need(auth.PermConnectionsManage), s.rd(s.attestItem))
	// Step-up like the other attestations that gate activation by a person's word
	// for a system that cannot be checked.
	s.handle(P, "/api/connections/{id}/checklist/{item}/attest-instead", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.attestInstead))
	s.handle(P, "/api/connections/{id}/checklist/{item}/skip", write, need(auth.PermConnectionsManage), s.rd(s.skipItem))
	s.handle(http.MethodDelete, "/api/connections/{id}/checklist/{item}/skip", write, need(auth.PermConnectionsManage), s.rd(s.unskipItem))
	s.handle(P, "/api/connections/{id}/transition", write, need(auth.PermConnectionsManage), s.rd(s.transition))
	s.handle(P, "/api/connections/{id}/activate", write, needStepUp(auth.PermConnectionsActivate, auth.StepUpPolicy), s.rd(s.activate))
	s.handle(P, "/api/connections/{id}/retire", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.retire))
	s.registerActivationRoutes()
	s.registerValidationRoutes()
	s.registerDryRunRoutes()
	s.registerHealthRoutes()
	s.registerMFARoutes()
}

// rdFunc is a readiness handler: it returns the status and body to send.
type rdFunc func(r *http.Request, p *params) (int, any, error)

// rd adapts a readiness handler. An error (including a *readiness.Error,
// which writeError renders as JSON) rolls the tenant transaction back; the
// body is written only after the transaction commits.
func (s *Server) rd(fn rdFunc) handlerFunc {
	return func(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
		status, body, err := fn(r, p)
		if err != nil {
			return nil, err
		}
		return statusBody{status, body}, nil
	}
}

func readinessErrorBody(e *readiness.Error) any {
	if e.Report != nil {
		return e.Report
	}
	body := map[string]any{"error": e.Code, "detail": e.Msg}
	if len(e.Fields) > 0 {
		body["fields"] = e.Fields
	}
	for k, v := range e.Extra {
		body[k] = v
	}
	return body
}

func badRequest(code, msg string) error {
	return &readiness.Error{Status: http.StatusUnprocessableEntity, Code: code, Msg: msg}
}

// decodeBody strictly decodes a JSON object body (unknown fields rejected).
// An empty body decodes to the zero value when allowEmpty is set.
func decodeBody(r *http.Request, v any, allowEmpty bool) error {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return errBodyTooLarge
		}
		return errBodyUnreadable
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		if allowEmpty {
			return nil
		}
		return badRequest("invalid_body", "a JSON body is required")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badRequest("invalid_body", err.Error())
	}
	if dec.More() {
		return badRequest("invalid_body", "trailing data after the JSON body")
	}
	return nil
}

// actor is the name readiness records (attested_by, skipped_by, ...): the
// authenticated principal's display name. The former X-Tessera-User header
// is no longer read: the actor comes only from the session (design §16.2).
func actor(r *http.Request) string { return principal(r).Display }

var idRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// connID validates the {id} path segment.
func connID(p *params) (string, error) {
	id := p.path["id"]
	if !idRE.MatchString(id) {
		return "", &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such connection"}
	}
	return id, nil
}

var itemRE = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)

func itemID(p *params) (string, error) {
	id := p.path["item"]
	if !itemRE.MatchString(id) {
		return "", &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such checklist item"}
	}
	return id, nil
}

// write runs fn in the request's tenant transaction (a write route).
func (s *Server) write(r *http.Request, fn func(c *store.TenantTx, now time.Time) error) error {
	return fn(store.TxFrom(r.Context()), s.clock())
}

// ---------------------------------------------------------------- templates

type templateSummary struct {
	ID             string   `json:"id"`
	Version        string   `json:"version"`
	DisplayName    string   `json:"display_name"`
	ConnectorTypes []string `json:"connector_types"`
	Role           string   `json:"role"`
	OverlayVersion int      `json:"overlay_version"`
	Items          int      `json:"items"`
	Required       int      `json:"required"`
	Recommended    int      `json:"recommended"`
	Optional       int      `json:"optional"`
}

func (s *Server) listTemplates(r *http.Request, _ *params) (int, any, error) {
	c := store.TxFrom(r.Context())
	out := []templateSummary{}
	for _, id := range s.readiness.Templates.IDs() {
		t, err := s.readiness.TemplateForTenant(c, id)
		if err != nil {
			return 0, nil, err
		}
		n := t.Count()
		out = append(out, templateSummary{ID: t.ID, Version: t.Version, DisplayName: t.DisplayName,
			ConnectorTypes: t.ConnectorTypes, Role: t.Role, OverlayVersion: t.OverlayVersion, Items: n.Items,
			Required: n.Required, Recommended: n.Recommended, Optional: n.Optional})
	}
	return http.StatusOK, out, nil
}

func (s *Server) getTemplate(r *http.Request, p *params) (int, any, error) {
	t, err := s.readiness.TemplateForTenant(store.TxFrom(r.Context()), p.path["type"])
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, t, nil
}

func (s *Server) putOverlay(r *http.Request, p *params) (int, any, error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return 0, nil, errBodyUnreadable
	}
	var out any
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		t, err := s.readiness.PutOverlay(c, p.path["type"], raw, actor(r), now)
		out = t
		return err
	})
	return http.StatusOK, out, err
}

// ---------------------------------------------------------------- connections

// legacyConnection describes an env-configured (TESSERA_CONNECTORS) demo
// connector: it syncs as before and is not governed by the checklist.
type legacyConnection struct {
	Legacy        bool   `json:"legacy"`
	System        string `json:"system"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	State         string `json:"state"`
	GovernedByID  any    `json:"governed_by"`
	ConnectorType string `json:"connector_type"`
}

func (s *Server) listConnections(r *http.Request, _ *params) (int, any, error) {
	c := store.TxFrom(r.Context())
	now := s.clock()
	conns, err := c.Connections()
	if err != nil {
		return 0, nil, err
	}
	out := []any{}
	governed := map[string]string{}
	for _, conn := range conns {
		v, _, err := s.readiness.View(c, conn.ID, now)
		if err != nil {
			return 0, nil, err
		}
		if err := s.attachScore(c, v, now); err != nil {
			return 0, nil, err
		}
		out = append(out, v)
		if conn.RetiredAt == nil {
			governed[conn.System] = conn.ID
		}
	}
	legacy, err := s.cfg.Connectors(now)
	if err != nil {
		return 0, nil, err
	}
	for _, l := range legacy {
		var by any
		if id, ok := governed[l.System()]; ok {
			by = id
		}
		out = append(out, legacyConnection{Legacy: true, System: l.System(), Name: l.DisplayName(), Type: l.TypeName(),
			State: "legacy", GovernedByID: by, ConnectorType: "legacy"})
	}
	return http.StatusOK, out, nil
}

func (s *Server) connectionView(c *store.TenantTx, id string, now time.Time) (*readiness.ConnectionView, error) {
	v, _, err := s.readiness.View(c, id, now)
	if err != nil {
		return nil, err
	}
	return v, s.attachScore(c, v, now)
}

func (s *Server) createConnection(r *http.Request, _ *params) (int, any, error) {
	var in readiness.CreateInput
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out any
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		b, err := s.readiness.Create(c, in, actor(r), now)
		if err != nil {
			return err
		}
		out, err = s.connectionView(c, b.Conn.ID, now)
		return err
	})
	return http.StatusCreated, out, err
}

func (s *Server) getConnection(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	v, err := s.connectionView(store.TxFrom(r.Context()), id, s.clock())
	return http.StatusOK, v, err
}

func (s *Server) patchConfig(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return 0, nil, errBodyUnreadable
	}
	var out map[string]any
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		res, err := s.readiness.PatchConfig(c, id, raw, actor(r), now)
		if err != nil {
			return err
		}
		v, err := s.connectionView(c, id, now)
		inv := res.Invalidated
		if inv == nil {
			inv = []string{}
		}
		out = map[string]any{"connection": v, "new_revision": res.NewRevision, "invalidated": inv,
			"fields": readiness.ValidateConn(res.Bundle.Config, res.Bundle.Template, res.Bundle.Conn.ConnectorType)}
		return err
	})
	return http.StatusOK, out, err
}

func (s *Server) putCredential(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	var in readiness.CredentialInput
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out any
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		b, err := s.readiness.SetCredential(c, id, in, actor(r), now)
		if err != nil {
			return err
		}
		out = readiness.RevisionOf(b).Credential
		return nil
	})
	return http.StatusOK, out, err
}

func (s *Server) getChecklist(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	now := s.clock()
	b, err := s.readiness.Current(store.TxFrom(r.Context()), id, now)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, readiness.Checklist(b, now), nil
}

// checklistAfter runs a checklist mutation and returns the new checklist.
func (s *Server) checklistAfter(r *http.Request, p *params, fn func(c *store.TenantTx, id, item string, now time.Time) (*readiness.Bundle, error)) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	item, err := itemID(p)
	if err != nil {
		return 0, nil, err
	}
	var out any
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		b, err := fn(c, id, item, now)
		if err != nil {
			return err
		}
		out = readiness.Checklist(b, now)
		return nil
	})
	return http.StatusOK, out, err
}

func (s *Server) attestItem(r *http.Request, p *params) (int, any, error) {
	var in struct {
		Note string `json:"note"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	return s.checklistAfter(r, p, func(c *store.TenantTx, id, item string, now time.Time) (*readiness.Bundle, error) {
		byUser := ""
		if pr := principal(r); pr != nil && pr.UserID != nil {
			byUser = pr.UserID.String()
		}
		return s.readiness.AttestAs(c, id, item, in.Note, actor(r), byUser, now)
	})
}

func (s *Server) attestInstead(r *http.Request, p *params) (int, any, error) {
	var in struct {
		Attester string `json:"attester"`
		Reason   string `json:"reason"`
		Evidence string `json:"evidence"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	return s.checklistAfter(r, p, func(c *store.TenantTx, id, item string, now time.Time) (*readiness.Bundle, error) {
		return s.readiness.AttestInstead(c, id, item, readiness.LiveAttestInput{Attester: in.Attester, Reason: in.Reason,
			Evidence: in.Evidence}, actor(r), now)
	})
}

func (s *Server) skipItem(r *http.Request, p *params) (int, any, error) {
	var in struct {
		Reason   string  `json:"reason"`
		ReviewBy *string `json:"review_by"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var review *time.Time
	if in.ReviewBy != nil {
		t, err := parseDate(*in.ReviewBy)
		if err != nil {
			return 0, nil, badRequest("invalid_review_by", "review_by must be a date (YYYY-MM-DD) or an RFC 3339 time")
		}
		review = &t
	}
	return s.checklistAfter(r, p, func(c *store.TenantTx, id, item string, now time.Time) (*readiness.Bundle, error) {
		return s.readiness.Skip(c, id, item, in.Reason, review, actor(r), now)
	})
}

func parseDate(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse("2006-01-02", v)
	return t.Add(24*time.Hour - time.Second), err // end of the day
}

func (s *Server) unskipItem(r *http.Request, p *params) (int, any, error) {
	return s.checklistAfter(r, p, func(c *store.TenantTx, id, item string, now time.Time) (*readiness.Bundle, error) {
		return s.readiness.Unskip(c, id, item, actor(r), now)
	})
}

func (s *Server) transition(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		To string `json:"to"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out any
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		if _, err := s.readiness.Transition(c, id, in.To, actor(r), now); err != nil {
			return err
		}
		var err error
		out, err = s.connectionView(c, id, now)
		return err
	})
	return http.StatusOK, out, err
}

func (s *Server) activate(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return 0, nil, err
	}
	var out any
	status := http.StatusOK
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		// A write-enabled revision needs a second person (DR-10): this call
		// opens the request and a different person approves it.
		two, err := s.readiness.RequiresSecondPerson(c, id)
		if err != nil {
			return err
		}
		if two {
			by, err := activationPerson(r)
			if err != nil {
				return err
			}
			req, err := s.readiness.RequestActivation(c, id, by, now)
			if err != nil {
				return err
			}
			status = http.StatusAccepted
			out = map[string]any{"status": "pending_approval", "request": activationOf(req)}
			return nil
		}
		_, ac, err := s.readiness.Activate(c, id, actor(r), now)
		if err != nil {
			return err
		}
		if err := s.firstSync(r, c, ac, now); err != nil {
			return err
		}
		out, err = s.connectionView(c, id, now)
		return err
	})
	return status, out, err
}

func (s *Server) retire(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Confirm bool `json:"confirm"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if !in.Confirm {
		return 0, nil, badRequest("confirmation_required", `send {"confirm": true} to retire the connection`)
	}
	var out any
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		if err := s.readiness.Retire(c, id, actor(r), now); err != nil {
			return err
		}
		var err error
		out, err = s.connectionView(c, id, now)
		return err
	})
	return http.StatusOK, out, err
}
