package api

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Two-person activation routes (design §4.4, §9; DR-10). POST .../activate on
// a write-enabled revision (write_mode not off) opens an activation request
// (202); a different person approves it, which applies the activation in the
// same transaction. Approving needs the same step-up as activating;
// rejecting or cancelling narrows access and needs only connections.activate.
func (s *Server) registerActivationRoutes() {
	s.handle(http.MethodGet, "/api/connections/{id}/activation", read, need(auth.PermConnectionsRead), s.rd(s.getActivation))
	s.handle(http.MethodPost, "/api/connections/{id}/activation/approve", write,
		needStepUp(auth.PermConnectionsActivate, auth.StepUpPolicy), s.rd(s.approveActivation))
	s.handle(http.MethodPost, "/api/connections/{id}/activation/reject", write,
		need(auth.PermConnectionsActivate), s.rd(s.rejectActivation))
}

// person is the acting principal as the two-person rule sees it. Routes that
// use it are user-only (a step-up route refuses API clients; reject checks).
func person(r *http.Request) (readiness.Person, error) {
	p := principal(r)
	if p.Kind != auth.KindUser || p.UserID == nil {
		return readiness.Person{}, &readiness.Error{Status: http.StatusForbidden, Code: "interactive_authentication_required",
			Msg: "this action needs a signed-in person"}
	}
	return readiness.Person{Key: "user:" + p.UserID.String(), Display: p.Display}, nil
}

type activationView struct {
	ID          string  `json:"id"`
	RevisionID  string  `json:"revision_id"`
	WriteMode   string  `json:"write_mode"`
	Status      string  `json:"status"`
	RequestedBy string  `json:"requested_by"`
	RequestedAt string  `json:"requested_at"`
	ExpiresAt   string  `json:"expires_at"`
	DecidedBy   *string `json:"decided_by"`
	DecidedAt   *string `json:"decided_at"`
	Note        string  `json:"decision_note"`
}

func activationOf(a *store.ActivationRequest) *activationView {
	if a == nil {
		return nil
	}
	v := &activationView{ID: a.ID, RevisionID: a.RevisionID, WriteMode: a.WriteMode, Status: a.Status,
		RequestedBy: a.RequestedBy, RequestedAt: store.RT(a.RequestedAt), ExpiresAt: store.RT(a.ExpiresAt), Note: a.DecisionNote}
	if a.DecidedAt != nil {
		by, at := a.DecidedBy, store.RT(*a.DecidedAt)
		v.DecidedBy, v.DecidedAt = &by, &at
	}
	return v
}

// decisionNote reads the optional {"note": "..."} body.
func decisionNote(r *http.Request) (string, error) {
	var in struct {
		Note string `json:"note"`
	}
	if err := decodeBody(r, &in, true); err != nil {
		return "", err
	}
	note := strings.TrimSpace(in.Note)
	if utf8.RuneCountInString(note) > 500 || strings.ContainsFunc(note, func(r rune) bool { return r < 0x20 && r != '\n' && r != '\t' || r == 0x7f }) {
		return "", badRequest("invalid_note", "note must be printable text of at most 500 characters")
	}
	return note, nil
}

func (s *Server) getActivation(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	c := store.TxFrom(r.Context())
	if _, err := c.Connection(id); errors.Is(err, store.ErrNotFound) {
		return 0, nil, &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such connection"}
	} else if err != nil {
		return 0, nil, err
	}
	a, err := c.LatestActivationRequest(id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"request": activationOf(a)}, nil
}

func (s *Server) approveActivation(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	by, err := person(r)
	if err != nil {
		return 0, nil, err
	}
	note, err := decisionNote(r)
	if err != nil {
		return 0, nil, err
	}
	var out any
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		_, ac, err := s.readiness.ApproveActivation(c, id, by, note, now)
		if err != nil {
			return err
		}
		if err := s.firstSync(r, c, ac, now); err != nil {
			return err
		}
		out, err = s.connectionView(c, id, now)
		return err
	})
	return http.StatusOK, out, err
}

func (s *Server) rejectActivation(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	by, err := person(r)
	if err != nil {
		return 0, nil, err
	}
	note, err := decisionNote(r)
	if err != nil {
		return 0, nil, err
	}
	var out any
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		a, err := s.readiness.RejectActivation(c, id, by, note, now)
		out = map[string]any{"request": activationOf(a)}
		return err
	})
	return http.StatusOK, out, err
}
