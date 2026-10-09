package api

import (
	"net/http"
	"regexp"
)

var runIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (s *Server) registerValidationRoutes() {
	s.handle(http.MethodPost, "/api/connections/{id}/validate", s.rd(s.validate))
	s.handle(http.MethodGet, "/api/connections/{id}/validations/{run}", s.rd(s.getValidation))
}

// validate runs the read-only live checks (simulated for demo connectors)
// and returns 202 with the run. Runs are short in the MVP, so the run has
// finished when the response is sent.
func (s *Server) validate(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return 0, nil, err
	}
	v, err := s.readiness.Validate(r.Context(), s.store, id, actor(r), s.clock)
	return http.StatusAccepted, v, err
}

func (s *Server) getValidation(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	run := p.path["run"]
	if !runIDRE.MatchString(run) {
		return 0, nil, badRequest("not_found", "no such run")
	}
	v, err := s.readiness.RunView(s.store.Read(r.Context()), id, run, s.clock())
	return http.StatusOK, v, err
}
