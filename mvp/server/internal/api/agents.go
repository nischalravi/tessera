package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Directory Agent admin routes (DR-11, design §5.3). The agents themselves
// speak to the separate mTLS listener (agent.Service.Handler), never to these.
// Issuing an enrolment code and revoking an agent need a fresh phishing-
// resistant sign-in like setting a connection credential: a code lets someone
// put a host inside the customer network on the path to the directory.
func (s *Server) registerAgentRoutes() {
	s.handle(http.MethodGet, "/api/agents", read, need(auth.PermConnectionsRead), s.rd(s.listAgents))
	s.handle(http.MethodPost, "/api/agents", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.createAgent)
	s.handle(http.MethodPost, "/api/agents/{id}/revoke", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.revokeAgent))
}

func (s *Server) listAgents(r *http.Request, _ *params) (int, any, error) {
	out, err := s.agents.List(store.TxFrom(r.Context()))
	return http.StatusOK, out, err
}

type createAgentInput struct {
	Name string `json:"name"`
}

func agentError(err error) error {
	switch {
	case errors.Is(err, agent.ErrName):
		return badRequest("invalid_name", err.Error())
	case errors.Is(err, store.ErrDuplicate):
		return &readiness.Error{Status: http.StatusConflict, Code: "name_taken", Msg: "an agent with that name already exists"}
	case errors.Is(err, store.ErrNotFound):
		return &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such agent"}
	}
	return err
}

// createAgent adds a pending agent and returns its single-use enrolment code.
// The code is in this response only; Tessera keeps its hash.
func (s *Server) createAgent(w http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var in createAgentInput
	if err := decodeBody(r, &in, false); err != nil {
		return nil, err
	}
	var out *agent.Enrolment
	err := s.write(r, func(c *store.TenantTx, now time.Time) (err error) {
		out, err = s.agents.Create(c, in.Name, actor(r), now)
		return err
	})
	if err != nil {
		return nil, agentError(err)
	}
	w.Header().Set("Cache-Control", "no-store") // the code is in this response only
	return statusBody{http.StatusCreated, out}, nil
}

func (s *Server) revokeAgent(r *http.Request, p *params) (int, any, error) {
	id := p.path["id"]
	if !idRE.MatchString(id) {
		return 0, nil, agentError(store.ErrNotFound)
	}
	var out *agent.View
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		if err := s.agents.Revoke(c, id, actor(r), now); err != nil {
			return err
		}
		v, err := s.agents.Get(c, id)
		out = v
		return err
	})
	if err != nil {
		return 0, nil, agentError(err)
	}
	return http.StatusOK, out, nil
}
