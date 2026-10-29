package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Config proposals by machine clients (issue #721, internal/admin/change_proposal.go). A machine client holding the
// config.propose scope (added only by an approved two-admin api_client.propose.grant change) files a change request
// for one configuration write. Nothing is written: the request waits for a human admin, who approves it in the
// admin center (POST /api/admin/change-requests/{id}/approve: admin.change.approve and a fresh step-up), which
// applies it. The client can never approve or apply, whatever it holds.
//
//	POST /api/proposals/catalog-items/{group_id}   body of PUT /api/catalog/items/{group_id}
//	POST /api/proposals/roles[/{role_id}]          body of POST /api/roles (PUT /api/roles/{role_id} with an id)
//	POST /api/proposals/sod-rulesets[/{ruleset_id}] body of POST /api/sod/rulesets (PUT with an id)
//	POST /api/proposals/alert-rules/{rule_id}      body of PUT /api/alerts/rules/{rule_id}
//	GET  /api/proposals/{change_id}                the status of one of this client's own proposals
//
// A proposal answers 202 with {change_id, status, url, payload_hash}; the poll adds result_id (the id of what an applied
// proposal made, when it can tell) and failure. The routes are phased: internal/admin opens its
// own transaction and writes the submitted event in it. Another client's proposal, or a person's change request, is
// a 404 here.
func (s *Server) registerProposalRoutes() {
	G, P := http.MethodGet, http.MethodPost
	propose := need(auth.PermConfigPropose)
	s.handle(P, "/api/proposals/catalog-items/{group_id}", phased, propose, s.proposer(admin.KindCatalogItem, "group_id"))
	s.handle(P, "/api/proposals/roles", phased, propose, s.proposer(admin.KindRole, ""))
	s.handle(P, "/api/proposals/roles/{role_id}", phased, propose, s.proposer(admin.KindRole, "role_id"))
	s.handle(P, "/api/proposals/sod-rulesets", phased, propose, s.proposer(admin.KindSoDRuleset, ""))
	s.handle(P, "/api/proposals/sod-rulesets/{ruleset_id}", phased, propose, s.proposer(admin.KindSoDRuleset, "ruleset_id"))
	s.handle(P, "/api/proposals/alert-rules/{rule_id}", phased, propose, s.proposer(admin.KindAlertRule, "rule_id"))
	s.handle(G, "/api/proposals/{change_id}", read, propose, s.getProposal)
}

// proposer is the handler of one kind; idVar names the path variable that is the proposal's id ("" for a create).
func (s *Server) proposer(kind, idVar string) handlerFunc {
	return func(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
		var body json.RawMessage
		if err := decodeBody(r, &body, false); err != nil {
			return nil, err
		}
		id := ""
		if idVar != "" {
			if id = strings.TrimSpace(p.path[idVar]); id == "" {
				return nil, errStatus(http.StatusNotFound, "Not Found")
			}
		}
		ch, err := s.admin.SubmitProposal(r.Context(), principal(r), kind, id, body)
		if err != nil {
			return nil, err
		}
		return statusBody{http.StatusAccepted, s.proposalView(ch, "")}, nil
	}
}

// proposalURL is where a human admin approves the request: the admin center's change requests page.
func (s *Server) proposalURL(id string) string {
	return strings.TrimRight(s.cfg.PublicURL, "/") + "/admin/change-requests?id=" + id
}

func (s *Server) proposalView(ch *store.AdminChange, resultID string) ojson.Object {
	var failure, result any
	if ch.Failure != "" {
		failure = ch.Failure
	}
	if resultID != "" {
		result = resultID
	}
	return ojson.Object{{Key: "change_id", Value: ch.ID.String()}, {Key: "type", Value: ch.Type},
		{Key: "status", Value: ch.Status}, {Key: "url", Value: s.proposalURL(ch.ID.String())},
		{Key: "payload_hash", Value: ch.PayloadHash}, {Key: "expires_at", Value: rt3339(ch.ExpiresAt)},
		{Key: "applied_at", Value: opt(ch.AppliedAt)}, {Key: "failure", Value: failure}, {Key: "result_id", Value: result}}
}

// getProposal is GET /api/proposals/{change_id}: the state of a proposal this client made (pending_approval,
// applied, rejected, cancelled, expired or failed), which a client polls. It shows nothing of anyone else's request.
func (s *Server) getProposal(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := pathUUID(p, "change_id")
	if err != nil {
		return nil, err
	}
	pr := principal(r)
	if pr == nil || pr.Kind != auth.KindAPIClient || pr.ClientID == "" {
		return nil, errStatus(http.StatusForbidden, "Forbidden")
	}
	tx := store.TxFrom(r.Context())
	client, err := tx.AdminChangeProposer(id)
	if err != nil {
		return nil, err
	}
	if client == "" || client != pr.ClientID {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	ch, err := tx.AdminChange(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	if err != nil {
		return nil, err
	}
	return s.proposalView(ch, admin.ProposalResult(tx, ch)), nil
}
