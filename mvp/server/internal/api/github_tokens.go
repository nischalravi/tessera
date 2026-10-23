package api

import (
	"context"
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ghtokens"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// GitHub and CI token inventory (issue #476), next to the OAuth app inventory:
//
//	GET  /api/github-tokens        fine-grained and classic personal access tokens, OAuth app
//	                               tokens (the GitHub CLI among them) and Actions secrets of the
//	                               connected organization, each with its age, last rotation,
//	                               owner and risk flags, and a summary
//	POST /api/github-tokens/sync   refresh from GitHub now (a background job also does this hourly)
//
// Only metadata is read and returned: GitHub never sends a token or secret
// value. The sync uses the GitHub credential of identity containment and sends
// GET requests only. A tenant with no GitHub connection or credential answers
// sync status "skipped" and an empty list.

func (s *Server) registerGitHubTokenRoutes() {
	s.handle(http.MethodGet, "/api/github-tokens", read, need(auth.PermGraphRead), s.listGitHubTokens)
	s.handle(http.MethodPost, "/api/github-tokens/sync", phased, need(auth.PermOAuthAppsManage), s.syncGitHubTokens)
}

func (s *Server) listGitHubTokens(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	tokens, sum, err := ghtokens.List(store.TxFrom(r.Context()), s.clock())
	if err != nil {
		return nil, err
	}
	return map[string]any{"tokens": tokens, "summary": sum, "stale_days": ghtokens.StaleDays, "unused_days": ghtokens.UnusedDays}, nil
}

func (s *Server) syncGitHubTokens(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(r.Context(), containTimeout)
	defer cancel()
	return s.ghtokens.Sync(ctx, s.store, principal(r).TenantID, actor(r))
}
