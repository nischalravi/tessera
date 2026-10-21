package api

import (
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// SoD page configuration (issue #298): which columns and filters SoD reviewers
// see on the conflicts page.
//
//	GET /api/sod/view-settings   the configuration; everyone who reads the conflicts needs it
//	PUT /api/sod/view-settings   {version, columns, filters}: replaces it
//
// Reading needs graph.read, like the conflicts. Changing needs sod.manage and a
// fresh phishing-resistant sign-in, and is audited in the same transaction. The
// conflicts page applies it; the API's conflict list itself is unchanged, so a
// hidden column is a display choice, not an access control.

func (s *Server) registerSodViewRoutes() {
	s.handle(http.MethodGet, "/api/sod/view-settings", read, need(auth.PermGraphRead), s.getSodView)
	s.handle(http.MethodPut, "/api/sod/view-settings", write, needStepUp(auth.PermSoDManage, auth.StepUpPolicy), s.putSodView)
}

type sodViewResponse struct {
	sod.ViewSettings
	Version   int      `json:"version"`
	Available []string `json:"available"`
	CanManage bool     `json:"can_manage"`
}

func (s *Server) sodViewResponse(r *http.Request, v sod.ViewSettings, ver int) sodViewResponse {
	return sodViewResponse{ViewSettings: v, Version: ver, Available: sod.ViewKeys, CanManage: s.can(r, auth.PermSoDManage)}
}

func (s *Server) getSodView(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	v, ver, err := sod.LoadView(store.TxFrom(r.Context()))
	if err != nil {
		return nil, err
	}
	return s.sodViewResponse(r, v, ver), nil
}

type sodViewBody struct {
	Version int `json:"version"`
	sod.ViewSettings
}

func (s *Server) putSodView(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b sodViewBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	v, ver, err := sod.SaveView(store.TxFrom(r.Context()), b.ViewSettings, b.Version, principal(r).Display, s.clock().UTC())
	if err != nil {
		return nil, cfgErr(err)
	}
	return s.sodViewResponse(r, v, ver), nil
}
