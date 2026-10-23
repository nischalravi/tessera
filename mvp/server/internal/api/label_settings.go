package api

import (
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/branding"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Labels and language (Admin > Branding & labels): the words a tenant renames, its default language and whether
// emails carry the logo.
//
//	GET /api/admin/labels   {version, default_language, email_logo, labels} with the terms and languages on offer
//	PUT /api/admin/labels   {version, default_language, email_logo, labels}: replaces them
//
// Reading needs admin.read; changing needs email.manage (as the branding it belongs to) and a fresh sign-in, and is
// audited with the old values. Everyone signed in gets the labels and the language with their preferences
// (GET /api/me/preferences), so the UI applies them before it renders.

func (s *Server) registerLabelRoutes() {
	s.handle(http.MethodGet, "/api/admin/labels", read, need(auth.PermAdminRead), s.getLabels)
	s.handle(http.MethodPut, "/api/admin/labels", write, needStepUp(auth.PermEmailManage, auth.StepUpPolicy), s.putLabels)
}

type labelsView struct {
	branding.Settings
	Version   int             `json:"version"`
	CanManage bool            `json:"can_manage"`
	Terms     []branding.Term `json:"terms"`
	Languages []string        `json:"languages"`
	MaxLabel  int             `json:"max_label"`
}

func (s *Server) labelsView(r *http.Request) (labelsView, error) {
	st, ver, err := branding.LoadSettings(store.TxFrom(r.Context()))
	if err != nil {
		return labelsView{}, err
	}
	return labelsView{Settings: st, Version: ver, CanManage: s.can(r, auth.PermEmailManage), Terms: branding.Terms,
		Languages: branding.Languages(), MaxLabel: branding.MaxLabel}, nil
}

func (s *Server) getLabels(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	return s.labelsView(r)
}

type putLabelsBody struct {
	Version int `json:"version"`
	branding.Settings
}

func (s *Server) putLabels(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b putLabelsBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if _, _, err := branding.SaveSettings(store.TxFrom(r.Context()), b.Settings, b.Version, principal(r).Display, s.clock().UTC()); err != nil {
		return nil, brandErr(cfgErr(err))
	}
	return s.labelsView(r)
}
