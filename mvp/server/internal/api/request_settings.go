package api

import (
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Tenant-wide request settings (issue #298):
//
//	GET /api/request-settings   the settings, for the request form and the admin page
//	PUT /api/request-settings   {version, ...}: replaces them
//
// Everyone who can request reads them (the form needs the limits). Changing them
// needs catalog.manage and a fresh phishing-resistant sign-in, and is audited in
// the same transaction. The server enforces them on submit (requests.Submit).

type requestSettingsView struct {
	requests.Settings
	Version          int  `json:"version"`
	CanManage        bool `json:"can_manage"`
	CanRequestOthers bool `json:"can_request_for_others"` // what the signed-in user may do under the policy
	MaxJustification int  `json:"max_justification_length"`
	MaxAttachments   int  `json:"max_attachments"`
	MaxHoursLimit    int  `json:"max_hours_limit"`
}

func (s *Server) requestSettingsView(r *http.Request, set requests.Settings, ver int) requestSettingsView {
	return requestSettingsView{Settings: set, Version: ver, CanManage: s.can(r, auth.PermCatalogManage),
		CanRequestOthers: s.mayRequestForOthers(r, set), MaxJustification: requests.MaxJustification,
		MaxAttachments: requests.MaxAttachments, MaxHoursLimit: requests.MaxHours}
}

func (s *Server) getRequestSettings(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	set, ver, err := requests.LoadSettings(store.TxFrom(r.Context()))
	if err != nil {
		return nil, err
	}
	return s.requestSettingsView(r, set, ver), nil
}

type requestSettingsBody struct {
	Version int `json:"version"`
	requests.Settings
}

func (s *Server) putRequestSettings(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	var b requestSettingsBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	set, ver, err := requests.SaveSettings(store.TxFrom(r.Context()), b.Settings, b.Version, by, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return s.requestSettingsView(r, set, ver), nil
}
