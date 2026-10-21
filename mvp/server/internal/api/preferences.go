package api

import (
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/prefs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// User preferences, under My account (issue #298):
//
//	GET /api/me/preferences   {time_zone, date_format, locale, landing_page} plus the choices on offer
//	PUT /api/me/preferences   the same four fields: replaces them
//
// Everyone signed in holds auth.self, and both calls act on the caller's own row
// only: there is no user id to name, so nobody can read or change another
// person's. An empty value is the default (the browser's time zone and locale,
// ISO dates, the home page). A machine client has no preferences. The UI uses
// them for date rendering and for the redirect from the root. Changes are
// audited in the same transaction.

func (s *Server) registerPreferenceRoutes() {
	self := need(auth.PermAuthenticated)
	s.handle(http.MethodGet, "/api/me/preferences", read, self, s.getPreferences)
	s.handle(http.MethodPut, "/api/me/preferences", write, self, s.putPreferences)
}

type preferencesView struct {
	prefs.Preferences
	TimeZones    []string `json:"time_zones"`
	DateFormats  []string `json:"date_formats"`
	Locales      []string `json:"locales"`
	LandingPages []string `json:"landing_pages"`
}

func preferencesResponse(p prefs.Preferences) preferencesView {
	return preferencesView{Preferences: p, TimeZones: commonTimeZones, DateFormats: prefs.DateFormats, Locales: prefs.Locales,
		LandingPages: prefs.LandingPages}
}

// commonTimeZones is the short list the UI offers first; any IANA name is accepted.
var commonTimeZones = []string{"UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
	"America/Sao_Paulo", "Europe/London", "Europe/Berlin", "Europe/Paris", "Africa/Johannesburg", "Asia/Dubai", "Asia/Kolkata",
	"Asia/Singapore", "Asia/Tokyo", "Australia/Sydney", "Pacific/Auckland"}

func (s *Server) getPreferences(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	pr, err := userPrincipal(r)
	if err != nil {
		return nil, err
	}
	p, err := prefs.Load(store.TxFrom(r.Context()), *pr.UserID)
	if err != nil {
		return nil, err
	}
	return preferencesResponse(p), nil
}

func (s *Server) putPreferences(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	pr, err := userPrincipal(r)
	if err != nil {
		return nil, err
	}
	var b prefs.Preferences
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	saved, err := prefs.Save(store.TxFrom(r.Context()), *pr.UserID, pr.Display, b, s.clock().UTC())
	if err != nil {
		return nil, cfgErr(err)
	}
	return preferencesResponse(saved), nil
}
