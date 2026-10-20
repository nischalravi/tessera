package api

import (
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/match"
	"github.com/nischalravi/tessera/mvp/server/internal/nhi"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Identity rules (Admin > Identity rules): one read of the rules the identity engines apply today, so an
// administrator sees them in one place.
//
//	GET /api/admin/identity-rules
//
// It reports, and does not duplicate, three engines: the matching and correlation rules (internal/identity/match,
// internal/correlation) with the tenant's settings, the group naming rules (internal/groups/naming) and the
// dormancy threshold of machine identities (internal/nhi). The matching settings are changed through
// PUT /api/admin/matching (identity.matching.configure, step-up), which already exists. Authoritative source per
// attribute and per-type dormancy thresholds have no engine yet and are listed in "not_configurable".

func (s *Server) registerIdentityRulesRoutes() {
	s.handle(http.MethodGet, "/api/admin/identity-rules", read, need(auth.PermGraphRead), s.identityRules)
}

type identityRulesView struct {
	Matching struct {
		Settings       matchingSettingsView `json:"settings"`
		Rules          []match.RuleInfo     `json:"rules"`
		NameStrong     float64              `json:"name_strong"`
		NamePossible   float64              `json:"name_possible"`
		SelfAsserted   string               `json:"self_asserted"`
		ChangeableWith string               `json:"changeable_with"`
	} `json:"matching"`
	Correlation struct {
		Proposals []ruleText `json:"proposals"`
		Decisions string     `json:"decisions"`
	} `json:"correlation"`
	GroupNaming struct {
		Separator       string `json:"separator"`
		Allowed         string `json:"allowed"`
		MaxSegment      int    `json:"max_segment"`
		MaxName         int    `json:"max_name"`
		MaxDisplay      int    `json:"max_display"`
		MaxDepth        int    `json:"max_depth"`
		CaseInsensitive bool   `json:"case_insensitive"`
	} `json:"group_naming"`
	Dormancy        []dormancyRule `json:"dormancy"`
	NotConfigurable []string       `json:"not_configurable"`
}

type ruleText struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type dormancyRule struct {
	IdentityType string `json:"identity_type"`
	Days         int    `json:"days"`
	Effect       string `json:"effect"`
}

func (s *Server) identityRules(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	c := store.TxFrom(r.Context())
	st, err := c.MatchingSettings()
	if err != nil {
		return nil, err
	}
	var v identityRulesView
	v.Matching.Settings = viewSettings(newViewer(c), st)
	v.Matching.Rules = match.Catalog()
	v.Matching.NameStrong, v.Matching.NamePossible = match.DefaultNameStrong, match.DefaultNamePossible
	v.Matching.SelfAsserted = "Self-asserted intake (sponsor invitations, self-registration, partner invitations) only ever proposes: a reviewer decides."
	v.Matching.ChangeableWith = "identity.matching.configure"
	v.Correlation.Proposals = []ruleText{
		{"email", "The account's login is the person's email address."},
		{"email_local_part", "The account's login is the part before the @ of the person's email address."},
	}
	v.Correlation.Decisions = "A reviewer's decision (link, not a person, merge) is pinned: connector sync never undoes it."
	n := &v.GroupNaming
	n.Separator, n.Allowed, n.MaxSegment, n.MaxName, n.MaxDisplay, n.MaxDepth, n.CaseInsensitive =
		naming.Sep, "letters, digits, underscore, hyphen and dot", naming.MaxExtension, naming.MaxName, naming.MaxDisplay, naming.MaxDepth, true
	v.Dormancy = []dormancyRule{{"Machine identities and AI agents", nhi.DormantDays, "Flagged dormant in the machine-identity inventory and counted in its risk score."}}
	v.NotConfigurable = []string{
		"Choose the authoritative source per attribute: no engine yet; sources are authoritative by kind (HRIS, SIS) today.",
		"Edit the correlation rule order (external ID, then email): fixed in the engine; the tenant can tune review and auto-link.",
		"Dormancy thresholds per identity type: one fixed threshold for machine identities; none for people.",
	}
	return v, nil
}
