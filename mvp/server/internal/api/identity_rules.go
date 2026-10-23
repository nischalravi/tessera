package api

import (
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/match"
	"github.com/nischalravi/tessera/mvp/server/internal/idrules"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Identity rules (Admin > Identity rules): one read of the rules the identity engines apply today, so an
// administrator sees them in one place.
//
//	GET /api/admin/identity-rules
//
// It reports, and does not duplicate, three engines: the matching and correlation rules (internal/identity/match,
// internal/correlation) with the tenant's settings, the group naming rules (internal/groups/naming) and the
// dormancy thresholds of machine identities (internal/nhi). The matching settings are changed through
// PUT /api/admin/matching (identity.matching.configure, step-up), which already exists.
//
//	PUT /api/admin/identity-rules   {version, correlation_order, authoritative, dormant_service_days, dormant_ai_agent_days}
//
// The PUT sets what the engines read through internal/idrules: the order the connector resolver correlates a
// reference to a person (external ID, email), the authoritative system per person attribute (a different system's
// value for a person already known is ignored) and the dormancy threshold per machine identity type. It needs
// matching.configure and a fresh phishing-resistant sign-in, and is audited with the old values. People have no
// usage-based dormancy engine yet and are listed in "not_configurable".

func (s *Server) registerIdentityRulesRoutes() {
	s.handle(http.MethodGet, "/api/admin/identity-rules", read, need(auth.PermGraphRead), s.identityRules)
	s.handle(http.MethodPut, "/api/admin/identity-rules", write, needStepUp(auth.PermMatchingConfigure, auth.StepUpPolicy), s.putIdentityRules)
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
	Rules           idRulesView    `json:"rules"`
	NotConfigurable []string       `json:"not_configurable"`
}

// idRulesView is the tenant's tunable rules with what the editor offers.
type idRulesView struct {
	idrules.Rules
	Version         int      `json:"version"`
	CanManage       bool     `json:"can_manage"`
	CorrelationKeys []string `json:"correlation_keys"`
	Attributes      []string `json:"attributes"`
	Systems         []string `json:"systems"`
	MinDays         int      `json:"min_days"`
	MaxDays         int      `json:"max_days"`
}

type ruleText struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type dormancyRule struct {
	IdentityType string `json:"identity_type"`
	Label        string `json:"label"`
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
	rules, ver, err := idrules.Load(c)
	if err != nil {
		return nil, err
	}
	systems, err := idrules.Systems(c)
	if err != nil {
		return nil, err
	}
	v.Rules = idRulesView{Rules: rules, Version: ver, CanManage: s.can(r, auth.PermMatchingConfigure), CorrelationKeys: idrules.CorrelationKeys,
		Attributes: idrules.Attributes, Systems: systems, MinDays: idrules.MinDormantDays, MaxDays: idrules.MaxDormantDays}
	const effect = "Flagged dormant in the machine-identity inventory and counted in its risk score."
	v.Dormancy = []dormancyRule{{"service", "Service identities", rules.DormantServiceDays, effect}, {"ai_agent", "AI agents", rules.DormantAIAgentDays, effect}}
	v.NotConfigurable = []string{
		"Dormancy of people: there is no usage-based dormancy for people yet; leavers follow the HR feed.",
	}
	return v, nil
}

type putIdentityRulesBody struct {
	Version int `json:"version"`
	idrules.Rules
}

func (s *Server) putIdentityRules(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b putIdentityRulesBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if _, _, err := idrules.Save(store.TxFrom(r.Context()), b.Rules, b.Version, principal(r).Display, s.clock().UTC()); err != nil {
		return nil, cfgErr(err)
	}
	return s.identityRules(nil, r, p)
}
