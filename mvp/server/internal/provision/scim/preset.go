package scim

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Tri is a fact about a vendor that is either confirmed by its public SCIM
// documentation (yes, no) or not confirmed (unknown). Unknown is never a guess:
// the client behaves as it does for any unlisted SCIM service, trying the
// standard form first and falling back where the response allows.
type Tri string

const (
	Yes     Tri = "yes"
	No      Tri = "no"
	Unknown Tri = "unknown"
)

// Operation-name case and member-removal style a vendor documents.
const (
	CaseLower = "lower" // "add", "replace", "remove" (RFC 7644)
	CaseTitle = "title" // "Add", "Replace", "Remove" (Entra style)

	RemoveByFilter = "filter" // PATCH remove on members[value eq "id"]
	RemoveByValue  = "value"  // PATCH remove on members with a value list
	RemoveUnknown  = "unknown"
	CaseUnknown    = "unknown"
)

// Quirks are the PATCH dialect differences the client tolerates. The zero
// value is not valid; use Unknown fields ("unknown"), which the client treats
// as standard-with-fallback. Dialect "entra" on the client implies title case
// and string booleans regardless of these flags.
type Quirks struct {
	OpCase        string `json:"op_case"`         // CaseLower, CaseTitle or CaseUnknown
	BoolAsString  Tri    `json:"bool_as_string"`  // booleans travel as "True"/"False"
	MemberRemove  string `json:"member_remove"`   // RemoveByFilter, RemoveByValue or RemoveUnknown
	ValueFilterOK Tri    `json:"value_filter_ok"` // PATCH paths with a [value filter] are accepted
}

// UnknownQuirks is the starting point: nothing confirmed.
func UnknownQuirks() Quirks {
	return Quirks{OpCase: CaseUnknown, BoolAsString: Unknown, MemberRemove: RemoveUnknown, ValueFilterOK: Unknown}
}

func (q Quirks) validate() error {
	if !slices.Contains([]string{CaseLower, CaseTitle, CaseUnknown}, q.OpCase) {
		return fmt.Errorf("op_case %q", q.OpCase)
	}
	if !slices.Contains([]string{RemoveByFilter, RemoveByValue, RemoveUnknown}, q.MemberRemove) {
		return fmt.Errorf("member_remove %q", q.MemberRemove)
	}
	for _, t := range []Tri{q.BoolAsString, q.ValueFilterOK} {
		if t != Yes && t != No && t != Unknown {
			return fmt.Errorf("tri value %q", t)
		}
	}
	return nil
}

// Auth methods a preset can name. The connection stores a bearer token today;
// AuthOAuth2CC is in the table for vendors that document it and is not offered
// by any preset until the connection can run the client-credentials grant.
const (
	AuthBearer   = "bearer_token"
	AuthOAuth2CC = "oauth2_client_credentials"
	AuthUnknown  = "unknown" // the vendor's auth for SCIM was not confirmed; a bearer token is entered
)

// Categories of the gallery.
const (
	CategoryCloudSaaS = "Cloud & SaaS"
	CategoryIdP       = "Identity providers"
)

// Mapping is Tessera's account fields against SCIM attribute paths. RFC 7643
// section 4.1 core User attributes; no vendor-specific mapping is encoded
// because none was confirmed from public documentation.
type Mapping map[string]string

// StandardMapping is the RFC 7643 core User mapping.
func StandardMapping() Mapping {
	return Mapping{
		"username":     "userName",
		"external_id":  "externalId",
		"display_name": "displayName",
		"active":       "active",
		"email":        `emails[type eq "work"].value`,
	}
}

// Preset is one vendor tile. Every field is data; nothing is free text typed
// by an admin.
type Preset struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Publisher string `json:"publisher"`
	Category  string `json:"category"`
	// LogoKey is the simple-icons slug ("" when the package has no icon for the brand).
	LogoKey string `json:"logo_key"`
	// BaseURLPattern is an anchored regexp the base URL must match. Empty when the
	// vendor's URL shape was not confirmed (a generic https check applies);
	// BaseURLExample then shows only the documented placeholder, or nothing.
	BaseURLPattern string  `json:"base_url_pattern,omitempty"`
	BaseURLExample string  `json:"base_url_example,omitempty"`
	Auth           string  `json:"auth"`
	Mapping        Mapping `json:"mapping"`
	Quirks         Quirks  `json:"quirks"`
	// Hint is where the vendor gates SCIM behind a plan or add-on, or where the
	// admin finds the URL and token.
	Hint string `json:"hint"`
	// Source is the vendor documentation the facts above came from.
	Source string `json:"source"`
}

var idRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Presets is the library. Facts are only those read from the vendor's public
// SCIM documentation (cited per entry); anything else is Unknown or empty.
var Presets = []Preset{
	{
		ID: "slack", Name: "Slack", Publisher: "Slack Technologies (Salesforce)", Category: CategoryCloudSaaS, LogoKey: "slack",
		// https://docs.slack.dev/admins/scim-api/ : base URL https://api.slack.com/scim/VERSION/ (v2 for SCIM 2.0);
		// OAuth token with the admin scope; PATCH operations remove, replace, add per SCIM V2;
		// only on Business+ and Enterprise plans.
		BaseURLPattern: `^https://api\.slack\.com/scim/v2/?$`, BaseURLExample: "https://api.slack.com/scim/v2",
		Auth: AuthBearer, Mapping: StandardMapping(),
		Quirks: Quirks{OpCase: CaseLower, BoolAsString: Unknown, MemberRemove: RemoveUnknown, ValueFilterOK: Unknown},
		Hint:   "SCIM needs a Business+ or Enterprise Slack plan. The token is an OAuth token with the admin scope.",
		Source: "https://docs.slack.dev/admins/scim-api/",
	},
	{
		ID: "zoom", Name: "Zoom", Publisher: "Zoom Communications", Category: CategoryCloudSaaS, LogoKey: "zoom",
		// Zoom's SCIM docs page was not reachable for verification: URL shape, auth and quirks are unknown.
		Auth: AuthUnknown, Mapping: StandardMapping(), Quirks: UnknownQuirks(),
		Hint:   "Copy the SCIM base URL and token from the Zoom admin portal. Not verified against Zoom's public documentation.",
		Source: "https://developers.zoom.us/docs/api/",
	},
	{
		ID: "box", Name: "Box", Publisher: "Box, Inc.", Category: CategoryCloudSaaS, LogoKey: "box",
		// Box's SCIM documentation was not reachable for verification.
		Auth: AuthUnknown, Mapping: StandardMapping(), Quirks: UnknownQuirks(),
		Hint:   "Copy the SCIM URL and token from the Box admin console. Not verified against Box's public documentation.",
		Source: "https://developer.box.com/",
	},
	{
		ID: "dropbox", Name: "Dropbox", Publisher: "Dropbox, Inc.", Category: CategoryCloudSaaS, LogoKey: "dropbox",
		// Dropbox's SCIM documentation was not reachable for verification.
		Auth: AuthUnknown, Mapping: StandardMapping(), Quirks: UnknownQuirks(),
		Hint:   "Copy the SCIM URL and token from the Dropbox admin console. Not verified against Dropbox's public documentation.",
		Source: "https://help.dropbox.com/",
	},
	{
		ID: "zendesk", Name: "Zendesk", Publisher: "Zendesk, Inc.", Category: CategoryCloudSaaS, LogoKey: "zendesk",
		// Zendesk's SCIM documentation was not reachable for verification.
		Auth: AuthUnknown, Mapping: StandardMapping(), Quirks: UnknownQuirks(),
		Hint:   "Copy the SCIM URL and token from Zendesk. Not verified against Zendesk's public documentation.",
		Source: "https://developer.zendesk.com/",
	},
	{
		ID: "databricks", Name: "Databricks", Publisher: "Databricks, Inc.", Category: CategoryCloudSaaS, LogoKey: "databricks",
		// https://docs.databricks.com/aws/en/admin/users-groups/scim/ : account admin copies the "SCIM token"
		// and "Account SCIM URL" from the account console; requires the Premium plan or above.
		// The URL shape differs by cloud and was not confirmed, so it is not pattern-checked.
		Auth: AuthBearer, Mapping: StandardMapping(), Quirks: UnknownQuirks(),
		Hint:   "Needs the Databricks Premium plan or above and an account admin. Copy the SCIM token and Account SCIM URL from the account console.",
		Source: "https://docs.databricks.com/aws/en/admin/users-groups/scim/",
	},
	{
		ID: "atlassian", Name: "Atlassian Cloud", Publisher: "Atlassian", Category: CategoryCloudSaaS, LogoKey: "atlassian",
		// https://developer.atlassian.com/cloud/admin/user-provisioning/rest/intro/ : directory base URL
		// https://api.atlassian.com/scim/directory/{directoryId}, bearer SCIM token generated when connecting an identity provider.
		BaseURLPattern: `^https://api\.atlassian\.com/scim/directory/[A-Za-z0-9-]+/?$`, BaseURLExample: "https://api.atlassian.com/scim/directory/{directoryId}",
		Auth: AuthBearer, Mapping: StandardMapping(), Quirks: UnknownQuirks(),
		Hint:   "Create a user provisioning directory in Atlassian Administration (Atlassian Guard) and copy its SCIM base URL and API key.",
		Source: "https://developer.atlassian.com/cloud/admin/user-provisioning/rest/intro/",
	},
	{
		ID: "pingone", Name: "PingOne", Publisher: "Ping Identity", Category: CategoryIdP, LogoKey: "pingidentity",
		// PingOne's public documentation lists SCIM provisioning pages but no inbound SCIM service
		// root could be confirmed; everything beyond https is unknown.
		Auth: AuthUnknown, Mapping: StandardMapping(), Quirks: UnknownQuirks(),
		Hint:   "Not verified against Ping Identity's public documentation; confirm the SCIM endpoint before use.",
		Source: "https://apidocs.pingidentity.com/pingone/platform/v1/api/",
	},
	{
		ID: "onelogin", Name: "OneLogin", Publisher: "One Identity (Quest)", Category: CategoryIdP, LogoKey: "onelogin",
		// OneLogin's SCIM service documentation was not confirmed.
		Auth: AuthUnknown, Mapping: StandardMapping(), Quirks: UnknownQuirks(),
		Hint:   "Not verified against OneLogin's public documentation; confirm the SCIM endpoint before use.",
		Source: "https://developers.onelogin.com/scim",
	},
	{
		ID: "jumpcloud", Name: "JumpCloud", Publisher: "JumpCloud", Category: CategoryIdP, LogoKey: "jumpcloud",
		// JumpCloud's SCIM documentation page was not reachable for verification.
		Auth: AuthUnknown, Mapping: StandardMapping(), Quirks: UnknownQuirks(),
		Hint:   "Not verified against JumpCloud's public documentation; confirm the SCIM endpoint before use.",
		Source: "https://docs.jumpcloud.com/",
	},
	{
		ID: "keycloak", Name: "Keycloak (SCIM extension)", Publisher: "Keycloak community (SCIM extension)", Category: CategoryIdP, LogoKey: "keycloak",
		// Keycloak has no built-in SCIM server; community extensions such as
		// https://github.com/Captain-P-Goldfish/scim-for-keycloak add one. The extension's endpoint was not
		// reachable for verification.
		Auth: AuthUnknown, Mapping: StandardMapping(), Quirks: UnknownQuirks(),
		Hint:   "Keycloak needs a SCIM extension installed; the base URL depends on the extension. Not verified.",
		Source: "https://github.com/Captain-P-Goldfish/scim-for-keycloak",
	},
	{
		ID: "auth0", Name: "Auth0", Publisher: "Okta (Auth0)", Category: CategoryIdP, LogoKey: "auth0",
		// https://auth0.com/docs/authenticate/protocols/scim/configure-inbound-scim : each enterprise connection
		// has its own SCIM endpoint https://{domain}/scim/v2/connections/{connectionId}/ and token;
		// the plan must include Enterprise Connections.
		BaseURLPattern: `^https://[A-Za-z0-9.-]+/scim/v2/connections/[A-Za-z0-9_-]+/?$`, BaseURLExample: "https://{tenant-domain}/scim/v2/connections/{connectionId}",
		Auth: AuthBearer, Mapping: StandardMapping(), Quirks: UnknownQuirks(),
		Hint:   "Needs an Auth0 plan or agreement that includes Enterprise Connections. Enable inbound SCIM on the enterprise connection and copy its endpoint and token.",
		Source: "https://auth0.com/docs/authenticate/protocols/scim/configure-inbound-scim",
	},
}

// PresetByID returns the preset with the id.
func PresetByID(id string) (Preset, bool) {
	for _, p := range Presets {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

// ValidatePresets checks the table: unique ids, compiling patterns that
// accept their own example, known auth and quirk values, https sources.
func ValidatePresets(ps []Preset) error {
	seen := map[string]bool{}
	for _, p := range ps {
		switch {
		case !idRE.MatchString(p.ID):
			return fmt.Errorf("preset %q: bad id", p.ID)
		case seen[p.ID]:
			return fmt.Errorf("preset %q: duplicate", p.ID)
		case p.Name == "" || p.Publisher == "":
			return fmt.Errorf("preset %q: name and publisher required", p.ID)
		case p.Category != CategoryCloudSaaS && p.Category != CategoryIdP:
			return fmt.Errorf("preset %q: category %q", p.ID, p.Category)
		case !slices.Contains([]string{AuthBearer, AuthOAuth2CC, AuthUnknown}, p.Auth):
			return fmt.Errorf("preset %q: auth %q", p.ID, p.Auth)
		case !strings.HasPrefix(p.Source, "https://"):
			return fmt.Errorf("preset %q: source must be an https URL", p.ID)
		case p.Hint == "":
			return fmt.Errorf("preset %q: hint required", p.ID)
		case p.Mapping["username"] == "":
			return fmt.Errorf("preset %q: mapping needs username", p.ID)
		}
		seen[p.ID] = true
		if err := p.Quirks.validate(); err != nil {
			return fmt.Errorf("preset %q: quirks: %v", p.ID, err)
		}
		if p.BaseURLPattern != "" {
			re, err := regexp.Compile(p.BaseURLPattern)
			if err != nil {
				return fmt.Errorf("preset %q: pattern: %v", p.ID, err)
			}
			if !strings.HasPrefix(p.BaseURLPattern, "^https://") || !strings.HasSuffix(p.BaseURLPattern, "$") {
				return fmt.Errorf("preset %q: pattern must be anchored and https", p.ID)
			}
			// The example holds {placeholders}; fill them to test the pattern.
			if ex := fillPlaceholders(p.BaseURLExample); !re.MatchString(ex) {
				return fmt.Errorf("preset %q: pattern does not match its example %q", p.ID, ex)
			}
		}
	}
	return nil
}

var placeholderRE = regexp.MustCompile(`\{[^}]*\}`)

func fillPlaceholders(s string) string { return placeholderRE.ReplaceAllString(s, "abc-123") }

// ValidateBaseURL checks a connection's base URL against the preset: https,
// no credentials, query or fragment, and the vendor's documented shape where
// one is known.
func (p Preset) ValidateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must be an https URL with no credentials, query or fragment")
	}
	if p.BaseURLPattern != "" && !regexp.MustCompile(p.BaseURLPattern).MatchString(raw) {
		return fmt.Errorf("does not look like a %s SCIM URL (expected %s)", p.Name, p.BaseURLExample)
	}
	return nil
}

// ClientQuirks is what the Client takes from a preset.
func (p Preset) ClientQuirks() Quirks { return p.Quirks }
