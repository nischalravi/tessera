package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	authnorm "github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/oauth2rp"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/samlsp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// IdPConfig is the full, secret-free configuration of an IdP connection
// (design §15.2 idp_connection.create, §18.2). The operator CLI reads the
// same shape from YAML and the admin-change workflow from the request
// payload, so one validator checks both. Secrets never live in it: the OIDC
// client secret travels separately (sealed) and a SAML connection gets a
// generated SP key.
type IdPConfig struct {
	Name             string            `json:"name"`
	Protocol         string            `json:"protocol"`
	Profile          string            `json:"profile"`
	Issuer           string            `json:"issuer,omitempty"`
	ClientID         string            `json:"client_id,omitempty"`
	ClientAuthMethod string            `json:"client_auth_method,omitempty"`
	Scopes           []string          `json:"scopes,omitempty"`
	IDTokenAlgs      []string          `json:"id_token_algs,omitempty"`
	VerifiedDomains  []string          `json:"verified_domains,omitempty"`
	GroupsClaim      string            `json:"groups_claim,omitempty"`
	GroupRoleMapping map[string]string `json:"group_role_mapping,omitempty"`
	JITProvisioning  *bool             `json:"jit_provisioning,omitempty"`
	DefaultRole      string            `json:"default_role,omitempty"`
	Default          bool              `json:"default,omitempty"`
	EntraTenantID    string            `json:"entra_tenant_id,omitempty"`
	StepUpRequest    map[string]any    `json:"step_up_request,omitempty"`
	AuthnMapping     map[string]any    `json:"authn_mapping,omitempty"`
	// SAML (protocol saml)
	IdPEntityID     string            `json:"idp_entity_id,omitempty"`
	IdPSSOURL       string            `json:"idp_sso_url,omitempty"`
	IdPSigningCerts []string          `json:"idp_signing_certs,omitempty"` // PEM or base64 DER; pinned
	SubjectSource   string            `json:"subject_source,omitempty"`    // nameid_persistent (default) | attribute:<name>
	AttributeMap    map[string]string `json:"attribute_map,omitempty"`     // email, name, groups -> attribute names
	AssumePhr       bool              `json:"assume_phishing_resistant,omitempty"`
	// OAuth 2.0-only providers (protocol oauth2)
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	UserinfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	SubjectField          string `json:"subject_field,omitempty"` // the user object's immutable id field ("id" for github)
}

// IdPOptions are the environment rules of IdPConfig.Connection.
type IdPOptions struct {
	// Prod refuses dev_mock and plain-http endpoints (§18.4).
	Prod bool
	// AllowAssumePhr permits assume_phishing_resistant, which only a
	// two-person admin change may set (§15.2); the operator CLI refuses it.
	AllowAssumePhr bool
}

// groupRoles are the roles an IdP group may confer: never an admin role (E1).
var groupRoles = []string{store.RoleViewer, store.RoleOperator, store.RoleAuditor}

// Clone returns a deep copy (validation fills defaults and edits maps).
func (f IdPConfig) Clone() IdPConfig {
	b, err := json.Marshal(f)
	if err != nil {
		return f
	}
	var c IdPConfig
	if json.Unmarshal(b, &c) != nil {
		return f
	}
	return c
}

// Connection validates f and returns the store row it describes, with status
// pending (the caller decides when it becomes active). f may be updated with
// defaults; Clone it first to keep the original.
func (f *IdPConfig) Connection(opt IdPOptions, now time.Time) (*store.IdPConnection, error) {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if strings.TrimSpace(f.Name) == "" {
		bad("name is required")
	}
	switch f.Protocol {
	case "oidc", "saml", "oauth2":
	default:
		bad("protocol %q: want oidc, saml or oauth2", f.Protocol)
	}
	switch {
	case f.Profile == store.ProfileDevMock:
		if opt.Prod {
			bad("profile dev_mock is refused with TESSERA_ENV=prod")
		}
	case f.Protocol == "saml" && f.Profile != store.ProfileGenericSAML:
		bad("profile %q: SAML connections use generic_saml", f.Profile)
	case f.Protocol == "oauth2" && f.Profile != store.ProfileGitHub && f.Profile != store.ProfileGenericOAuth2:
		bad("profile %q: OAuth 2.0 connections use github or generic_oauth2", f.Profile)
	case f.Protocol == "oidc" && !slices.Contains([]string{store.ProfileOkta, store.ProfileEntra, store.ProfileGoogle,
		store.ProfileGenericOIDC}, f.Profile):
		bad("profile %q: want okta, entra, google or generic_oidc", f.Profile)
	}
	if f.AssumePhr && !opt.AllowAssumePhr {
		bad("assume_phishing_resistant needs a two-person admin change (design §15.2); it cannot be set here")
	}
	switch f.Protocol {
	case "saml":
		f.checkSAML(opt.Prod, bad)
	case "oauth2":
		f.checkOAuth2(opt.Prod, bad)
	default:
		f.checkOIDC(opt.Prod, bad)
	}
	if f.DefaultRole == "" {
		f.DefaultRole = store.RoleViewer
	}
	if !slices.Contains(groupRoles, f.DefaultRole) {
		bad("default_role %q: want viewer, operator or auditor", f.DefaultRole)
	}
	for g, r := range f.GroupRoleMapping {
		if !slices.Contains(groupRoles, r) {
			bad("group_role_mapping[%q] = %q: groups grant viewer, operator or auditor only (never admin roles)", g, r)
		}
	}
	for _, a := range f.IDTokenAlgs {
		if !slices.Contains([]string{"RS256", "PS256", "ES256", "EdDSA"}, a) {
			bad("id_token_algs: %q is not allowed", a)
		}
	}
	mapping := f.AuthnMapping
	if f.EntraTenantID != "" {
		if mapping == nil {
			mapping = map[string]any{}
		}
		mapping["entra_tenant_id"] = f.EntraTenantID
	}
	enc := func(v any, def string) json.RawMessage {
		if v == nil || (fmt.Sprint(v) == "map[]") {
			return json.RawMessage(def)
		}
		b, err := json.Marshal(v)
		if err != nil {
			bad("%v", err)
		}
		return b
	}
	authnMapping := enc(mapping, "{}")
	if _, err := authnorm.ParseMapping(authnMapping); err != nil {
		bad("authn_mapping: %v", err)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	jit := false
	if f.JITProvisioning != nil {
		jit = *f.JITProvisioning
	}
	c := &store.IdPConnection{ID: uuid.New(), Name: strings.TrimSpace(f.Name), Protocol: f.Protocol, Profile: f.Profile,
		Status: "pending", IsDefault: f.Default, VerifiedDomains: enc(f.VerifiedDomains, "[]"), StepUpRequest: enc(f.StepUpRequest, "{}"),
		AuthnMapping: authnMapping, GroupRoleMapping: enc(f.GroupRoleMapping, "{}"), JITProvisioning: jit,
		DefaultRole: f.DefaultRole, PinCerts: true, AssumePhishingResistant: f.AssumePhr, CreatedAt: now, UpdatedAt: now}
	switch f.Protocol {
	case "saml":
		entity, sso := f.IdPEntityID, f.IdPSSOURL
		c.IdPEntityID, c.IdPSSOURL, c.IdPSigningCerts = &entity, &sso, enc(f.IdPSigningCerts, "[]")
		c.SubjectSource, c.AttributeMap = f.SubjectSource, enc(f.AttributeMap, "{}")
	case "oauth2":
		oc := oauth2rp.Connection{Profile: f.Profile, AuthorizationURL: f.AuthorizationEndpoint, TokenURL: f.TokenEndpoint,
			UserinfoURL: f.UserinfoEndpoint, SubjectField: f.SubjectField, Scopes: f.Scopes}.Defaults()
		clientID := f.ClientID
		c.ClientID, c.SubjectSource = &clientID, "field:"+oc.SubjectField
		c.AuthorizationEndpoint, c.TokenEndpoint, c.UserinfoEndpoint = &oc.AuthorizationURL, &oc.TokenURL, &oc.UserinfoURL
		if len(f.Scopes) == 0 && f.Profile == store.ProfileGitHub {
			f.Scopes = []string{"read:user", "user:email"}
		}
		if len(f.Scopes) == 0 {
			c.Scopes = json.RawMessage("[]")
		}
	default:
		issuer, clientID, method := f.Issuer, f.ClientID, f.ClientAuthMethod
		c.Issuer, c.ClientID, c.ClientAuthMethod = &issuer, &clientID, &method
	}
	if len(f.Scopes) > 0 {
		c.Scopes = enc(f.Scopes, "[]")
	}
	if len(f.IDTokenAlgs) > 0 {
		c.IDTokenAlgs = enc(f.IDTokenAlgs, "[]")
	}
	if f.GroupsClaim != "" {
		g := f.GroupsClaim
		c.GroupsClaim = &g
	}
	return c, nil
}

// NeedsClientSecret reports whether the protocol authenticates with a client
// secret (OIDC and OAuth 2.0); a SAML connection gets a generated SP key.
func (f *IdPConfig) NeedsClientSecret() bool { return f.Protocol == "oidc" || f.Protocol == "oauth2" }

// checkIssuer validates an OIDC issuer: an exact absolute URL (https in
// production), and for Entra never a multi-tenant template.
func checkIssuer(prod bool, profile, issuer string, bad func(string, ...any)) {
	iss, err := url.Parse(issuer)
	switch {
	case issuer == "" || err != nil || iss.Host == "":
		bad("issuer must be an absolute URL")
	case prod && iss.Scheme != "https":
		bad("issuer must be https with TESSERA_ENV=prod")
	case strings.HasSuffix(issuer, "/") || iss.RawQuery != "" || iss.Fragment != "":
		bad("issuer %q must be exact: no trailing slash, query or fragment", issuer)
	case profile == store.ProfileEntra && strings.Contains(issuer, "{tenantid}"):
		bad("issuer: Entra multi-tenant templates are not supported; configure the tenant-specific issuer")
	}
}

// checkEndpoint validates a URL the server will call or redirect to:
// absolute, http or https (https in production).
func checkEndpoint(prod bool, name, v string, bad func(string, ...any)) {
	u, err := url.Parse(v)
	switch {
	case err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http"):
		bad("%s must be an absolute URL", name)
	case prod && u.Scheme != "https":
		bad("%s must be https with TESSERA_ENV=prod", name)
	}
}

// checkSubjectSource validates where a user's immutable subject comes from:
// a SAML NameID or attribute, an OAuth 2.0 id field, never an email or name;
// an OIDC connection always uses sub.
func checkSubjectSource(protocol, v string, bad func(string, ...any)) {
	switch protocol {
	case "saml":
		if v != "nameid_persistent" && (!strings.HasPrefix(v, "attribute:") || len(v) == len("attribute:")) {
			bad("subject_source %q: want nameid_persistent or attribute:<name> (never email)", v)
		}
	case "oauth2":
		field, ok := strings.CutPrefix(v, "field:")
		switch strings.ToLower(field) {
		case "", "email", "login", "username", "preferred_username", "name", "upn":
			ok = false
		}
		if !ok {
			bad("subject_source %q: want field:<immutable id field>, never a name or email", v)
		}
	default:
		bad("subject_source does not apply to an %s connection (users are keyed on sub)", protocol)
	}
}

// checkOIDC validates the OIDC fields.
func (f *IdPConfig) checkOIDC(prod bool, bad func(string, ...any)) {
	checkIssuer(prod, f.Profile, f.Issuer, bad)
	if f.ClientID == "" {
		bad("client_id is required")
	}
	switch f.ClientAuthMethod {
	case "", "client_secret_basic":
		f.ClientAuthMethod = "client_secret_basic"
	case "private_key_jwt":
		bad("client_auth_method private_key_jwt is not supported yet; use client_secret_basic")
	default:
		bad("client_auth_method %q: want client_secret_basic", f.ClientAuthMethod)
	}
	if f.Profile == store.ProfileEntra && f.EntraTenantID == "" {
		bad("entra_tenant_id is required for the entra profile")
	}
}

// checkOAuth2 validates an OAuth 2.0-only connection: the github profile
// defaults its endpoints and subject field; generic_oauth2 needs all three
// endpoints (https in prod) and the immutable id field.
func (f *IdPConfig) checkOAuth2(prod bool, bad func(string, ...any)) {
	if f.ClientID == "" {
		bad("client_id is required")
	}
	if f.Issuer != "" || f.IdPEntityID != "" || f.SubjectSource != "" {
		bad("issuer, idp_entity_id and subject_source are not OAuth 2.0 settings (use subject_field)")
	}
	switch f.ClientAuthMethod {
	case "", "client_secret_basic":
	default:
		bad("client_auth_method %q: OAuth 2.0 connections use a client secret", f.ClientAuthMethod)
	}
	eps := map[string]string{"authorization_endpoint": f.AuthorizationEndpoint, "token_endpoint": f.TokenEndpoint,
		"userinfo_endpoint": f.UserinfoEndpoint}
	for name, v := range eps {
		if v == "" {
			if f.Profile != store.ProfileGitHub {
				bad("%s is required for generic_oauth2", name)
			}
			continue
		}
		u, err := url.Parse(v)
		switch {
		case err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http"):
			bad("%s must be an absolute URL", name)
		case prod && u.Scheme != "https":
			bad("%s must be https with TESSERA_ENV=prod", name)
		}
	}
	switch strings.ToLower(f.SubjectField) {
	case "":
		if f.Profile != store.ProfileGitHub {
			bad("subject_field is required for generic_oauth2: the user object's immutable id field")
		}
	case "email", "login", "username", "preferred_username", "name", "upn":
		bad("subject_field %q: users are keyed on an immutable id, never a name or email", f.SubjectField)
	}
}

// checkSAML validates the SAML fields: an exact entity ID, an SSO URL
// (https in prod) and at least one pinned signing certificate.
func (f *IdPConfig) checkSAML(prod bool, bad func(string, ...any)) {
	if f.IdPEntityID == "" {
		bad("idp_entity_id is required")
	}
	sso, err := url.Parse(f.IdPSSOURL)
	switch {
	case f.IdPSSOURL == "" || err != nil || sso.Host == "":
		bad("idp_sso_url must be an absolute URL")
	case prod && sso.Scheme != "https":
		bad("idp_sso_url must be https with TESSERA_ENV=prod")
	}
	if len(f.IdPSigningCerts) == 0 {
		bad("idp_signing_certs: pin at least one signing certificate")
	} else if _, err := samlsp.ParseCerts(f.IdPSigningCerts); err != nil {
		bad("idp_signing_certs: %v", err)
	}
	if f.SubjectSource != "" && f.SubjectSource != "nameid_persistent" &&
		(!strings.HasPrefix(f.SubjectSource, "attribute:") || len(f.SubjectSource) == len("attribute:")) {
		bad("subject_source %q: want nameid_persistent or attribute:<name> (never email)", f.SubjectSource)
	}
	for k := range f.AttributeMap {
		if !slices.Contains([]string{"email", "name", "groups"}, k) {
			bad("attribute_map: unknown key %q (want email, name, groups)", k)
		}
	}
	if f.ClientID != "" || f.Issuer != "" {
		bad("issuer and client_id are OIDC settings; a SAML connection uses idp_entity_id and idp_sso_url")
	}
}
