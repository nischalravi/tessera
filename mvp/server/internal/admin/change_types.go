package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	authnorm "github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/samlsp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The change types of design §15.2. Each has a payload struct (decoded with
// DisallowUnknownFields), a plan (validation against the tenant's current
// state plus the policy: who approves, how long it waits) and an applier.
// The applier runs the plan again, so a request that went stale while it
// waited is refused rather than applied.

// revokedTrustChanged is the revocation reason of the sessions that signed in
// through a connection whose trust changed (§15.6).
const revokedTrustChanged = "idp_trust_changed"

var changeTypes = map[string]*changeType{
	TypeRoleGrant: typed(TypeRoleGrant, nil, planRoleGrant, applyRoleGrant,
		func(e *env, v *roleGrantPayload) string {
			return fmt.Sprintf("Grant %s to %s", v.Role, e.name(v.UserID))
		}),
	TypeRoleRevoke: typed(TypeRoleRevoke, nil, planRoleRevoke, applyRoleRevoke,
		func(e *env, v *roleRevokePayload) string {
			return fmt.Sprintf("Revoke %s from %s", v.Role, e.name(v.UserID))
		}),
	TypeIdPCreate: withSecret(typed(TypeIdPCreate, func(v *idpCreatePayload) {
		if v.ConnectionID == uuid.Nil {
			v.ConnectionID = uuid.New()
		}
	}, planIdPCreate, applyIdPCreate,
		func(_ *env, v *idpCreatePayload) string {
			return fmt.Sprintf("Create IdP connection %q (%s, %s)", v.Name, v.Protocol, v.Profile)
		})),
	TypeIdPUpdateTrust: typed(TypeIdPUpdateTrust, nil, planIdPTrust, applyIdPTrust,
		func(e *env, v *idpTrustPayload) string {
			return fmt.Sprintf("Change the trust settings of IdP connection %s (%s)", e.connName(v.ConnectionID),
				strings.Join(v.fields(), ", "))
		}),
	TypeIdPUpdateCosmetic: typed(TypeIdPUpdateCosmetic, nil, planIdPCosmetic, applyIdPCosmetic,
		func(e *env, v *idpCosmeticPayload) string {
			return "Change the display settings of IdP connection " + e.connName(v.ConnectionID)
		}),
	TypeIdPDisable: typed(TypeIdPDisable, nil, planIdPDisable, applyIdPDisable,
		func(e *env, v *idpDisablePayload) string {
			return "Disable IdP connection " + e.connName(v.ConnectionID)
		}),
	TypeTenantSettings: typed(TypeTenantSettings, nil, planSettings, applySettings,
		func(_ *env, v *settingsPayload) string {
			return "Change tenant settings (" + strings.Join(v.fields(), ", ") + ")"
		}),
	TypeSecurityContacts: typed(TypeSecurityContacts, nil, planContacts, applyContacts,
		func(_ *env, v *contactsPayload) string {
			return fmt.Sprintf("Replace the tenant's security contacts (%d)", len(v.Contacts))
		}),
	TypeBGRegister: typed(TypeBGRegister, prepBGRegister, planBGRegister, applyBGRegister,
		func(_ *env, v *bgRegisterPayload) string {
			return fmt.Sprintf("Enrol the break-glass key %q (custodian %s)", v.Label, v.Custodian)
		}),
	TypeBGRevoke: typed(TypeBGRevoke, nil, planBGRevoke, applyBGRevoke,
		func(e *env, v *bgRevokePayload) string {
			return "Revoke the break-glass key " + e.bgKeyName(v.CredentialID)
		}),
}

// withSecret marks the type that carries a sealed client secret.
func withSecret(t *changeType) *changeType {
	t.submitSecret = func(e *env, v any, id uuid.UUID, secret string) ([]byte, error) {
		p := v.(*idpCreatePayload)
		if !p.NeedsClientSecret() {
			if secret != "" {
				return nil, invalid("a SAML connection has no client secret")
			}
			return nil, nil
		}
		switch {
		case secret == "":
			return nil, invalid("client_secret is required for an OIDC or OAuth 2.0 connection")
		case len(secret) > maxSecretBytes:
			return nil, invalid("client_secret is longer than %d bytes", maxSecretBytes)
		case e.svc.Sealer == nil:
			return nil, newErr(503, "sealer_unavailable", "no key-encryption key is configured to seal the client secret")
		}
		return e.svc.Sealer.Seal([]byte(secret), secretAAD(e.tx.Tenant(), id))
	}
	return t
}

// secretAAD binds a request's sealed client secret to its tenant and row.
func secretAAD(t tenancy.ID, id uuid.UUID) []byte {
	return seal.AAD(t, "admin_change_requests", "secret_enc", id.String())
}

func (e *env) connName(id uuid.UUID) string {
	c, err := e.tx.IdPConnection(id)
	if err != nil {
		return "unknown connection"
	}
	return c.Name
}

// ---------------------------------------------------------------- role.grant

type roleGrantPayload struct {
	UserID uuid.UUID `json:"user_id"`
	Role   string    `json:"role"`
}

// planRoleGrant: viewer, operator and auditor need one admin with a step-up;
// policy_admin and tenant_admin need two and 24 h. A tenant with fewer than
// two admins may grant tenant_admin with one person and the 24 h (§15.2
// bootstrap). break_glass is enrolled by breakglass.register.
func planRoleGrant(e *env, v *roleGrantPayload) (plan, error) {
	role := auth.Role(v.Role)
	switch role {
	case auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor, auth.RolePolicyAdmin, auth.RoleTenantAdmin:
	case auth.RoleBreakGlass:
		return plan{}, invalid("break_glass is enrolled with a breakglass.register request, not granted")
	default:
		return plan{}, invalid("role %q: want viewer, operator, auditor, policy_admin or tenant_admin", v.Role)
	}
	u, err := e.user(v.UserID)
	if err != nil {
		return plan{}, err
	}
	if u.Status != "active" {
		return plan{}, conflict("user_disabled", "the user is disabled")
	}
	if u.IsBreakGlass {
		return plan{}, conflict("break_glass_user", "a break-glass user holds no other role")
	}
	as, err := e.tx.RoleAssignments(u.ID)
	if err != nil {
		return plan{}, err
	}
	for _, a := range as {
		if a.Role == v.Role && (a.ExpiresAt == nil || a.ExpiresAt.After(e.now)) {
			return plan{}, conflict("already_granted", "the user already holds %s", v.Role)
		}
	}
	pl := plan{target: u.ID.String()}
	if !role.IsAdmin() {
		return pl, nil
	}
	pl.twoPerson, pl.cooling = true, CoolingOff
	if role == auth.RoleTenantAdmin {
		admins, err := e.activeAdmins()
		if err != nil {
			return plan{}, err
		}
		if len(admins) < bootstrapAdmins {
			pl.twoPerson = false
		}
	}
	return pl, nil
}

func applyRoleGrant(e *env, ch *store.AdminChange, v *roleGrantPayload) error {
	if _, err := planRoleGrant(e, v); err != nil {
		return err
	}
	by, cid := ch.RequestedBy, ch.ID.String()
	err := e.tx.InsertRoleAssignment(&store.RoleAssignment{UserID: v.UserID, Role: v.Role, Source: store.RoleSourceManual,
		GrantedByUserID: &by, ChangeRequestID: &cid, CreatedAt: e.now})
	if errors.Is(err, store.ErrDuplicate) {
		return conflict("already_granted", "the user already holds %s", v.Role)
	}
	if err != nil {
		return err
	}
	// the target's sessions re-evaluate their active roles (§15.6)
	_, err = e.tx.RevokeUserSessions(v.UserID, auth.RevokedRoleChange, e.now)
	return err
}

// ---------------------------------------------------------------- role.revoke

type roleRevokePayload struct {
	UserID uuid.UUID `json:"user_id"`
	Role   string    `json:"role"`
}

// planRoleRevoke: revoking another user's admin role needs two people (no
// cooling-off); a non-admin role, or your own, needs one. Removing a
// tenant_admin is refused if fewer than min_admins active admins would remain.
func planRoleRevoke(e *env, v *roleRevokePayload) (plan, error) {
	role := auth.Role(v.Role)
	if !slices.Contains(auth.AllRoles(), role) {
		return plan{}, invalid("unknown role %q", v.Role)
	}
	if role == auth.RoleBreakGlass {
		return plan{}, invalid("break_glass is removed with a breakglass.revoke request")
	}
	u, err := e.user(v.UserID)
	if err != nil {
		return plan{}, err
	}
	as, err := e.tx.RoleAssignments(u.ID)
	if err != nil {
		return plan{}, err
	}
	if !slices.ContainsFunc(as, func(a *store.RoleAssignment) bool { return a.Role == v.Role }) {
		return plan{}, conflict("not_assigned", "the user does not hold %s", v.Role)
	}
	pl := plan{target: u.ID.String(), twoPerson: role.IsAdmin() && u.ID != e.by}
	if role == auth.RoleTenantAdmin {
		isAdmin, err := e.isActiveAdmin(u.ID)
		if err != nil {
			return plan{}, err
		}
		if isAdmin {
			t, err := e.tenantRecord()
			if err != nil {
				return plan{}, err
			}
			admins, err := e.activeAdmins()
			if err != nil {
				return plan{}, err
			}
			if len(admins)-1 < t.MinAdmins {
				return plan{}, conflict("min_admins", "this would leave %d active admins; the tenant needs at least %d",
					len(admins)-1, t.MinAdmins)
			}
		}
	}
	return pl, nil
}

func applyRoleRevoke(e *env, _ *store.AdminChange, v *roleRevokePayload) error {
	if _, err := planRoleRevoke(e, v); err != nil {
		return err
	}
	as, err := e.tx.RoleAssignments(v.UserID)
	if err != nil {
		return err
	}
	for _, a := range as {
		if a.Role == v.Role {
			if err := e.tx.DeleteRoleAssignment(a.ID); err != nil {
				return err
			}
		}
	}
	_, err = e.tx.RevokeUserSessions(v.UserID, auth.RevokedRoleChange, e.now)
	return err
}

// ---------------------------------------------------------------- idp_connection.create

type idpCreatePayload struct {
	ConnectionID uuid.UUID `json:"connection_id"`
	IdPConfig
}

func (v *idpCreatePayload) options(e *env) IdPOptions {
	return IdPOptions{Prod: e.svc.Prod, AllowAssumePhr: true}
}

// planIdPCreate: two people and 24 h. The connection is created pending when
// applied; it becomes active after the requester's successful test login.
func planIdPCreate(e *env, v *idpCreatePayload) (plan, error) {
	cfg := v.IdPConfig.Clone()
	if _, err := cfg.Connection(v.options(e), e.now); err != nil {
		return plan{}, invalid("%v", err)
	}
	if v.ConnectionID == uuid.Nil {
		return plan{}, invalid("connection_id is required")
	}
	if _, err := e.tx.IdPConnection(v.ConnectionID); err == nil {
		return plan{}, conflict("connection_exists", "a connection with that id exists")
	} else if !errors.Is(err, store.ErrNotFound) {
		return plan{}, err
	}
	cs, err := e.tx.IdPConnections()
	if err != nil {
		return plan{}, err
	}
	name := strings.TrimSpace(v.Name)
	if slices.ContainsFunc(cs, func(c *store.IdPConnection) bool { return strings.EqualFold(c.Name, name) }) {
		return plan{}, conflict("name_taken", "a connection named %q exists", name)
	}
	return plan{twoPerson: true, cooling: CoolingOff, target: v.ConnectionID.String()}, nil
}

func applyIdPCreate(e *env, ch *store.AdminChange, v *idpCreatePayload) error {
	if _, err := planIdPCreate(e, v); err != nil {
		return err
	}
	cfg := v.IdPConfig.Clone()
	conn, err := cfg.Connection(v.options(e), e.now)
	if err != nil {
		return invalid("%v", err)
	}
	conn.ID = v.ConnectionID
	cid := ch.ID.String()
	conn.LastChangeRequestID = &cid
	if e.svc.Sealer == nil {
		return newErr(503, "sealer_unavailable", "no key-encryption key is configured to seal the connection's secrets")
	}
	t := e.tx.Tenant()
	if cfg.NeedsClientSecret() {
		if len(ch.SecretEnc) == 0 {
			return invalid("the sealed client secret is missing")
		}
		secret, err := e.svc.Sealer.Open(ch.SecretEnc, secretAAD(t, ch.ID))
		if err != nil {
			return fmt.Errorf("open the request's client secret: %w", err)
		}
		if conn.ClientSecretEnc, err = e.svc.Sealer.Seal(secret, auth.ClientSecretAAD(t, conn.ID)); err != nil {
			return err
		}
	} else {
		keyPEM, certPEM, err := samlsp.GenerateSPKey("Tessera SP "+conn.ID.String(), e.now)
		if err != nil {
			return err
		}
		if conn.SPKeyEnc, err = e.svc.Sealer.Seal(keyPEM, auth.SPKeyAAD(t, conn.ID)); err != nil {
			return err
		}
		conn.SPCertPEM = &certPEM
	}
	conn.Status = "pending"
	if err := e.tx.InsertIdPConnection(conn); errors.Is(err, store.ErrDuplicate) {
		return conflict("name_taken", "a connection named %q exists", conn.Name)
	} else if err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------- idp_connection.update_trust

// idpTrustPayload is a diff: only the fields present change. These are the
// fields that decide whom the connection trusts (§15.2).
type idpTrustPayload struct {
	ConnectionID          uuid.UUID          `json:"connection_id"`
	Issuer                *string            `json:"issuer,omitempty"`
	DiscoveryURL          *string            `json:"discovery_url,omitempty"`
	ClientID              *string            `json:"client_id,omitempty"`
	IdPEntityID           *string            `json:"idp_entity_id,omitempty"`
	IdPSSOURL             *string            `json:"idp_sso_url,omitempty"`
	IdPSigningCerts       *[]string          `json:"idp_signing_certs,omitempty"`
	MetadataURL           *string            `json:"metadata_url,omitempty"`
	AuthorizationEndpoint *string            `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         *string            `json:"token_endpoint,omitempty"`
	UserinfoEndpoint      *string            `json:"userinfo_endpoint,omitempty"`
	SubjectSource         *string            `json:"subject_source,omitempty"`
	AssumePhr             *bool              `json:"assume_phishing_resistant,omitempty"`
	AuthnMapping          *map[string]any    `json:"authn_mapping,omitempty"`
	StepUpRequest         *map[string]any    `json:"step_up_request,omitempty"`
	GroupRoleMapping      *map[string]string `json:"group_role_mapping,omitempty"`
}

// fields names the fields the diff changes.
func (v *idpTrustPayload) fields() []string {
	var out []string
	add := func(set bool, name string) {
		if set {
			out = append(out, name)
		}
	}
	add(v.Issuer != nil, "issuer")
	add(v.DiscoveryURL != nil, "discovery_url")
	add(v.ClientID != nil, "client_id")
	add(v.IdPEntityID != nil, "idp_entity_id")
	add(v.IdPSSOURL != nil, "idp_sso_url")
	add(v.IdPSigningCerts != nil, "idp_signing_certs")
	add(v.MetadataURL != nil, "metadata_url")
	add(v.AuthorizationEndpoint != nil, "authorization_endpoint")
	add(v.TokenEndpoint != nil, "token_endpoint")
	add(v.UserinfoEndpoint != nil, "userinfo_endpoint")
	add(v.SubjectSource != nil, "subject_source")
	add(v.AssumePhr != nil, "assume_phishing_resistant")
	add(v.AuthnMapping != nil, "authn_mapping")
	add(v.StepUpRequest != nil, "step_up_request")
	add(v.GroupRoleMapping != nil, "group_role_mapping")
	return out
}

// applyTo validates the diff against c's protocol and writes it into c.
func (v *idpTrustPayload) applyTo(c *store.IdPConnection, prod bool) error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	only := func(set bool, field string, protocols ...string) bool {
		if !set {
			return false
		}
		if !slices.Contains(protocols, c.Protocol) {
			bad("%s does not apply to a %s connection", field, c.Protocol)
			return false
		}
		return true
	}
	str := func(s *string) *string { x := *s; return &x }
	if only(v.Issuer != nil, "issuer", "oidc") {
		checkIssuer(prod, c.Profile, *v.Issuer, bad)
		c.Issuer = str(v.Issuer)
	}
	if only(v.DiscoveryURL != nil, "discovery_url", "oidc") {
		if *v.DiscoveryURL != "" {
			checkEndpoint(prod, "discovery_url", *v.DiscoveryURL, bad)
		}
		c.DiscoveryURL = str(v.DiscoveryURL)
	}
	if only(v.ClientID != nil, "client_id", "oidc", "oauth2") {
		if strings.TrimSpace(*v.ClientID) == "" || len(*v.ClientID) > 255 {
			bad("client_id is required (at most 255 characters)")
		}
		c.ClientID = str(v.ClientID)
	}
	if only(v.IdPEntityID != nil, "idp_entity_id", "saml") {
		if strings.TrimSpace(*v.IdPEntityID) == "" {
			bad("idp_entity_id is required")
		}
		c.IdPEntityID = str(v.IdPEntityID)
	}
	if only(v.IdPSSOURL != nil, "idp_sso_url", "saml") {
		checkEndpoint(prod, "idp_sso_url", *v.IdPSSOURL, bad)
		c.IdPSSOURL = str(v.IdPSSOURL)
	}
	if only(v.IdPSigningCerts != nil, "idp_signing_certs", "saml") {
		if len(*v.IdPSigningCerts) == 0 {
			bad("idp_signing_certs: pin at least one signing certificate")
		} else if _, err := samlsp.ParseCerts(*v.IdPSigningCerts); err != nil {
			bad("idp_signing_certs: %v", err)
		}
		c.IdPSigningCerts = mustJSON(*v.IdPSigningCerts)
	}
	if only(v.MetadataURL != nil, "metadata_url", "saml") {
		if *v.MetadataURL != "" {
			checkEndpoint(prod, "metadata_url", *v.MetadataURL, bad)
		}
		c.MetadataURL = str(v.MetadataURL)
	}
	for _, f := range []struct {
		in   *string
		name string
		out  **string
	}{{v.AuthorizationEndpoint, "authorization_endpoint", &c.AuthorizationEndpoint},
		{v.TokenEndpoint, "token_endpoint", &c.TokenEndpoint}, {v.UserinfoEndpoint, "userinfo_endpoint", &c.UserinfoEndpoint}} {
		if only(f.in != nil, f.name, "oauth2") {
			checkEndpoint(prod, f.name, *f.in, bad)
			*f.out = str(f.in)
		}
	}
	if v.SubjectSource != nil {
		checkSubjectSource(c.Protocol, *v.SubjectSource, bad)
		c.SubjectSource = *v.SubjectSource
	}
	if v.AssumePhr != nil {
		c.AssumePhishingResistant = *v.AssumePhr
	}
	if v.AuthnMapping != nil {
		b := mustJSON(*v.AuthnMapping)
		if _, err := authnorm.ParseMapping(b); err != nil {
			bad("authn_mapping: %v", err)
		}
		c.AuthnMapping = b
	}
	if v.StepUpRequest != nil {
		b := mustJSON(*v.StepUpRequest)
		if len(b) > 16<<10 {
			bad("step_up_request is larger than 16 KiB")
		}
		c.StepUpRequest = b
	}
	if v.GroupRoleMapping != nil {
		if len(*v.GroupRoleMapping) > 500 {
			bad("group_role_mapping has more than 500 entries")
		}
		for g, r := range *v.GroupRoleMapping {
			if strings.TrimSpace(g) == "" || len(g) > 256 {
				bad("group_role_mapping: group names are 1 to 256 characters")
			}
			if !slices.Contains(groupRoles, r) {
				bad("group_role_mapping[%q] = %q: groups grant viewer, operator or auditor only (never admin roles)", g, r)
			}
		}
		c.GroupRoleMapping = mustJSON(*v.GroupRoleMapping)
	}
	return errors.Join(errs...)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

// planIdPTrust: two people and 24 h; applying revokes every session that
// came through the connection.
func planIdPTrust(e *env, v *idpTrustPayload) (plan, error) {
	c, err := e.connection(v.ConnectionID)
	if err != nil {
		return plan{}, err
	}
	if c.Status == "disabled" {
		return plan{}, conflict("connection_disabled", "the connection is disabled")
	}
	if len(v.fields()) == 0 {
		return plan{}, invalid("no field to change")
	}
	next := *c
	if err := v.applyTo(&next, e.svc.Prod); err != nil {
		return plan{}, invalid("%v", err)
	}
	return plan{twoPerson: true, cooling: CoolingOff, target: c.ID.String()}, nil
}

func applyIdPTrust(e *env, ch *store.AdminChange, v *idpTrustPayload) error {
	if _, err := planIdPTrust(e, v); err != nil {
		return err
	}
	c, err := e.connection(v.ConnectionID)
	if err != nil {
		return err
	}
	if err := v.applyTo(c, e.svc.Prod); err != nil {
		return invalid("%v", err)
	}
	cid := ch.ID.String()
	if err := e.tx.UpdateIdPConnectionTrust(c, e.now, &cid); err != nil {
		return err
	}
	_, err = e.tx.RevokeConnectionSessions(c.ID, revokedTrustChanged, e.now)
	return err
}

// ---------------------------------------------------------------- idp_connection.update_cosmetic

type idpCosmeticPayload struct {
	ConnectionID    uuid.UUID `json:"connection_id"`
	Name            *string   `json:"name,omitempty"`
	VerifiedDomains *[]string `json:"verified_domains,omitempty"`
	IsDefault       *bool     `json:"is_default,omitempty"`
}

var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// cosmetic returns the connection with the diff applied.
func (v *idpCosmeticPayload) cosmetic(e *env, c *store.IdPConnection) (*store.IdPConnection, error) {
	if v.Name == nil && v.VerifiedDomains == nil && v.IsDefault == nil {
		return nil, invalid("no field to change")
	}
	next := *c
	if v.Name != nil {
		name := strings.TrimSpace(*v.Name)
		if name == "" || len(name) > 200 {
			return nil, invalid("name is required (at most 200 characters)")
		}
		cs, err := e.tx.IdPConnections()
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(cs, func(o *store.IdPConnection) bool { return o.ID != c.ID && strings.EqualFold(o.Name, name) }) {
			return nil, conflict("name_taken", "a connection named %q exists", name)
		}
		next.Name = name
	}
	if v.VerifiedDomains != nil {
		if len(*v.VerifiedDomains) > 50 {
			return nil, invalid("verified_domains has more than 50 entries")
		}
		out := make([]string, 0, len(*v.VerifiedDomains))
		for _, d := range *v.VerifiedDomains {
			d = strings.ToLower(strings.TrimSpace(d))
			if len(d) > 253 || !domainRE.MatchString(d) {
				return nil, invalid("verified_domains: %q is not a domain name", d)
			}
			if !slices.Contains(out, d) {
				out = append(out, d)
			}
		}
		next.VerifiedDomains = mustJSON(out)
	}
	if v.IsDefault != nil {
		if *v.IsDefault && c.Status != "active" {
			return nil, conflict("connection_not_active", "only an active connection can be the default")
		}
		next.IsDefault = *v.IsDefault
	}
	return &next, nil
}

// planIdPCosmetic: one admin with a step-up, no cooling-off.
func planIdPCosmetic(e *env, v *idpCosmeticPayload) (plan, error) {
	c, err := e.connection(v.ConnectionID)
	if err != nil {
		return plan{}, err
	}
	if _, err := v.cosmetic(e, c); err != nil {
		return plan{}, err
	}
	return plan{target: c.ID.String()}, nil
}

func applyIdPCosmetic(e *env, ch *store.AdminChange, v *idpCosmeticPayload) error {
	c, err := e.connection(v.ConnectionID)
	if err != nil {
		return err
	}
	next, err := v.cosmetic(e, c)
	if err != nil {
		return err
	}
	cid := ch.ID.String()
	if err := e.tx.UpdateIdPConnectionCosmetic(next, e.now, &cid); errors.Is(err, store.ErrDuplicate) {
		return conflict("name_taken", "a connection named %q exists", next.Name)
	} else if err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------- idp_connection.disable

type idpDisablePayload struct {
	ConnectionID uuid.UUID `json:"connection_id"`
}

// planIdPDisable: one admin, immediate. Refused for the last active
// connection unless a break-glass user exists to sign in without it.
func planIdPDisable(e *env, v *idpDisablePayload) (plan, error) {
	c, err := e.connection(v.ConnectionID)
	if err != nil {
		return plan{}, err
	}
	if c.Status == "disabled" {
		return plan{}, conflict("already_disabled", "the connection is already disabled")
	}
	if c.Status == "active" {
		cs, err := e.tx.IdPConnections()
		if err != nil {
			return plan{}, err
		}
		others := 0
		for _, o := range cs {
			if o.ID != c.ID && o.Status == "active" {
				others++
			}
		}
		if others == 0 {
			us, err := e.tx.PlatformUsers()
			if err != nil {
				return plan{}, err
			}
			if !slices.ContainsFunc(us, func(u *store.PlatformUser) bool { return u.IsBreakGlass && u.Status == "active" }) {
				return plan{}, conflict("last_connection", "this is the last active IdP connection and no break-glass key exists; "+
					"disabling it would lock everyone out")
			}
		}
	}
	return plan{target: c.ID.String()}, nil
}

func applyIdPDisable(e *env, ch *store.AdminChange, v *idpDisablePayload) error {
	if _, err := planIdPDisable(e, v); err != nil {
		return err
	}
	c, err := e.connection(v.ConnectionID)
	if err != nil {
		return err
	}
	cid := ch.ID.String()
	if err := e.tx.SetIdPConnectionStatus(c.ID, c.Status, "disabled", e.now, &cid); err != nil {
		return err
	}
	_, err = e.tx.RevokeConnectionSessions(c.ID, auth.RevokedIdPDisabled, e.now)
	return err
}

// ---------------------------------------------------------------- tenant.settings.update

// settingsPayload is a diff of the tenant settings of §18.3 and of the
// min_admins floor (which lives on the tenant row). Ranges are the design's.
type settingsPayload struct {
	LoginACR              *string `json:"login_acr,omitempty"`
	RequirePhrForAll      *bool   `json:"require_phr_for_all,omitempty"`
	SessionAdminIdleS     *int    `json:"session_admin_idle_s,omitempty"`
	SessionAdminAbsoluteS *int    `json:"session_admin_absolute_s,omitempty"`
	SessionUserIdleS      *int    `json:"session_user_idle_s,omitempty"`
	SessionUserAbsoluteS  *int    `json:"session_user_absolute_s,omitempty"`
	StepUpPolicyMaxAgeS   *int    `json:"step_up_policy_max_age_s,omitempty"`
	StepUpAdminMaxAgeS    *int    `json:"step_up_admin_max_age_s,omitempty"`
	DeviceGrantEnabled    *bool   `json:"device_grant_enabled,omitempty"`
	MinAdmins             *int    `json:"min_admins,omitempty"`
	// BreakGlassAAGUIDAllowlist limits the authenticator models a break-glass
	// key may be (§15.4). An empty list lifts the limit.
	BreakGlassAAGUIDAllowlist *[]string `json:"breakglass_aaguid_allowlist,omitempty"`
}

type intSetting struct {
	key         string
	get         func(*settingsPayload) *int
	def, lo, hi int
}

var intSettings = []intSetting{
	{"session_admin_idle_s", func(v *settingsPayload) *int { return v.SessionAdminIdleS }, 900, 300, 3600},
	{"session_admin_absolute_s", func(v *settingsPayload) *int { return v.SessionAdminAbsoluteS }, 43200, 3600, 43200},
	{"session_user_idle_s", func(v *settingsPayload) *int { return v.SessionUserIdleS }, 3600, 900, 14400},
	{"session_user_absolute_s", func(v *settingsPayload) *int { return v.SessionUserAbsoluteS }, 86400, 3600, 86400},
	{"step_up_policy_max_age_s", func(v *settingsPayload) *int { return v.StepUpPolicyMaxAgeS }, 900, 60, 900},
	{"step_up_admin_max_age_s", func(v *settingsPayload) *int { return v.StepUpAdminMaxAgeS }, 300, 60, 300},
}

// maxMinAdmins bounds the min_admins floor.
const maxMinAdmins = 100

func (v *settingsPayload) fields() []string {
	var out []string
	add := func(set bool, k string) {
		if set {
			out = append(out, k)
		}
	}
	add(v.LoginACR != nil, "login_acr")
	add(v.RequirePhrForAll != nil, "require_phr_for_all")
	for _, s := range intSettings {
		add(s.get(v) != nil, s.key)
	}
	add(v.DeviceGrantEnabled != nil, "device_grant_enabled")
	add(v.MinAdmins != nil, "min_admins")
	add(v.BreakGlassAAGUIDAllowlist != nil, keyAAGUIDAllowlist)
	return out
}

// keyAAGUIDAllowlist is the tenant setting that limits break-glass key models.
const keyAAGUIDAllowlist = "breakglass_aaguid_allowlist"

// maxAAGUIDs bounds the allowlist.
const maxAAGUIDs = 50

// settingsView is the tenant's current settings with defaults filled in.
type settingsView struct {
	raw       map[string]json.RawMessage
	loginACR  string
	requirePh bool
	ints      map[string]int
	device    bool
	minAdmins int
	// aaguids is the break-glass AAGUID allowlist, canonical lower-case
	// UUIDs, sorted; empty means any model.
	aaguids []string
}

// normalizeAAGUIDs validates an allowlist and returns it as canonical
// lower-case UUIDs, sorted and without duplicates.
func normalizeAAGUIDs(in []string) ([]string, error) {
	if len(in) > maxAAGUIDs {
		return nil, invalid("%s has more than %d entries", keyAAGUIDAllowlist, maxAAGUIDs)
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		id, err := uuid.Parse(strings.TrimSpace(s))
		if err != nil || len(strings.TrimSpace(s)) != 36 {
			return nil, invalid("%s: %q is not an AAGUID (a UUID such as 2fc0579f-8113-47ea-b116-bb5a8db9202a)", keyAAGUIDAllowlist, s)
		}
		if c := id.String(); !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out, nil
}

// aaguidsWiden reports whether next admits a model cur does not: any model
// (an empty list) where cur limited them, or a model cur did not list.
func aaguidsWiden(cur, next []string) bool {
	if len(cur) == 0 {
		return false
	}
	if len(next) == 0 {
		return true
	}
	for _, a := range next {
		if !slices.Contains(cur, a) {
			return true
		}
	}
	return false
}

func viewSettings(t store.Tenant) settingsView {
	s := settingsView{raw: map[string]json.RawMessage{}, loginACR: authnorm.ACRPhr, ints: map[string]int{}, device: true,
		minAdmins: t.MinAdmins}
	_ = json.Unmarshal([]byte(t.Settings), &s.raw)
	if s.raw == nil {
		s.raw = map[string]json.RawMessage{}
	}
	if b, ok := s.raw["login_acr"]; ok {
		var x string
		if json.Unmarshal(b, &x) == nil && slices.Contains(loginACRs, x) {
			s.loginACR = x
		}
	}
	if b, ok := s.raw["require_phr_for_all"]; ok {
		_ = json.Unmarshal(b, &s.requirePh)
	}
	if b, ok := s.raw["device_grant_enabled"]; ok {
		_ = json.Unmarshal(b, &s.device)
	}
	if b, ok := s.raw[keyAAGUIDAllowlist]; ok {
		var list []string
		if json.Unmarshal(b, &list) == nil {
			s.aaguids, _ = normalizeAAGUIDs(list)
		}
	}
	for _, d := range intSettings {
		s.ints[d.key] = d.def
		if b, ok := s.raw[d.key]; ok {
			var x int
			if json.Unmarshal(b, &x) == nil && x >= d.lo && x <= d.hi {
				s.ints[d.key] = x
			}
		}
	}
	return s
}

var loginACRs = []string{authnorm.ACRAAL2, authnorm.ACRPhr, authnorm.ACRPhrh}

func acrRank(a string) int { return slices.Index(loginACRs, a) }

// weakens reports whether the diff lowers a protection of the tenant: a
// weaker login, longer sessions or step-up windows, an enabled device grant,
// a lower floor. Only a weakening change needs two people and 24 h.
func (v *settingsPayload) weakens(cur settingsView) bool {
	w := v.LoginACR != nil && acrRank(*v.LoginACR) < acrRank(cur.loginACR)
	w = w || (v.RequirePhrForAll != nil && cur.requirePh && !*v.RequirePhrForAll)
	for _, s := range intSettings {
		if n := s.get(v); n != nil && *n > cur.ints[s.key] {
			w = true
		}
	}
	w = w || (v.DeviceGrantEnabled != nil && *v.DeviceGrantEnabled && !cur.device)
	w = w || (v.MinAdmins != nil && *v.MinAdmins < cur.minAdmins)
	if v.BreakGlassAAGUIDAllowlist != nil {
		next, _ := normalizeAAGUIDs(*v.BreakGlassAAGUIDAllowlist) // check() has refused a bad list
		w = w || aaguidsWiden(cur.aaguids, next)
	}
	return w
}

// changes reports whether the diff changes any value.
func (v *settingsPayload) changes(cur settingsView) bool {
	c := v.LoginACR != nil && *v.LoginACR != cur.loginACR
	c = c || (v.RequirePhrForAll != nil && *v.RequirePhrForAll != cur.requirePh)
	for _, s := range intSettings {
		if n := s.get(v); n != nil && *n != cur.ints[s.key] {
			c = true
		}
	}
	c = c || (v.DeviceGrantEnabled != nil && *v.DeviceGrantEnabled != cur.device)
	c = c || (v.MinAdmins != nil && *v.MinAdmins != cur.minAdmins)
	if v.BreakGlassAAGUIDAllowlist != nil {
		next, _ := normalizeAAGUIDs(*v.BreakGlassAAGUIDAllowlist)
		c = c || !slices.Equal(next, cur.aaguids)
	}
	return c
}

func (v *settingsPayload) check(cur settingsView) error {
	if len(v.fields()) == 0 {
		return invalid("no setting to change")
	}
	if v.LoginACR != nil && !slices.Contains(loginACRs, *v.LoginACR) {
		return invalid("login_acr %q: want one of %s", *v.LoginACR, strings.Join(loginACRs, ", "))
	}
	next := map[string]int{}
	for _, s := range intSettings {
		next[s.key] = cur.ints[s.key]
		if n := s.get(v); n != nil {
			if *n < s.lo || *n > s.hi {
				return invalid("%s %d: allowed range is %d to %d", s.key, *n, s.lo, s.hi)
			}
			next[s.key] = *n
		}
	}
	if next["session_admin_idle_s"] > next["session_admin_absolute_s"] || next["session_user_idle_s"] > next["session_user_absolute_s"] {
		return invalid("an idle timeout cannot exceed its absolute timeout")
	}
	if v.MinAdmins != nil && (*v.MinAdmins < 2 || *v.MinAdmins > maxMinAdmins) {
		return invalid("min_admins %d: allowed range is 2 to %d", *v.MinAdmins, maxMinAdmins)
	}
	if v.BreakGlassAAGUIDAllowlist != nil {
		if _, err := normalizeAAGUIDs(*v.BreakGlassAAGUIDAllowlist); err != nil {
			return err
		}
	}
	if !v.changes(cur) {
		return invalid("the diff changes nothing")
	}
	return nil
}

// planSettings: strengthening one admin, immediate; weakening two people and 24 h.
func planSettings(e *env, v *settingsPayload) (plan, error) {
	t, err := e.tenantRecord()
	if err != nil {
		return plan{}, err
	}
	cur := viewSettings(t)
	if err := v.check(cur); err != nil {
		return plan{}, err
	}
	pl := plan{target: "tenant"}
	if v.weakens(cur) {
		pl.twoPerson, pl.cooling = true, CoolingOff
	}
	return pl, nil
}

func applySettings(e *env, _ *store.AdminChange, v *settingsPayload) error {
	if _, err := planSettings(e, v); err != nil {
		return err
	}
	t, err := e.tenantRecord()
	if err != nil {
		return err
	}
	cur := viewSettings(t)
	set := func(k string, x any) { cur.raw[k] = mustJSON(x) }
	if v.LoginACR != nil {
		set("login_acr", *v.LoginACR)
	}
	if v.RequirePhrForAll != nil {
		set("require_phr_for_all", *v.RequirePhrForAll)
	}
	for _, s := range intSettings {
		if n := s.get(v); n != nil {
			set(s.key, *n)
		}
	}
	if v.DeviceGrantEnabled != nil {
		set("device_grant_enabled", *v.DeviceGrantEnabled)
	}
	if v.BreakGlassAAGUIDAllowlist != nil {
		list, err := normalizeAAGUIDs(*v.BreakGlassAAGUIDAllowlist)
		if err != nil {
			return err
		}
		set(keyAAGUIDAllowlist, list)
	}
	b, err := json.Marshal(cur.raw)
	if err != nil {
		return err
	}
	if err := e.tx.UpdateTenantSettings(string(b)); err != nil {
		return err
	}
	if v.MinAdmins != nil {
		return e.tx.UpdateTenantMinAdmins(*v.MinAdmins)
	}
	return nil
}

// ---------------------------------------------------------------- tenant.security_contacts.update

type contactsPayload struct {
	Contacts []Contact `json:"contacts"`
}

const maxContacts = 10

// normalized validates the contacts and returns them with lower-cased addresses.
func (v *contactsPayload) normalized() ([]Contact, error) {
	if len(v.Contacts) == 0 || len(v.Contacts) > maxContacts {
		return nil, invalid("contacts: give 1 to %d security contacts", maxContacts)
	}
	out := make([]Contact, 0, len(v.Contacts))
	seen := map[string]bool{}
	for _, c := range v.Contacts {
		name, email := strings.TrimSpace(c.Name), strings.ToLower(strings.TrimSpace(c.Email))
		addr, err := mail.ParseAddress(email)
		switch {
		case name == "" || len(name) > 200:
			return nil, invalid("contacts: every contact needs a name (at most 200 characters)")
		case err != nil || addr.Address != email || len(email) > 320:
			return nil, invalid("contacts: %q is not an email address", c.Email)
		case seen[email]:
			return nil, invalid("contacts: %q is listed twice", email)
		}
		seen[email] = true
		out = append(out, Contact{Name: name, Email: email})
	}
	return out, nil
}

// planContacts: always two people and 24 h (the contacts decide who may
// request operator recovery, §15.5).
func planContacts(_ *env, v *contactsPayload) (plan, error) {
	if _, err := v.normalized(); err != nil {
		return plan{}, err
	}
	return plan{twoPerson: true, cooling: CoolingOff, target: "tenant"}, nil
}

func applyContacts(e *env, _ *store.AdminChange, v *contactsPayload) error {
	cs, err := v.normalized()
	if err != nil {
		return err
	}
	b, err := json.Marshal(cs)
	if err != nil {
		return err
	}
	return e.tx.UpdateTenantSecurityContacts(string(b))
}
