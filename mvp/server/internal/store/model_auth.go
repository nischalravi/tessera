package store

import (
	"encoding/json"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Tenant is a customer tenant (GLOBAL table). Settings and security contacts
// (design §18.3, §15.5) arrive with the PRs that use them; their columns
// already exist with empty defaults.
type Tenant struct {
	ID        tenancy.ID
	Slug      string // ^[a-z0-9][a-z0-9-]{2,39}$; "_platform" is reserved
	Name      string
	Status    string // active | suspended | recovery
	Cell      string // "local"
	MinAdmins int    // default 2
	CreatedAt time.Time
}

// PlatformSlug is the slug of the reserved tenancy.Platform tenant.
const PlatformSlug = "_platform"

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,39}$`)

// ValidSlug reports whether s may be used as a (non-reserved) tenant slug.
func ValidSlug(s string) bool { return slugRE.MatchString(s) }

// ---------------------------------------------------------------- auth core (PR5)
//
// The rows of schema/0005_auth.sql (design §7.4). Bearer secrets never appear
// here in plain text: Session.SecretHash and LoginTransaction.CookieHash are
// SHA-256 hex digests.

// Roles (design §12.1). The role-to-permission map is internal/auth.
const (
	RoleViewer      = "viewer"
	RoleOperator    = "operator"
	RoleAuditor     = "auditor"
	RolePolicyAdmin = "policy_admin"
	RoleTenantAdmin = "tenant_admin"
	RoleBreakGlass  = "break_glass"
)

// Role-assignment sources.
const (
	RoleSourceManual     = "manual"
	RoleSourceIdPGroup   = "idp_group"
	RoleSourceBootstrap  = "bootstrap"
	RoleSourceBreakGlass = "break_glass"
)

// Session kinds and states.
const (
	SessionBrowser    = "browser"
	SessionCLI        = "cli"
	SessionBreakGlass = "break_glass"

	SessionActive  = "active"
	SessionRevoked = "revoked"
	SessionExpired = "expired"
)

// IdP connection profiles (design §8.2).
const (
	ProfileOkta        = "okta"
	ProfileEntra       = "entra"
	ProfileGoogle      = "google"
	ProfileGenericOIDC = "generic_oidc"
	ProfileGenericSAML = "generic_saml"
	ProfileDevMock     = "dev_mock"
)

// IdPConnection is one of a tenant's OIDC or SAML identity providers. JSON
// columns are kept as raw JSON here; internal/auth decodes them into typed
// structs. Sealed secrets (ClientSecretEnc, SPKeyEnc) are opened only by the
// login flows (PR6, PR9).
type IdPConnection struct {
	ID                      uuid.UUID
	TenantID                tenancy.ID
	Name                    string
	Protocol                string // oidc | saml
	Profile                 string // okta | entra | google | generic_oidc | generic_saml | dev_mock
	Status                  string // pending | active | disabled
	IsDefault               bool
	VerifiedDomains         json.RawMessage // ["acme.com"]: home-realm discovery only
	Issuer                  *string
	DiscoveryURL            *string
	ClientID                *string
	ClientAuthMethod        *string
	ClientSecretEnc         []byte
	ClientSigningKID        *string
	Scopes                  json.RawMessage
	IDTokenAlgs             json.RawMessage
	StepUpRequest           json.RawMessage
	IdPEntityID             *string
	IdPSSOURL               *string
	IdPSigningCerts         json.RawMessage
	MetadataURL             *string
	PinCerts                bool
	SPKeyEnc                []byte
	SPCertPEM               *string
	SubjectSource           string
	AttributeMap            json.RawMessage
	AuthnMapping            json.RawMessage
	AssumePhishingResistant bool
	GroupsClaim             *string
	GroupRoleMapping        json.RawMessage
	JITProvisioning         bool
	DefaultRole             string
	CreatedAt, UpdatedAt    time.Time
	LastChangeRequestID     *string
}

// PlatformUser is a person who signs in to Tessera. Distinct from Identity,
// which is a governed identity in the customer's estate.
type PlatformUser struct {
	ID             uuid.UUID
	TenantID       tenancy.ID
	Email          *string // display and notifications only, never matching
	DisplayName    string
	Status         string // active | disabled
	IsBreakGlass   bool
	IdentityID     *int64
	CreatedAt      time.Time
	LastLoginAt    *time.Time
	DisabledAt     *time.Time
	DisabledReason *string
}

// ExternalLogin is the immutable link (connection, subject) -> user; the
// only way a login resolves to a user.
type ExternalLogin struct {
	ID               uuid.UUID
	TenantID         tenancy.ID
	UserID           uuid.UUID
	IdPConnectionID  uuid.UUID
	Issuer           string
	Subject          string
	EmailAtLastLogin *string
	CreatedAt        time.Time
	LastSeenAt       *time.Time
}

// RoleAssignment grants a role to a platform user.
type RoleAssignment struct {
	ID              uuid.UUID
	TenantID        tenancy.ID
	UserID          uuid.UUID
	Role            string
	Source          string
	GrantedByUserID *uuid.UUID
	ChangeRequestID *string // required for admin roles unless Source is bootstrap
	CreatedAt       time.Time
	ExpiresAt       *time.Time
}

// AuthnContextRecord is one successful authentication or step-up, immutable
// once written (a trigger refuses UPDATE and DELETE).
type AuthnContextRecord struct {
	ID                uuid.UUID
	TenantID          tenancy.ID
	UserID            uuid.UUID
	IdPConnectionID   *uuid.UUID // nil for break-glass
	Protocol          string     // oidc | saml | webauthn
	Purpose           string     // login | step_up | device_approval | break_glass | bootstrap
	ACR               *string    // raw, as asserted
	AMR               []string   // raw, as asserted
	Methods           []string   // RFC 8176 vocabulary
	AAL               int        // 0 unknown | 1 | 2 | 3
	PhishingResistant bool
	PhrBasis          string // acr | amr | connection_attestation | webauthn_attested | none
	TesseraACR        string // urn:tessera:acr:{aal1|aal2|phr|phrh}
	AuthTime          time.Time
	IdPSessionID      *string
	IP                *string
	UserAgent         *string
	MappingProfile    string
	MappingVersion    int
	ClaimsSHA256      string
	CreatedAt         time.Time
}

// Session is a server-side session. SecretHash is the SHA-256 hex of the
// cookie secret (the secret itself is never stored).
type Session struct {
	ID                    uuid.UUID // the sid
	TenantID              tenancy.ID
	UserID                uuid.UUID
	Kind                  string // browser | cli | break_glass
	SecretHash            *string
	CSRFSecret            *string
	InitialAuthnContextID uuid.UUID
	CurrentAuthnContextID uuid.UUID
	ClientID              *string
	CreatedAt             time.Time
	LastActivityAt        time.Time
	IdleExpiresAt         time.Time
	AbsoluteExpiresAt     time.Time
	Status                string // active | revoked | expired
	RevokedAt             *time.Time
	RevokedReason         *string
	IPFirst               *string
	UserAgentFirst        *string
}

// LoginTransaction is the pre-auth state of one OIDC or SAML round trip.
type LoginTransaction struct {
	ID                      uuid.UUID
	TenantID                tenancy.ID
	CookieHash              string
	IdPConnectionID         uuid.UUID
	Purpose                 string
	StateHash               *string
	Nonce                   *string
	PKCEVerifierEnc         []byte
	SAMLRequestID           *string
	RequiredTesseraACR      *string
	MaxAge                  *int64
	SessionID               *uuid.UUID
	ExpectedExternalLoginID *uuid.UUID
	ReturnTo                string
	CreatedAt               time.Time
	ExpiresAt               time.Time
	ConsumedAt              *time.Time
}

// UserRef names who did something in a workflow: a platform user (ID) and
// the display string the workflow tables keep (decided_by). A zero ID means
// no platform user (seed data, system jobs).
type UserRef struct {
	ID      uuid.UUID
	Display string
}

func (u UserRef) idOrNil() any {
	if u.ID == uuid.Nil {
		return nil
	}
	return u.ID.String()
}
