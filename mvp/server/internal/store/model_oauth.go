package store

import (
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The rows of schema/0358_oauth.sql (design §7.4). Device codes, user codes
// and refresh tokens appear only as SHA-256 hex digests.

// API client kinds and states.
const (
	ClientFirstPartyCLI = "first_party_cli"
	ClientMachine       = "machine"

	ClientActive   = "active"
	ClientDisabled = "disabled"
)

// APIClient is an OAuth client of a tenant.
type APIClient struct {
	ID                      uuid.UUID
	TenantID                tenancy.ID // zero on insert means "this transaction's tenant"
	ClientID                string     // "tessera-cli" (first party) | "tsc_<base32 16>"
	Name                    string
	Kind                    string   // first_party_cli | machine
	GrantTypes              []string // cli: [device_code, refresh_token]
	TokenEndpointAuthMethod string   // none (cli) | private_key_jwt (machine)
	JWKS                    []byte   // machine public keys
	DPoPRequired            bool
	AllowedScopes           []string
	Roles                   []string
	OwnerUserID             *uuid.UUID
	Status                  string // active | disabled
	CreatedAt               time.Time
	LastUsedAt              *time.Time
}

// Device grant states.
const (
	DevicePending  = "pending"
	DeviceApproved = "approved"
	DeviceDenied   = "denied"
	DeviceExpired  = "expired"
	DeviceConsumed = "consumed"
)

// DeviceGrant is an RFC 8628 device authorization.
type DeviceGrant struct {
	ID                     uuid.UUID
	TenantID               tenancy.ID
	ClientID               string
	DeviceCodeHash         string
	UserCodeHash           string // sha256 of the normalized user code
	Scope                  string
	RequiredTesseraACR     *string
	MaxAge                 *int
	Status                 string
	RequestIP              *string
	RequestUserAgent       *string
	Interval               int // seconds between polls
	LastPolledAt           *time.Time
	CreatedAt              time.Time
	ExpiresAt              time.Time
	ApprovedByUserID       *uuid.UUID
	ApprovedAuthnContextID *uuid.UUID
	ApprovedAt             *time.Time
	SessionID              *uuid.UUID
}

// RefreshToken is a rotating, DPoP-bound refresh token.
type RefreshToken struct {
	ID                uuid.UUID
	TenantID          tenancy.ID
	TokenHash         string
	FamilyID          uuid.UUID
	ParentID          *uuid.UUID
	SessionID         uuid.UUID
	UserID            uuid.UUID
	ClientID          string
	DPoPJKT           string // RFC 7638 thumbprint, base64url
	Scope             string
	IssuedAt          time.Time
	ExpiresAt         time.Time // idle expiry
	AbsoluteExpiresAt time.Time // the CLI session's absolute expiry
	UsedAt            *time.Time
	RevokedAt         *time.Time
	RevokedReason     *string
}
