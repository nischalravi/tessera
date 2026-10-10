package store

import (
	"encoding/json"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Signing-key purposes and statuses (design §7.4, §10.6).
const (
	KeyPurposeAccessToken     = "access_token"
	KeyPurposeIdPClientAuth   = "idp_client_auth"
	KeyPurposeAuditCheckpoint = "audit_checkpoint"

	KeyNext    = "next"
	KeyActive  = "active"
	KeyRetired = "retired"
	KeyRevoked = "revoked"
)

// TenantSigningKey is a per-tenant ES256 key. PrivateKeyEnc is sealed under
// the KEK and is never serialized.
type TenantSigningKey struct {
	KID           string // "{slug}-{yyyymmdd}-{rand6}"
	TenantID      tenancy.ID
	Purpose       string // access_token | idp_client_auth
	Alg           string // ES256
	PublicJWK     json.RawMessage
	PrivateKeyEnc []byte `json:"-"`
	Status        string // next | active | retired | revoked
	CreatedAt     time.Time
	ActivatedAt   *time.Time
	RetiredAt     *time.Time // set when retired, or when revoked
}

// PlatformKey is a platform-wide Ed25519 key (GLOBAL table), used to sign
// audit checkpoints. Old public keys are kept forever.
type PlatformKey struct {
	KID           string
	Purpose       string // audit_checkpoint
	Alg           string // EdDSA
	PublicJWK     json.RawMessage
	PrivateKeyEnc []byte `json:"-"`
	Status        string // active | retired | revoked
	CreatedAt     time.Time
}
