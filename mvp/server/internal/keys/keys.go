// Package keys manages Tessera's signing keys (design
// docs/design/phase-0-platform-security.md §10.6, threat E6):
//
//   - Per-tenant ES256 keys, one set per purpose (access_token,
//     idp_client_auth). EnsureKeys keeps exactly one active and one next key
//     per tenant and purpose and moves keys next → active → retired. An
//     active key is rotated after 30 days, but only once the next key has
//     been published for at least 7 days, so relying parties have it cached.
//     A retired key stays in the JWKS for 24 h, then only in the DB (as
//     evidence). A revoked key is never published again, and RevokeKey
//     activates the next key at once.
//   - One platform Ed25519 key (audit_checkpoint), rotated yearly. Old public
//     keys stay published forever so old checkpoints can be verified.
//
// Private keys are generated with crypto/ecdsa and crypto/ed25519, stored
// only sealed under the KEK (internal/seal) with an AAD bound to the tenant,
// table, column, purpose, algorithm and kid (so a row moved to another
// purpose no longer opens), and checked against the stored public key when
// unsealed. go-jose v4 (the JOSE library of the design, §6) renders public
// JWKs; no private member is ever published.
package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The design's type names.
type (
	TenantSigningKey = store.TenantSigningKey
	PlatformKey      = store.PlatformKey
)

// Lifetimes (§10.2).
const (
	ActiveLifetime   = 30 * 24 * time.Hour
	NextLeadTime     = 7 * 24 * time.Hour
	RetiredGrace     = 24 * time.Hour
	PlatformLifetime = 365 * 24 * time.Hour
)

// Algorithms.
const (
	AlgES256 = "ES256"
	AlgEdDSA = "EdDSA"
)

// TenantPurposes are the purposes EnsureKeys maintains for every tenant.
var TenantPurposes = []string{store.KeyPurposeAccessToken, store.KeyPurposeIdPClientAuth}

// PlatformKIDPrefix prefixes platform key ids.
const PlatformKIDPrefix = "platform"

// KIDPattern matches every kid this package issues: "{slug}-{yyyymmdd}-{rand6}".
var KIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,39}-[0-9]{8}-[a-z0-9]{6}$`)

const kidAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

var errKeyMismatch = errors.New("keys: sealed private key does not match the stored public key")

// NewKID returns "{prefix}-{yyyymmdd}-{rand6}", the date in UTC.
func NewKID(prefix string, now time.Time) (string, error) {
	kid := fmt.Sprintf("%s-%s-%s", prefix, now.UTC().Format("20060102"), seal.RandomString(6, kidAlphabet))
	if !KIDPattern.MatchString(kid) {
		return "", fmt.Errorf("keys: invalid kid prefix %q", prefix)
	}
	return kid, nil
}

// tenantAAD is the AAD a tenant private key is sealed under. Binding the
// purpose and algorithm stops a database writer from moving a key to another
// purpose (RFC 8725 §3.12: one key per token type).
func tenantAAD(t tenancy.ID, purpose, alg, kid string) []byte {
	return seal.AAD(t, "tenant_signing_keys", "private_key_enc", purpose, alg, kid)
}

// platformAAD is the AAD a platform private key is sealed under.
func platformAAD(purpose, alg, kid string) []byte {
	return seal.AAD(tenancy.Platform, "platform_keys", "private_key_enc", purpose, alg, kid)
}

// ---------------------------------------------------------------- tenant keys

// EnsureKeys brings this tenant's keys for every purpose to the steady state
// (one active, one next) at now, rotating an expired active key. It runs at
// tenant creation, at startup and daily. slug is the tenant's slug, used only
// to name new keys.
func EnsureKeys(tx *store.TenantTx, slug string, s *seal.Sealer, now time.Time) error {
	for _, p := range TenantPurposes {
		if err := ensurePurpose(tx, slug, p, s, now); err != nil {
			return fmt.Errorf("keys: %s: %w", p, err)
		}
	}
	return nil
}

func ensurePurpose(tx *store.TenantTx, slug, purpose string, s *seal.Sealer, now time.Time) error {
	ks, err := tx.SigningKeys(purpose)
	if err != nil {
		return err
	}
	var active, next *TenantSigningKey
	for _, k := range ks {
		switch k.Status {
		case store.KeyActive:
			active = k
		case store.KeyNext:
			next = k
		}
	}
	switch {
	case active == nil && next != nil:
		// first activation, or emergency after the active key was revoked
		if err := tx.ActivateSigningKey(next.KID, now); err != nil {
			return err
		}
		next = nil
	case active == nil:
		if err := createTenantKey(tx, slug, purpose, store.KeyActive, s, now); err != nil {
			return err
		}
	case next != nil && !now.Before(activeSince(active).Add(ActiveLifetime)) && !now.Before(next.CreatedAt.Add(NextLeadTime)):
		if err := tx.RetireSigningKey(active.KID, now); err != nil {
			return err
		}
		if err := tx.ActivateSigningKey(next.KID, now); err != nil {
			return err
		}
		next = nil
	}
	if next == nil {
		return createTenantKey(tx, slug, purpose, store.KeyNext, s, now)
	}
	return nil
}

func activeSince(k *TenantSigningKey) time.Time {
	if k.ActivatedAt != nil {
		return *k.ActivatedAt
	}
	return k.CreatedAt
}

func createTenantKey(tx *store.TenantTx, slug, purpose, status string, s *seal.Sealer, now time.Time) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	defer clear(der)
	var lastErr error
	for range 3 { // a kid collision is astronomically unlikely; retry anyway
		kid, err := NewKID(slug, now)
		if err != nil {
			return err
		}
		pub, err := publicJWK(&priv.PublicKey, kid, AlgES256)
		if err != nil {
			return err
		}
		enc, err := s.Seal(der, tenantAAD(tx.Tenant(), purpose, AlgES256, kid))
		if err != nil {
			return err
		}
		k := &TenantSigningKey{KID: kid, TenantID: tx.Tenant(), Purpose: purpose, Alg: AlgES256, PublicJWK: pub,
			PrivateKeyEnc: enc, Status: status, CreatedAt: now}
		if status == store.KeyActive {
			k.ActivatedAt = &now
		}
		if lastErr = tx.InsertSigningKey(k); !errors.Is(lastErr, store.ErrDuplicate) {
			return lastErr
		}
	}
	return lastErr
}

// RevokeKey revokes one of this tenant's keys (ErrNotFound for an unknown,
// already revoked or other tenant's kid) and restores the steady state: if
// the active key was revoked, the next key becomes active at once.
func RevokeKey(tx *store.TenantTx, slug, kid string, s *seal.Sealer, now time.Time) error {
	if err := tx.RevokeSigningKey(kid, now); err != nil {
		return err
	}
	return EnsureKeys(tx, slug, s, now)
}

// Published reports whether a key belongs in the JWKS at now: next and
// active keys, and retired keys for RetiredGrace after retirement. Revoked
// keys never.
func Published(k *TenantSigningKey, now time.Time) bool {
	switch k.Status {
	case store.KeyNext, store.KeyActive:
		return true
	case store.KeyRetired:
		return k.RetiredAt != nil && now.Before(k.RetiredAt.Add(RetiredGrace))
	}
	return false
}

// PublishedKeys returns this tenant's keys for purpose that are published
// at now (the keys a token may verify against, §10.4).
func PublishedKeys(tx *store.TenantTx, purpose string, now time.Time) ([]*TenantSigningKey, error) {
	ks, err := tx.SigningKeys(purpose)
	if err != nil {
		return nil, err
	}
	var out []*TenantSigningKey
	for _, k := range ks {
		if Published(k, now) {
			out = append(out, k)
		}
	}
	return out, nil
}

// JWKSFor returns this tenant's public JWK Set for purpose at now, for
// GET /t/{slug}/.well-known/jwks.json (served with Cache-Control:
// max-age=300). It contains only public keys.
func JWKSFor(tx *store.TenantTx, purpose string, now time.Time) (*jose.JSONWebKeySet, error) {
	ks, err := PublishedKeys(tx, purpose, now)
	if err != nil {
		return nil, err
	}
	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	for _, k := range ks {
		jwk, err := parsePublicJWK(k.PublicJWK, k.KID, k.Alg)
		if err != nil {
			return nil, err
		}
		set.Keys = append(set.Keys, jwk)
	}
	return set, nil
}

// SigningKey is an unsealed private key and its kid.
type SigningKey struct {
	KID string
	Alg string
	Key crypto.Signer // *ecdsa.PrivateKey or ed25519.PrivateKey
}

// String never reveals the key.
func (k *SigningKey) String() string {
	return fmt.Sprintf("keys.SigningKey{KID:%s Alg:%s Key:REDACTED}", k.KID, k.Alg)
}

// GoString never reveals the key.
func (k *SigningKey) GoString() string { return k.String() }

// ActiveSigningKey unseals this tenant's active key for purpose.
func ActiveSigningKey(tx *store.TenantTx, purpose string, s *seal.Sealer) (*SigningKey, error) {
	ks, err := tx.SigningKeys(purpose)
	if err != nil {
		return nil, err
	}
	for _, k := range ks {
		if k.Status != store.KeyActive {
			continue
		}
		priv, err := unseal(s, k.PrivateKeyEnc, tenantAAD(tx.Tenant(), k.Purpose, k.Alg, k.KID), k.PublicJWK)
		if err != nil {
			return nil, fmt.Errorf("keys: %s: %w", k.KID, err)
		}
		return &SigningKey{KID: k.KID, Alg: k.Alg, Key: priv}, nil
	}
	return nil, fmt.Errorf("keys: no active %s key: %w", purpose, store.ErrNotFound)
}

// ---------------------------------------------------------------- platform keys

// EnsurePlatformKey keeps one active audit-checkpoint key, rotating it after
// PlatformLifetime. Retired platform keys stay published.
func EnsurePlatformKey(sys *store.SystemTx, s *seal.Sealer, now time.Time) error {
	ks, err := sys.PlatformKeys(store.KeyPurposeAuditCheckpoint)
	if err != nil {
		return err
	}
	for _, k := range ks {
		if k.Status != store.KeyActive {
			continue
		}
		if now.Before(k.CreatedAt.Add(PlatformLifetime)) {
			return nil
		}
		if err := sys.RetirePlatformKey(k.KID); err != nil {
			return err
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	defer clear(der)
	kid, err := NewKID(PlatformKIDPrefix, now)
	if err != nil {
		return err
	}
	jwk, err := publicJWK(pub, kid, AlgEdDSA)
	if err != nil {
		return err
	}
	enc, err := s.Seal(der, platformAAD(store.KeyPurposeAuditCheckpoint, AlgEdDSA, kid))
	if err != nil {
		return err
	}
	return sys.InsertPlatformKey(PlatformKey{KID: kid, Purpose: store.KeyPurposeAuditCheckpoint, Alg: AlgEdDSA,
		PublicJWK: jwk, PrivateKeyEnc: enc, Status: store.KeyActive, CreatedAt: now})
}

// PlatformJWKS returns every non-revoked platform public key (for GET
// /api/audit/keys, PR3).
func PlatformJWKS(sys *store.SystemTx) (*jose.JSONWebKeySet, error) {
	ks, err := sys.PlatformKeys(store.KeyPurposeAuditCheckpoint)
	if err != nil {
		return nil, err
	}
	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	for _, k := range ks {
		if k.Status == store.KeyRevoked {
			continue
		}
		jwk, err := parsePublicJWK(k.PublicJWK, k.KID, k.Alg)
		if err != nil {
			return nil, err
		}
		set.Keys = append(set.Keys, jwk)
	}
	return set, nil
}

// ActivePlatformKey unseals the active audit-checkpoint key.
func ActivePlatformKey(sys *store.SystemTx, s *seal.Sealer) (*SigningKey, error) {
	ks, err := sys.PlatformKeys(store.KeyPurposeAuditCheckpoint)
	if err != nil {
		return nil, err
	}
	for _, k := range ks {
		if k.Status == store.KeyActive {
			priv, err := unseal(s, k.PrivateKeyEnc, platformAAD(k.Purpose, k.Alg, k.KID), k.PublicJWK)
			if err != nil {
				return nil, fmt.Errorf("keys: %s: %w", k.KID, err)
			}
			return &SigningKey{KID: k.KID, Alg: k.Alg, Key: priv}, nil
		}
	}
	return nil, fmt.Errorf("keys: no active platform key: %w", store.ErrNotFound)
}

// ---------------------------------------------------------------- bootstrap

// ErrWrongKEK is returned by EnsureAll when the KEK cannot open the keys
// already sealed in the database (a lost or swapped KEK).
var ErrWrongKEK = errors.New("keys: the KEK cannot open the signing keys in this database (wrong or lost KEK; restore it, or reseed a dev database)")

// EnsureAll is the ensure_keys bootstrap step: the platform key, then every
// active tenant's keys, each tenant in its own transaction. Before anything
// is rotated or minted it checks that the KEK opens the keys already sealed
// (the active platform key, and one active key per tenant inside that
// tenant's transaction), so a wrong KEK fails closed with ErrWrongKEK and
// writes nothing, even on a rotation day. An error in one tenant does not
// stop the others; all errors are returned joined.
func EnsureAll(ctx context.Context, db *store.DB, s *seal.Sealer, now time.Time) error {
	var tenants []store.Tenant
	if err := db.InSystem(ctx, "ensure platform keys", func(sys *store.SystemTx) error {
		if err := kekOpens(func() error { _, err := ActivePlatformKey(sys, s); return err }); err != nil {
			return err
		}
		if err := EnsurePlatformKey(sys, s, now); err != nil {
			return err
		}
		// a fresh database: check the key just sealed opens
		if err := kekOpens(func() error { _, err := ActivePlatformKey(sys, s); return err }); err != nil {
			return err
		}
		var err error
		tenants, err = sys.ActiveTenants()
		return err
	}); err != nil {
		return fmt.Errorf("keys: platform: %w", err)
	}
	var errs []error
	for _, t := range tenants {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if err := db.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			if err := tenantKEKOpens(tx, s); err != nil {
				return err
			}
			return EnsureKeys(tx, t.Slug, s, now)
		}); err != nil {
			errs = append(errs, fmt.Errorf("keys: tenant %s: %w", t.Slug, err))
		}
	}
	return errors.Join(errs...)
}

// kekOpens runs an unseal and maps a failure to open to ErrWrongKEK. No key
// to open (a fresh database or tenant) is not an error.
func kekOpens(unsealActive func() error) error {
	switch err := unsealActive(); {
	case err == nil, errors.Is(err, store.ErrNotFound):
		return nil
	case errors.Is(err, seal.ErrOpen):
		return ErrWrongKEK
	default:
		return err
	}
}

// tenantKEKOpens unseals this tenant's first active key, if it has one.
func tenantKEKOpens(tx *store.TenantTx, s *seal.Sealer) error {
	for _, p := range TenantPurposes {
		var found bool
		if err := kekOpens(func() error {
			_, err := ActiveSigningKey(tx, p, s)
			found = err == nil || !errors.Is(err, store.ErrNotFound)
			return err
		}); err != nil || found {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------- JWK helpers

func publicJWK(pub crypto.PublicKey, kid, alg string) ([]byte, error) {
	jwk := jose.JSONWebKey{Key: pub, KeyID: kid, Algorithm: alg, Use: "sig"}
	if !jwk.IsPublic() || !jwk.Valid() {
		return nil, errors.New("keys: not a valid public key")
	}
	return json.Marshal(jwk)
}

// parsePublicJWK parses a stored public JWK and refuses anything that is not
// a public key with the row's kid and algorithm, so a tampered row can never
// publish private material or another key id.
func parsePublicJWK(raw []byte, kid, alg string) (jose.JSONWebKey, error) {
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(raw); err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("keys: %s: stored public JWK: %w", kid, err)
	}
	if !jwk.IsPublic() || !jwk.Valid() || jwk.KeyID != kid || jwk.Algorithm != alg || jwk.Use != "sig" {
		return jose.JSONWebKey{}, fmt.Errorf("keys: %s: stored public JWK is not a public %s signing key with that kid", kid, alg)
	}
	return jwk, nil
}

func unseal(s *seal.Sealer, enc, aad, publicJWK []byte) (crypto.Signer, error) {
	der, err := s.Open(enc, aad)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errKeyMismatch
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(publicJWK); err != nil {
		return nil, err
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if pub, ok := signer.Public().(equaler); !ok || !pub.Equal(jwk.Key) {
		return nil, errKeyMismatch
	}
	return signer, nil
}
