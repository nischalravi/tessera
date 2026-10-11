// Package transport moves a tenant's configuration between environments
// (dev → test → prod) as signed, versioned bundles (issue #170).
//
// A bundle holds the tenant's connections (configuration and owners, never
// credentials: an external secret reference such as vault:<path> travels as
// a reference, a secret Tessera holds is marked "set in the target"),
// readiness overlays, and sign-in connections (never client secrets or SP
// keys). It is a JWS (flattened JSON, EdDSA) signed with the tenant's config
// signing key; the target accepts it only from a signer it trusts.
//
// Import is two steps: Plan shows what would be added, changed or removed,
// and Apply makes the changes and records the bundle hash. Imported
// connections are drafts or new config revisions, never active: they go
// through validation and dry runs in the target. Sign-in connections are
// only ever added as pending; a change to an existing one is shown, not
// applied (sign-in trust goes through the admin change workflow). A
// production server refuses a bundle that carries dev-only values
// (config.DevOnlyURL, the dev mock IdP).
package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Format and Version identify bundles.
const (
	Format  = "tessera-config-bundle"
	Version = 1
	// MediaType is the JWS "typ".
	MediaType = "tessera-config-bundle+json"
	// MaxBundleBytes caps an uploaded bundle.
	MaxBundleBytes = 4 << 20
)

// Error is a refused request; Code is stable for API clients.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Bundle is the signed content.
type Bundle struct {
	Format            string        `json:"format"`
	Version           int           `json:"version"`
	Source            Source        `json:"source"`
	ExportedAt        time.Time     `json:"exported_at"`
	Connections       []Connection  `json:"connections"`
	Overlays          []Overlay     `json:"overlays"`
	IdentityProviders []IdP         `json:"identity_providers"`
	Excluded          []ExcludedRef `json:"excluded,omitempty"`
}

// Source is where a bundle came from.
type Source struct {
	TenantID   string `json:"tenant_id"`
	Tenant     string `json:"tenant"` // slug
	Env        string `json:"env"`
	Instance   string `json:"instance,omitempty"` // TESSERA_PUBLIC_URL
	ExportedBy string `json:"exported_by"`
}

// Credential says how a connection authenticates, without the secret.
type Credential struct {
	// Kind is "none", "reference" (an external secret store; Reference
	// travels) or "sealed" (Tessera held the secret: set it in the target).
	Kind      string `json:"kind"`
	Reference string `json:"reference,omitempty"`
}

// Connection is a connection's portable configuration.
type Connection struct {
	Name           string          `json:"name"`
	ConnectorType  string          `json:"connector_type"`
	System         string          `json:"system"`
	Role           string          `json:"role"`
	TechnicalOwner *string         `json:"technical_owner,omitempty"`
	BusinessOwner  *string         `json:"business_owner,omitempty"`
	Config         json.RawMessage `json:"config"`
	Credential     Credential      `json:"credential"`
}

// Overlay is a tenant's change to a readiness template.
type Overlay struct {
	TemplateID string `json:"template_id"`
	Version    int    `json:"version"`
	Body       string `json:"body"`
}

// IdP is a sign-in connection without its secrets.
type IdP struct {
	Name                    string          `json:"name"`
	Protocol                string          `json:"protocol"`
	Profile                 string          `json:"profile"`
	VerifiedDomains         json.RawMessage `json:"verified_domains"`
	Issuer                  *string         `json:"issuer,omitempty"`
	DiscoveryURL            *string         `json:"discovery_url,omitempty"`
	ClientID                *string         `json:"client_id,omitempty"`
	ClientAuthMethod        *string         `json:"client_auth_method,omitempty"`
	Scopes                  json.RawMessage `json:"scopes"`
	IDTokenAlgs             json.RawMessage `json:"id_token_algs"`
	StepUpRequest           json.RawMessage `json:"step_up_request"`
	IdPEntityID             *string         `json:"idp_entity_id,omitempty"`
	IdPSSOURL               *string         `json:"idp_sso_url,omitempty"`
	IdPSigningCerts         json.RawMessage `json:"idp_signing_certs"`
	MetadataURL             *string         `json:"metadata_url,omitempty"`
	PinCerts                bool            `json:"pin_certs"`
	SubjectSource           string          `json:"subject_source"`
	AttributeMap            json.RawMessage `json:"attribute_map"`
	AuthnMapping            json.RawMessage `json:"authn_mapping"`
	AssumePhishingResistant bool            `json:"assume_phishing_resistant"`
	GroupsClaim             *string         `json:"groups_claim,omitempty"`
	GroupRoleMapping        json.RawMessage `json:"group_role_mapping"`
	JITProvisioning         bool            `json:"jit_provisioning"`
	DefaultRole             string          `json:"default_role"`
	// NeedsSecret: the source had a client secret; set one in the target.
	NeedsSecret bool `json:"needs_secret"`
}

// ExcludedRef names something the export left out, and why.
type ExcludedRef struct {
	Section string `json:"section"`
	Name    string `json:"name"`
	Reason  string `json:"reason"`
}

// ------------------------------------------------------------------ export

// SigningKeyAAD binds a config signing key's sealed private half to its row.
func SigningKeyAAD(t tenancy.ID, kid string) []byte {
	return seal.AAD(t, "config_signing_keys", "private_sealed", kid)
}

// SigningKey returns the tenant's active config signing key, creating it on
// first use.
func SigningKey(tx *store.TenantTx, sealer *seal.Sealer, now time.Time) (*store.ConfigSigningKey, ed25519.PrivateKey, error) {
	if sealer == nil {
		return nil, nil, errors.New("transport: no sealer")
	}
	k, err := tx.ActiveConfigSigningKey()
	if errors.Is(err, store.ErrNotFound) {
		pub, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, nil, gerr
		}
		kid := "cfg-" + now.UTC().Format("20060102") + "-" + strings.ToLower(seal.RandomString(6, "abcdefghijklmnopqrstuvwxyz0123456789"))
		sealed, serr := sealer.Seal(priv, SigningKeyAAD(tx.Tenant(), kid))
		if serr != nil {
			return nil, nil, serr
		}
		k = &store.ConfigSigningKey{KID: kid, PublicKey: pub, PrivateSealed: sealed, Status: "active", CreatedAt: now}
		if err := tx.InsertConfigSigningKey(k); err != nil {
			return nil, nil, err
		}
		return k, priv, nil
	} else if err != nil {
		return nil, nil, err
	}
	raw, err := sealer.Open(k.PrivateSealed, SigningKeyAAD(tx.Tenant(), k.KID))
	if err != nil {
		return nil, nil, errors.New("transport: the config signing key cannot be opened (wrong KEK?)")
	}
	priv := ed25519.PrivateKey(raw)
	if len(priv) != ed25519.PrivateKeySize || !priv.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(k.PublicKey)) {
		return nil, nil, errors.New("transport: the config signing key does not match its public key")
	}
	return k, priv, nil
}

// Collect gathers the tenant's portable configuration.
func Collect(tx *store.TenantTx, rd *readiness.Service, now time.Time) (*Bundle, error) {
	b := &Bundle{Format: Format, Version: Version, ExportedAt: now.UTC(), Connections: []Connection{}, Overlays: []Overlay{},
		IdentityProviders: []IdP{}}
	conns, err := tx.Connections()
	if err != nil {
		return nil, err
	}
	for _, c := range conns {
		if c.RetiredAt != nil {
			b.Excluded = append(b.Excluded, ExcludedRef{"connections", c.Name, "retired"})
			continue
		}
		cur, err := rd.Current(tx, c.ID, now)
		if err != nil {
			return nil, err
		}
		item := Connection{Name: c.Name, ConnectorType: c.ConnectorType, System: c.System, Role: c.Role,
			TechnicalOwner: c.TechnicalOwner, BusinessOwner: c.BusinessOwner, Config: compactJSON(cur.Rev.Config),
			Credential: Credential{Kind: "none"}}
		if r := cur.Rev.SecretRef; r != nil && *r != "" {
			if strings.HasPrefix(*r, "sealed:") {
				item.Credential = Credential{Kind: "sealed"}
			} else {
				item.Credential = Credential{Kind: "reference", Reference: *r}
			}
		}
		b.Connections = append(b.Connections, item)
	}
	for _, id := range rd.Templates.IDs() {
		o, err := tx.LatestOverlay(id)
		if err != nil {
			return nil, err
		}
		if o != nil {
			b.Overlays = append(b.Overlays, Overlay{TemplateID: id, Version: o.Version, Body: o.Body})
		}
	}
	idps, err := tx.IdPConnections()
	if err != nil {
		return nil, err
	}
	for _, c := range idps {
		if c.Profile == "dev_mock" {
			b.Excluded = append(b.Excluded, ExcludedRef{"identity_providers", c.Name, "the dev mock IdP never travels"})
			continue
		}
		b.IdentityProviders = append(b.IdentityProviders, idpOf(c))
	}
	return b, nil
}

func idpOf(c *store.IdPConnection) IdP {
	return IdP{Name: c.Name, Protocol: c.Protocol, Profile: c.Profile, VerifiedDomains: compactRaw(c.VerifiedDomains, "[]"),
		Issuer: c.Issuer, DiscoveryURL: c.DiscoveryURL, ClientID: c.ClientID, ClientAuthMethod: c.ClientAuthMethod,
		Scopes: compactRaw(c.Scopes, "[]"), IDTokenAlgs: compactRaw(c.IDTokenAlgs, "[]"), StepUpRequest: compactRaw(c.StepUpRequest, "{}"),
		IdPEntityID: c.IdPEntityID, IdPSSOURL: c.IdPSSOURL, IdPSigningCerts: compactRaw(c.IdPSigningCerts, "[]"),
		MetadataURL: c.MetadataURL, PinCerts: c.PinCerts, SubjectSource: c.SubjectSource, AttributeMap: compactRaw(c.AttributeMap, "{}"),
		AuthnMapping: compactRaw(c.AuthnMapping, "{}"), AssumePhishingResistant: c.AssumePhishingResistant, GroupsClaim: c.GroupsClaim,
		GroupRoleMapping: compactRaw(c.GroupRoleMapping, "{}"), JITProvisioning: c.JITProvisioning, DefaultRole: c.DefaultRole,
		NeedsSecret: len(c.ClientSecretEnc) > 0}
}

func compactJSON(s string) json.RawMessage { return compactRaw(json.RawMessage(s), "{}") }

// compactRaw normalizes JSON so equal values compare equal: decoded and
// re-encoded (Go sorts object keys).
func compactRaw(r json.RawMessage, empty string) json.RawMessage {
	if len(r) == 0 || string(r) == "null" {
		return json.RawMessage(empty)
	}
	var v any
	if err := json.Unmarshal(r, &v); err != nil {
		return r
	}
	b, err := json.Marshal(v)
	if err != nil {
		return r
	}
	return b
}

// Signed is a bundle as exported: a JWS in flattened JSON serialization.
type Signed struct {
	JWS  []byte `json:"-"`
	Hash string `json:"hash"` // sha256 of the payload, hex
	KID  string `json:"kid"`
}

// Export signs the tenant's configuration.
func Export(tx *store.TenantTx, rd *readiness.Service, sealer *seal.Sealer, src Source, now time.Time) (*Signed, *Bundle, error) {
	b, err := Collect(tx, rd, now)
	if err != nil {
		return nil, nil, err
	}
	b.Source = src
	k, priv, err := SigningKey(tx, sealer, now)
	if err != nil {
		return nil, nil, err
	}
	payload, err := json.Marshal(b)
	if err != nil {
		return nil, nil, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithType(MediaType).WithHeader("kid", k.KID))
	if err != nil {
		return nil, nil, err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(payload)
	return &Signed{JWS: []byte(obj.FullSerialize()), Hash: hex.EncodeToString(sum[:]), KID: k.KID}, b, nil
}

// PublicKey is a signer's public key as shared between tenants.
type PublicKey struct {
	KID       string `json:"kid"`
	PublicKey string `json:"public_key"` // base64url, 32 bytes Ed25519
	Tenant    string `json:"tenant"`
}

// EncodeKey renders a public key for sharing.
func EncodeKey(k *store.ConfigSigningKey, tenant string) PublicKey {
	return PublicKey{KID: k.KID, PublicKey: base64.RawURLEncoding.EncodeToString(k.PublicKey), Tenant: tenant}
}

// DecodeKey parses a shared public key.
func DecodeKey(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(s), "="))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, refuse(422, "invalid_key", "the public key must be 32 bytes, base64url")
	}
	return b, nil
}

// ------------------------------------------------------------------ verify

// Verified is a bundle whose signature checked out against a trusted signer.
type Verified struct {
	Bundle *Bundle
	Hash   string
	Signer *store.TrustedSigner
}

// Verify parses a bundle and checks its signature against the tenant's
// trusted signers. A bundle signed by the tenant itself is not trusted
// unless its own key is listed: transport is between tenants.
func Verify(tx *store.TenantTx, raw []byte) (*Verified, error) {
	if len(raw) > MaxBundleBytes {
		return nil, refuse(413, "bundle_too_large", "a bundle is at most %d MiB", MaxBundleBytes>>20)
	}
	obj, err := jose.ParseSignedJSON(string(raw), []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil || len(obj.Signatures) != 1 {
		return nil, refuse(422, "invalid_bundle", "the file is not a signed Tessera configuration bundle")
	}
	h := obj.Signatures[0].Protected
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != MediaType {
		return nil, refuse(422, "invalid_bundle", "the file is not a Tessera configuration bundle (typ %q)", typ)
	}
	signer, err := tx.TrustedSigner(h.KeyID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(403, "untrusted_signer", "bundle signed by %q, which this tenant does not trust; add its public key under trusted signers first", h.KeyID)
	} else if err != nil {
		return nil, err
	}
	payload, err := obj.Verify(ed25519.PublicKey(signer.PublicKey))
	if err != nil {
		return nil, refuse(403, "bad_signature", "the bundle's signature does not verify with trusted key %q: it was changed or signed by another key", h.KeyID)
	}
	var b Bundle
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, refuse(422, "invalid_bundle", "the bundle content is not valid: %v", err)
	}
	if b.Format != Format || b.Version != Version {
		return nil, refuse(422, "unsupported_bundle", "bundle format %s v%d is not supported (want %s v%d)", b.Format, b.Version, Format, Version)
	}
	sum := sha256.Sum256(payload)
	return &Verified{Bundle: &b, Hash: hex.EncodeToString(sum[:]), Signer: signer}, nil
}

// secretFree reports a reason when a bundle carries something that looks
// like a secret: a sealed credential reference, or a config key that names
// a secret with a value.
func secretFree(b *Bundle) []string {
	var out []string
	for _, c := range b.Connections {
		if c.Credential.Kind == "sealed" && c.Credential.Reference != "" || strings.HasPrefix(c.Credential.Reference, "sealed:") {
			out = append(out, fmt.Sprintf("connection %q carries a sealed credential", c.Name))
		}
		var m map[string]any
		if json.Unmarshal(c.Config, &m) == nil {
			for _, k := range secretKeys(m, "") {
				out = append(out, fmt.Sprintf("connection %q config has a secret-like value at %s", c.Name, k))
			}
		}
	}
	return out
}

var secretWords = []string{"password", "secret", "token", "private_key", "apikey", "api_key"}

func secretKeys(m map[string]any, prefix string) []string {
	var out []string
	for k, v := range m {
		path := strings.TrimPrefix(prefix+"."+k, ".")
		switch x := v.(type) {
		case map[string]any:
			out = append(out, secretKeys(x, path)...)
		case string:
			lk := strings.ToLower(k)
			if x != "" && slices.ContainsFunc(secretWords, func(w string) bool { return strings.Contains(lk, w) }) &&
				!strings.HasSuffix(lk, "_ref") && !strings.HasSuffix(lk, "_reference") {
				out = append(out, path)
			}
		}
	}
	slices.Sort(out)
	return out
}
