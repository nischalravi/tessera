package mcpauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Access tokens are RFC 9068 JWTs ("at+jwt") signed with the tenant's active
// access_token key (internal/keys, ES256). They are short-lived, audience
// bound to one resource indicator, carry a jti and, for delegated calls, the
// RFC 8693 act chain. Revocation is checked on introspection against the
// mcp_tokens row of the jti.
const (
	// TokenType is the JOSE typ header of an access token.
	TokenType = "at+jwt"
	// MaxTTL is the longest access-token lifetime (and the default).
	MaxTTL = 5 * time.Minute
	// MaxActDepth bounds the nesting of act claims (actor, sub-agent, ...).
	MaxActDepth = 3
	// MaxTokenBytes bounds a token (or actor assertion) this server parses.
	MaxTokenBytes = 8 << 10
)

// Actor is an RFC 8693 act claim: who is acting, and the actors before it.
type Actor struct {
	Sub      string `json:"sub"`
	ClientID string `json:"client_id,omitempty"`
	Act      *Actor `json:"act,omitempty"`
}

// Depth is the number of nested actors (a nil chain is 0).
func (a *Actor) Depth() int {
	n := 0
	for x := a; x != nil; x = x.Act {
		n++
	}
	return n
}

// Contains reports whether sub already appears in the chain.
func (a *Actor) Contains(sub string) bool {
	for x := a; x != nil; x = x.Act {
		if x.Sub == sub {
			return true
		}
	}
	return false
}

// Claims are the claims of an access token.
type Claims struct {
	Issuer        string           `json:"iss"`
	Subject       string           `json:"sub"`
	Audience      jwt.Audience     `json:"aud"`
	Expiry        *jwt.NumericDate `json:"exp"`
	NotBefore     *jwt.NumericDate `json:"nbf"`
	IssuedAt      *jwt.NumericDate `json:"iat"`
	ID            string           `json:"jti"`
	Scope         string           `json:"scope"`
	ClientID      string           `json:"client_id"`
	Act           *Actor           `json:"act,omitempty"`
	PolicyVersion string           `json:"policy_version"`
}

// Mint signs claims with the tenant's active access-token key.
func Mint(tx *store.TenantTx, s *seal.Sealer, c Claims) (string, error) {
	k, err := keys.ActiveSigningKey(tx, store.KeyPurposeAccessToken, s)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(k.Alg),
		Key: jose.JSONWebKey{Key: k.Key, KeyID: k.KID}}, (&jose.SignerOptions{}).WithType(TokenType))
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(c).Serialize()
}

// Verification failures. The message is for logs and the decision log, never
// the token.
var (
	ErrTokenInvalid = errors.New("token is not valid")
	ErrTokenExpired = errors.New("token has expired")
	// ErrIssuerMismatch: the signature is ours but the issuer is not the one asked for.
	ErrIssuerMismatch = errors.New("token issuer does not match")
)

// Verify checks a token's signature against the tenant's published access
// keys, its type, issuer (ErrIssuerMismatch when it is signed by us but names
// another issuer), lifetime and act depth. It does not check
// revocation or audience (the caller does, against the mcp_tokens row).
func Verify(tx *store.TenantTx, raw, issuer string, now time.Time) (*Claims, error) {
	if raw == "" || len(raw) > MaxTokenBytes {
		return nil, ErrTokenInvalid
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(tok.Headers) != 1 {
		return nil, ErrTokenInvalid
	}
	h := tok.Headers[0]
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != TokenType || h.KeyID == "" {
		return nil, ErrTokenInvalid
	}
	set, err := keys.JWKSFor(tx, store.KeyPurposeAccessToken, now, nil)
	if err != nil {
		return nil, err
	}
	found := set.Key(h.KeyID)
	if len(found) != 1 {
		return nil, ErrTokenInvalid
	}
	var c Claims
	if err := tok.Claims(found[0].Key, &c); err != nil {
		return nil, ErrTokenInvalid
	}
	if c.Issuer != issuer {
		return nil, ErrIssuerMismatch
	}
	switch {
	case c.Subject == "" || c.ID == "" || len(c.Audience) != 1:
		return nil, ErrTokenInvalid
	case c.Expiry == nil || c.IssuedAt == nil:
		return nil, ErrTokenInvalid
	case !now.Before(c.Expiry.Time()):
		return nil, ErrTokenExpired
	case c.NotBefore != nil && now.Before(c.NotBefore.Time()):
		return nil, ErrTokenInvalid
	case c.Expiry.Time().Sub(c.IssuedAt.Time()) > MaxTTL:
		return nil, ErrTokenInvalid
	case c.Act.Depth() > MaxActDepth:
		return nil, ErrTokenInvalid
	}
	return &c, nil
}

// SubjectID is the identity id of an "identity:<id>" subject.
func SubjectID(sub string) (int64, bool) {
	n, ok := strings.CutPrefix(sub, "identity:")
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseInt(n, 10, 64)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != n {
		return 0, false
	}
	return id, true
}

// SubjectOf is the token subject of an identity.
func SubjectOf(id int64) string { return fmt.Sprintf("identity:%d", id) }

// actJSON is the stored form of an act chain.
func actJSON(a *Actor) string {
	if a == nil {
		return "null"
	}
	b, _ := json.Marshal(a)
	return string(b)
}
