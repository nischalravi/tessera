package oauth

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth/dpop"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Access tokens (RFC 9068 JWTs, design §10.1) and their verification at the
// resource server (§10.4).

// MaxTokenBytes bounds an access token (§10.4 rule 1).
const MaxTokenBytes = 8 << 10

// Skews allowed when checking a token (§10.4 rule 5).
const (
	expLeeway = 30 * time.Second
	iatLeeway = 30 * time.Second
)

// SubjectPrefix prefixes the user id in sub.
const SubjectPrefix = "usr_"

type confirmation struct {
	JKT string `json:"jkt"`
}

// accessClaims is the payload of an access token minted for a user.
type accessClaims struct {
	Issuer    string        `json:"iss"`
	Subject   string        `json:"sub"`
	Audience  string        `json:"aud"`
	ClientID  string        `json:"client_id"`
	IssuedAt  int64         `json:"iat"`
	NotBefore int64         `json:"nbf"`
	Expiry    int64         `json:"exp"`
	JTI       string        `json:"jti"`
	Scope     string        `json:"scope"`
	TenantID  string        `json:"tid"`
	SessionID string        `json:"sid"`
	AuthTime  int64         `json:"auth_time"`
	ACR       string        `json:"acr,omitempty"`
	AMR       []string      `json:"amr,omitempty"`
	Cnf       *confirmation `json:"cnf"`
}

// mintInput is what an access token is minted for.
type mintInput struct {
	Slug      string
	User      uuid.UUID
	Session   uuid.UUID
	ClientID  string
	Scope     string
	AuthTime  time.Time
	ACR       string
	AMR       []string
	JKT       string
	Now       time.Time
	SigningTx *store.TenantTx // the tenant's transaction (keys are read from it)
}

// mintAccessToken signs an access token with the tenant's active access_token
// key, bound to the DPoP key jkt (cnf.jkt). It returns the token and its
// lifetime. The token carries no roles: the resource server reads them from
// the database on every request (§10.1).
func (s *Service) mintAccessToken(in mintInput) (string, time.Duration, error) {
	if s.cfg.Sealer == nil {
		return "", 0, errors.New("oauth: no sealer to open the signing key")
	}
	k, err := keys.ActiveSigningKey(in.SigningTx, store.KeyPurposeAccessToken, s.cfg.Sealer)
	if err != nil {
		return "", 0, err
	}
	priv, ok := k.Key.(*ecdsa.PrivateKey)
	if !ok || k.Alg != keys.AlgES256 {
		return "", 0, fmt.Errorf("oauth: signing key %s is not ES256", k.KID)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: priv, KeyID: k.KID}},
		(&jose.SignerOptions{}).WithType("at+jwt"))
	if err != nil {
		return "", 0, err
	}
	ttl := s.cfg.AccessTokenTTL
	if slices.Contains(strings.Fields(in.Scope), "tessera:admin") && ttl > AdminAccessTokenTTL {
		ttl = AdminAccessTokenTTL
	}
	now := in.Now.UTC()
	c := accessClaims{Issuer: s.Issuer(in.Slug), Subject: SubjectPrefix + in.User.String(), Audience: s.cfg.APIAudience,
		ClientID: in.ClientID, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: now.Add(ttl).Unix(),
		JTI: "at_" + seal.RandomSecret(16), Scope: in.Scope, TenantID: in.SigningTx.Tenant().String(),
		SessionID: in.Session.String(), AuthTime: in.AuthTime.Unix(), ACR: in.ACR, AMR: in.AMR,
		Cnf: &confirmation{JKT: in.JKT}}
	tok, err := jwt.Signed(signer).Claims(c).Serialize()
	return tok, ttl, err
}

// rawClaims reads a token's claims for verification. aud is kept raw: a list
// is refused.
type rawClaims struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  json.RawMessage `json:"aud"`
	ClientID  string          `json:"client_id"`
	IssuedAt  *float64        `json:"iat"`
	NotBefore *float64        `json:"nbf"`
	Expiry    *float64        `json:"exp"`
	JTI       string          `json:"jti"`
	Scope     string          `json:"scope"`
	TenantID  string          `json:"tid"`
	SessionID string          `json:"sid"`
	Cnf       *confirmation   `json:"cnf"`
}

// forbiddenTokenHeaders must not appear in an access token's header (§10.4
// rule 2): a token never names or carries its own key.
var forbiddenTokenHeaders = []string{"jku", "x5u", "jwk", "x5c", "x5t", "x5t#S256", "crit"}

// challenge builds the WWW-Authenticate value of a refused token
// (RFC 9449 §7.1: DPoP error=..., algs=...).
func challenge(code, description string) string {
	c := `DPoP error="` + code + `"`
	if description != "" {
		c += `, error_description="` + description + `"`
	}
	return c + `, algs="ES256 EdDSA"`
}

func refuse(description string) (*auth.VerifiedToken, *auth.TokenFailure, error) {
	return nil, &auth.TokenFailure{Reason: auth.FailInvalidToken, Challenge: challenge("invalid_token", description)}, nil
}

// VerifyAccessToken implements auth.TokenVerifier: design §10.4 steps 1 to 5
// and 7 (step 6, the live session, is auth.Authenticator's). A token is
// accepted only as "Authorization: DPoP <token>" with a valid proof of the key
// it is bound to; err is set only when the database failed.
func (s *Service) VerifyAccessToken(r *http.Request) (*auth.VerifiedToken, *auth.TokenFailure, error) {
	ctx := r.Context()
	now := s.now()
	// 1. one Authorization header, scheme DPoP, size
	hs := r.Header.Values("Authorization")
	if len(hs) != 1 {
		return refuse("exactly one Authorization header is required")
	}
	scheme, token, _ := strings.Cut(hs[0], " ")
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		// every token Tessera issues is DPoP-bound, and a bound token must not
		// be used under Bearer (RFC 9449 §7.1)
		return refuse("a DPoP-bound access token must use the DPoP authentication scheme")
	case !strings.EqualFold(scheme, "DPoP"):
		return refuse("unsupported authentication scheme")
	}
	token = strings.TrimSpace(token)
	if token == "" || len(token) > MaxTokenBytes || strings.ContainsAny(token, " \t") {
		return refuse("the access token is empty or too large")
	}
	// 2. the header, read without trusting it
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return refuse("the access token is not a compact JWS")
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return refuse("the access token header is not base64url")
	}
	var hdr map[string]json.RawMessage
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return refuse("the access token header is not a JSON object")
	}
	for _, k := range forbiddenTokenHeaders {
		if _, ok := hdr[k]; ok {
			return refuse("the access token header must not contain " + k)
		}
	}
	var typ, alg, kid string
	_ = json.Unmarshal(hdr["typ"], &typ)
	_ = json.Unmarshal(hdr["alg"], &alg)
	_ = json.Unmarshal(hdr["kid"], &kid)
	if !strings.EqualFold(typ, "at+jwt") || alg != "ES256" || kid == "" || len(kid) > 64 {
		return refuse("the access token must be an at+jwt signed with ES256 and name its key")
	}
	// 3. the issuer names the tenant; only that tenant's keys can verify it
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return refuse("the access token payload is not base64url")
	}
	var unverified struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &unverified); err != nil {
		return refuse("the access token payload is not a JSON object")
	}
	slug, ok := strings.CutPrefix(unverified.Issuer, s.cfg.PublicURL+"/t/")
	if !ok || strings.Contains(slug, "/") {
		return refuse("the access token issuer is not this server")
	}
	tenant, active, err := s.tenantBySlug(ctx, slug)
	if err != nil {
		return nil, nil, err
	}
	if !active {
		return refuse("the access token issuer is unknown")
	}
	// 4. and 5. the signature and the claims, inside the tenant
	var c rawClaims
	var reason string
	err = s.db.ReadTenant(ctx, tenant.ID, func(tx *store.TenantTx) error {
		set, err := keys.JWKSFor(tx, store.KeyPurposeAccessToken, now, s.cfg.Log)
		if err != nil {
			return err
		}
		ks := set.Key(kid)
		if len(ks) != 1 {
			reason = "the access token key is not one of the tenant's published keys"
			return nil
		}
		tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			reason = "the access token cannot be parsed"
			return nil
		}
		if err := tok.Claims(ks[0].Key, &c); err != nil {
			reason = "the access token signature is invalid"
			return nil
		}
		if reason = s.checkClaims(&c, tenant, slug, now); reason != "" {
			return nil
		}
		cl, err := tx.APIClientByClientID(c.ClientID)
		if errors.Is(err, store.ErrNotFound) {
			reason = "the access token client is unknown"
			return nil
		}
		if err != nil {
			return err
		}
		if cl.Status != store.ClientActive || cl.Kind != store.ClientFirstPartyCLI {
			reason = "the access token client is not active"
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if reason != "" {
		return refuse(reason)
	}
	// 7. the DPoP proof, bound to this request, this token and its key
	_, err = s.dpop.ValidateProof(ctx, r.Header, dpop.ProofParams{Method: r.Method, URL: s.cfg.PublicURL + r.URL.Path,
		AccessToken: token, ExpectedJKT: c.Cnf.JKT, RequireNonce: s.cfg.RSNonce, Now: now})
	if err != nil {
		var pe *dpop.ProofError
		if !errors.As(err, &pe) {
			return nil, nil, err
		}
		if pe.Code == dpop.CodeUseNonce {
			return nil, &auth.TokenFailure{Reason: auth.FailDPoPNonce, Challenge: challenge(dpop.CodeUseNonce, ""),
				Nonce: pe.NewNonce}, nil
		}
		return nil, &auth.TokenFailure{Reason: auth.FailInvalidDPoP, Challenge: challenge(dpop.CodeInvalidProof, "")}, nil
	}
	user, _ := strings.CutPrefix(c.Subject, SubjectPrefix)
	uid, _ := uuid.Parse(user)
	sid, _ := uuid.Parse(c.SessionID)
	return &auth.VerifiedToken{Tenant: tenant, UserID: uid, SessionID: sid, ClientID: c.ClientID,
		Scopes: strings.Fields(c.Scope)}, nil, nil
}

// checkClaims is §10.4 rule 5 for a token whose signature verified; it
// returns why the claims are refused, or "".
func (s *Service) checkClaims(c *rawClaims, tenant store.Tenant, slug string, now time.Time) string {
	if c.Issuer != s.Issuer(slug) {
		return "the access token issuer does not match"
	}
	var aud string
	if json.Unmarshal(c.Audience, &aud) != nil || aud != s.cfg.APIAudience {
		return "the access token audience is not this API"
	}
	if c.Expiry == nil || !time.Unix(int64(*c.Expiry), 0).Add(expLeeway).After(now) {
		return "the access token has expired"
	}
	if c.IssuedAt == nil || time.Unix(int64(*c.IssuedAt), 0).After(now.Add(iatLeeway)) {
		return "the access token was issued in the future"
	}
	if c.NotBefore != nil && time.Unix(int64(*c.NotBefore), 0).After(now.Add(iatLeeway)) {
		return "the access token is not yet valid"
	}
	if c.TenantID != tenant.ID.String() {
		return "the access token tenant does not match its issuer"
	}
	if c.ClientID == "" || strings.TrimSpace(c.Scope) == "" {
		return "the access token has no client or scope"
	}
	if c.Cnf == nil || c.Cnf.JKT == "" {
		return "the access token is not DPoP-bound"
	}
	// machine tokens (no sid) arrive with PR11: refuse them rather than guess
	if _, err := uuid.Parse(c.SessionID); err != nil {
		return "the access token names no session"
	}
	if u, ok := strings.CutPrefix(c.Subject, SubjectPrefix); !ok {
		return "the access token subject is not a user"
	} else if _, err := uuid.Parse(u); err != nil {
		return "the access token subject is not a user"
	}
	return ""
}
