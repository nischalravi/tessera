// Package oidcrp is Tessera's OpenID Connect relying party for browser
// sign-in (design docs/design/phase-0-platform-security.md §9.1, §10.4):
// discovery and JWKS through safehttp, the authorization URL with PKCE S256,
// the code exchange, and ValidateIDToken.
//
// go-oidc verifies the signature (with an explicit algorithm allow-list),
// iss, aud and exp; this package adds what go-oidc does not cover: a size
// cap, refusal of jku/x5u/jwk/x5c/crit headers, azp with several audiences,
// the iat window, the nonce, auth_time and max_age, and the RFC 9207 iss
// authorization-response parameter. Every refusal is an *Error with a
// machine-readable Reason for the auth.login.failure audit event.
//
// Time comes from Config.Now (the injected clock), never time.Now.
package oidcrp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"

	"github.com/nischalravi/tessera/mvp/server/internal/obs"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// Limits and windows (§10.4).
const (
	MaxIDTokenBytes = 16 << 10
	// iat may be at most this far in the future and at most IatMaxAge old.
	IatSkew   = 60 * time.Second
	IatMaxAge = 10 * time.Minute
	// AuthTimeSkew is the slack on max_age (now - auth_time <= max_age + skew).
	AuthTimeSkew = 60 * time.Second
	// StepUpSkew is the slack on a step-up's auth_time >= transaction start.
	StepUpSkew = 5 * time.Second
	// DiscoveryTTL is how long a connection's discovery document is cached.
	DiscoveryTTL = time.Hour
)

// AllowedAlgs are the only ID-token algorithms Tessera ever accepts; a
// connection narrows them (id_token_algs) and so does the IdP's discovery.
var AllowedAlgs = []string{oidc.RS256, oidc.PS256, oidc.ES256, oidc.EdDSA}

// Failure reasons (auth.login.failure detail.reason).
const (
	ReasonDiscovery       = "discovery_failed"
	ReasonJWKSHost        = "jwks_host_not_allowed"
	ReasonIssParam        = "iss_parameter_mismatch"
	ReasonTokenExchange   = "token_exchange_failed"
	ReasonNoIDToken       = "id_token_missing"
	ReasonTooLarge        = "id_token_too_large"
	ReasonMalformed       = "id_token_malformed"
	ReasonAlg             = "id_token_alg_not_allowed"
	ReasonHeader          = "id_token_forbidden_header"
	ReasonSignature       = "id_token_signature_invalid"
	ReasonIssuer          = "id_token_iss_mismatch"
	ReasonAudience        = "id_token_aud_mismatch"
	ReasonAzp             = "id_token_azp_mismatch"
	ReasonExpired         = "id_token_expired"
	ReasonIat             = "id_token_iat_out_of_window"
	ReasonNonce           = "id_token_nonce_mismatch"
	ReasonAuthTimeMissing = "auth_time_missing"
	ReasonAuthTimeStale   = "auth_time_stale"
	ReasonSubject         = "subject_missing"
)

// Error is a refused sign-in step. Reason is safe to audit; Err (the cause)
// is for logs only and never shown to the user.
type Error struct {
	Reason string
	Err    error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return "oidcrp: " + e.Reason + ": " + e.Err.Error()
	}
	return "oidcrp: " + e.Reason
}

func (e *Error) Unwrap() error { return e.Err }

func fail(reason string, err error) error { return &Error{Reason: reason, Err: err} }

// ReasonOf returns the audit reason of err ("internal_error" for anything
// that is not an *Error).
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return "internal_error"
}

// Connection is what the RP needs from an IdP connection.
type Connection struct {
	Key          string // cache key: the connection id
	Issuer       string
	ClientID     string
	ClientSecret string // client_secret_basic; the opened client_secret_enc
	Scopes       []string
	IDTokenAlgs  []string // connection.id_token_algs; empty means AllowedAlgs
	// JWKSHosts are hosts the discovery document's jwks_uri may name besides
	// the issuer's (the profile allow-list, e.g. login.microsoftonline.com).
	JWKSHosts []string
}

// Config configures an RP.
type Config struct {
	// HTTP makes every outbound request (discovery, JWKS, token): a safehttp
	// client. Required.
	HTTP *http.Client
	// Now is the clock. Required.
	Now func() time.Time
}

// RP is a relying party serving every connection. It caches each
// connection's discovery document (and go-oidc its JWKS) for DiscoveryTTL.
type RP struct {
	cfg Config

	mu    sync.Mutex
	cache map[string]*provider
}

type provider struct {
	p       *oidc.Provider
	meta    metadata
	algs    []string
	fetched time.Time
	conn    Connection
}

type metadata struct {
	Issuer      string   `json:"issuer"`
	JWKSURI     string   `json:"jwks_uri"`
	IDTokenAlgs []string `json:"id_token_signing_alg_values_supported"`
	IssParam    bool     `json:"authorization_response_iss_parameter_supported"`
}

// New returns an RP.
func New(cfg Config) (*RP, error) {
	if cfg.HTTP == nil || cfg.Now == nil {
		return nil, errors.New("oidcrp: Config needs HTTP and Now")
	}
	return &RP{cfg: cfg, cache: map[string]*provider{}}, nil
}

// ctx carries the outbound client for go-oidc and x/oauth2. The client also
// allows the port the connection's issuer URL names (safehttp only allows
// 443 and 8443 otherwise); go-oidc keeps the client, not the context, for
// its later JWKS fetches, so the allowance travels with it.
func (rp *RP) ctx(ctx context.Context, c Connection) context.Context {
	return oidc.ClientContext(ctx, safehttp.WithConfiguredPorts(rp.cfg.HTTP, c.Issuer))
}

// provider returns the connection's (cached) discovery.
func (rp *RP) provider(ctx context.Context, c Connection) (*provider, error) {
	rp.mu.Lock()
	cached := rp.cache[c.Key]
	rp.mu.Unlock()
	now := rp.cfg.Now()
	if cached != nil && now.Sub(cached.fetched) < DiscoveryTTL && cached.conn.Issuer == c.Issuer &&
		slices.Equal(cached.conn.IDTokenAlgs, c.IDTokenAlgs) && cached.conn.ClientID == c.ClientID {
		return cached, nil
	}
	if c.Issuer == "" || c.ClientID == "" {
		return nil, fail(ReasonDiscovery, errors.New("connection has no issuer or client_id"))
	}
	// go-oidc fetches <issuer>/.well-known/openid-configuration and requires
	// the document's issuer to equal it exactly. The provider keeps the
	// context's client for its JWKS fetches, so the context must not be the
	// request's (it is cancelled when the request ends).
	done := obs.StartCall(obs.ConnOIDC, "discovery")
	p, err := oidc.NewProvider(rp.ctx(context.WithoutCancel(ctx), c), c.Issuer)
	done(err)
	if err != nil {
		return nil, fail(ReasonDiscovery, err)
	}
	var m metadata
	if err := p.Claims(&m); err != nil {
		return nil, fail(ReasonDiscovery, err)
	}
	if err := checkJWKSHost(c, m.JWKSURI); err != nil {
		return nil, err
	}
	algs := intersect(AllowedAlgs, c.IDTokenAlgs, m.IDTokenAlgs)
	if len(algs) == 0 {
		return nil, fail(ReasonDiscovery, errors.New("no ID-token algorithm is allowed by Tessera, the connection and the IdP"))
	}
	pr := &provider{p: p, meta: m, algs: algs, fetched: now, conn: c}
	rp.mu.Lock()
	rp.cache[c.Key] = pr
	rp.mu.Unlock()
	return pr, nil
}

func checkJWKSHost(c Connection, jwks string) error {
	ju, err := url.Parse(jwks)
	iu, ierr := url.Parse(c.Issuer)
	if err != nil || ierr != nil || ju.Host == "" {
		return fail(ReasonJWKSHost, fmt.Errorf("jwks_uri %q", jwks))
	}
	if strings.EqualFold(ju.Host, iu.Host) || slices.ContainsFunc(c.JWKSHosts, func(h string) bool { return strings.EqualFold(h, ju.Hostname()) }) {
		return nil
	}
	return fail(ReasonJWKSHost, fmt.Errorf("jwks_uri host %s is neither the issuer's nor allowed", ju.Host))
}

// intersect keeps the values of base present in every non-empty list.
func intersect(base []string, lists ...[]string) []string {
	var out []string
	for _, a := range base {
		ok := true
		for _, l := range lists {
			if len(l) > 0 && !slices.Contains(l, a) {
				ok = false
			}
		}
		if ok {
			out = append(out, a)
		}
	}
	return out
}

// AuthRequest is one authorization request.
type AuthRequest struct {
	RedirectURI string
	State       string
	Nonce       string
	Verifier    string // PKCE code_verifier; the URL carries its S256 challenge
	ACRValues   []string
	MaxAge      *int64
	Prompt      string // "login" for step-up
	// Claims is the OIDC claims request parameter (Entra acrs), raw JSON.
	Claims string
}

func (rp *RP) oauth(pr *provider, c Connection, redirectURI string) *oauth2.Config {
	scopes := c.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	ep := pr.p.Endpoint()
	ep.AuthStyle = oauth2.AuthStyleInHeader // client_secret_basic
	return &oauth2.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, Endpoint: ep, RedirectURL: redirectURI,
		Scopes: scopes}
}

// AuthURL returns the IdP authorization URL for r.
func (rp *RP) AuthURL(ctx context.Context, c Connection, r AuthRequest) (string, error) {
	pr, err := rp.provider(ctx, c)
	if err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(r.Verifier), oidc.Nonce(r.Nonce)}
	if len(r.ACRValues) > 0 {
		opts = append(opts, oauth2.SetAuthURLParam("acr_values", strings.Join(r.ACRValues, " ")))
	}
	if r.MaxAge != nil {
		opts = append(opts, oauth2.SetAuthURLParam("max_age", fmt.Sprint(*r.MaxAge)))
	}
	if r.Prompt != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", r.Prompt))
	}
	if r.Claims != "" {
		opts = append(opts, oauth2.SetAuthURLParam("claims", r.Claims))
	}
	return rp.oauth(pr, c, r.RedirectURI).AuthCodeURL(r.State, opts...), nil
}

// Callback is what the redirect brought back plus what the transaction kept.
type Callback struct {
	Code        string
	Iss         string // RFC 9207 iss parameter ("" when absent)
	RedirectURI string
	Verifier    string
	Nonce       string
	MaxAge      *int64
	// NotBefore, for a step-up, is the transaction's start: auth_time must
	// not be older (minus StepUpSkew).
	NotBefore *time.Time
}

// Exchange checks the iss parameter, redeems the code and validates the ID
// token.
func (rp *RP) Exchange(ctx context.Context, c Connection, cb Callback) (*IDToken, error) {
	pr, err := rp.provider(ctx, c)
	if err != nil {
		return nil, err
	}
	// RFC 9207: when the IdP says it sends iss, it must be the issuer; when it
	// sends one anyway, it must match too (mix-up defence).
	if (pr.meta.IssParam || cb.Iss != "") && cb.Iss != c.Issuer {
		return nil, fail(ReasonIssParam, fmt.Errorf("iss parameter %q", cb.Iss))
	}
	tok, err := rp.oauth(pr, c, cb.RedirectURI).Exchange(rp.ctx(ctx, c), cb.Code, oauth2.VerifierOption(cb.Verifier))
	if err != nil {
		return nil, fail(ReasonTokenExchange, err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, fail(ReasonNoIDToken, nil)
	}
	v := pr.p.VerifierContext(rp.ctx(context.WithoutCancel(ctx), c), &oidc.Config{ClientID: c.ClientID,
		SupportedSigningAlgs: pr.algs, Now: rp.cfg.Now})
	return ValidateIDToken(ctx, v, raw, Expect{Issuer: c.Issuer, ClientID: c.ClientID, Algs: pr.algs, Nonce: cb.Nonce,
		MaxAge: cb.MaxAge, NotBefore: cb.NotBefore, Now: rp.cfg.Now()})
}

// Verifier verifies a raw ID token's signature, iss, aud and exp (go-oidc's
// *oidc.IDTokenVerifier).
type Verifier interface {
	Verify(ctx context.Context, raw string) (*oidc.IDToken, error)
}

// Expect is what an ID token must satisfy beyond the Verifier's checks.
type Expect struct {
	Issuer, ClientID string
	Algs             []string
	Nonce            string
	MaxAge           *int64
	NotBefore        *time.Time
	Now              time.Time
}

// IDToken is a validated ID token's claims.
type IDToken struct {
	Subject  string
	Issuer   string
	ACR      string
	AMR      []string
	ACRS     []string
	TID, OID string
	AuthTime time.Time
	Email    string
	Name     string
	Groups   []string
	SID      string
	// Raw is the claims JSON (hashed into the AuthnContext as evidence).
	Raw []byte
}

type claims struct {
	Iss      string       `json:"iss"`
	Sub      string       `json:"sub"`
	Aud      audience     `json:"aud"`
	Azp      string       `json:"azp"`
	Exp      *json.Number `json:"exp"`
	Iat      *json.Number `json:"iat"`
	Nonce    string       `json:"nonce"`
	AuthTime *json.Number `json:"auth_time"`
	ACR      string       `json:"acr"`
	AMR      []string     `json:"amr"`
	ACRS     []string     `json:"acrs"`
	TID      string       `json:"tid"`
	OID      string       `json:"oid"`
	Email    string       `json:"email"`
	Name     string       `json:"name"`
	Groups   []string     `json:"groups"`
	SID      string       `json:"sid"`
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = audience{s}
		return nil
	}
	var l []string
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	*a = l
	return nil
}

func unixOf(n *json.Number) (time.Time, bool) {
	if n == nil {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil || f < 0 || f > 1e11 {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0).UTC(), true
}

// forbiddenHeaders must never appear in an ID token's protected header: a
// verifier that honoured them would fetch or trust attacker keys.
var forbiddenHeaders = []string{"jku", "x5u", "jwk", "x5c", "crit"}

// ValidateIDToken validates a raw ID token (§10.4, ID tokens 1-6): size,
// algorithm and header (before any key is used), then v (signature, iss,
// aud, exp), then azp, iat, nonce and auth_time.
func ValidateIDToken(ctx context.Context, v Verifier, raw string, e Expect) (*IDToken, error) {
	if len(raw) > MaxIDTokenBytes {
		return nil, fail(ReasonTooLarge, nil)
	}
	algs := make([]jose.SignatureAlgorithm, 0, len(e.Algs))
	for _, a := range e.Algs {
		algs = append(algs, jose.SignatureAlgorithm(a))
	}
	jws, err := jose.ParseSigned(raw, algs)
	if err != nil {
		if strings.Count(raw, ".") == 2 {
			return nil, fail(ReasonAlg, err)
		}
		return nil, fail(ReasonMalformed, err)
	}
	if len(jws.Signatures) != 1 {
		return nil, fail(ReasonMalformed, errors.New("not exactly one signature"))
	}
	if hdr, err := protectedHeader(raw); err != nil {
		return nil, fail(ReasonMalformed, err)
	} else {
		for _, k := range forbiddenHeaders {
			if _, ok := hdr[k]; ok {
				return nil, fail(ReasonHeader, fmt.Errorf("%s header", k))
			}
		}
	}
	// The unverified claims only label a failure of v; nothing is trusted
	// before v succeeds.
	var pre claims
	_ = json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &pre)
	tok, err := v.Verify(ctx, raw)
	if err != nil {
		var exp *oidc.TokenExpiredError
		switch {
		case errors.As(err, &exp):
			return nil, fail(ReasonExpired, err)
		case pre.Iss != e.Issuer:
			return nil, fail(ReasonIssuer, err)
		case !slices.Contains(pre.Aud, e.ClientID):
			return nil, fail(ReasonAudience, err)
		}
		return nil, fail(ReasonSignature, err)
	}
	var c claims
	payload := jws.UnsafePayloadWithoutVerification() // the payload v just verified
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		return nil, fail(ReasonMalformed, err)
	}
	if c.Iss != e.Issuer || tok.Issuer != e.Issuer {
		return nil, fail(ReasonIssuer, nil)
	}
	if !slices.Contains(c.Aud, e.ClientID) {
		return nil, fail(ReasonAudience, nil)
	}
	if (len(c.Aud) > 1 || c.Azp != "") && c.Azp != e.ClientID {
		return nil, fail(ReasonAzp, fmt.Errorf("azp %q", c.Azp))
	}
	iat, ok := unixOf(c.Iat)
	if !ok || iat.After(e.Now.Add(IatSkew)) || iat.Before(e.Now.Add(-IatMaxAge)) {
		return nil, fail(ReasonIat, nil)
	}
	if e.Nonce == "" || !constantEqual(c.Nonce, e.Nonce) {
		return nil, fail(ReasonNonce, nil)
	}
	at, ok := unixOf(c.AuthTime)
	if !ok {
		return nil, fail(ReasonAuthTimeMissing, nil)
	}
	if e.MaxAge != nil && e.Now.Sub(at) > time.Duration(*e.MaxAge)*time.Second+AuthTimeSkew {
		return nil, fail(ReasonAuthTimeStale, fmt.Errorf("auth_time %s, max_age %d", at, *e.MaxAge))
	}
	if e.NotBefore != nil && at.Before(e.NotBefore.Add(-StepUpSkew)) {
		return nil, fail(ReasonAuthTimeStale, fmt.Errorf("auth_time %s before the step-up started", at))
	}
	if at.After(e.Now.Add(IatSkew)) {
		return nil, fail(ReasonAuthTimeStale, fmt.Errorf("auth_time %s in the future", at))
	}
	if c.Sub == "" {
		return nil, fail(ReasonSubject, nil)
	}
	return &IDToken{Subject: c.Sub, Issuer: c.Iss, ACR: c.ACR, AMR: c.AMR, ACRS: c.ACRS, TID: c.TID, OID: c.OID,
		AuthTime: at, Email: c.Email, Name: c.Name, Groups: c.Groups, SID: c.SID, Raw: payload}, nil
}

func protectedHeader(raw string) (map[string]any, error) {
	i := strings.IndexByte(raw, '.')
	if i < 0 {
		return nil, errors.New("no header")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw[:i])
	if err != nil {
		return nil, err
	}
	var h map[string]any
	return h, json.Unmarshal(b, &h)
}

func constantEqual(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}
