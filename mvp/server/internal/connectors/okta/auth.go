package okta

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// tokenSource gets and caches OAuth access tokens with a private_key_jwt
// client assertion (RFC 7523). Neither the key, the assertion nor the token is
// ever logged or put in an error.
type tokenSource struct {
	clientID string
	kid      string
	scopes   []string
	tokenURL string
	signer   jose.Signer
	api      *connsync.Client // a client without Authorize, for the token endpoint
	now      func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

func newTokenSource(cfg Config, base *url.URL, api *connsync.Client, now func() time.Time) (*tokenSource, error) {
	key, alg, err := parseKey(cfg.PrivateKey.Reveal())
	if err != nil {
		return nil, fmt.Errorf("okta: private key: %w", err)
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if cfg.KeyID != "" {
		opts = opts.WithHeader("kid", cfg.KeyID)
	}
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		return nil, fmt.Errorf("okta: private key: %w", err)
	}
	tokenAPI := *api
	tokenAPI.Authorize, tokenAPI.OnUnauthorized = nil, nil
	u := *base
	u.Path = "/oauth2/v1/token"
	return &tokenSource{clientID: cfg.ClientID, kid: cfg.KeyID, scopes: cfg.Scopes, tokenURL: u.String(),
		signer: sg, api: &tokenAPI, now: now}, nil
}

// parseKey reads a PEM private key (PKCS#8, PKCS#1 RSA or SEC1 EC).
func parseKey(p string) (crypto.Signer, jose.SignatureAlgorithm, error) {
	blk, _ := pem.Decode([]byte(p))
	if blk == nil {
		return nil, "", errors.New("not PEM encoded")
	}
	var k any
	var err error
	switch blk.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(blk.Bytes)
	default:
		return nil, "", errors.New("unsupported PEM type")
	}
	if err != nil {
		return nil, "", errors.New("cannot parse the key")
	}
	switch v := k.(type) {
	case *rsa.PrivateKey:
		if v.N.BitLen() < 2048 {
			return nil, "", errors.New("RSA key is shorter than 2048 bits")
		}
		return v, jose.RS256, nil
	case *ecdsa.PrivateKey:
		if v.Curve != elliptic.P256() {
			return nil, "", errors.New("only P-256 EC keys are supported")
		}
		return v, jose.ES256, nil
	}
	return nil, "", errors.New("unsupported key type")
}

func (t *tokenSource) assertion() (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	now := t.now()
	payload, err := json.Marshal(map[string]any{"iss": t.clientID, "sub": t.clientID, "aud": t.tokenURL,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": hex.EncodeToString(jti)})
	if err != nil {
		return "", err
	}
	obj, err := t.signer.Sign(payload)
	if err != nil {
		return "", errors.New("cannot sign the client assertion")
	}
	return obj.CompactSerialize()
}

// authorization returns "Bearer <token>", fetching a token when none is cached.
func (t *tokenSource) authorization(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token != "" && t.now().Before(t.expires.Add(-time.Minute)) {
		return "Bearer " + t.token, nil
	}
	as, err := t.assertion()
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {strings.Join(t.scopes, " ")},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {as}}
	resp, err := t.api.Do(ctx, http.MethodPost, t.tokenURL, http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("okta: token request: %w", err)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := connsync.DecodeJSON(resp.Body, &tr); err != nil {
		return "", fmt.Errorf("okta: token response: %w", err)
	}
	if tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "Bearer") {
		return "", errors.New("okta: token response has no bearer token")
	}
	if tr.ExpiresIn <= 0 || tr.ExpiresIn > 86400 {
		tr.ExpiresIn = 300
	}
	t.token, t.expires = tr.AccessToken, t.now().Add(time.Duration(tr.ExpiresIn)*time.Second)
	return "Bearer " + t.token, nil
}

func (t *tokenSource) invalidate() {
	t.mu.Lock()
	t.token = ""
	t.mu.Unlock()
}
