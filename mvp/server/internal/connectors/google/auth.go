package google

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
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

// parseServiceAccountKey reads the JSON key file Google issues for a service
// account. Only the e-mail, the private key and its id are used: the file's
// own token_uri is ignored, so a doctored key file cannot point the signed
// assertion somewhere else. Errors never quote the file.
func parseServiceAccountKey(raw string) (email string, key connsync.Secret, kid string, err error) {
	var f struct {
		Type         string `json:"type"`
		ClientEmail  string `json:"client_email"`
		PrivateKey   string `json:"private_key"`
		PrivateKeyID string `json:"private_key_id"`
	}
	if json.Unmarshal([]byte(raw), &f) != nil {
		return "", connsync.Secret{}, "", errors.New("is not a JSON service account key file")
	}
	if f.Type != "service_account" || f.ClientEmail == "" || f.PrivateKey == "" {
		return "", connsync.Secret{}, "", errors.New("is not a service account key (type, client_email and private_key are required)")
	}
	return f.ClientEmail, connsync.NewSecret(f.PrivateKey), f.PrivateKeyID, nil
}

// parseKey reads a PEM RSA private key (PKCS#8 or PKCS#1) of 2048 bits or more.
func parseKey(p string) (crypto.Signer, error) {
	blk, _ := pem.Decode([]byte(p))
	if blk == nil {
		return nil, errors.New("not PEM encoded")
	}
	var k any
	var err error
	switch blk.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	default:
		return nil, errors.New("unsupported PEM type")
	}
	if err != nil {
		return nil, errors.New("cannot parse the key")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	if rk.N.BitLen() < 2048 {
		return nil, errors.New("RSA key is shorter than 2048 bits")
	}
	return rk, nil
}

// tokenSource gets and caches access tokens with the JWT bearer grant
// (RFC 7523) under domain-wide delegation: the assertion is signed RS256 with
// the service account key, names the impersonated administrator as sub, and
// lists the read-only scopes. Neither the key, the assertion nor the token is
// ever logged or put in an error.
type tokenSource struct {
	iss, sub, scope string
	tokenURL        string
	signer          jose.Signer
	api             *connsync.Client // without Authorize, for the token endpoint
	now             func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

func newTokenSource(cfg Config, tokenURL *url.URL, api *connsync.Client, now func() time.Time) (*tokenSource, error) {
	key, err := parseKey(cfg.PrivateKey.Reveal())
	if err != nil {
		return nil, fmt.Errorf("google: private key: %w", err)
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if cfg.KeyID != "" {
		opts = opts.WithHeader("kid", cfg.KeyID)
	}
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, opts)
	if err != nil {
		return nil, errors.New("google: private key: cannot use it to sign")
	}
	tokenAPI := *api
	tokenAPI.Authorize, tokenAPI.OnUnauthorized = nil, nil
	return &tokenSource{iss: cfg.ServiceAccountEmail, sub: cfg.AdminEmail, scope: strings.Join(cfg.Scopes(), " "),
		tokenURL: tokenURL.String(), signer: sg, api: &tokenAPI, now: now}, nil
}

func (t *tokenSource) assertion() (string, error) {
	now := t.now()
	payload, err := json.Marshal(map[string]any{"iss": t.iss, "sub": t.sub, "scope": t.scope, "aud": t.tokenURL,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	if err != nil {
		return "", err
	}
	obj, err := t.signer.Sign(payload)
	if err != nil {
		return "", errors.New("cannot sign the assertion")
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
		return "", fmt.Errorf("google: token request: %w", err)
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {as}}
	resp, err := t.api.Do(ctx, http.MethodPost, t.tokenURL, http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("google: token request: %w", err)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := connsync.DecodeJSON(resp.Body, &tr); err != nil {
		return "", fmt.Errorf("google: token response: %w", err)
	}
	if tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "Bearer") {
		return "", errors.New("google: token response has no bearer token")
	}
	if tr.ExpiresIn <= 0 || tr.ExpiresIn > 86400 {
		tr.ExpiresIn = 3600
	}
	t.token, t.expires = tr.AccessToken, t.now().Add(time.Duration(tr.ExpiresIn)*time.Second)
	return "Bearer " + t.token, nil
}

func (t *tokenSource) invalidate() {
	t.mu.Lock()
	t.token = ""
	t.mu.Unlock()
}
