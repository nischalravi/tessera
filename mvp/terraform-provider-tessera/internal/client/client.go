// Package client is the Tessera API client of the Terraform provider. It
// authenticates the way every machine client does (RFC 7523 private_key_jwt
// client credentials, optionally with DPoP, RFC 9449) and talks only to the
// public API under /api/v1.
package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	maxBody       = 8 << 20
	assertionLife = 60 * time.Second
	// refreshMargin renews a token this long before it expires.
	refreshMargin = 30 * time.Second
	// APIPrefix is the versioned API the provider speaks (errors are one envelope, lists are {items,next_cursor}).
	APIPrefix = "/api/v1"
)

// Config is what the provider block resolves to.
type Config struct {
	Endpoint string // the server's public URL, https unless it is a loopback address
	Tenant   string // tenant slug
	ClientID string // the machine client's id (tsc_...)
	// PrivateKeyPEM is the client's private key (PKCS#8, SEC1 EC or PKCS#8 Ed25519): ES256 or EdDSA.
	PrivateKeyPEM string
	KeyID         string // the kid registered with the client; optional when it has one key
	Scope         string // optional; empty asks for every scope the client holds
	DPoP          bool   // bind the token to a per-run key; needed when the client has dpop_required
	CAFile        string // extra trusted CA (PEM) for a private PKI
	SkipTLSVerify bool   // never the default
	UserAgent     string
}

// APIError is a non-2xx answer.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	switch {
	case e.Code != "" && e.Message != "":
		return fmt.Sprintf("%s: %s (HTTP %d)", e.Code, e.Message, e.Status)
	case e.Code != "":
		return fmt.Sprintf("%s (HTTP %d)", e.Code, e.Status)
	default:
		return fmt.Sprintf("HTTP %d", e.Status)
	}
}

// IsNotFound reports a 404.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// Client is safe for concurrent use (Terraform applies resources in parallel).
type Client struct {
	cfg      Config
	base     *url.URL
	http     *http.Client
	signer   jose.Signer
	dpopKey  *ecdsa.PrivateKey
	tokenURL string

	mu        sync.Mutex
	token     string
	tokenType string
	expires   time.Time
	nonce     string
}

// New validates cfg and builds a client. It does no network I/O: the token is fetched on first use.
func New(cfg Config) (*Client, error) {
	base, err := ValidateEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	if !validSlug(cfg.Tenant) {
		return nil, errors.New("tenant must be the tenant slug (lowercase letters, digits and hyphens, 3 to 40 characters)")
	}
	if cfg.ClientID == "" || len(cfg.ClientID) > 128 || strings.ContainsAny(cfg.ClientID, " \r\n\t") {
		return nil, errors.New("client_id is required (the id of a machine client, from Admin > API clients)")
	}
	key, err := ParsePrivateKey(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	var alg jose.SignatureAlgorithm
	switch key.(type) {
	case *ecdsa.PrivateKey:
		alg = jose.ES256
	case ed25519.PrivateKey:
		alg = jose.EdDSA
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if cfg.KeyID != "" {
		opts = opts.WithHeader(jose.HeaderKey("kid"), cfg.KeyID)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		return nil, fmt.Errorf("private_key: %w", err)
	}
	c := &Client{cfg: cfg, base: base, signer: signer}
	if cfg.DPoP {
		if c.dpopKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, err
		}
	}
	if c.http, err = httpClient(cfg, base); err != nil {
		return nil, err
	}
	return c, nil
}

func validSlug(s string) bool {
	if len(s) < 3 || len(s) > 40 || s[0] == '-' {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// ValidateEndpoint accepts an https URL, or http only for a loopback host (a local `tessera serve`), with no user info,
// query or fragment, and returns it without a trailing slash.
func ValidateEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("endpoint must be a URL such as https://tessera.example.com (no credentials, query or fragment)")
	}
	switch u.Scheme {
	case "https":
	case "http":
		h := u.Hostname()
		if h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return nil, errors.New("endpoint must use https (plain http is accepted only for localhost)")
		}
	default:
		return nil, errors.New("endpoint must use https (plain http is accepted only for localhost)")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

// ParsePrivateKey reads a PEM EC (P-256) or Ed25519 private key.
func ParsePrivateKey(pemText string) (crypto.Signer, error) {
	blk, _ := pem.Decode([]byte(strings.TrimSpace(pemText)))
	if blk == nil {
		return nil, errors.New("private_key must be a PEM private key (PKCS#8 or SEC1) for ES256 or EdDSA")
	}
	var k any
	var err error
	if blk.Type == "EC PRIVATE KEY" {
		k, err = x509.ParseECPrivateKey(blk.Bytes)
	} else {
		k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	}
	if err != nil {
		return nil, errors.New("private_key cannot be parsed as a PEM private key")
	}
	switch kk := k.(type) {
	case *ecdsa.PrivateKey:
		if kk.Curve != elliptic.P256() {
			return nil, errors.New("private_key: an EC key must be P-256 (ES256)")
		}
		return kk, nil
	case ed25519.PrivateKey:
		return kk, nil
	}
	return nil, errors.New("private_key: only ES256 (P-256) and EdDSA (Ed25519) keys are accepted")
}

func httpClient(cfg Config, base *url.URL) (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12} // #nosec G402 -- verification is on unless the operator turns it off
	if cfg.SkipTLSVerify {
		tc.InsecureSkipVerify = true // #nosec G402 -- explicit opt-in, documented as for tests only
	}
	if cfg.CAFile != "" {
		pemBytes, err := os.ReadFile(cfg.CAFile) // #nosec G304 G304 -- the operator's own config path
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("ca_file holds no PEM certificate")
		}
		tc.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tc
	return &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
		// the token and the proofs go to the configured origin only
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Scheme != base.Scheme || req.URL.Host != base.Host {
				return errors.New("refusing to follow a redirect to another origin")
			}
			return nil
		},
	}, nil
}

// ---------------------------------------------------------------- token

func (c *Client) discover(ctx context.Context) (string, error) {
	u := c.base.String() + "/t/" + c.cfg.Tenant + "/.well-known/oauth-authorization-server"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	c.decorate(req)
	res, err := c.http.Do(req) // #nosec G107 -- the configured endpoint
	if err != nil {
		return "", fmt.Errorf("reading the tenant's OAuth metadata: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the tenant's OAuth metadata answered HTTP %d (is tenant %q right?)", res.StatusCode, c.cfg.Tenant)
	}
	var md struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(b, &md); err != nil || md.TokenEndpoint == "" {
		return "", errors.New("the tenant's OAuth metadata has no token_endpoint")
	}
	tu, err := url.Parse(md.TokenEndpoint)
	if err != nil || tu.Scheme != c.base.Scheme || tu.Host != c.base.Host {
		return "", fmt.Errorf("the token endpoint %q is not on the configured endpoint's origin; set endpoint to the server's public URL (TESSERA_PUBLIC_URL)", md.TokenEndpoint)
	}
	return md.TokenEndpoint, nil
}

func (c *Client) decorate(req *http.Request) {
	ua := c.cfg.UserAgent
	if ua == "" {
		ua = "terraform-provider-tessera"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")
}

func (c *Client) assertion(aud string) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	now := time.Now()
	return jwt.Signed(c.signer).Claims(map[string]any{
		"iss": c.cfg.ClientID, "sub": c.cfg.ClientID, "aud": aud,
		"iat": now.Unix(), "exp": now.Add(assertionLife).Unix(), "jti": base64.RawURLEncoding.EncodeToString(jti),
	}).Serialize()
}

// proof builds a DPoP proof for a request (RFC 9449 §4.2); ath binds it to an access token.
func (c *Client) proof(method, rawURL, accessToken, nonce string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	u.RawQuery, u.Fragment = "", ""
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: c.dpopKey},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	claims := map[string]any{"jti": base64.RawURLEncoding.EncodeToString(jti), "htm": method, "htu": u.String(), "iat": time.Now().Unix()}
	if accessToken != "" {
		h := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(h[:])
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

// ensureToken returns a valid access token, minting one when needed. Callers hold c.mu.
func (c *Client) ensureToken(ctx context.Context, force bool) error {
	if !force && c.token != "" && time.Now().Add(refreshMargin).Before(c.expires) {
		return nil
	}
	if c.tokenURL == "" {
		tu, err := c.discover(ctx)
		if err != nil {
			return err
		}
		c.tokenURL = tu
	}
	for attempt := 0; ; attempt++ {
		as, err := c.assertion(c.tokenURL)
		if err != nil {
			return err
		}
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.cfg.ClientID},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {as}}
		if c.cfg.Scope != "" {
			form.Set("scope", c.cfg.Scope)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		c.decorate(req)
		if c.dpopKey != nil {
			p, err := c.proof(http.MethodPost, c.tokenURL, "", c.nonce)
			if err != nil {
				return err
			}
			req.Header.Set("DPoP", p)
		}
		res, err := c.http.Do(req) // #nosec G107 -- the configured endpoint
		if err != nil {
			return fmt.Errorf("token request: %w", err)
		}
		b, _ := io.ReadAll(io.LimitReader(res.Body, maxBody))
		_ = res.Body.Close()
		if n := res.Header.Get("DPoP-Nonce"); n != "" {
			c.nonce = n
		}
		if res.StatusCode != http.StatusOK {
			var e struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			_ = json.Unmarshal(b, &e)
			if e.Error == "use_dpop_nonce" && attempt == 0 && c.nonce != "" {
				continue
			}
			return &APIError{Status: res.StatusCode, Code: printable(e.Error), Message: "token request refused: " + printable(e.Description)}
		}
		var t struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
		}
		if err := json.Unmarshal(b, &t); err != nil || t.AccessToken == "" {
			return errors.New("the token response is not a token")
		}
		if c.dpopKey != nil && !strings.EqualFold(t.TokenType, "DPoP") {
			return errors.New("dpop is on but the server issued a Bearer token; the client is not DPoP-bound")
		}
		c.token, c.tokenType = t.AccessToken, "Bearer"
		if c.dpopKey != nil {
			c.tokenType = "DPoP"
		}
		if t.ExpiresIn <= 0 {
			t.ExpiresIn = 60
		}
		c.expires = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
		return nil
	}
}

// printable trims a server-supplied string for an error message.
func printable(s string) string {
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// ---------------------------------------------------------------- requests

// Do calls the API at path (a path under /api/v1, such as /groups/folders) with a JSON body (nil for none) and decodes a
// JSON answer into out (nil to discard). A non-2xx answer is an *APIError. A stale token is renewed once.
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\\r\n") {
		return fmt.Errorf("%q is not an API path", path)
	}
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	full := c.base.String() + APIPrefix + path
	renewed, noncesTried := false, false
	for {
		c.mu.Lock()
		if err := c.ensureToken(ctx, false); err != nil {
			c.mu.Unlock()
			return err
		}
		tok, typ, nonce := c.token, c.tokenType, c.nonce
		var proof string
		if c.dpopKey != nil {
			var err error
			if proof, err = c.proof(method, full, tok, nonce); err != nil {
				c.mu.Unlock()
				return err
			}
		}
		c.mu.Unlock()

		req, err := http.NewRequestWithContext(ctx, method, full, bytes.NewReader(body))
		if err != nil {
			return err
		}
		c.decorate(req)
		req.Header.Set("Authorization", typ+" "+tok)
		if proof != "" {
			req.Header.Set("DPoP", proof)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := c.http.Do(req) // #nosec G107 -- the configured endpoint
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(io.LimitReader(res.Body, maxBody))
		_ = res.Body.Close()
		if n := res.Header.Get("DPoP-Nonce"); n != "" {
			c.mu.Lock()
			c.nonce = n
			c.mu.Unlock()
		}
		if res.StatusCode == http.StatusUnauthorized {
			ch := res.Header.Get("WWW-Authenticate")
			switch {
			case strings.Contains(ch, "use_dpop_nonce") && !noncesTried:
				noncesTried = true
				continue
			case !renewed:
				renewed = true
				c.mu.Lock()
				err := c.ensureToken(ctx, true)
				c.mu.Unlock()
				if err != nil {
					return err
				}
				continue
			}
		}
		if res.StatusCode < 200 || res.StatusCode > 299 {
			return parseError(res.StatusCode, b)
		}
		if out != nil && len(bytes.TrimSpace(b)) > 0 {
			if err := json.Unmarshal(b, out); err != nil {
				return fmt.Errorf("the answer to %s %s is not the expected JSON: %w", method, path, err)
			}
		}
		return nil
	}
}

// parseError reads the /api/v1 envelope {"error":{"code","message","field"}}, and the older {"error":"code","detail":"..."}.
func parseError(status int, b []byte) error {
	ae := &APIError{Status: status}
	var env struct {
		Error  json.RawMessage `json:"error"`
		Detail string          `json:"detail"`
		Msg    string          `json:"message"`
	}
	if json.Unmarshal(b, &env) == nil && len(env.Error) > 0 {
		var obj struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Field   string `json:"field"`
		}
		var s string
		switch {
		case json.Unmarshal(env.Error, &obj) == nil && obj.Code != "":
			ae.Code, ae.Message = obj.Code, obj.Message
			if obj.Field != "" {
				ae.Message += " (field " + obj.Field + ")"
			}
		case json.Unmarshal(env.Error, &s) == nil:
			ae.Code, ae.Message = s, env.Detail
			if ae.Message == "" {
				ae.Message = env.Msg
			}
		}
	}
	ae.Code, ae.Message = printable(ae.Code), printable(ae.Message)
	return ae
}
