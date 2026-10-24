package azurerbac

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// assertionSigner signs the client assertion of certificate authentication.
type assertionSigner struct {
	key    *rsa.PrivateKey
	thumb  string // base64url SHA-256 of the certificate's DER encoding (x5t#S256)
	expire time.Time
}

// parseCredential returns nil for a client secret, and the signer when the credential is a PEM
// holding a certificate and its RSA private key. A PEM that holds only one of them is refused.
func parseCredential(cred string) (*assertionSigner, error) {
	if !strings.HasPrefix(strings.TrimSpace(cred), "-----BEGIN") {
		return nil, nil
	}
	var key *rsa.PrivateKey
	var cert *x509.Certificate
	rest := []byte(cred)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		switch b.Type {
		case "CERTIFICATE":
			if cert == nil {
				c, err := x509.ParseCertificate(b.Bytes)
				if err != nil {
					return nil, errors.New("azurerbac: the certificate in the credential cannot be parsed")
				}
				cert = c
			}
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
			rk, ok := k.(*rsa.PrivateKey)
			if err != nil || !ok {
				return nil, errors.New("azurerbac: the private key must be an RSA key")
			}
			key = rk
		case "RSA PRIVATE KEY":
			k, err := x509.ParsePKCS1PrivateKey(b.Bytes)
			if err != nil {
				return nil, errors.New("azurerbac: the private key cannot be parsed")
			}
			key = k
		}
	}
	if key == nil || cert == nil {
		return nil, errors.New("azurerbac: the credential PEM must hold a certificate and its RSA private key")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(key.N) != 0 || pub.E != key.E {
		return nil, errors.New("azurerbac: the private key does not belong to the certificate")
	}
	sum := sha256.Sum256(cert.Raw)
	return &assertionSigner{key: key, thumb: base64.RawURLEncoding.EncodeToString(sum[:]), expire: cert.NotAfter}, nil
}

// assertion builds the signed client assertion (RFC 7523 as Microsoft documents it: PS256, x5t#S256,
// iss and sub the client id, aud the token endpoint, a ten minute life).
func (s *assertionSigner) assertion(clientID, audience string, now time.Time) (string, error) {
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return "", err
	}
	hdr, _ := json.Marshal(map[string]string{"alg": "PS256", "typ": "JWT", "x5t#S256": s.thumb})
	claims, _ := json.Marshal(map[string]any{"aud": audience, "iss": clientID, "sub": clientID, "jti": hex.EncodeToString(jti[:]),
		"nbf": now.Unix(), "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix()})
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(hdr) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPSS(rand.Reader, s.key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// tokenSource gets and caches client-credentials access tokens for Azure Resource Manager. The
// secret, the assertion and the token are never logged or put in an error.
type tokenSource struct {
	cfg      Config
	tokenURL string
	scope    string
	signer   *assertionSigner
	api      *connsync.Client // without Authorize, for the token endpoint
	now      func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

func newTokenSource(cfg Config, authority, arm *url.URL, signer *assertionSigner, api *connsync.Client, now func() time.Time) *tokenSource {
	tokenAPI := *api
	tokenAPI.Authorize, tokenAPI.OnUnauthorized = nil, nil
	u := *authority
	u.Path = "/" + url.PathEscape(cfg.TenantID) + "/oauth2/v2.0/token"
	scope := *arm
	scope.Path = "/.default"
	return &tokenSource{cfg: cfg, tokenURL: u.String(), scope: scope.String(), signer: signer, api: &tokenAPI, now: now}
}

func (t *tokenSource) form() (url.Values, error) {
	f := url.Values{"grant_type": {"client_credentials"}, "client_id": {t.cfg.ClientID}, "scope": {t.scope}}
	if t.signer == nil {
		f.Set("client_secret", t.cfg.Credential.Reveal())
		return f, nil
	}
	a, err := t.signer.assertion(t.cfg.ClientID, t.tokenURL, t.now())
	if err != nil {
		return nil, errors.New("azurerbac: the client assertion cannot be signed")
	}
	f.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	f.Set("client_assertion", a)
	return f, nil
}

func (t *tokenSource) authorization(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token != "" && t.now().Before(t.expires.Add(-time.Minute)) {
		return "Bearer " + t.token, nil
	}
	f, err := t.form()
	if err != nil {
		return "", err
	}
	resp, err := t.api.Do(ctx, http.MethodPost, t.tokenURL, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(f.Encode()))
	if err != nil {
		if s := connsync.Status(err); s == http.StatusBadRequest || s == http.StatusUnauthorized || s == http.StatusForbidden {
			return "", fmt.Errorf("azurerbac: token request: %w (%v)", ErrCredential, err)
		}
		return "", fmt.Errorf("azurerbac: token request: %w", err)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := connsync.DecodeJSON(resp.Body, &tr); err != nil {
		return "", fmt.Errorf("azurerbac: token response: %w", err)
	}
	if tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "Bearer") {
		return "", errors.New("azurerbac: token response has no bearer token")
	}
	if tr.ExpiresIn <= 0 || tr.ExpiresIn > 86400 {
		tr.ExpiresIn = 600
	}
	t.token, t.expires = tr.AccessToken, t.now().Add(time.Duration(tr.ExpiresIn)*time.Second)
	return "Bearer " + t.token, nil
}

func (t *tokenSource) invalidate() {
	t.mu.Lock()
	t.token = ""
	t.mu.Unlock()
}
