package cloudcred

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GCP finds OAuth access tokens.
type GCP struct {
	Env
	// HTTP is the guarded client (Google OAuth). Meta is the safehttp metadata client.
	HTTP, Meta *http.Client
	// TokenURL replaces https://oauth2.googleapis.com/token (tests). A key
	// file's own token_uri is ignored: the endpoint is never taken from a file.
	TokenURL string

	mu     sync.Mutex
	tokens map[string]*cached[string]
}

// Token returns an access token for scope: from the service-account key at
// GOOGLE_APPLICATION_CREDENTIALS when set, else from the metadata server
// (workload identity on GKE, the attached service account on GCE).
func (g *GCP) Token(ctx context.Context, scope string) (string, error) {
	g.mu.Lock()
	if g.tokens == nil {
		g.tokens = map[string]*cached[string]{}
	}
	c := g.tokens[scope]
	if c == nil {
		c = &cached[string]{}
		g.tokens[scope] = c
	}
	g.mu.Unlock()
	return c.get(g.now(), func() (string, time.Time, error) {
		if p := g.get("GOOGLE_APPLICATION_CREDENTIALS"); p != "" {
			return g.serviceAccount(ctx, p, scope)
		}
		return g.metadata(ctx)
	})
}

type gcpToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

func (t gcpToken) result(now time.Time) (string, time.Time, error) {
	if t.AccessToken == "" {
		return "", time.Time{}, errors.New("cloudcred: GCP: no access token in the response")
	}
	if t.ExpiresIn <= 0 {
		t.ExpiresIn = 3600
	}
	return t.AccessToken, now.Add(time.Duration(t.ExpiresIn) * time.Second), nil
}

func (g *GCP) metadata(ctx context.Context) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imdsBase+"/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	b, err := do(g.Meta, req, "GCP metadata server")
	if err != nil {
		return "", time.Time{}, errors.Join(ErrNoCredentials, err)
	}
	var t gcpToken
	if err := json.Unmarshal(b, &t); err != nil {
		return "", time.Time{}, errors.New("cloudcred: GCP metadata server: unexpected response")
	}
	return t.result(g.now())
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (g *GCP) serviceAccount(ctx context.Context, path, scope string) (string, time.Time, error) {
	raw, err := g.read(path)
	if err != nil {
		return "", time.Time{}, errors.New("cloudcred: cannot read GOOGLE_APPLICATION_CREDENTIALS")
	}
	var key struct {
		Type, ClientEmail, PrivateKey, PrivateKeyID string
	}
	var kj map[string]string
	if err := json.Unmarshal(raw, &kj); err != nil {
		return "", time.Time{}, errors.New("cloudcred: GOOGLE_APPLICATION_CREDENTIALS is not a JSON key file")
	}
	key.Type, key.ClientEmail, key.PrivateKey, key.PrivateKeyID = kj["type"], kj["client_email"], kj["private_key"], kj["private_key_id"]
	if key.Type != "service_account" || key.ClientEmail == "" || key.PrivateKey == "" {
		return "", time.Time{}, errors.New("cloudcred: GOOGLE_APPLICATION_CREDENTIALS must be a service_account key (workload identity federation files are not supported)")
	}
	blk, _ := pem.Decode([]byte(key.PrivateKey))
	if blk == nil {
		return "", time.Time{}, errors.New("cloudcred: the service-account private key is not PEM")
	}
	k8, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	rk, ok := k8.(*rsa.PrivateKey)
	if err != nil || !ok {
		return "", time.Time{}, errors.New("cloudcred: the service-account private key is not an RSA PKCS#8 key")
	}
	endpoint := g.TokenURL
	if endpoint == "" {
		endpoint = "https://oauth2.googleapis.com/token"
	}
	now := g.now()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": key.PrivateKeyID})
	claims, _ := json.Marshal(map[string]any{"iss": key.ClientEmail, "scope": scope, "aud": endpoint,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	signing := b64(hdr) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, sum[:])
	if err != nil {
		return "", time.Time{}, errors.New("cloudcred: cannot sign the service-account assertion")
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {signing + "." + b64(sig)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	b, err := do(g.HTTP, req, "GCP service account")
	if err != nil {
		return "", time.Time{}, err
	}
	var t gcpToken
	if err := json.Unmarshal(b, &t); err != nil {
		return "", time.Time{}, errors.New("cloudcred: GCP service account: unexpected response")
	}
	return t.result(now)
}
