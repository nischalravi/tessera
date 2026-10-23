package cloudcred

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Azure finds access tokens for a resource (https://storage.azure.com,
// https://vault.azure.net).
type Azure struct {
	Env
	// HTTP is the guarded client (Microsoft Entra). Meta is the safehttp metadata client.
	HTTP, Meta *http.Client
	// LoginURL replaces https://login.microsoftonline.com (tests, sovereign clouds).
	LoginURL string

	mu     sync.Mutex
	tokens map[string]*cached[string]
}

// Token returns a bearer token for resource, fetched with workload identity
// federation (AZURE_FEDERATED_TOKEN_FILE, AZURE_TENANT_ID, AZURE_CLIENT_ID) or
// else the managed identity endpoint (AZURE_CLIENT_ID picks a user-assigned
// identity).
func (z *Azure) Token(ctx context.Context, resource string) (string, error) {
	resource = strings.TrimRight(resource, "/")
	z.mu.Lock()
	if z.tokens == nil {
		z.tokens = map[string]*cached[string]{}
	}
	c := z.tokens[resource]
	if c == nil {
		c = &cached[string]{}
		z.tokens[resource] = c
	}
	z.mu.Unlock()
	return c.get(z.now(), func() (string, time.Time, error) {
		if z.get("AZURE_FEDERATED_TOKEN_FILE") != "" && z.get("AZURE_TENANT_ID") != "" && z.get("AZURE_CLIENT_ID") != "" {
			return z.federated(ctx, resource)
		}
		return z.managed(ctx, resource)
	})
}

type azToken struct {
	AccessToken string          `json:"access_token"`
	ExpiresIn   json.RawMessage `json:"expires_in"` // a number (Entra) or a string (IMDS)
}

func (t azToken) result(now time.Time) (string, time.Time, error) {
	if t.AccessToken == "" {
		return "", time.Time{}, errors.New("cloudcred: Azure: no access token in the response")
	}
	secs := int64(3600)
	if s := strings.Trim(string(t.ExpiresIn), `" `); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
			secs = n
		}
	}
	return t.AccessToken, now.Add(time.Duration(secs) * time.Second), nil
}

func (z *Azure) federated(ctx context.Context, resource string) (string, time.Time, error) {
	assertion, err := z.read(z.get("AZURE_FEDERATED_TOKEN_FILE"))
	if err != nil {
		return "", time.Time{}, errors.New("cloudcred: cannot read AZURE_FEDERATED_TOKEN_FILE")
	}
	base := z.LoginURL
	if base == "" {
		base = "https://login.microsoftonline.com"
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {z.get("AZURE_CLIENT_ID")},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {strings.TrimSpace(string(assertion))}, "scope": {resource + "/.default"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(base, "/")+"/"+url.PathEscape(z.get("AZURE_TENANT_ID"))+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	b, err := do(z.HTTP, req, "Azure workload identity")
	if err != nil {
		return "", time.Time{}, err
	}
	var t azToken
	if err := json.Unmarshal(b, &t); err != nil {
		return "", time.Time{}, errors.New("cloudcred: Azure workload identity: unexpected response")
	}
	return t.result(z.now())
}

func (z *Azure) managed(ctx context.Context, resource string) (string, time.Time, error) {
	q := url.Values{"api-version": {"2018-02-01"}, "resource": {resource}}
	if id := z.get("AZURE_CLIENT_ID"); id != "" {
		q.Set("client_id", id)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imdsBase+"/metadata/identity/oauth2/token?"+q.Encode(), nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Metadata", "true")
	b, err := do(z.Meta, req, "Azure managed identity")
	if err != nil {
		return "", time.Time{}, errors.Join(ErrNoCredentials, err)
	}
	var t azToken
	if err := json.Unmarshal(b, &t); err != nil {
		return "", time.Time{}, errors.New("cloudcred: Azure managed identity: unexpected response")
	}
	return t.result(z.now())
}
