// Package salesforce reads a Salesforce org's access model into Tessera's graph
// (users, profiles, roles, permission sets and permission set groups, and who
// holds them) and writes user lifecycle and permission-set assignment back
// through provisioning (issue #555).
//
// Authentication is the OAuth 2.0 JWT bearer flow: a connected app holds the
// certificate, Tessera signs a short-lived assertion (RS256) with the matching
// private key and exchanges it for an access token. No password and no refresh
// token is kept. The API host is the configured base URL only: the instance_url
// in a token response is never followed, so a response cannot redirect the
// bearer token.
//
// Mapping onto Tessera's graph (Discover):
//
//	profile                  -> group (kind salesforce_profile), not requestable: a user has exactly one
//	role                     -> group (kind salesforce_role), not requestable
//	permission set           -> group (kind salesforce_permission_set), requestable
//	permission set group     -> group (kind salesforce_permission_set_group), requestable; member_of each component set
//	system permission flag   -> permission "sf:<Flag>" on the resource "org"; a profile or set -grants-> the flags it enables
//	user                     -> account (disabled when inactive or frozen), correlated by e-mail; -member_of-> profile, role,
//	                            and each permission set or group assigned now
//
// A profile's own hidden permission set (IsOwnedByProfile) and the set Salesforce
// generates for a group (Type Group) are not groups: they fold into the profile
// and the group.
package salesforce

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
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// DefaultAPIVersion is the REST API version used when the config names none.
const DefaultAPIVersion = "v61.0"

const (
	tokenPath    = "/services/oauth2/token"
	jwtGrant     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	assertionTTL = 3 * time.Minute
	// tokenTTL is how long a token is reused. Salesforce does not return expires_in for this
	// flow and the org's session timeout decides; a 401 drops the token early.
	tokenTTL = 10 * time.Minute
	maxPages = 5000
)

var (
	idRE      = regexp.MustCompile(`^[a-zA-Z0-9]{15,18}$`)
	versionRE = regexp.MustCompile(`^v[0-9]{2}\.0$`)
	// soqlText is what may sit inside a quoted SOQL literal (a username): no quote, backslash or control.
	soqlText = regexp.MustCompile(`^[^'\\\x00-\x1f]{1,200}$`)
)

// Config configures one org.
type Config struct {
	// BaseURL is the org's My Domain URL (https://acme.my.salesforce.com): the API host.
	BaseURL string
	// LoginURL is the token endpoint's origin and the assertion's audience. Empty: BaseURL. A sandbox
	// logs in at https://test.salesforce.com.
	LoginURL string
	// ClientID is the connected app's consumer key.
	ClientID string
	// Username is the integration user the assertion names (sub).
	Username string
	// PrivateKey is the PEM RSA private key whose certificate the connected app holds.
	PrivateKey connsync.Secret
	// APIVersion is "v61.0" and the like.
	APIVersion string
}

// Client is a retrying REST client of one org.
type Client struct {
	api      *connsync.Client
	base     *url.URL
	tokenURL string
	aud      string
	cfg      Config
	key      *rsa.PrivateKey
	version  string
	now      func() time.Time

	mu      sync.Mutex
	access  string
	expires time.Time
}

// Open validates cfg and returns the client. hc is the server's safehttp client.
func Open(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Client, error) {
	if hc == nil {
		return nil, errors.New("salesforce: an internal/safehttp client is required")
	}
	if now == nil {
		now = time.Now
	}
	if cfg.ClientID == "" || len(cfg.ClientID) > 256 || !soqlText.MatchString(cfg.Username) || cfg.PrivateKey.Empty() {
		return nil, errors.New("salesforce: a consumer key, an integration username and a private key are required")
	}
	base, err := connsync.ParseBaseURL(cfg.BaseURL, rt)
	if err != nil {
		return nil, fmt.Errorf("salesforce: base URL: %w", err)
	}
	login := base
	if cfg.LoginURL != "" {
		if login, err = connsync.ParseBaseURL(cfg.LoginURL, rt); err != nil {
			return nil, fmt.Errorf("salesforce: login URL: %w", err)
		}
	}
	if base.Path != "" || login.Path != "" {
		return nil, errors.New("salesforce: the base and login URLs are hosts without a path")
	}
	version := cfg.APIVersion
	if version == "" {
		version = DefaultAPIVersion
	}
	if !versionRE.MatchString(version) {
		return nil, errors.New("salesforce: the API version looks like v61.0")
	}
	key, err := parseKey(cfg.PrivateKey.Reveal())
	if err != nil {
		return nil, err
	}
	tu := *login
	tu.Path = tokenPath
	c := &Client{base: base, tokenURL: tu.String(), aud: login.Scheme + "://" + login.Host, cfg: cfg, key: key, version: version, now: now}
	c.api = &connsync.Client{HC: hc, Now: now, Header: http.Header{"Accept": {"application/json"}, "User-Agent": {"tessera-connector/salesforce"}}}
	c.api.Authorize = c.authorize
	c.api.OnUnauthorized = func() { c.mu.Lock(); c.access = ""; c.mu.Unlock() }
	return c, nil
}

func parseKey(pemText string) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode([]byte(pemText))
	if blk == nil {
		return nil, errors.New("salesforce: the private key is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("salesforce: the private key is not a PKCS#1 or PKCS#8 RSA key")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("salesforce: the private key is not RSA")
	}
	return rk, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// assertion builds the signed JWT of the bearer flow.
func (c *Client) assertion() (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{"iss": c.cfg.ClientID, "sub": c.cfg.Username, "aud": c.aud, "exp": c.now().Add(assertionTTL).Unix()})
	in := b64(hdr) + "." + b64(claims)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", errors.New("salesforce: cannot sign the assertion")
	}
	return in + "." + b64(sig), nil
}

func (c *Client) authorize(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.access != "" && c.now().Before(c.expires) {
		return "Bearer " + c.access, nil
	}
	as, err := c.assertion()
	if err != nil {
		return "", err
	}
	plain := *c.api
	plain.Authorize, plain.OnUnauthorized = nil, nil
	resp, err := plain.Do(ctx, http.MethodPost, c.tokenURL, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		[]byte(url.Values{"grant_type": {jwtGrant}, "assertion": {as}}.Encode()))
	if err != nil {
		return "", fmt.Errorf("salesforce: token request: %w", err)
	}
	var tr struct {
		Access string `json:"access_token"`
		Type   string `json:"token_type"`
	}
	if err := connsync.DecodeJSON(resp.Body, &tr); err != nil {
		return "", fmt.Errorf("salesforce: token response: %w", err)
	}
	if tr.Access == "" || !strings.EqualFold(tr.Type, "bearer") {
		return "", errors.New("salesforce: token response has no bearer token")
	}
	c.access, c.expires = tr.Access, c.now().Add(tokenTTL)
	return "Bearer " + c.access, nil
}

func (c *Client) dataPath(rest string) string {
	return "/services/data/" + c.version + rest
}

func (c *Client) u(path string, q url.Values) string {
	x := *c.base
	x.Path = path
	x.RawQuery = q.Encode()
	return x.String()
}

// record is one SOQL row.
type record map[string]any

func (r record) str(k string) string { s, _ := r[k].(string); return s }
func (r record) flag(k string) bool  { b, _ := r[k].(bool); return b }

func (r record) time(k string) *time.Time {
	s := r.str(k)
	for _, l := range []string{time.RFC3339, "2006-01-02T15:04:05.000-0700", "2006-01-02"} {
		if t, err := time.Parse(l, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

// query runs a SOQL query and calls each for every row, following nextRecordsUrl
// (same origin, under /services/data/).
func (c *Client) query(ctx context.Context, soql string, each func(record) error) error {
	next := c.u(c.dataPath("/query"), url.Values{"q": {soql}})
	for i := 0; next != ""; i++ {
		if i >= maxPages {
			return fmt.Errorf("salesforce: more than %d pages; stopping", maxPages)
		}
		var page struct {
			Done    bool     `json:"done"`
			Next    string   `json:"nextRecordsUrl"`
			Records []record `json:"records"`
		}
		if _, err := c.api.GetJSON(ctx, next, nil, &page); err != nil {
			return err
		}
		for _, r := range page.Records {
			if err := each(r); err != nil {
				return err
			}
		}
		next = ""
		if !page.Done && page.Next != "" {
			if !strings.HasPrefix(page.Next, "/services/data/") || strings.Contains(page.Next, "..") {
				return errors.New("salesforce: page link leaves the REST API")
			}
			next = c.u(page.Next, nil)
		}
	}
	return nil
}

func (c *Client) rows(ctx context.Context, soql string) ([]record, error) {
	var out []record
	err := c.query(ctx, soql, func(r record) error { out = append(out, r); return nil })
	return out, err
}

// create makes an sobject and returns its id.
func (c *Client) create(ctx context.Context, sobject string, body map[string]any) (string, error) {
	b, _ := json.Marshal(body)
	resp, err := c.api.Do(ctx, http.MethodPost, c.u(c.dataPath("/sobjects/"+sobject), nil), http.Header{"Content-Type": {"application/json"}}, b)
	if err != nil {
		return "", err
	}
	var out struct {
		ID      string `json:"id"`
		Success bool   `json:"success"`
	}
	if err := connsync.DecodeJSON(resp.Body, &out); err != nil || !out.Success || !idRE.MatchString(out.ID) {
		return "", fmt.Errorf("salesforce: create %s: %w", sobject, connsync.ErrMalformed)
	}
	return out.ID, nil
}

func (c *Client) update(ctx context.Context, sobject, id string, body map[string]any) error {
	if !idRE.MatchString(id) {
		return errors.New("salesforce: invalid record id")
	}
	b, _ := json.Marshal(body)
	_, err := c.api.Do(ctx, http.MethodPatch, c.u(c.dataPath("/sobjects/"+sobject+"/"+id), nil), http.Header{"Content-Type": {"application/json"}}, b)
	return err
}

func (c *Client) remove(ctx context.Context, sobject, id string) error {
	if !idRE.MatchString(id) {
		return errors.New("salesforce: invalid record id")
	}
	_, err := c.api.Do(ctx, http.MethodDelete, c.u(c.dataPath("/sobjects/"+sobject+"/"+id), nil), nil, nil)
	return err
}
