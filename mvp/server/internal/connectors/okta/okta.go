// Package okta is the production read connector for Okta (Management API v1).
//
// It discovers users (with last login), groups and their members, apps and
// their user and group assignments, and administrator roles, and streams app
// sign-in usage from the System Log. It is read-only: no request it sends
// changes anything in the org.
//
// Authentication is an OAuth 2.0 service app with private_key_jwt (preferred:
// short-lived tokens, scopes limited to okta.*.read) or an SSWS API token.
// Every call goes through internal/safehttp, with the org URL validated as an
// https URL on a well-formed domain. Rate limits are honoured through the
// shared connsync client (429, Retry-After, X-Rate-Limit-Reset).
//
// Mapping onto Tessera's model (so ingest and correlation are reused):
//
//	user               -> account (kind user, lastLogin) and, unless disabled by
//	                      configuration, an identity keyed by employeeNumber (else
//	                      okta:<id>) with the e-mail address for correlation
//	group              -> group (kind group); membership is account -member_of-> group
//	app                -> resource (kind app) with one permission "access"
//	app assignment     -> account -direct_grant-> permission (user assignment) and
//	                      group -grants-> permission (group assignment)
//	administrator role -> group (kind role, privileged); an admin account or
//	                      group is -member_of-> the role
//
// Okta has no nested groups, so no group-in-group edges are produced.
//
// Incremental sync reads only users and groups changed since the checkpoint
// (search=lastUpdated gt ...) and merges them into the stored snapshot. Okta
// reports no deletions, so a full read is repeated at least every
// MaxIncrementalAge (24 hours by default) and on demand.
package okta

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// System is the graph system name.
const System = "okta"

// Default OAuth scopes: read-only, one per object class the connector reads.
var DefaultScopes = []string{"okta.users.read", "okta.groups.read", "okta.apps.read", "okta.roles.read", "okta.logs.read"}

// Config configures one Okta org. Exactly one of the OAuth client
// (ClientID + PrivateKey) and APIToken must be set.
type Config struct {
	// OrgURL is the org's base URL, e.g. https://example.okta.com.
	OrgURL string
	// OAuth 2.0 service app (private_key_jwt).
	ClientID   string
	PrivateKey connsync.Secret // PEM, PKCS#8 or PKCS#1 RSA, or EC
	KeyID      string          // the key's kid as registered in Okta
	Scopes     []string        // default DefaultScopes
	// SSWS API token.
	APIToken connsync.Secret
	// EmitIdentities also emits an identity per user. Turn it off when an HR
	// system is the authoritative source of identities.
	EmitIdentities bool
	// MaxIncrementalAge is how long an incremental chain may run before a full
	// read repairs what Okta does not report (deletions). Default 24h.
	MaxIncrementalAge time.Duration
	// SkipAuthMethods turns off reading each user's enrolled factors (one
	// request per active user per sync) for the MFA posture report.
	SkipAuthMethods bool
	// PushNumberMatch declares that Okta Verify push always requires number
	// matching, for when the authenticator settings cannot be read.
	PushNumberMatch bool
}

// Connector implements connectors.Connector for Okta.
type Connector struct {
	cfg  Config
	base *url.URL
	api  *connsync.Client
	tok  *tokenSource // nil with an SSWS token
	now  func() time.Time
	// maxEventPages bounds one StreamEvents run.
	maxEventPages int
}

// New builds a connector. hc must come from connsync.NewHTTPClient (safehttp).
func New(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Connector, error) {
	base, err := connsync.ParseBaseURL(cfg.OrgURL, rt)
	if err != nil {
		return nil, fmt.Errorf("okta: org URL: %w", err)
	}
	if base.Path != "" {
		return nil, errors.New("okta: org URL must not have a path")
	}
	oauth := cfg.ClientID != "" || !cfg.PrivateKey.Empty()
	switch {
	case oauth && !cfg.APIToken.Empty():
		return nil, errors.New("okta: configure either OAuth (client id and private key) or an API token, not both")
	case oauth && (cfg.ClientID == "" || cfg.PrivateKey.Empty()):
		return nil, errors.New("okta: OAuth needs both a client id and a private key")
	case !oauth && cfg.APIToken.Empty():
		return nil, errors.New("okta: no credential configured (OAuth client or API token)")
	}
	if hc == nil {
		return nil, errors.New("okta: an internal/safehttp client is required")
	}
	if now == nil {
		now = time.Now
	}
	if cfg.MaxIncrementalAge <= 0 {
		cfg.MaxIncrementalAge = 24 * time.Hour
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = DefaultScopes
	}
	c := &Connector{cfg: cfg, base: base, now: now, maxEventPages: 100}
	c.api = &connsync.Client{HC: hc, Now: now, Header: http.Header{
		"Accept": {"application/json"}, "User-Agent": {"tessera-connector/okta"}}}
	if oauth {
		ts, err := newTokenSource(cfg, base, c.api, now)
		if err != nil {
			return nil, err
		}
		c.tok = ts
		c.api.Authorize = ts.authorization
		c.api.OnUnauthorized = ts.invalidate
	} else {
		auth := "SSWS " + cfg.APIToken.Reveal()
		c.api.Authorize = func(context.Context) (string, error) { return auth, nil }
	}
	return c, nil
}

// FromEnv builds the connector from TESSERA_OKTA_* variables:
//
//	TESSERA_OKTA_ORG_URL            https://example.okta.com
//	TESSERA_OKTA_CLIENT_ID          OAuth service app client id
//	TESSERA_OKTA_PRIVATE_KEY        reference to the PEM key: file:/abs/path or env:NAME
//	TESSERA_OKTA_KEY_ID             kid of that key
//	TESSERA_OKTA_API_TOKEN          reference to an SSWS token (instead of OAuth)
//	TESSERA_OKTA_EMIT_IDENTITIES    true (default) or false
//	TESSERA_OKTA_AUTH_METHODS       true (default) or false: read enrolled factors (MFA posture)
//	TESSERA_OKTA_PUSH_NUMBER_MATCH  true if Okta Verify push always requires number matching (default false)
//	TESSERA_OKTA_MAX_INCREMENTAL_AGE  duration, default 24h
func FromEnv(getenv func(string) string, now time.Time) (connectors.Connector, error) {
	cfg := Config{OrgURL: getenv("TESSERA_OKTA_ORG_URL"), ClientID: getenv("TESSERA_OKTA_CLIENT_ID"),
		KeyID: getenv("TESSERA_OKTA_KEY_ID"), EmitIdentities: true}
	if v := getenv("TESSERA_OKTA_EMIT_IDENTITIES"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, errors.New("TESSERA_OKTA_EMIT_IDENTITIES must be true or false")
		}
		cfg.EmitIdentities = b
	}
	if v := getenv("TESSERA_OKTA_PUSH_NUMBER_MATCH"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, errors.New("TESSERA_OKTA_PUSH_NUMBER_MATCH must be true or false")
		}
		cfg.PushNumberMatch = b
	}
	if v := getenv("TESSERA_OKTA_AUTH_METHODS"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, errors.New("TESSERA_OKTA_AUTH_METHODS must be true or false")
		}
		cfg.SkipAuthMethods = !b
	}
	if v := getenv("TESSERA_OKTA_MAX_INCREMENTAL_AGE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute {
			return nil, errors.New("TESSERA_OKTA_MAX_INCREMENTAL_AGE must be a duration of at least 1m")
		}
		cfg.MaxIncrementalAge = d
	}
	var err error
	if ref := getenv("TESSERA_OKTA_PRIVATE_KEY"); ref != "" {
		if cfg.PrivateKey, err = connsync.ResolveSecret(ref, getenv); err != nil {
			return nil, fmt.Errorf("TESSERA_OKTA_PRIVATE_KEY: %w", err)
		}
	}
	if ref := getenv("TESSERA_OKTA_API_TOKEN"); ref != "" {
		if cfg.APIToken, err = connsync.ResolveSecret(ref, getenv); err != nil {
			return nil, fmt.Errorf("TESSERA_OKTA_API_TOKEN: %w", err)
		}
	}
	rt := connsync.RuntimeFromEnv(getenv)
	hc, err := connsync.NewHTTPClient(rt, safehttp.Options{})
	if err != nil {
		return nil, err
	}
	return New(cfg, rt, hc, func() time.Time { return time.Now().UTC() })
}

func (*Connector) System() string      { return System }
func (*Connector) DisplayName() string { return "Okta" }
func (*Connector) TypeName() string    { return "OktaConnector" }

// ---------------------------------------------------------------- helpers

// validID restricts ids that are put into URL paths and external ids.
func validID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r == '_' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}

func strp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// nextLink returns the rel="next" target of the Link headers.
func nextLink(h http.Header) string {
	for _, v := range h.Values("Link") {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if !strings.Contains(part, `rel="next"`) {
				continue
			}
			if i, j := strings.Index(part, "<"), strings.Index(part, ">"); i == 0 && j > 1 {
				return part[1:j]
			}
		}
	}
	return ""
}

// path builds an absolute API URL.
func (c *Connector) path(p string, q url.Values) string {
	u := *c.base
	u.Path = p
	if q != nil {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// list walks a paged collection, decoding each page into []T.
func list[T any](ctx context.Context, c *Connector, first string, each func(T) error) error {
	return connsync.Walk(ctx, c.base, first, func(ctx context.Context, pageURL string) (string, error) {
		var items []T
		h, err := c.api.GetJSON(ctx, pageURL, nil, &items)
		if err != nil {
			return "", err
		}
		for _, it := range items {
			if err := each(it); err != nil {
				return "", err
			}
		}
		return nextLink(h), nil
	})
}
