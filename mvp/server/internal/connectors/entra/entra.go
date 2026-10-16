// Package entra is the production read connector for Microsoft Entra ID, over
// Microsoft Graph v1.0 with the OAuth 2.0 client credentials flow.
//
// It discovers users (with last sign-in when AuditLog.Read.All is granted),
// groups and their members (nested groups become group-in-group edges), service
// principals, app role assignments and directory role assignments, and streams
// app sign-in usage from the sign-in log. It is read-only: only Graph read
// permissions are needed and no request it sends changes anything.
//
// Mapping onto Tessera's model (so ingest and correlation are reused):
//
//	user                 -> account (kind user) and, unless disabled by configuration,
//	                        an identity keyed by employeeId (else entra:<id>) with the
//	                        e-mail address for correlation
//	group                -> group (security_group, m365_group or group; a
//	                        role-assignable group is privileged); a member user or
//	                        service principal is account -member_of-> group, a member
//	                        group is group -member_of-> group (nesting)
//	service principal    -> resource (kind app) with an "access" permission plus one
//	                        permission per app role; one owned by this tenant is also
//	                        an account of kind service with a service identity
//	app role assignment  -> principal -direct_grant-> permission (user, service
//	                        principal) or group -grants-> permission (group)
//	directory role       -> group (kind role; privileged unless a reader role); its
//	                        assigned principals are -member_of-> the role
//
// Incremental sync uses Graph delta queries (users/delta, groups/delta) and
// stores the deltaLinks as the checkpoint cursor; an expired delta token
// (HTTP 410 or syncStateNotFound) falls back to a full read. Service
// principals, app assignments and directory roles are re-read on every sync:
// Graph has no delta for them and they are small next to users and groups.
package entra

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// System is the graph system name.
const System = "entra"

// Default endpoints (the public cloud). National clouds override them.
const (
	DefaultGraphURL     = "https://graph.microsoft.com"
	DefaultAuthorityURL = "https://login.microsoftonline.com"
)

var guidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Config configures one Entra tenant.
type Config struct {
	// TenantID is the directory (tenant) GUID.
	TenantID     string
	ClientID     string
	ClientSecret connsync.Secret
	GraphURL     string // default DefaultGraphURL
	AuthorityURL string // default DefaultAuthorityURL
	// EmitIdentities also emits an identity per user and service principal. Turn
	// it off when an HR system is the authoritative source of identities.
	EmitIdentities bool
	// SignInActivity reads signInActivity (needs AuditLog.Read.All and Entra ID
	// P1/P2). If Graph refuses, last sign-in is left empty and the sync goes on.
	SignInActivity bool
	// MaxIncrementalAge forces a full read after this long; zero never does
	// (delta queries report deletions).
	MaxIncrementalAge time.Duration
}

// Connector implements connectors.Connector for Entra ID.
type Connector struct {
	cfg  Config
	base *url.URL // Graph
	api  *connsync.Client
	tok  *tokenSource
	now  func() time.Time
	// maxEventPages bounds one StreamEvents run.
	maxEventPages int
}

// New builds a connector. hc must come from connsync.NewHTTPClient (safehttp).
func New(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Connector, error) {
	if !guidRE.MatchString(cfg.TenantID) {
		return nil, errors.New("entra: tenant id must be the directory GUID")
	}
	if cfg.ClientID == "" || len(cfg.ClientID) > 128 || cfg.ClientSecret.Empty() {
		return nil, errors.New("entra: a client id and client secret are required")
	}
	if cfg.GraphURL == "" {
		cfg.GraphURL = DefaultGraphURL
	}
	if cfg.AuthorityURL == "" {
		cfg.AuthorityURL = DefaultAuthorityURL
	}
	base, err := connsync.ParseBaseURL(cfg.GraphURL, rt)
	if err != nil {
		return nil, fmt.Errorf("entra: graph URL: %w", err)
	}
	authority, err := connsync.ParseBaseURL(cfg.AuthorityURL, rt)
	if err != nil {
		return nil, fmt.Errorf("entra: authority URL: %w", err)
	}
	if hc == nil {
		return nil, errors.New("entra: an internal/safehttp client is required")
	}
	if now == nil {
		now = time.Now
	}
	c := &Connector{cfg: cfg, base: base, now: now, maxEventPages: 100}
	c.api = &connsync.Client{HC: hc, Now: now, Header: http.Header{
		"Accept": {"application/json"}, "User-Agent": {"tessera-connector/entra"}}}
	c.tok = newTokenSource(cfg, authority, base, c.api, now)
	c.api.Authorize = c.tok.authorization
	c.api.OnUnauthorized = c.tok.invalidate
	return c, nil
}

// FromEnv builds the connector from TESSERA_ENTRA_* variables:
//
//	TESSERA_ENTRA_TENANT_ID        directory (tenant) GUID
//	TESSERA_ENTRA_CLIENT_ID        application (client) id
//	TESSERA_ENTRA_CLIENT_SECRET    reference to the secret: file:/abs/path or env:NAME
//	TESSERA_ENTRA_GRAPH_URL        default https://graph.microsoft.com
//	TESSERA_ENTRA_AUTHORITY_URL    default https://login.microsoftonline.com
//	TESSERA_ENTRA_EMIT_IDENTITIES  true (default) or false
//	TESSERA_ENTRA_SIGNIN_ACTIVITY  true (default) or false
//	TESSERA_ENTRA_MAX_INCREMENTAL_AGE  duration; default none
func FromEnv(getenv func(string) string, now time.Time) (connectors.Connector, error) {
	cfg := Config{TenantID: getenv("TESSERA_ENTRA_TENANT_ID"), ClientID: getenv("TESSERA_ENTRA_CLIENT_ID"),
		GraphURL: getenv("TESSERA_ENTRA_GRAPH_URL"), AuthorityURL: getenv("TESSERA_ENTRA_AUTHORITY_URL"),
		EmitIdentities: true, SignInActivity: true}
	for name, dst := range map[string]*bool{"TESSERA_ENTRA_EMIT_IDENTITIES": &cfg.EmitIdentities,
		"TESSERA_ENTRA_SIGNIN_ACTIVITY": &cfg.SignInActivity} {
		if v := getenv(name); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, fmt.Errorf("%s must be true or false", name)
			}
			*dst = b
		}
	}
	if v := getenv("TESSERA_ENTRA_MAX_INCREMENTAL_AGE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute {
			return nil, errors.New("TESSERA_ENTRA_MAX_INCREMENTAL_AGE must be a duration of at least 1m")
		}
		cfg.MaxIncrementalAge = d
	}
	ref := getenv("TESSERA_ENTRA_CLIENT_SECRET")
	if ref == "" {
		return nil, errors.New("TESSERA_ENTRA_CLIENT_SECRET (a file: or env: reference) is required")
	}
	var err error
	if cfg.ClientSecret, err = connsync.ResolveSecret(ref, getenv); err != nil {
		return nil, fmt.Errorf("TESSERA_ENTRA_CLIENT_SECRET: %w", err)
	}
	rt := connsync.RuntimeFromEnv(getenv)
	hc, err := connsync.NewHTTPClient(rt, safehttp.Options{})
	if err != nil {
		return nil, err
	}
	return New(cfg, rt, hc, func() time.Time { return time.Now().UTC() })
}

func (*Connector) System() string      { return System }
func (*Connector) DisplayName() string { return "Microsoft Entra ID" }
func (*Connector) TypeName() string    { return "EntraConnector" }

// ---------------------------------------------------------------- helpers

func validID(s string) bool { return guidRE.MatchString(s) }

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

// graph builds an absolute v1.0 URL. query is added verbatim (OData keys such
// as $select must not be percent-encoded).
func (c *Connector) graph(path, rawQuery string) string {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/v1.0" + path
	u.RawQuery = rawQuery
	return u.String()
}

// page is one Graph collection page.
type page[T any] struct {
	Value     []T    `json:"value"`
	NextLink  string `json:"@odata.nextLink"`
	DeltaLink string `json:"@odata.deltaLink"`
}

// listAll walks a collection and returns the final @odata.deltaLink, if any.
func listAll[T any](ctx context.Context, c *Connector, first string, each func(T) error) (string, error) {
	var delta string
	err := connsync.Walk(ctx, c.base, first, func(ctx context.Context, pageURL string) (string, error) {
		var p page[T]
		if _, err := c.api.GetJSON(ctx, pageURL, nil, &p); err != nil {
			return "", err
		}
		for _, it := range p.Value {
			if err := each(it); err != nil {
				return "", err
			}
		}
		if p.DeltaLink != "" {
			delta = p.DeltaLink
		}
		return p.NextLink, nil
	})
	return delta, err
}
