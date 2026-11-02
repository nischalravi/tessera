// Package google is the production read connector for Google Workspace, over
// the Admin SDK Directory API with a service account and domain-wide
// delegation.
//
// It discovers users (last login, suspended, archived), groups and their
// members (a member of type GROUP becomes a group-in-group edge) and admin
// role assignments. It is read-only: only read-only scopes are requested and
// every request is a GET (the one POST is the OAuth token request).
//
// Mapping onto Tessera's model (so ingest and correlation are reused):
//
//	user              -> account (kind user; suspended or archived is disabled) and,
//	                     unless disabled by configuration, an identity keyed by the
//	                     employee id in externalIds (else google:<id>) with the
//	                     primary e-mail address for correlation
//	group             -> group (kind group); a member user is account -member_of->
//	                     group, a member group is group -member_of-> group (nesting)
//	admin role        -> group (kind role; privileged unless a reader role); the
//	                     users and groups it is assigned to are -member_of-> the role
//
// Incremental sync. The Directory API has no change feed: users.list, groups.list
// and members.list take no updatedMin, and showDeleted only lists users deleted
// in the last 20 days. So users, groups and role assignments are read on every
// sync (they are listings of at most a few hundred pages), and what is saved by
// the checkpoint is the member list of each group with a fingerprint (etag and
// directMembersCount). An incremental sync re-reads the members only of groups
// whose fingerprint changed, which is where the request volume is. A member
// swap that leaves both unchanged is repaired by the periodic full read
// (MaxIncrementalAge, default 24h) or by a full re-sync on demand.
//
// Not covered, deferred: OAuth tokens and third-party app access. Listing a
// user's tokens (users.tokens.list) needs the admin.directory.user.security
// scope, which can also revoke them, so it is not a read-only scope; the
// Reports API (admin.reports.audit.readonly, applicationName=token) would give
// authorize events but no inventory. StreamEvents therefore yields nothing.
package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// System is the graph system name.
const System = "google"

// Default endpoints (Google's public service).
const (
	DefaultAPIURL   = "https://admin.googleapis.com"
	DefaultTokenURL = "https://oauth2.googleapis.com/token" // #nosec G101 -- a public endpoint URL, not a credential
)

// Read-only OAuth scopes, the only ones this connector ever requests.
const (
	ScopeUsers   = "https://www.googleapis.com/auth/admin.directory.user.readonly"
	ScopeGroups  = "https://www.googleapis.com/auth/admin.directory.group.readonly"
	ScopeMembers = "https://www.googleapis.com/auth/admin.directory.group.member.readonly"
	ScopeRoles   = "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly"
)

var customerRE = regexp.MustCompile(`^(my_customer|C[0-9a-z]{3,20})$`)

// Config configures one Google Workspace customer.
type Config struct {
	// ServiceAccountEmail is the service account's client_email; the JWT's issuer.
	ServiceAccountEmail string
	// PrivateKey is the service account's PEM private key (RSA, 2048 bits or more).
	PrivateKey connsync.Secret
	// KeyID is the key's private_key_id (the JWT header kid); optional.
	KeyID string
	// AdminEmail is the administrator the service account impersonates
	// (domain-wide delegation). Use an account with read access only.
	AdminEmail string
	// Customer is the customer id, or my_customer (the default).
	Customer string
	// Domain, when set, lists the users of that domain only (a customer can
	// own several domains).
	Domain string
	// OrgUnits, when set, restricts the user read to these org unit paths
	// (for example /Engineering); users elsewhere are never read. Empty reads
	// the whole customer or domain.
	OrgUnits []string
	APIURL   string // default DefaultAPIURL
	TokenURL string // default DefaultTokenURL
	// EmitIdentities also emits an identity per user. Turn it off when an HR
	// system is the authoritative source of identities.
	EmitIdentities bool
	// Groups reads groups and members (scopes group.readonly and
	// group.member.readonly). Roles reads admin roles (rolemanagement.readonly).
	// Turn one off when the delegation in the admin console does not grant its
	// scope: Google refuses the whole token request if any scope is missing.
	Groups, Roles bool
	// MaxIncrementalAge forces a full read after this long (default 24h, set by
	// FromEnv); zero never does.
	MaxIncrementalAge time.Duration
}

// Scopes returns the OAuth scopes the configuration needs, all read-only.
func (c Config) Scopes() []string {
	s := []string{ScopeUsers}
	if c.Groups {
		s = append(s, ScopeGroups, ScopeMembers)
	}
	if c.Roles {
		s = append(s, ScopeRoles)
	}
	return s
}

// Connector implements connectors.Connector for Google Workspace.
type Connector struct {
	cfg  Config
	base *url.URL
	api  *connsync.Client
	tok  *tokenSource
	now  func() time.Time
}

// New builds a connector. hc is the server's shared safehttp client.
func New(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Connector, error) {
	if !validEmail(cfg.ServiceAccountEmail) || !validEmail(cfg.AdminEmail) {
		return nil, errors.New("google: a service account e-mail and an administrator e-mail to impersonate are required")
	}
	if cfg.PrivateKey.Empty() {
		return nil, errors.New("google: a service account private key is required")
	}
	if len(cfg.KeyID) > 128 {
		return nil, errors.New("google: key id is too long")
	}
	if cfg.Customer == "" {
		cfg.Customer = "my_customer"
	}
	if !customerRE.MatchString(cfg.Customer) {
		return nil, errors.New("google: customer must be my_customer or a customer id such as C01a2b3c4")
	}
	if cfg.Domain != "" && !connsync.ValidDomain(cfg.Domain) {
		return nil, errors.New("google: domain is not a well-formed domain name")
	}
	if len(cfg.OrgUnits) > connsync.MaxOrgUnits {
		return nil, fmt.Errorf("google: at most %d org units", connsync.MaxOrgUnits)
	}
	for _, ou := range cfg.OrgUnits {
		if !connsync.ValidOrgUnitPath(ou) {
			return nil, errors.New("google: an org unit is not a well-formed path (it starts with / and has no quote or backslash)")
		}
	}
	if cfg.APIURL == "" {
		cfg.APIURL = DefaultAPIURL
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = DefaultTokenURL
	}
	base, err := connsync.ParseBaseURL(cfg.APIURL, rt)
	if err != nil {
		return nil, fmt.Errorf("google: API URL: %w", err)
	}
	tokenURL, err := connsync.ParseBaseURL(cfg.TokenURL, rt)
	if err != nil {
		return nil, fmt.Errorf("google: token URL: %w", err)
	}
	if hc == nil {
		return nil, errors.New("google: an internal/safehttp client is required")
	}
	if now == nil {
		now = time.Now
	}
	c := &Connector{cfg: cfg, base: base, now: now}
	c.api = &connsync.Client{HC: hc, Now: now, RetryOn: connsync.IsGoogleRateLimit, Header: http.Header{
		"Accept": {"application/json"}, "User-Agent": {"tessera-connector/google"}}}
	if c.tok, err = newTokenSource(cfg, tokenURL, c.api, now); err != nil {
		return nil, err
	}
	c.api.Authorize = c.tok.authorization
	c.api.OnUnauthorized = c.tok.invalidate
	return c, nil
}

// FromEnv builds the connector from TESSERA_GOOGLE_* variables:
//
//	TESSERA_GOOGLE_SERVICE_ACCOUNT_KEY  reference (file:/abs/path or env:NAME) to the
//	                                    service account's JSON key file
//	TESSERA_GOOGLE_ADMIN_EMAIL          administrator to impersonate
//	TESSERA_GOOGLE_CUSTOMER             default my_customer
//	TESSERA_GOOGLE_DOMAIN               optional: only this domain's users
//	TESSERA_GOOGLE_ORG_UNITS            optional: comma-separated org unit paths; only their users are read
//	TESSERA_GOOGLE_API_URL              default https://admin.googleapis.com
//	TESSERA_GOOGLE_TOKEN_URL            default https://oauth2.googleapis.com/token
//	TESSERA_GOOGLE_EMIT_IDENTITIES      true (default) or false
//	TESSERA_GOOGLE_GROUPS               true (default) or false
//	TESSERA_GOOGLE_ROLES                true (default) or false
//	TESSERA_GOOGLE_MAX_INCREMENTAL_AGE  duration; default 24h, 0 disables
func FromEnv(getenv func(string) string, now time.Time, rt connsync.Runtime, hc *http.Client) (connectors.Connector, error) {
	cfg := Config{AdminEmail: getenv("TESSERA_GOOGLE_ADMIN_EMAIL"), Customer: getenv("TESSERA_GOOGLE_CUSTOMER"),
		Domain: getenv("TESSERA_GOOGLE_DOMAIN"), APIURL: getenv("TESSERA_GOOGLE_API_URL"), TokenURL: getenv("TESSERA_GOOGLE_TOKEN_URL"),
		EmitIdentities: true, Groups: true, Roles: true, MaxIncrementalAge: 24 * time.Hour}
	for _, ou := range strings.Split(getenv("TESSERA_GOOGLE_ORG_UNITS"), ",") {
		if ou = strings.TrimSpace(ou); ou != "" {
			cfg.OrgUnits = append(cfg.OrgUnits, ou)
		}
	}
	for name, dst := range map[string]*bool{"TESSERA_GOOGLE_EMIT_IDENTITIES": &cfg.EmitIdentities,
		"TESSERA_GOOGLE_GROUPS": &cfg.Groups, "TESSERA_GOOGLE_ROLES": &cfg.Roles} {
		if v := getenv(name); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, fmt.Errorf("%s must be true or false", name)
			}
			*dst = b
		}
	}
	if v := getenv("TESSERA_GOOGLE_MAX_INCREMENTAL_AGE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 || d > 0 && d < time.Minute {
			return nil, errors.New("TESSERA_GOOGLE_MAX_INCREMENTAL_AGE must be 0 or a duration of at least 1m")
		}
		cfg.MaxIncrementalAge = d
	}
	ref := getenv("TESSERA_GOOGLE_SERVICE_ACCOUNT_KEY")
	if ref == "" {
		return nil, errors.New("TESSERA_GOOGLE_SERVICE_ACCOUNT_KEY (a file: or env: reference) is required")
	}
	sec, err := connsync.ResolveSecret(ref, getenv)
	if err != nil {
		return nil, fmt.Errorf("TESSERA_GOOGLE_SERVICE_ACCOUNT_KEY: %w", err)
	}
	if cfg.ServiceAccountEmail, cfg.PrivateKey, cfg.KeyID, err = parseServiceAccountKey(sec.Reveal()); err != nil {
		return nil, fmt.Errorf("TESSERA_GOOGLE_SERVICE_ACCOUNT_KEY: %w", err)
	}
	return New(cfg, rt, hc, func() time.Time { return time.Now().UTC() })
}

// Stored is a Google Workspace connection as the readiness service holds it:
// the scope fields of its stored config and its opened credential.
type Stored struct {
	// Customer, Domain and OrgUnits are the connection's customer, domain and
	// base_dns (org unit paths). Empty values read as they do for FromEnv.
	Customer, Domain string
	OrgUnits         []string
	// Credential is the sealed credential, opened: the service account's JSON key
	// file. It may carry "admin_email", the administrator to impersonate, which
	// is the fallback for AdminEmail.
	Credential string
	// AdminEmail is the config's admin_email, the administrator to impersonate.
	// It wins over the credential's.
	AdminEmail string
}

// FromStored builds the connector of a connection from its stored config
// instead of TESSERA_GOOGLE_* variables, so the connection's org units, customer
// and domain scope the sync. Nothing is read from the environment: getenv only
// supplies the dev endpoint overrides TESSERA_GOOGLE_API_URL and
// TESSERA_GOOGLE_TOKEN_URL (the caller passes the layer that refuses them outside
// dev). Groups, roles and identities are read, as FromEnv does by default.
func FromStored(s Stored, getenv func(string) string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (connectors.Connector, error) {
	cfg := Config{Customer: s.Customer, Domain: s.Domain, OrgUnits: slices.Clone(s.OrgUnits),
		APIURL: getenv("TESSERA_GOOGLE_API_URL"), TokenURL: getenv("TESSERA_GOOGLE_TOKEN_URL"),
		EmitIdentities: true, Groups: true, Roles: true, MaxIncrementalAge: 24 * time.Hour}
	var extra struct {
		AdminEmail string `json:"admin_email"`
	}
	if s.Credential == "" {
		return nil, errors.New("google: the connection has no stored credential")
	}
	_ = json.Unmarshal([]byte(s.Credential), &extra) // a malformed file is reported by parseServiceAccountKey
	cfg.AdminEmail = strings.TrimSpace(s.AdminEmail)
	if cfg.AdminEmail == "" {
		cfg.AdminEmail = strings.TrimSpace(extra.AdminEmail)
	}
	var err error
	if cfg.ServiceAccountEmail, cfg.PrivateKey, cfg.KeyID, err = parseServiceAccountKey(s.Credential); err != nil {
		return nil, fmt.Errorf("google: credential: %w", err)
	}
	if cfg.AdminEmail == "" {
		return nil, errors.New(`google: the connection must name the administrator to impersonate (its admin_email, or "admin_email" next to the service account key fields)`)
	}
	return New(cfg, rt, hc, now)
}

func (*Connector) System() string      { return System }
func (*Connector) DisplayName() string { return "Google Workspace" }
func (*Connector) TypeName() string    { return "GoogleConnector" }

// StreamEvents yields nothing: usage and app access are deferred (see the
// package comment). It still honours a cancelled context.
func (c *Connector) StreamEvents(ctx context.Context, _ *time.Time, _ func(connectors.Event) error) error {
	return ctx.Err()
}

// ---------------------------------------------------------------- helpers

func validEmail(s string) bool {
	at := strings.LastIndexByte(s, '@')
	return len(s) <= 254 && at > 0 && connsync.ValidDomain(s[at+1:]) && !strings.ContainsAny(s, " \t\r\n,;<>\"")
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.Year() <= 1970 { // Google reports "never" as 1970-01-01
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

// dir builds an absolute Directory API URL; the query is encoded.
func (c *Connector) dir(path string, q url.Values) *url.URL {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/admin/directory/v1" + path
	u.RawQuery = q.Encode()
	return &u
}

// maxPageToken bounds a server-supplied page token.
const maxPageToken = 4096

// paged walks a Directory API collection. Google pages by pageToken, never by
// link, so the next URL is built here from the first one: a token can only
// change a query value, never the host.
func paged[R any](ctx context.Context, c *Connector, first *url.URL, next func(*R) string, each func(*R) error) error {
	return connsync.Walk(ctx, c.base, first.String(), func(ctx context.Context, pageURL string) (string, error) {
		var r R
		if _, err := c.api.GetJSON(ctx, pageURL, nil, &r); err != nil {
			return "", err
		}
		if err := each(&r); err != nil {
			return "", err
		}
		tok := next(&r)
		if tok == "" {
			return "", nil
		}
		if len(tok) > maxPageToken {
			return "", fmt.Errorf("%w: page token is too long", connsync.ErrMalformed)
		}
		u, err := url.Parse(pageURL)
		if err != nil {
			return "", err
		}
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return "", err
		}
		q.Set("pageToken", tok)
		u.RawQuery = q.Encode()
		return u.String(), nil
	})
}
