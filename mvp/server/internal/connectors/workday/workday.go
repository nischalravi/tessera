// Package workday is the production read connector for Workday as the
// authoritative HR source, over the Workday REST API with an OAuth 2.0 API
// client (refresh-token grant, or client credentials).
//
// It reads workers (employee id, e-mail, manager, supervisory organization,
// job title, hire and termination dates, worker type) and the effective-dated
// worker events (hire, terminate, job change, manager change). It is
// read-only: every request is a GET, except the OAuth token request.
//
// Mapping onto Tessera's model (so ingest, correlation and the joiner / mover
// / leaver flow are reused):
//
//	worker               -> identity (human) keyed by the employee id, with the work
//	                        e-mail for correlation, and a workday account keyed the
//	                        same; terminated once the termination date has come
//	supervisory org      -> group (kind supervisory_org); the worker's account is
//	                        -member_of-> the group
//	hire event           -> hris event "joiner"
//	terminate event      -> hris event "leaver"
//	job / manager change -> hris event "mover"
//
// Effective dating. Workday records changes before they take effect. Nothing
// is applied early:
//
//   - a worker whose hire date is still ahead is not an identity or account yet;
//     only its hire event exists, pending, with the future effective date;
//   - a termination date still ahead leaves the worker active; the leaver event
//     is pending with the future effective date, and the worker turns terminated
//     at the first sync on or after that date;
//   - an event is always emitted with its own effective date, never "now", and
//     ingest keeps it pending until a person executes it.
//
// A hire that has already taken effect is emitted as a historical joiner (the
// identity came from the worker record, so executing it would create the
// person twice), and so is any event older than EventWindow (the legacy process
// handled it).
//
// Incremental sync. Workers are read with Updated_From=<watermark> and merged
// onto the stored snapshot (Workday keeps terminated workers, so there is no
// deletion to see); a full read repairs the rest every MaxIncrementalAge or on
// demand. Events are read with Updated_From the same way; a full read asks for
// Effective_From=<now - EventWindow>, which also returns future-dated events
// entered long ago.
//
// The endpoint paths are configurable (WorkersPath, EventsPath) so a tenant can
// point them at a custom report (RaaS) that returns the same JSON; the
// documented shapes are in README.md.
package workday

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
)

// System is the graph system name. It is the name the demo Workday feed and
// the joiner flow already use.
const System = "workday"

// Default endpoint paths; {tenant} is replaced by the configured tenant.
const (
	DefaultWorkersPath = "/ccx/api/v1/{tenant}/workers"
	DefaultEventsPath  = "/ccx/api/v1/{tenant}/workerEvents"
	defaultTokenPath   = "/ccx/oauth2/{tenant}/token" // #nosec G101 -- an endpoint path, not a credential
)

// pageSize is the page size asked of Workday (its maximum for these endpoints).
const pageSize = 100

var (
	tenantRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	pathRE   = regexp.MustCompile(`^/[A-Za-z0-9._~{}/-]{0,200}$`)
)

// Config configures one Workday tenant.
type Config struct {
	// Tenant is the Workday tenant name (the {tenant} in API paths).
	Tenant string
	// BaseURL is the tenant's services host, for example
	// https://wd2-impl-services1.workday.com.
	BaseURL string
	// TokenURL is the OAuth token endpoint; default BaseURL + /ccx/oauth2/{tenant}/token.
	TokenURL string
	// WorkersPath and EventsPath are the endpoint paths (see the package comment).
	WorkersPath, EventsPath string
	ClientID                string
	ClientSecret            connsync.Secret
	// RefreshToken, when set, uses the refresh-token grant. Without it the
	// client-credentials grant is used.
	RefreshToken connsync.Secret
	// EmitIdentities emits an identity per worker. It is on by default: Workday
	// is HR-authoritative, and the other connectors should turn their own off.
	EmitIdentities bool
	// EventWindow is how far back an event still counts as new (default 30 days).
	EventWindow time.Duration
	// MaxIncrementalAge forces a full read after this long (default 24h, set by
	// FromEnv); zero never does.
	MaxIncrementalAge time.Duration
}

// Connector implements connectors.Connector for Workday.
type Connector struct {
	cfg     Config
	base    *url.URL
	workers string // absolute path
	events  string
	api     *connsync.Client
	tok     *tokenSource
	now     func() time.Time
}

// New builds a connector. hc is the server's shared safehttp client.
func New(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Connector, error) {
	if !tenantRE.MatchString(cfg.Tenant) {
		return nil, errors.New("workday: the tenant name is missing or not a plain name")
	}
	if cfg.ClientID == "" || len(cfg.ClientID) > 256 || cfg.ClientSecret.Empty() {
		return nil, errors.New("workday: a client id and client secret are required")
	}
	if cfg.WorkersPath == "" {
		cfg.WorkersPath = DefaultWorkersPath
	}
	if cfg.EventsPath == "" {
		cfg.EventsPath = DefaultEventsPath
	}
	for name, p := range map[string]string{"workers path": cfg.WorkersPath, "events path": cfg.EventsPath} {
		if !pathRE.MatchString(p) || strings.Contains(p, "..") || strings.Contains(p, "//") {
			return nil, fmt.Errorf("workday: %s must be an absolute path of plain characters", name)
		}
	}
	if cfg.EventWindow == 0 {
		cfg.EventWindow = 30 * 24 * time.Hour
	}
	if cfg.EventWindow < 24*time.Hour {
		return nil, errors.New("workday: the event window must be at least 24h")
	}
	base, err := connsync.ParseBaseURL(cfg.BaseURL, rt)
	if err != nil {
		return nil, fmt.Errorf("workday: base URL: %w", err)
	}
	if base.Path != "" {
		return nil, errors.New("workday: base URL must be a host without a path (set the paths instead)")
	}
	if cfg.TokenURL == "" {
		u := *base
		u.Path = strings.ReplaceAll(defaultTokenPath, "{tenant}", url.PathEscape(cfg.Tenant))
		cfg.TokenURL = u.String()
	}
	tokenURL, err := connsync.ParseBaseURL(cfg.TokenURL, rt)
	if err != nil {
		return nil, fmt.Errorf("workday: token URL: %w", err)
	}
	if hc == nil {
		return nil, errors.New("workday: an internal/safehttp client is required")
	}
	if now == nil {
		now = time.Now
	}
	c := &Connector{cfg: cfg, base: base, now: now,
		workers: strings.ReplaceAll(cfg.WorkersPath, "{tenant}", url.PathEscape(cfg.Tenant)),
		events:  strings.ReplaceAll(cfg.EventsPath, "{tenant}", url.PathEscape(cfg.Tenant))}
	c.api = &connsync.Client{HC: hc, Now: now, Header: http.Header{
		"Accept": {"application/json"}, "User-Agent": {"tessera-connector/workday"}}}
	c.tok = newTokenSource(cfg, tokenURL, c.api, now)
	c.api.Authorize = c.tok.authorization
	c.api.OnUnauthorized = c.tok.invalidate
	return c, nil
}

// FromEnv builds the connector from TESSERA_WORKDAY_* variables:
//
//	TESSERA_WORKDAY_BASE_URL            tenant services host, https://wd2-impl-services1.workday.com
//	TESSERA_WORKDAY_TENANT              tenant name
//	TESSERA_WORKDAY_CLIENT_ID           API client id
//	TESSERA_WORKDAY_CLIENT_SECRET       reference to the API client secret: file:/abs/path or env:NAME
//	TESSERA_WORKDAY_REFRESH_TOKEN       optional reference to a refresh token (else client credentials)
//	TESSERA_WORKDAY_TOKEN_URL           default <base>/ccx/oauth2/<tenant>/token
//	TESSERA_WORKDAY_WORKERS_PATH        default /ccx/api/v1/{tenant}/workers
//	TESSERA_WORKDAY_EVENTS_PATH         default /ccx/api/v1/{tenant}/workerEvents
//	TESSERA_WORKDAY_EMIT_IDENTITIES     true (default) or false
//	TESSERA_WORKDAY_EVENT_WINDOW        duration, default 720h (at least 24h)
//	TESSERA_WORKDAY_MAX_INCREMENTAL_AGE duration; default 24h, 0 disables
func FromEnv(getenv func(string) string, now time.Time, rt connsync.Runtime, hc *http.Client) (connectors.Connector, error) {
	cfg := Config{Tenant: getenv("TESSERA_WORKDAY_TENANT"), BaseURL: getenv("TESSERA_WORKDAY_BASE_URL"),
		ClientID: getenv("TESSERA_WORKDAY_CLIENT_ID"), TokenURL: getenv("TESSERA_WORKDAY_TOKEN_URL"),
		WorkersPath: getenv("TESSERA_WORKDAY_WORKERS_PATH"), EventsPath: getenv("TESSERA_WORKDAY_EVENTS_PATH"),
		EmitIdentities: true, MaxIncrementalAge: 24 * time.Hour}
	if v := getenv("TESSERA_WORKDAY_EMIT_IDENTITIES"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, errors.New("TESSERA_WORKDAY_EMIT_IDENTITIES must be true or false")
		}
		cfg.EmitIdentities = b
	}
	if v := getenv("TESSERA_WORKDAY_EVENT_WINDOW"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 24*time.Hour {
			return nil, errors.New("TESSERA_WORKDAY_EVENT_WINDOW must be a duration of at least 24h")
		}
		cfg.EventWindow = d
	}
	if v := getenv("TESSERA_WORKDAY_MAX_INCREMENTAL_AGE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 || d > 0 && d < time.Minute {
			return nil, errors.New("TESSERA_WORKDAY_MAX_INCREMENTAL_AGE must be 0 or a duration of at least 1m")
		}
		cfg.MaxIncrementalAge = d
	}
	ref := getenv("TESSERA_WORKDAY_CLIENT_SECRET")
	if ref == "" {
		return nil, errors.New("TESSERA_WORKDAY_CLIENT_SECRET (a file: or env: reference) is required")
	}
	var err error
	if cfg.ClientSecret, err = connsync.ResolveSecret(ref, getenv); err != nil {
		return nil, fmt.Errorf("TESSERA_WORKDAY_CLIENT_SECRET: %w", err)
	}
	if ref := getenv("TESSERA_WORKDAY_REFRESH_TOKEN"); ref != "" {
		if cfg.RefreshToken, err = connsync.ResolveSecret(ref, getenv); err != nil {
			return nil, fmt.Errorf("TESSERA_WORKDAY_REFRESH_TOKEN: %w", err)
		}
	}
	return New(cfg, rt, hc, func() time.Time { return time.Now().UTC() })
}

func (*Connector) System() string      { return System }
func (*Connector) DisplayName() string { return "Workday" }
func (*Connector) TypeName() string    { return "WorkdayConnector" }

// ---------------------------------------------------------------- helpers

// parseDate reads an effective date: a plain date, or a timestamp (in UTC).
func parseDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339, "2006-01-02T15:04:05.999999999Z0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

func strp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// url builds an absolute API URL; the query is encoded.
func (c *Connector) url(path string, q url.Values) string {
	u := *c.base
	u.Path = path
	u.RawQuery = q.Encode()
	return u.String()
}

// page is one Workday collection page (limit and offset paging).
type page[T any] struct {
	Total int `json:"total"`
	Data  []T `json:"data"`
}

// maxTotal bounds the total a page may claim, so a hostile count cannot turn
// into endless paging (connsync.MaxPages bounds it as well).
const maxTotal = 5_000_000

// listAll walks a limit/offset collection. The next URL is built here, so it
// can only ever be on the configured host.
func listAll[T any](ctx context.Context, c *Connector, path string, q url.Values, each func(T) error) error {
	q = cloneValues(q)
	q.Set("limit", strconv.Itoa(pageSize))
	q.Set("offset", "0")
	return connsync.Walk(ctx, c.base, c.url(path, q), func(ctx context.Context, pageURL string) (string, error) {
		var p page[T]
		if _, err := c.api.GetJSON(ctx, pageURL, nil, &p); err != nil {
			return "", err
		}
		if p.Total < 0 || p.Total > maxTotal || len(p.Data) > pageSize*10 {
			return "", fmt.Errorf("%w: implausible page size or total", connsync.ErrMalformed)
		}
		for _, it := range p.Data {
			if err := each(it); err != nil {
				return "", err
			}
		}
		u, err := url.Parse(pageURL)
		if err != nil {
			return "", err
		}
		nq, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return "", err
		}
		off, _ := strconv.Atoi(nq.Get("offset"))
		next := off + len(p.Data)
		if len(p.Data) == 0 || next >= p.Total {
			return "", nil
		}
		nq.Set("offset", strconv.Itoa(next))
		u.RawQuery = nq.Encode()
		return u.String(), nil
	})
}

func cloneValues(q url.Values) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}
	return out
}
