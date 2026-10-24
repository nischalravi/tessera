// Package servicenow reads a ServiceNow instance's access model into Tessera's graph (users, groups, roles and
// who holds them) through the Table API, and writes user lifecycle, group membership and role assignment back
// through provisioning, or raises a ticket for a person to do it (issue #559).
//
// Authentication is HTTP basic (a dedicated integration user) or the OAuth client credentials grant (a token
// from the instance's /oauth_token.do). The API host is the configured base URL only: a *.service-now.com or
// *.servicenowservices.com (gov) host. A Link header pointing anywhere else is refused, so a response cannot
// redirect the credential.
//
// Mapping onto Tessera's graph (Discover):
//
//	sys_user             -> account (disabled when inactive or locked out), correlated by e-mail
//	sys_user_group       -> group (kind servicenow_group), requestable; a user is member_of the groups of sys_user_grmember
//	sys_user_role        -> group (kind servicenow_role), requestable; privileged for admin, security_admin and any role
//	                        flagged elevated privilege; a user is member_of the roles of sys_user_has_role (inherited ones too)
//
// Every encoded query (sysparm_query) is built from fixed text and values that passed an allow-list: a value
// is never free text, so a caret (the condition separator), a "javascript:" value or any operator cannot be
// injected.
package servicenow

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Authentication modes.
const (
	AuthBasic = "basic"
	AuthOAuth = "oauth"
)

const (
	tokenPath = "/oauth_token.do" // #nosec G101 -- URL path, not a credential
	tablePath = "/api/now/table/"
	// PageSize is sysparm_limit of every read. The instance applies it before ACL evaluation, so a page can
	// hold fewer rows than the limit while more remain: paging ends at the Link header's end or an empty page.
	PageSize  = 500
	maxPages  = 4000
	tokenTTL  = 25 * time.Minute // when the token response gives no expires_in
	tokenSkew = time.Minute
)

var (
	// sysIDRE is a ServiceNow sys_id: 32 lower-case hex characters.
	sysIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// nameRE is what may sit in an encoded-query value: letters, digits and a few punctuation marks. No caret
	// (condition separator), colon ("javascript:" and "dynamic:" values are evaluated by the instance), equals,
	// parenthesis or control character.
	nameRE = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} @._+'-]{0,199}$`)
	// clientRE is an OAuth client id or an integration username.
	clientRE = regexp.MustCompile(`^[^\x00-\x1f\x7f\s]{1,256}$`)
)

// hostSuffixes are the domains an instance lives under: service-now.com, and servicenowservices.com for
// the US government community cloud.
var hostSuffixes = []string{".service-now.com", ".servicenowservices.com"}

// Config configures one instance.
type Config struct {
	// BaseURL is the instance: https://acme.service-now.com.
	BaseURL string
	// AuthMode is AuthBasic (default) or AuthOAuth.
	AuthMode string
	// Username is the integration user (basic) or the OAuth client id (oauth).
	Username string
	// Secret is the integration user's password (basic) or the OAuth client secret (oauth).
	Secret connsync.Secret
}

// Client is a retrying Table API client of one instance.
type Client struct {
	api  *connsync.Client
	base *url.URL
	cfg  Config
	now  func() time.Time

	mu      sync.Mutex
	access  string
	expires time.Time
}

// Open validates cfg and returns the client. hc is the server's safehttp client.
func Open(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Client, error) {
	if hc == nil {
		return nil, errors.New("servicenow: an internal/safehttp client is required")
	}
	if now == nil {
		now = time.Now
	}
	if cfg.AuthMode == "" {
		cfg.AuthMode = AuthBasic
	}
	if cfg.AuthMode != AuthBasic && cfg.AuthMode != AuthOAuth {
		return nil, errors.New("servicenow: the authentication mode is basic or oauth")
	}
	if !clientRE.MatchString(cfg.Username) || cfg.Secret.Empty() {
		return nil, errors.New("servicenow: a username (or OAuth client id) and its secret are required")
	}
	base, err := CheckURL(cfg.BaseURL, rt)
	if err != nil {
		return nil, fmt.Errorf("servicenow: base URL: %w", err)
	}
	if base.Path != "" {
		return nil, errors.New("servicenow: the base URL is a host without a path")
	}
	c := &Client{base: base, cfg: cfg, now: now}
	c.api = &connsync.Client{HC: hc, Now: now, Header: http.Header{"Accept": {"application/json"}, "User-Agent": {"tessera-connector/servicenow"}}}
	c.api.Authorize = c.authorize
	c.api.OnUnauthorized = func() { c.mu.Lock(); c.access = ""; c.mu.Unlock() }
	return c, nil
}

// CheckURL parses a base URL and refuses a host that is not ServiceNow's. The only exception is the dev
// loopback exception (connsync.Runtime.AllowLoopback, refused in prod by the configuration), which lets a test
// point at a local fake. The credential goes only to these hosts.
func CheckURL(raw string, rt connsync.Runtime) (*url.URL, error) {
	u, err := connsync.ParseBaseURL(raw, rt)
	if err != nil {
		return nil, err
	}
	host := strings.ToLower(u.Hostname())
	if rt.Env != config.Prod && rt.AllowLoopback {
		if a, err := netip.ParseAddr(host); err == nil && a.IsLoopback() {
			return u, nil
		}
	}
	for _, suf := range hostSuffixes {
		if strings.HasSuffix(host, suf) && len(host) > len(suf) {
			return u, nil
		}
	}
	return nil, errors.New("the host must be a ServiceNow domain (*.service-now.com or *.servicenowservices.com)")
}

func (c *Client) authorize(ctx context.Context) (string, error) {
	if c.cfg.AuthMode == AuthBasic {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.cfg.Username+":"+c.cfg.Secret.Reveal())), nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.access != "" && c.now().Before(c.expires) {
		return "Bearer " + c.access, nil
	}
	plain := *c.api
	plain.Authorize, plain.OnUnauthorized = nil, nil
	tu := *c.base
	tu.Path = tokenPath
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.cfg.Username}, "client_secret": {c.cfg.Secret.Reveal()}}
	resp, err := plain.Do(ctx, http.MethodPost, tu.String(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("servicenow: token request: %w", err)
	}
	var tr struct {
		Access  string `json:"access_token"`
		Type    string `json:"token_type"`
		Expires int    `json:"expires_in"`
	}
	if err := connsync.DecodeJSON(resp.Body, &tr); err != nil {
		return "", fmt.Errorf("servicenow: token response: %w", err)
	}
	if tr.Access == "" || !strings.EqualFold(tr.Type, "bearer") {
		return "", errors.New("servicenow: token response has no bearer token")
	}
	ttl := tokenTTL
	if tr.Expires > 0 {
		ttl = time.Duration(tr.Expires)*time.Second - tokenSkew
	}
	c.access, c.expires = tr.Access, c.now().Add(max(ttl, time.Second))
	return "Bearer " + c.access, nil
}

// Mode names how the client authenticates, for a prober.
func (c *Client) Mode() string {
	if c.cfg.AuthMode == AuthOAuth {
		return "client_credentials"
	}
	return "basic"
}

// Identity is the username or OAuth client id, for a prober.
func (c *Client) Identity() string { return c.cfg.Username }

// record is one Table API row. Every value is a string in the answer (booleans too); a reference field is a
// sys_id string with sysparm_exclude_reference_link=true.
type record map[string]any

func (r record) str(k string) string {
	switch v := r[k].(type) {
	case string:
		return v
	case map[string]any: // a reference that kept its link: {"link": ..., "value": sys_id}
		s, _ := v["value"].(string)
		return s
	}
	return ""
}

func (r record) flag(k string) bool {
	switch v := r[k].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}

// time parses a ServiceNow date-time ("2006-01-02 15:04:05", UTC).
func (r record) time(k string) *time.Time {
	s := r.str(k)
	for _, l := range []string{"2006-01-02 15:04:05", time.RFC3339, "2006-01-02"} {
		if t, err := time.ParseInLocation(l, s, time.UTC); err == nil {
			return &t
		}
	}
	return nil
}

// Value checks an encoded-query value against the allow-list; the error never quotes it.
func Value(v string) (string, error) {
	if !nameRE.MatchString(v) {
		return "", errors.New("servicenow: a value in a query has characters the instance's encoded query cannot take safely")
	}
	return v, nil
}

// SysID checks a sys_id.
func SysID(v string) (string, error) {
	if !sysIDRE.MatchString(v) {
		return "", errors.New("servicenow: not a sys_id")
	}
	return v, nil
}

func (c *Client) tableURL(table string, q url.Values) string {
	x := *c.base
	x.Path = tablePath + table
	x.RawQuery = q.Encode()
	return x.String()
}

// nextLink returns the rel="next" target of a Link header, "" when there is none.
func nextLink(h string) string {
	for _, part := range strings.Split(h, ",") {
		seg := strings.Split(strings.TrimSpace(part), ";")
		if len(seg) < 2 {
			continue
		}
		for _, p := range seg[1:] {
			p = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(p)), " ", "")
			if p == `rel="next"` || p == "rel=next" {
				return strings.Trim(strings.TrimSpace(seg[0]), "<>")
			}
		}
	}
	return ""
}

// each reads every row of a table that matches the encoded query (fixed text and checked values only), a page
// at a time, and calls fn for each. fields is the fixed list of columns to return.
func (c *Client) each(ctx context.Context, table, query string, fields []string, fn func(record) error) error {
	q := url.Values{"sysparm_query": {query}, "sysparm_fields": {strings.Join(fields, ",")}, "sysparm_limit": {strconv.Itoa(PageSize)},
		"sysparm_offset": {"0"}, "sysparm_exclude_reference_link": {"true"}, "sysparm_display_value": {"false"}, "sysparm_no_count": {"true"}}
	next := c.tableURL(table, q)
	want := tablePath + table
	offset := 0
	for i := 0; next != ""; i++ {
		if i >= maxPages {
			return fmt.Errorf("servicenow: more than %d pages of %s; stopping", maxPages, table)
		}
		var page struct {
			Result []record `json:"result"`
		}
		hdr, err := c.api.GetJSON(ctx, next, nil, &page)
		if err != nil {
			return err
		}
		for _, r := range page.Result {
			if err := fn(r); err != nil {
				return err
			}
		}
		if len(page.Result) == 0 {
			return nil
		}
		offset += len(page.Result)
		next = ""
		if link := hdr.Get("Link"); link != "" {
			n := nextLink(link)
			if n == "" {
				return nil // the Link header has no next page: this was the last
			}
			u, err := connsync.SameOrigin(c.base, n)
			if err != nil || u.Path != want {
				return errors.New("servicenow: page link leaves the Table API")
			}
			next = u.String()
			continue
		}
		q.Set("sysparm_offset", strconv.Itoa(offset)) // no Link header: offset paging, until an empty page
		next = c.tableURL(table, q)
	}
	return nil
}

func (c *Client) rows(ctx context.Context, table, query string, fields []string) ([]record, error) {
	var out []record
	err := c.each(ctx, table, query, fields, func(r record) error { out = append(out, r); return nil })
	return out, err
}

// one reads at most one row (sysparm_limit=1), for a lookup.
func (c *Client) one(ctx context.Context, table, query string, fields []string) (record, error) {
	q := url.Values{"sysparm_query": {query}, "sysparm_fields": {strings.Join(fields, ",")}, "sysparm_limit": {"1"},
		"sysparm_exclude_reference_link": {"true"}, "sysparm_display_value": {"false"}, "sysparm_no_count": {"true"}}
	var page struct {
		Result []record `json:"result"`
	}
	if _, err := c.api.GetJSON(ctx, c.tableURL(table, q), nil, &page); err != nil {
		return nil, err
	}
	if len(page.Result) == 0 {
		return nil, nil
	}
	return page.Result[0], nil
}

// create inserts a row and returns its sys_id.
func (c *Client) create(ctx context.Context, table string, body map[string]any) (record, error) {
	b, err := jsonBody(body)
	if err != nil {
		return nil, err
	}
	resp, err := c.api.Do(ctx, http.MethodPost, c.tableURL(table, url.Values{"sysparm_exclude_reference_link": {"true"}}), http.Header{"Content-Type": {"application/json"}}, b)
	if err != nil {
		return nil, err
	}
	var out struct {
		Result record `json:"result"`
	}
	if err := connsync.DecodeJSON(resp.Body, &out); err != nil || !sysIDRE.MatchString(out.Result.str("sys_id")) {
		return nil, fmt.Errorf("servicenow: create %s: %w", table, connsync.ErrMalformed)
	}
	return out.Result, nil
}

func (c *Client) update(ctx context.Context, table, id string, body map[string]any) error {
	if !sysIDRE.MatchString(id) {
		return errors.New("servicenow: invalid sys_id")
	}
	b, err := jsonBody(body)
	if err != nil {
		return err
	}
	_, err = c.api.Do(ctx, http.MethodPatch, c.tableURL(table+"/"+id, nil), http.Header{"Content-Type": {"application/json"}}, b)
	return err
}

func (c *Client) remove(ctx context.Context, table, id string) error {
	if !sysIDRE.MatchString(id) {
		return errors.New("servicenow: invalid sys_id")
	}
	_, err := c.api.Do(ctx, http.MethodDelete, c.tableURL(table+"/"+id, nil), nil, nil)
	return err
}
