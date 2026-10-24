// Package atlassian reads an Atlassian Cloud site's access model into Tessera's graph (users, groups, project
// roles and, from the organization admin API, product access) and writes group membership and project role
// actors back through provisioning (issue #559).
//
// Account provisioning (create, update, suspend, delete) is not here: the Atlassian Cloud SCIM preset already
// does it (internal/provision/scim). This package adds what SCIM does not carry: groups as the site holds them,
// project roles and the products an account can use.
//
// Two APIs are read:
//
//   - the site's Jira Cloud REST API (https://<site>.atlassian.net/rest/api/3), signed in with HTTP basic: the
//     e-mail of a dedicated account and its API token. It lists users (/users/search), groups (/group/bulk,
//     /group/member) and project roles (/project/{key}/role, .../role/{id}), and writes group membership
//     (/group/user) and role actors.
//   - optionally the organization admin API (https://api.atlassian.com/admin), with an organization API key as
//     bearer: /v1/orgs/{orgId}/users lists managed accounts with the products they use (product_access).
//
// Hosts: *.atlassian.net for the site and api.atlassian.com for the admin API, nothing else. A pagination link
// to any other origin is refused, so a response cannot redirect a credential.
//
// Mapping onto Tessera's graph (Discover):
//
//	user (accountType atlassian, customer) -> account, correlated by e-mail when the profile shows one; app -> service account
//	group                                  -> group (kind atlassian_group), requestable; privileged when the site lists it
//	                                          with access type site-admin or admin
//	project role of a configured project   -> group (kind jira_project_role, "KEY/roleId"), requestable; privileged for
//	                                          the project's admin role; its actors are members
//	product (admin API)                    -> group (kind atlassian_product, "product:key"), not requestable: access is
//	                                          granted through groups
package atlassian

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

const (
	// DefaultAdminURL is the organization admin API's origin.
	DefaultAdminURL = "https://api.atlassian.com"
	adminHost       = "api.atlassian.com"
	maxPages        = 2000
	// MaxProjects bounds the project keys whose roles are read; each key costs one call plus one per role.
	MaxProjects = 50
	maxRoles    = 40
	// MaxGroups bounds the groups whose members are read (one call per group and page).
	MaxGroups = 5000
)

var (
	accountRE = regexp.MustCompile(`^[A-Za-z0-9:_|-]{1,128}$`)
	groupRE   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	projectRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{1,99}$`)
	roleIDRE  = regexp.MustCompile(`^[0-9]{1,12}$`)
	orgRE     = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	emailRE   = regexp.MustCompile(`^[^\x00-\x1f\x7f\s]{3,256}$`)
	productRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// IsProjectKey and IsOrgID report whether a setting is well formed (the readiness settings use them).
func IsProjectKey(s string) bool { return projectRE.MatchString(s) }

// IsOrgID reports whether s looks like an organization id.
func IsOrgID(s string) bool { return orgRE.MatchString(s) }

// Config configures one site.
type Config struct {
	// BaseURL is the site: https://acme.atlassian.net.
	BaseURL string
	// Email and Token are the dedicated account's e-mail and API token (HTTP basic).
	Email string
	Token connsync.Secret
	// OrgID and AdminKey, both or neither, add the organization admin API (product access).
	OrgID    string
	AdminKey connsync.Secret
	// AdminURL overrides DefaultAdminURL. Only the dev loopback exception admits another host.
	AdminURL string
	// ProjectKeys are the projects whose roles are read (none: no project roles).
	ProjectKeys []string
}

// Client is a retrying REST client of one site (and its organization).
type Client struct {
	site  *connsync.Client
	admin *connsync.Client
	base  *url.URL
	adm   *url.URL
	cfg   Config
}

// Open validates cfg and returns the client. hc is the server's safehttp client.
func Open(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Client, error) {
	if hc == nil {
		return nil, errors.New("atlassian: an internal/safehttp client is required")
	}
	if now == nil {
		now = time.Now
	}
	if !emailRE.MatchString(cfg.Email) || !strings.Contains(cfg.Email, "@") || cfg.Token.Empty() {
		return nil, errors.New("atlassian: the account e-mail and its API token are required")
	}
	base, err := CheckSiteURL(cfg.BaseURL, rt)
	if err != nil {
		return nil, fmt.Errorf("atlassian: base URL: %w", err)
	}
	if base.Path != "" {
		return nil, errors.New("atlassian: the base URL is a host without a path")
	}
	if len(cfg.ProjectKeys) > MaxProjects {
		return nil, fmt.Errorf("atlassian: at most %d project keys", MaxProjects)
	}
	for _, k := range cfg.ProjectKeys {
		if !projectRE.MatchString(k) {
			return nil, errors.New("atlassian: a project key is not valid")
		}
	}
	c := &Client{base: base, cfg: cfg}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(cfg.Email+":"+cfg.Token.Reveal()))
	hdr := http.Header{"Accept": {"application/json"}, "User-Agent": {"tessera-connector/atlassian"}}
	c.site = &connsync.Client{HC: hc, Now: now, Header: hdr, Authorize: func(context.Context) (string, error) { return auth, nil }}
	if cfg.OrgID != "" || !cfg.AdminKey.Empty() {
		if !orgRE.MatchString(cfg.OrgID) || cfg.AdminKey.Empty() {
			return nil, errors.New("atlassian: the organization id and the admin API key go together")
		}
		raw := cfg.AdminURL
		if raw == "" {
			raw = DefaultAdminURL
		}
		if c.adm, err = CheckAdminURL(raw, rt); err != nil {
			return nil, fmt.Errorf("atlassian: admin API URL: %w", err)
		}
		bearer := "Bearer " + cfg.AdminKey.Reveal()
		c.admin = &connsync.Client{HC: hc, Now: now, Header: hdr, Authorize: func(context.Context) (string, error) { return bearer, nil }}
	}
	return c, nil
}

func loopback(u *url.URL, rt connsync.Runtime) bool {
	if rt.Env == config.Prod || !rt.AllowLoopback {
		return false
	}
	a, err := netip.ParseAddr(u.Hostname())
	return err == nil && a.IsLoopback()
}

// CheckSiteURL parses a site URL and refuses a host that is not *.atlassian.net. The only exception is the dev
// loopback exception (connsync.Runtime.AllowLoopback, refused in prod by the configuration), which lets a test
// point at a local fake. The API token goes only to these hosts.
func CheckSiteURL(raw string, rt connsync.Runtime) (*url.URL, error) {
	u, err := connsync.ParseBaseURL(raw, rt)
	if err != nil {
		return nil, err
	}
	host := strings.ToLower(u.Hostname())
	if loopback(u, rt) || (strings.HasSuffix(host, ".atlassian.net") && len(host) > len(".atlassian.net")) {
		return u, nil
	}
	return nil, errors.New("the host must be an Atlassian Cloud site (*.atlassian.net)")
}

// CheckAdminURL parses the admin API origin: api.atlassian.com, or a loopback fake under the dev exception.
func CheckAdminURL(raw string, rt connsync.Runtime) (*url.URL, error) {
	u, err := connsync.ParseBaseURL(raw, rt)
	if err != nil {
		return nil, err
	}
	if loopback(u, rt) || strings.EqualFold(u.Hostname(), adminHost) {
		if u.Path != "" {
			return nil, errors.New("the admin API URL is a host without a path")
		}
		return u, nil
	}
	return nil, errors.New("the admin API host must be api.atlassian.com")
}

// Mode names how the client authenticates, for a prober.
func (c *Client) Mode() string { return "api_token" }

// Identity is the account e-mail, for a prober.
func (c *Client) Identity() string { return c.cfg.Email }

// HasAdmin reports whether the organization admin API is configured.
func (c *Client) HasAdmin() bool { return c.admin != nil }

func (c *Client) siteURL(path string, q url.Values) string {
	x := *c.base
	x.Path = path
	x.RawQuery = q.Encode()
	return x.String()
}

func (c *Client) adminURL(path string, q url.Values) string {
	x := *c.adm
	x.Path = path
	x.RawQuery = q.Encode()
	return x.String()
}

// page is a Jira PageBean: values, and whether this is the last page.
type page struct {
	Values []jiraItem `json:"values"`
	IsLast bool       `json:"isLast"`
}

// jiraItem carries the fields of the user, group and project items a page holds.
type jiraItem struct {
	AccountID    string `json:"accountId"`
	AccountType  string `json:"accountType"`
	EmailAddress string `json:"emailAddress"`
	DisplayName  string `json:"displayName"`
	Active       bool   `json:"active"`
	GroupID      string `json:"groupId"`
	Name         string `json:"name"`
}

// paged walks a PageBean endpoint (startAt, maxResults, isLast) and calls fn for every item. An empty page ends
// the walk even when isLast is missing.
func (c *Client) paged(ctx context.Context, path string, q url.Values, size int, fn func(jiraItem) error) error {
	start := 0
	for i := 0; ; i++ {
		if i >= maxPages {
			return fmt.Errorf("atlassian: more than %d pages of %s; stopping", maxPages, path)
		}
		qq := url.Values{}
		for k, v := range q {
			qq[k] = v
		}
		qq.Set("startAt", fmt.Sprint(start))
		qq.Set("maxResults", fmt.Sprint(size))
		var p page
		if _, err := c.site.GetJSON(ctx, c.siteURL(path, qq), nil, &p); err != nil {
			return err
		}
		for _, it := range p.Values {
			if err := fn(it); err != nil {
				return err
			}
		}
		if p.IsLast || len(p.Values) == 0 {
			return nil
		}
		start += len(p.Values)
	}
}

// allUsers walks /users/search, which answers a plain array (no isLast): an empty page ends it.
func (c *Client) allUsers(ctx context.Context, fn func(jiraItem) error) error {
	const size = 1000
	start := 0
	for i := 0; ; i++ {
		if i >= maxPages {
			return fmt.Errorf("atlassian: more than %d pages of users; stopping", maxPages)
		}
		var us []jiraItem
		q := url.Values{"startAt": {fmt.Sprint(start)}, "maxResults": {fmt.Sprint(size)}}
		if _, err := c.site.GetJSON(ctx, c.siteURL("/rest/api/3/users/search", q), nil, &us); err != nil {
			return err
		}
		for _, u := range us {
			if err := fn(u); err != nil {
				return err
			}
		}
		if len(us) == 0 {
			return nil
		}
		start += len(us)
	}
}

// adminUser is a managed account of the organization with the products it uses.
type adminUser struct {
	AccountID     string `json:"account_id"`
	AccountType   string `json:"account_type"`
	AccountStatus string `json:"account_status"`
	Email         string `json:"email"`
	ProductAccess []struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	} `json:"product_access"`
}

// adminUsers walks /admin/v1/orgs/{orgId}/users, following links.next on the same origin and path only.
func (c *Client) adminUsers(ctx context.Context, fn func(adminUser) error) error {
	path := "/admin/v1/orgs/" + c.cfg.OrgID + "/users"
	next := c.adminURL(path, nil)
	for i := 0; next != ""; i++ {
		if i >= maxPages {
			return fmt.Errorf("atlassian: more than %d pages of organization users; stopping", maxPages)
		}
		var p struct {
			Data  []adminUser `json:"data"`
			Links struct {
				Next string `json:"next"`
			} `json:"links"`
		}
		if _, err := c.admin.GetJSON(ctx, next, nil, &p); err != nil {
			return err
		}
		for _, u := range p.Data {
			if err := fn(u); err != nil {
				return err
			}
		}
		next = ""
		if n := p.Links.Next; n != "" && len(p.Data) > 0 {
			u, err := connsync.SameOrigin(c.adm, n)
			if err != nil || u.Path != path {
				return errors.New("atlassian: page link leaves the organization users API")
			}
			next = u.String()
		}
	}
	return nil
}
