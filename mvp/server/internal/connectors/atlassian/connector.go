package atlassian

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// System is the connector's system name.
const System = "atlassian"

// Group kinds.
const (
	KindGroup       = "atlassian_group"
	KindProjectRole = "jira_project_role"
	KindProduct     = "atlassian_product"
)

// ParseCredential splits the credential of a connection: an API token, or JSON with the token and the
// organization admin API key
//
//	{"api_token":"ATATT...","admin_api_key":"..."}
//
// The error never repeats a secret.
func ParseCredential(s string) (token, adminKey string, err error) {
	s = strings.TrimSpace(s)
	if len(s) > 8<<10 {
		return "", "", errors.New("the Atlassian credential is too long")
	}
	if !strings.HasPrefix(s, "{") {
		if s == "" || strings.ContainsAny(s, " \t\r\n\x00") {
			return "", "", errors.New("the Atlassian credential is an API token, or JSON with api_token and admin_api_key")
		}
		return s, "", nil
	}
	var c struct {
		APIToken string `json:"api_token"`
		AdminKey string `json:"admin_api_key"`
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil || c.APIToken == "" || strings.ContainsAny(c.APIToken+c.AdminKey, " \t\r\n\x00") {
		return "", "", errors.New("the Atlassian credential is an API token, or JSON with api_token and admin_api_key")
	}
	return c.APIToken, c.AdminKey, nil
}

func list(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ConfigFromEnv reads TESSERA_ATLASSIAN_*:
//
//	TESSERA_ATLASSIAN_BASE_URL    https://acme.atlassian.net
//	TESSERA_ATLASSIAN_EMAIL       the dedicated account's e-mail
//	TESSERA_ATLASSIAN_CREDENTIAL  reference (file:/abs/path or env:NAME) to the API token, or to JSON {"api_token","admin_api_key"}
//	TESSERA_ATLASSIAN_ORG_ID      optional: the organization id, for the admin API (needs admin_api_key)
//	TESSERA_ATLASSIAN_PROJECTS    optional: comma separated project keys whose roles are read
//	TESSERA_ATLASSIAN_ADMIN_URL   dev and test only: a fake of the admin API (refused outside the dev loopback exception)
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	const p = "TESSERA_ATLASSIAN_"
	secret, err := connsync.ResolveSecret(getenv(p+"CREDENTIAL"), getenv)
	if err != nil {
		return Config{}, errors.New(p + "CREDENTIAL: " + err.Error())
	}
	token, admin, err := ParseCredential(secret.Reveal())
	if err != nil {
		return Config{}, err
	}
	cfg := Config{BaseURL: getenv(p + "BASE_URL"), Email: strings.TrimSpace(getenv(p + "EMAIL")), Token: connsync.NewSecret(token),
		OrgID: strings.TrimSpace(getenv(p + "ORG_ID")), AdminURL: strings.TrimSpace(getenv(p + "ADMIN_URL")), ProjectKeys: list(getenv(p + "PROJECTS"))}
	if admin != "" {
		cfg.AdminKey = connsync.NewSecret(admin)
	}
	return cfg, nil
}

// Connector is the read connector (connectors.Connector).
type Connector struct{ c *Client }

// NewConnector wraps a client.
func NewConnector(c *Client) *Connector { return &Connector{c} }

func (*Connector) System() string      { return System }
func (*Connector) DisplayName() string { return "Atlassian Cloud" }
func (*Connector) TypeName() string    { return "AtlassianConnector" }

// StreamEvents: no usage is read here.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// FromEnv builds the read connector from TESSERA_ATLASSIAN_* (ConfigFromEnv).
func FromEnv(getenv func(string) string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (connectors.Connector, error) {
	cfg, err := ConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	c, err := Open(cfg, rt, hc, now)
	if err != nil {
		return nil, err
	}
	return NewConnector(c), nil
}

// ProbeResult is what one bounded read found.
type ProbeResult struct {
	Users, Groups, AdminUsers int
}

// Probe proves the credential (the account's own record), then reads one page of users and groups and, when
// the admin API is configured, of organization users. It keeps counts only.
func (c *Client) Probe(ctx context.Context) (ProbeResult, error) {
	var r ProbeResult
	var me jiraItem
	if _, err := c.site.GetJSON(ctx, c.siteURL("/rest/api/3/myself", nil), nil, &me); err != nil {
		return r, err
	}
	var us []jiraItem
	if _, err := c.site.GetJSON(ctx, c.siteURL("/rest/api/3/users/search", url.Values{"startAt": {"0"}, "maxResults": {"50"}}), nil, &us); err != nil {
		return r, err
	}
	r.Users = len(us)
	var p page
	if _, err := c.site.GetJSON(ctx, c.siteURL("/rest/api/3/group/bulk", url.Values{"startAt": {"0"}, "maxResults": {"50"}}), nil, &p); err != nil {
		return r, err
	}
	r.Groups = len(p.Values)
	if c.admin != nil {
		var ap struct {
			Data []adminUser `json:"data"`
		}
		if _, err := c.admin.GetJSON(ctx, c.adminURL("/admin/v1/orgs/"+c.cfg.OrgID+"/users", nil), nil, &ap); err != nil {
			return r, fmt.Errorf("organization admin API: %w", err)
		}
		r.AdminUsers = len(ap.Data)
	}
	return r, nil
}

// roleActors is a project role as /project/{key}/role/{id} returns it.
type roleActors struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Admin  bool   `json:"admin"`
	Actors []struct {
		Type      string `json:"type"`
		ActorUser *struct {
			AccountID string `json:"accountId"`
		} `json:"actorUser"`
		ActorGroup *struct {
			GroupID string `json:"groupId"`
		} `json:"actorGroup"`
	} `json:"actors"`
}

// roleIDs lists the roles of a project as id and name: the answer maps a role's name to its URL, whose last
// segment is the id. The URL itself is never followed.
func (c *Client) roleIDs(ctx context.Context, key string) (map[string]string, error) {
	var m map[string]string
	if _, err := c.site.GetJSON(ctx, c.siteURL("/rest/api/3/project/"+key+"/role", nil), nil, &m); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for name, link := range m {
		u, err := url.Parse(link)
		if err != nil {
			continue
		}
		id := u.Path[strings.LastIndex(u.Path, "/")+1:]
		if roleIDRE.MatchString(id) {
			out[id] = name
		}
	}
	return out, nil
}

func (c *Client) role(ctx context.Context, key, id string) (*roleActors, error) {
	if !projectRE.MatchString(key) || !roleIDRE.MatchString(id) {
		return nil, errors.New("atlassian: invalid project role reference")
	}
	var r roleActors
	if _, err := c.site.GetJSON(ctx, c.siteURL("/rest/api/3/project/"+key+"/role/"+id, url.Values{"excludeInactiveUsers": {"true"}}), nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Discover reads users, groups and their members, the project roles of the configured projects and, with the
// admin API, the products each account uses.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	res := &connectors.DiscoveryResult{}
	acc := map[string]int{} // accountId -> index in res.Accounts
	if err := c.c.allUsers(ctx, func(u jiraItem) error {
		if !accountRE.MatchString(u.AccountID) {
			return nil
		}
		status, kind := "active", "user"
		if !u.Active {
			status = "disabled"
		}
		if u.AccountType == "app" {
			kind = "service"
		}
		name := u.EmailAddress
		if name == "" {
			name = u.AccountID
		}
		a := connectors.AccountRecord{System: System, ExternalID: u.AccountID, Username: name, Kind: kind, Status: status,
			Attributes: map[string]string{"accountId": u.AccountID, "accountType": u.AccountType, "emailAddress": u.EmailAddress, "displayName": u.DisplayName, "active": fmt.Sprint(u.Active)}}
		if e := strings.ToLower(strings.TrimSpace(u.EmailAddress)); e != "" {
			a.Identity = &connectors.IdentityRef{Email: e}
		}
		acc[u.AccountID] = len(res.Accounts)
		res.Accounts = append(res.Accounts, a)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("users: %w", err)
	}

	privileged := map[string]bool{}
	for _, t := range []string{"site-admin", "admin"} {
		if err := c.c.paged(ctx, "/rest/api/3/group/bulk", url.Values{"accessType": {t}}, 100, func(g jiraItem) error {
			privileged[g.GroupID] = true
			return nil
		}); err != nil {
			return nil, fmt.Errorf("admin groups: %w", err)
		}
	}
	var groupIDs []string
	if err := c.c.paged(ctx, "/rest/api/3/group/bulk", nil, 100, func(g jiraItem) error {
		if !groupRE.MatchString(g.GroupID) {
			return nil
		}
		if len(groupIDs) >= MaxGroups {
			return fmt.Errorf("more than %d groups", MaxGroups)
		}
		groupIDs = append(groupIDs, g.GroupID)
		res.Groups = append(res.Groups, connectors.GroupRecord{System: System, ExternalID: g.GroupID, Name: g.Name, Kind: KindGroup,
			Privileged: privileged[g.GroupID], Requestable: true})
		return nil
	}); err != nil {
		return nil, fmt.Errorf("groups: %w", err)
	}

	seen := map[string]bool{}
	member := func(account, group string) {
		if _, known := acc[account]; !known {
			return
		}
		if k := account + ">" + group; !seen[k] {
			seen[k] = true
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: connectors.Ref{Kind: "account", System: System, ExternalID: account},
				Dst: connectors.Ref{Kind: "group", System: System, ExternalID: group}, Relation: "member_of"})
		}
	}
	for _, g := range groupIDs {
		if err := c.c.paged(ctx, "/rest/api/3/group/member", url.Values{"groupId": {g}, "includeInactiveUsers": {"true"}}, 50, func(u jiraItem) error {
			member(u.AccountID, g)
			return nil
		}); err != nil {
			return nil, fmt.Errorf("group members: %w", err)
		}
	}

	for _, key := range c.c.cfg.ProjectKeys {
		roles, err := c.c.roleIDs(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("project roles of %s: %w", key, err)
		}
		ids := make([]string, 0, len(roles))
		for id := range roles {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		if len(ids) > maxRoles {
			ids = ids[:maxRoles]
		}
		for _, id := range ids {
			r, err := c.c.role(ctx, key, id)
			if err != nil {
				return nil, fmt.Errorf("project role %s/%s: %w", key, id, err)
			}
			ext := key + "/" + id
			res.Groups = append(res.Groups, connectors.GroupRecord{System: System, ExternalID: ext, Name: key + ": " + roles[id], Kind: KindProjectRole,
				Privileged: r.Admin, Requestable: true})
			for _, a := range r.Actors {
				switch {
				case a.ActorUser != nil:
					member(a.ActorUser.AccountID, ext)
				case a.ActorGroup != nil && groupRE.MatchString(a.ActorGroup.GroupID):
					res.Edges = append(res.Edges, connectors.EdgeRecord{Src: connectors.Ref{Kind: "group", System: System, ExternalID: a.ActorGroup.GroupID},
						Dst: connectors.Ref{Kind: "group", System: System, ExternalID: ext}, Relation: "member_of"})
				}
			}
		}
	}

	if c.c.admin != nil {
		products := map[string]bool{}
		if err := c.c.adminUsers(ctx, func(u adminUser) error {
			i, known := acc[u.AccountID]
			if !known {
				return nil
			}
			if e := strings.ToLower(strings.TrimSpace(u.Email)); e != "" && res.Accounts[i].Identity == nil {
				res.Accounts[i].Identity = &connectors.IdentityRef{Email: e}
				res.Accounts[i].Attributes["emailAddress"] = u.Email
			}
			if u.AccountStatus == "inactive" || u.AccountStatus == "closed" {
				res.Accounts[i].Status = "disabled"
			}
			for _, p := range u.ProductAccess {
				if !productRE.MatchString(p.Key) {
					continue
				}
				ext := "product:" + p.Key
				if !products[ext] {
					products[ext] = true
					name := p.Name
					if name == "" {
						name = p.Key
					}
					res.Groups = append(res.Groups, connectors.GroupRecord{System: System, ExternalID: ext, Name: name, Kind: KindProduct})
				}
				member(u.AccountID, ext)
			}
			return nil
		}); err != nil {
			return nil, fmt.Errorf("organization users: %w", err)
		}
	}
	return res, nil
}
