package loaders

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// The scim source reads the groups of an external SCIM 2.0 service provider
// (RFC 7643, RFC 7644): GET /Groups with their members, and GET /Users to turn
// a member's SCIM id into the attribute that identifies the person here. All
// traffic goes through the SSRF-guarded client (internal/safehttp). The
// credential (a bearer token, or the client secret of a client-credentials
// grant) is the loader's sealed secret: it is sent only in the Authorization
// header or the token request, and is in no error or log line.

// Bounds of one read of a SCIM provider.
const (
	scimDefaultPage = 100
	// MaxSCIMResources bounds the users and the groups one run reads: more is an
	// error, never a cut-off, which would look like people who left.
	MaxSCIMResources = 1_000_000
	scimMaxPages     = 20_000
	scimMaxBody      = 32 << 20
	scimTokenBody    = 64 << 10
	// scimMaxGroupFetches bounds the one-by-one reads of groups a provider lists
	// without their members.
	scimMaxGroupFetches = 50_000
)

type scimSource struct{ noChanges }

type scimClient struct {
	http   *http.Client
	base   string
	bearer string
}

type scimList struct {
	TotalResults int               `json:"totalResults"`
	StartIndex   int               `json:"startIndex"`
	ItemsPerPage int               `json:"itemsPerPage"`
	Resources    []json.RawMessage `json:"Resources"`
}

type scimMember struct {
	Value   string `json:"value"`
	Type    string `json:"type"`
	Display string `json:"display"`
}

type scimGroup struct {
	ID          string        `json:"id"`
	DisplayName string        `json:"displayName"`
	ExternalID  string        `json:"externalId"`
	Members     *[]scimMember `json:"members"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
	Type    string `json:"type"`
}

type scimUser struct {
	ID         string      `json:"id"`
	UserName   string      `json:"userName"`
	ExternalID string      `json:"externalId"`
	Active     *bool       `json:"active"`
	Emails     []scimEmail `json:"emails"`
}

// email is the primary address, else the work one, else the first.
func (u *scimUser) email() string {
	best := ""
	rank := -1
	for _, e := range u.Emails {
		r := 0
		switch {
		case e.Primary:
			r = 3
		case strings.EqualFold(e.Type, "work"):
			r = 2
		default:
			r = 1
		}
		if strings.TrimSpace(e.Value) != "" && r > rank {
			best, rank = strings.TrimSpace(e.Value), r
		}
	}
	return best
}

func scimFail(format string, args ...any) error {
	return conflict("source_fetch_failed", format, args...)
}

// get fetches one SCIM URL and decodes its JSON. The body of an error answer is
// never read into the error: a provider may echo what it was sent.
func (c *scimClient) get(ctx context.Context, rawURL string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return scimFail("the SCIM URL is not valid")
	}
	req.Header.Set("Accept", "application/scim+json, application/json")
	req.Header.Set("Authorization", "Bearer "+c.bearer)
	resp, err := c.http.Do(req)
	if err != nil {
		return scimFail("the SCIM provider could not be reached: %v", urlErrReason(err))
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return conflict("source_auth_failed", "the SCIM provider refused the credential (HTTP %d)", resp.StatusCode)
	case resp.StatusCode == http.StatusTooManyRequests:
		return scimFail("the SCIM provider is rate limiting this loader (HTTP 429): lower the schedule")
	case resp.StatusCode != http.StatusOK:
		return scimFail("the SCIM provider answered HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, scimMaxBody+1))
	if err != nil {
		return scimFail("reading the SCIM answer failed")
	}
	if len(b) > scimMaxBody {
		return conflict("source_too_large", "a SCIM page is larger than %d bytes: lower page_size", scimMaxBody)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return scimFail("the SCIM provider's answer is not SCIM JSON")
	}
	return nil
}

// urlErrReason is the cause of a client error without its URL (which may name
// a token endpoint's query).
func urlErrReason(err error) string {
	if ue, ok := err.(*url.Error); ok && ue.Err != nil {
		return ue.Err.Error()
	}
	return err.Error()
}

// list reads every page of a resource type: startIndex and count (RFC 7644
// §3.4.2.4), an optional filter. fn gets each resource.
func (c *scimClient) list(ctx context.Context, resource, filter string, page int, fn func(json.RawMessage) error) error {
	start, seen := 1, 0
	for pages := 0; ; pages++ {
		if pages >= scimMaxPages {
			return conflict("source_too_large", "the SCIM provider returned more than %d pages", scimMaxPages)
		}
		q := url.Values{"startIndex": {strconv.Itoa(start)}, "count": {strconv.Itoa(page)}}
		if filter != "" {
			q.Set("filter", filter)
		}
		var l scimList
		if err := c.get(ctx, c.base+"/"+resource+"?"+q.Encode(), &l); err != nil {
			return err
		}
		for _, r := range l.Resources {
			if seen++; seen > MaxSCIMResources {
				return conflict("source_too_large", "the SCIM provider returned more than %d %s", MaxSCIMResources, resource)
			}
			if err := fn(r); err != nil {
				return err
			}
		}
		if len(l.Resources) == 0 || start+len(l.Resources) > l.TotalResults {
			return nil
		}
		start += len(l.Resources)
	}
}

// token returns the bearer to send: the secret itself, or an access token from
// the client-credentials grant.
func (s scimSource) token(ctx context.Context, job LoaderJob, cfg *SCIMConfig) (string, error) {
	if len(job.Secret) == 0 {
		return "", conflict("source_auth_missing", "the loader has no credential")
	}
	if cfg.Auth != "client_credentials" {
		return string(job.Secret), nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {cfg.ClientID}, "client_secret": {string(job.Secret)}}
	if cfg.Scope != "" {
		form.Set("scope", cfg.Scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", conflict("source_auth_failed", "token_url is not valid")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := job.Env.HTTP.Do(req)
	if err != nil {
		return "", conflict("source_auth_failed", "the token endpoint could not be reached: %v", urlErrReason(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", conflict("source_auth_failed", "the token endpoint refused the client credentials (HTTP %d)", resp.StatusCode)
	}
	var t struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, scimTokenBody))
	if err != nil || json.Unmarshal(b, &t) != nil || t.AccessToken == "" || (t.TokenType != "" && !strings.EqualFold(t.TokenType, "bearer")) {
		return "", conflict("source_auth_failed", "the token endpoint's answer holds no bearer access token")
	}
	return t.AccessToken, nil
}

func (cfg *SCIMConfig) subjectSource() string {
	switch {
	case cfg.SubjectSource != "":
		return cfg.SubjectSource
	case cfg.SubjectAttr == "email":
		return "email"
	case cfg.SubjectAttr == "id":
		return "scim_id"
	}
	return "identity"
}

// subject is the user's identifier by the configured attribute ("" if the user
// has none).
func (cfg *SCIMConfig) subject(u *scimUser) string {
	switch cfg.SubjectAttr {
	case "userName":
		return strings.TrimSpace(u.UserName)
	case "email":
		return u.email()
	case "externalId":
		return strings.TrimSpace(u.ExternalID)
	}
	return strings.TrimSpace(u.ID)
}

func (s scimSource) Full(ctx context.Context, job LoaderJob) ([]LoadedGroup, error) {
	var cfg SCIMConfig
	if err := decodeConfig(job, &cfg); err != nil {
		return nil, err
	}
	if job.Env.HTTP == nil {
		return nil, conflict("source_unavailable", "no outbound HTTP client is configured")
	}
	bearer, err := s.token(ctx, job, &cfg)
	if err != nil {
		return nil, err
	}
	page := cfg.PageSize
	if page == 0 {
		page = scimDefaultPage
	}
	c := &scimClient{http: job.Env.HTTP, base: strings.TrimRight(cfg.BaseURL, "/"), bearer: bearer}

	var groups []scimGroup
	if err := c.list(ctx, "Groups", cfg.GroupFilter, page, func(r json.RawMessage) error {
		var g scimGroup
		if err := json.Unmarshal(r, &g); err != nil || g.ID == "" {
			return scimFail("a SCIM group has no id")
		}
		groups = append(groups, g)
		return nil
	}); err != nil {
		return nil, err
	}
	// a provider may list groups without their members: read those one by one
	fetched := 0
	for i := range groups {
		if groups[i].Members != nil {
			continue
		}
		if fetched++; fetched > scimMaxGroupFetches {
			return nil, conflict("source_too_large", "the SCIM provider lists %d groups without members", len(groups))
		}
		var g scimGroup
		if err := c.get(ctx, c.base+"/Groups/"+url.PathEscape(groups[i].ID), &g); err != nil {
			return nil, err
		}
		if g.Members == nil {
			g.Members = &[]scimMember{}
		}
		groups[i].Members = g.Members
	}

	// the users, unless the member's SCIM id is the identifier
	users := map[string]*scimUser{}
	if cfg.SubjectAttr != "id" || cfg.OnlyActive == nil || *cfg.OnlyActive {
		if err := c.list(ctx, "Users", cfg.UserFilter, page, func(r json.RawMessage) error {
			var u scimUser
			if err := json.Unmarshal(r, &u); err != nil || u.ID == "" {
				return scimFail("a SCIM user has no id")
			}
			users[u.ID] = &u
			return nil
		}); err != nil {
			return nil, err
		}
	}
	onlyActive := cfg.OnlyActive == nil || *cfg.OnlyActive
	source := cfg.subjectSource()

	var out []LoadedGroup
	used := map[string]bool{}
	for _, g := range groups {
		name := g.DisplayName
		if cfg.GroupName == "externalId" {
			name = g.ExternalID
		}
		if strings.TrimSpace(name) == "" {
			name = g.ID
		}
		ext := cfg.NamePrefix + sanitizeExt(name)
		if used[strings.ToLower(ext)] {
			ext += "_" + sanitizeExt(g.ID)
		}
		used[strings.ToLower(ext)] = true
		lg := LoadedGroup{Name: ext, DisplayName: g.DisplayName}
		seen := map[string]bool{}
		for _, m := range *g.Members {
			if m.Type != "" && !strings.EqualFold(m.Type, "User") {
				continue // nested groups are not followed
			}
			if m.Value == "" || seen[m.Value] {
				continue
			}
			seen[m.Value] = true
			u := users[m.Value]
			switch {
			case u == nil && cfg.SubjectAttr == "id" && !onlyActive:
				lg.Members = append(lg.Members, SubjectRef{Source: source, Identifier: m.Value})
			case u == nil && cfg.UserFilter != "":
				continue // the user filter says who may be a member
			case u == nil && cfg.SubjectAttr == "id":
				continue // not an active user the provider lists
			case u == nil:
				// a member the provider does not list as a user: visible as unresolved
				lg.Members = append(lg.Members, SubjectRef{Source: "scim_id", Identifier: m.Value})
			case onlyActive && u.Active != nil && !*u.Active:
				continue
			default:
				id := cfg.subject(u)
				if id == "" {
					lg.Members = append(lg.Members, SubjectRef{Source: "scim_id", Identifier: u.ID})
				} else {
					lg.Members = append(lg.Members, SubjectRef{Source: source, Identifier: id})
				}
			}
		}
		job.Stats.Rows += len(lg.Members)
		out = append(out, lg)
	}
	return out, nil
}
