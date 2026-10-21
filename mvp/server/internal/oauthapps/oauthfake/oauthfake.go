// Package oauthfake holds stateful fakes of the four providers' app and grant
// APIs (Google Admin SDK, Microsoft Graph, Salesforce REST, GitHub REST), for
// the tests of internal/oauthapps and of the API, and for local runs without a
// real tenant. Each Fake is an http.Handler that keeps its apps and grants in
// memory, answers the calls the readers make, and deletes on revoke, so a read
// after a revoke shows what the provider would.
//
// A fake checks the bearer token, pages its lists (so the readers' paging is
// exercised) and can be told to misbehave: Refuse makes every delete answer
// 403, Sticky makes a delete answer 204 without removing anything (so the
// verifying re-read finds the grant still there), FailReads makes every read
// answer 500.
package oauthfake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Token is the bearer token every fake accepts.
const Token = "tok-oauthfake" // #nosec G101 -- fixed token of an in-process test fake, not a credential

// Fake is the shared part of a provider fake.
type Fake struct {
	mu     sync.Mutex
	calls  []string
	Refuse atomic.Bool // every delete answers 403
	Sticky atomic.Bool // a delete answers 204 and removes nothing
	// FailReads makes every GET answer 500 (a provider that fails mid-sync).
	FailReads atomic.Bool
	// PageSize is the size of a page of a paged list (0: 2, small on purpose).
	PageSize int
}

// Calls returns the "METHOD path" of every request so far.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// Deleted counts the delete calls so far.
func (f *Fake) Deleted() int {
	n := 0
	for _, c := range f.Calls() {
		if strings.HasPrefix(c, "DELETE ") {
			n++
		}
	}
	return n
}

func (f *Fake) size() int {
	if f.PageSize > 0 {
		return f.PageSize
	}
	return 2
}

// begin records the call and takes the fake's lock, which the handler holds
// until end (so a test's With sees a consistent state, and the race detector
// sees the ordering). It reports false, with the lock released and the answer
// written, when the request is refused.
func (f *Fake) begin(w http.ResponseWriter, r *http.Request) bool {
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	switch {
	case r.Header.Get("Authorization") != "Bearer "+Token:
		http.Error(w, "bad token", http.StatusUnauthorized)
	case f.FailReads.Load() && r.Method == http.MethodGet:
		http.Error(w, "boom", http.StatusInternalServerError)
	default:
		return true
	}
	f.mu.Unlock()
	return false
}

func (f *Fake) end() { f.mu.Unlock() }

// With runs fn holding the fake's lock: tests change the fake's data in it.
func (f *Fake) With(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

// del answers a delete: false means the caller must not remove anything.
func (f *Fake) del(w http.ResponseWriter) bool {
	switch {
	case f.Refuse.Load():
		http.Error(w, "refused", http.StatusForbidden)
		return false
	case f.Sticky.Load():
		w.WriteHeader(http.StatusNoContent)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func notFound(w http.ResponseWriter) { http.Error(w, "not found", http.StatusNotFound) }

// window returns the part of n items a page holds: from the offset named by
// token (an integer) up to the page size, and the next token ("" at the end).
func window(token string, n, size int) (from, to int, next string) {
	from, _ = strconv.Atoi(token)
	from = max(0, min(from, n))
	to = min(from+size, n)
	if to < n {
		next = strconv.Itoa(to)
	}
	return from, to, next
}

// ---------------------------------------------------------------- Google

// GoogleToken is one OAuth token of a Google user.
type GoogleToken struct {
	ClientID, DisplayText string
	Anonymous             bool
	Scopes                []string
}

// GoogleUser is a Google Workspace user and the tokens the user issued.
type GoogleUser struct {
	ID, Email string
	Admin     bool
	Tokens    []GoogleToken
}

// Google fakes the Admin SDK Directory API.
type Google struct {
	Fake
	Users []*GoogleUser
}

func (g *Google) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !g.begin(w, r) {
		return
	}
	defer g.end()
	p := strings.TrimPrefix(r.URL.Path, "/admin/directory/v1/users")
	if p == "" && r.Method == http.MethodGet {
		from, to, next := window(r.URL.Query().Get("pageToken"), len(g.Users), g.size())
		users := []map[string]any{}
		for _, u := range g.Users[from:to] {
			users = append(users, map[string]any{"id": u.ID, "primaryEmail": u.Email, "isAdmin": u.Admin})
		}
		out := map[string]any{"users": users}
		if next != "" {
			out["nextPageToken"] = next
		}
		writeJSON(w, out)
		return
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	var u *GoogleUser
	for _, c := range g.Users {
		if len(parts) > 0 && (c.ID == parts[0] || c.Email == parts[0]) {
			u = c
		}
	}
	if u == nil || len(parts) < 2 || parts[1] != "tokens" {
		notFound(w)
		return
	}
	switch {
	case len(parts) == 2 && r.Method == http.MethodGet:
		items := []map[string]any{}
		for _, t := range u.Tokens {
			items = append(items, map[string]any{"clientId": t.ClientID, "displayText": t.DisplayText, "anonymous": t.Anonymous, "scopes": t.Scopes})
		}
		writeJSON(w, map[string]any{"items": items})
	case len(parts) == 3 && r.Method == http.MethodDelete:
		idx := -1
		for i, t := range u.Tokens {
			if t.ClientID == parts[2] {
				idx = i
			}
		}
		if idx < 0 {
			notFound(w)
			return
		}
		if g.del(w) {
			u.Tokens = append(u.Tokens[:idx:idx], u.Tokens[idx+1:]...)
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		notFound(w)
	}
}

// ---------------------------------------------------------------- Entra

// EntraSP is a service principal.
type EntraSP struct {
	ID, AppID, Name, Publisher string
	VerifiedPublisher          string
	Roles                      map[string]string // app role id -> value (a resource's roles)
}

// EntraDelegated is an oauth2PermissionGrant.
type EntraDelegated struct {
	ID, ClientSP, ConsentType, Principal, Scope string
}

// EntraRole is an app role assignment of a client service principal.
type EntraRole struct {
	ID, ClientSP, Resource, RoleID, Created string
}

// Entra fakes the parts of Microsoft Graph the reader calls.
type Entra struct {
	Fake
	BaseURL   string // the server's URL, for @odata.nextLink
	SPs       []*EntraSP
	Delegated []*EntraDelegated
	Roles     []*EntraRole
	UserNames map[string]string // user id -> user principal name
}

func (e *Entra) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !e.begin(w, r) {
		return
	}
	defer e.end()
	path := strings.TrimPrefix(r.URL.Path, "/v1.0/")
	parts := strings.Split(path, "/")
	switch {
	case path == "servicePrincipals" && r.Method == http.MethodGet:
		from, to, next := window(r.URL.Query().Get("skip"), len(e.SPs), e.size())
		vals := []map[string]any{}
		for _, sp := range e.SPs[from:to] {
			v := map[string]any{"id": sp.ID, "appId": sp.AppID, "displayName": sp.Name, "publisherName": sp.Publisher}
			if sp.VerifiedPublisher != "" {
				v["verifiedPublisher"] = map[string]any{"verifiedPublisherId": sp.VerifiedPublisher}
			}
			vals = append(vals, v)
		}
		e.page(w, "servicePrincipals", vals, next)
	case len(parts) == 2 && parts[0] == "servicePrincipals" && r.Method == http.MethodGet:
		for _, sp := range e.SPs {
			if sp.ID == parts[1] {
				roles := []map[string]any{}
				for id, v := range sp.Roles {
					roles = append(roles, map[string]any{"id": id, "value": v})
				}
				writeJSON(w, map[string]any{"id": sp.ID, "appRoles": roles})
				return
			}
		}
		notFound(w)
	case len(parts) == 3 && parts[0] == "servicePrincipals" && parts[2] == "appRoleAssignments" && r.Method == http.MethodGet:
		var rows []*EntraRole
		client := "" // the stored principal id; the next link never repeats the request path
		for _, ra := range e.Roles {
			if ra.ClientSP == parts[1] {
				rows = append(rows, ra)
				client = ra.ClientSP
			}
		}
		from, to, next := window(r.URL.Query().Get("skip"), len(rows), e.size())
		vals := []map[string]any{}
		for _, ra := range rows[from:to] {
			vals = append(vals, map[string]any{"id": ra.ID, "appRoleId": ra.RoleID, "resourceId": ra.Resource, "createdDateTime": ra.Created})
		}
		e.page(w, "servicePrincipals/"+client+"/appRoleAssignments", vals, next)
	case len(parts) == 4 && parts[0] == "servicePrincipals" && parts[2] == "appRoleAssignments" && r.Method == http.MethodDelete:
		for i, ra := range e.Roles {
			if ra.ID == parts[3] && ra.ClientSP == parts[1] {
				if e.del(w) {
					e.Roles = append(e.Roles[:i:i], e.Roles[i+1:]...)
					w.WriteHeader(http.StatusNoContent)
				}
				return
			}
		}
		notFound(w)
	case path == "oauth2PermissionGrants" && r.Method == http.MethodGet:
		from, to, next := window(r.URL.Query().Get("skip"), len(e.Delegated), e.size())
		vals := []map[string]any{}
		for _, d := range e.Delegated[from:to] {
			vals = append(vals, map[string]any{"id": d.ID, "clientId": d.ClientSP, "consentType": d.ConsentType, "principalId": d.Principal, "scope": d.Scope})
		}
		e.page(w, "oauth2PermissionGrants", vals, next)
	case len(parts) == 2 && parts[0] == "oauth2PermissionGrants" && (r.Method == http.MethodGet || r.Method == http.MethodDelete):
		for i, d := range e.Delegated {
			if d.ID != parts[1] {
				continue
			}
			switch {
			case r.Method == http.MethodGet:
				writeJSON(w, map[string]any{"id": d.ID})
			case e.del(w):
				e.Delegated = append(e.Delegated[:i:i], e.Delegated[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
			}
			return
		}
		notFound(w)
	case len(parts) == 2 && parts[0] == "users" && r.Method == http.MethodGet:
		for id, n := range e.UserNames {
			if id == parts[1] { // answer with the stored id, never the request path
				writeJSON(w, map[string]any{"id": id, "userPrincipalName": n})
				return
			}
		}
		notFound(w)
	default:
		notFound(w)
	}
}

func (e *Entra) page(w http.ResponseWriter, path string, vals []map[string]any, next string) {
	out := map[string]any{"value": vals}
	if next != "" {
		out["@odata.nextLink"] = e.BaseURL + "/v1.0/" + path + "?skip=" + next
	}
	writeJSON(w, out)
}

// ---------------------------------------------------------------- Salesforce

// SalesforceToken is one OauthToken row.
type SalesforceToken struct {
	ID, AppName, AppID, UserID, Username string
	ModifyAll                            bool
	Created, LastUsed, Scopes            string
}

// Salesforce fakes the REST query and sobject calls the reader makes.
type Salesforce struct {
	Fake
	Tokens []*SalesforceToken
}

func (s *Salesforce) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.begin(w, r) {
		return
	}
	defer s.end()
	const api = "/services/data/v59.0"
	switch {
	case r.URL.Path == api+"/query" && r.Method == http.MethodGet:
		if !strings.Contains(r.URL.Query().Get("q"), "FROM OauthToken") {
			http.Error(w, "unsupported query", http.StatusBadRequest)
			return
		}
		s.records(w, "0")
	case strings.HasPrefix(r.URL.Path, api+"/query/") && r.Method == http.MethodGet:
		s.records(w, strings.TrimPrefix(r.URL.Path, api+"/query/"))
	case strings.HasPrefix(r.URL.Path, api+"/sobjects/OauthToken/"):
		id := strings.TrimPrefix(r.URL.Path, api+"/sobjects/OauthToken/")
		for i, t := range s.Tokens {
			if t.ID != id {
				continue
			}
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, map[string]any{"Id": t.ID})
			case http.MethodDelete:
				if s.del(w) {
					s.Tokens = append(s.Tokens[:i:i], s.Tokens[i+1:]...)
					w.WriteHeader(http.StatusNoContent)
				}
			default:
				http.Error(w, "method", http.StatusMethodNotAllowed)
			}
			return
		}
		notFound(w)
	default:
		notFound(w)
	}
}

func (s *Salesforce) records(w http.ResponseWriter, cursor string) {
	from, to, next := window(cursor, len(s.Tokens), s.size())
	recs := []map[string]any{}
	for _, t := range s.Tokens[from:to] {
		rec := map[string]any{"Id": t.ID, "AppName": t.AppName, "AppMenuItemId": t.AppID, "UserId": t.UserID,
			"CreatedDate": t.Created, "RequestedScopes": t.Scopes,
			"User": map[string]any{"Username": t.Username, "Profile": map[string]any{"PermissionsModifyAllData": t.ModifyAll}}}
		if t.LastUsed != "" {
			rec["LastUsedDate"] = t.LastUsed
		}
		recs = append(recs, rec)
	}
	out := map[string]any{"totalSize": len(s.Tokens), "done": next == "", "records": recs}
	if next != "" {
		out["nextRecordsUrl"] = "/services/data/v59.0/query/" + next
	}
	writeJSON(w, out)
}

// ---------------------------------------------------------------- GitHub

// GitHubInstall is a GitHub App installation of the organization.
type GitHubInstall struct {
	ID          int64
	Slug        string
	Owner       string
	Permissions map[string]string
	Created     string
}

// GitHubCredential is a SAML SSO credential authorization.
type GitHubCredential struct {
	ID                   int64
	Login, Type          string
	Authorized, Accessed string
	Scopes               []string
}

// GitHub fakes the organization installation and credential authorization calls.
type GitHub struct {
	Fake
	Org         string
	Installs    []*GitHubInstall
	Credentials []*GitHubCredential
	NoSAML      bool // credential-authorizations answers 404, as an org without SAML SSO does
}

func (g *GitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !g.begin(w, r) {
		return
	}
	defer g.end()
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 {
		page = 1
	}
	if per < 1 || per > 100 {
		per = 100
	}
	base := "/orgs/" + g.Org
	switch {
	case r.URL.Path == base+"/installations" && r.Method == http.MethodGet:
		from, to := bounds(page, per, len(g.Installs))
		items := []map[string]any{}
		for _, in := range g.Installs[from:to] {
			items = append(items, map[string]any{"id": in.ID, "app_slug": in.Slug, "permissions": in.Permissions, "created_at": in.Created})
		}
		writeJSON(w, map[string]any{"total_count": len(g.Installs), "installations": items})
	case strings.HasPrefix(r.URL.Path, "/apps/") && r.Method == http.MethodGet:
		slug := strings.TrimPrefix(r.URL.Path, "/apps/")
		for _, in := range g.Installs {
			if in.Slug == slug {
				writeJSON(w, map[string]any{"slug": in.Slug, "owner": map[string]any{"login": in.Owner}})
				return
			}
		}
		notFound(w)
	case r.URL.Path == base+"/credential-authorizations" && r.Method == http.MethodGet:
		if g.NoSAML {
			notFound(w)
			return
		}
		from, to := bounds(page, per, len(g.Credentials))
		items := []map[string]any{}
		for _, c := range g.Credentials[from:to] {
			items = append(items, map[string]any{"login": c.Login, "credential_id": c.ID, "credential_type": c.Type,
				"credential_authorized_at": c.Authorized, "credential_accessed_at": c.Accessed, "scopes": c.Scopes})
		}
		writeJSON(w, items)
	case strings.HasPrefix(r.URL.Path, base+"/credential-authorizations/") && r.Method == http.MethodDelete:
		id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, base+"/credential-authorizations/"), 10, 64)
		for i, c := range g.Credentials {
			if c.ID == id {
				if g.del(w) {
					g.Credentials = append(g.Credentials[:i:i], g.Credentials[i+1:]...)
					w.WriteHeader(http.StatusNoContent)
				}
				return
			}
		}
		notFound(w)
	default:
		notFound(w)
	}
}

func bounds(page, per, n int) (from, to int) {
	from = min((page-1)*per, n)
	return from, min(from+per, n)
}

// SortedCalls is Calls, sorted, for assertions that do not depend on order.
func (f *Fake) SortedCalls() []string {
	c := f.Calls()
	sort.Strings(c)
	return c
}

// ID formats a numbered fake id of the given width (for Salesforce, 18 characters).
func ID(prefix string, n int) string {
	s := fmt.Sprintf("%s%d", prefix, n)
	for len(s) < 18 {
		s += "A"
	}
	return s
}
