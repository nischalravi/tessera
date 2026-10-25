// Package copilotfake is an in-process Dataverse Web API with Copilot Studio tables (issue #562) and the Entra
// token endpoint, for tests: the client-credentials grant, bearer-checked OData reads of bots, botcomponents
// and systemusers with @odata.nextLink paging, and the faults a service shows.
package copilotfake

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Token is the access token the fake issues.
const Token = "eyJ0eXAi.dataverse-access-token" // #nosec G101 -- a fixed test token of an in-process fake, not a credential

// Bot is one agent.
type Bot struct {
	ID, Name, Schema string
	State, AuthMode  int
	Created          string
	Owner, Creator   string // systemuser or team ids
}

// Component is one bot component.
type Component struct{ ID, Name, Schema, Bot string }

// Fake is one environment plus its tenant's token endpoint.
type Fake struct {
	// PageSize is the rows per page (0: all in one).
	PageSize int
	// Deny makes the API answer 403; NotJSON a body that is no JSON; LeakLink makes nextLink point at another host.
	Deny, NotJSON, LeakLink bool
	// Description is served on every bot, and Data on every component, so a test can prove they are not selected.
	Description string
	// Base is the server URL the next links point at (set it to the test server's URL).
	Base string

	tenant, client, secret string
	mu                     sync.Mutex
	bots                   []Bot
	comps                  []Component
	users                  map[string]string // systemuser id -> e-mail address
	writes                 int
	selects                []string
	cursors                map[string]cursor
	scopes                 []string
}

// New returns a fake.
func New(tenant, client, secret string, users map[string]string, bots []Bot, comps []Component) *Fake {
	return &Fake{tenant: tenant, client: client, secret: secret, bots: bots, comps: comps, users: users}
}

// Writes counts requests other than GET and the token POST.
func (f *Fake) Writes() int { f.mu.Lock(); defer f.mu.Unlock(); return f.writes }

// Selects are the $select options of every API request.
func (f *Fake) Selects() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.selects...)
}

// Scopes are the scopes asked of the token endpoint.
func (f *Fake) Scopes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.scopes...)
}

const api = "/api/data/v9.2/"

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/"+f.tenant+"/oauth2/v2.0/token" && r.Method == http.MethodPost {
		_ = r.ParseForm()
		f.mu.Lock()
		f.scopes = append(f.scopes, r.PostForm.Get("scope"))
		f.mu.Unlock()
		if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != f.client || r.PostForm.Get("client_secret") != f.secret {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": Token, "token_type": "Bearer", "expires_in": 3600})
		return
	}
	if r.Method != http.MethodGet {
		f.mu.Lock()
		f.writes++
		f.mu.Unlock()
		http.Error(w, `{"error":{"code":"0x80060888"}}`, http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+Token {
		http.Error(w, `{"error":{"code":"0x80072ee7"}}`, http.StatusUnauthorized)
		return
	}
	if f.Deny {
		http.Error(w, `{"error":{"code":"0x80040220"}}`, http.StatusForbidden)
		return
	}
	f.mu.Lock()
	f.selects = append(f.selects, r.URL.Query().Get("$select"))
	f.mu.Unlock()
	if f.NotJSON {
		_, _ = w.Write([]byte("<html>not json</html>"))
		return
	}
	switch {
	case r.URL.Path == api+"bots":
		var rows []map[string]any
		for _, b := range f.bots {
			rows = append(rows, map[string]any{"botid": b.ID, "name": b.Name, "schemaname": b.Schema, "statecode": b.State, "authenticationmode": b.AuthMode,
				"createdon": b.Created, "_ownerid_value": b.Owner, "_createdby_value": b.Creator, "description": f.Description})
		}
		f.page(w, r, "bots", rows)
	case r.URL.Path == api+"botcomponents":
		var rows []map[string]any
		for _, c := range f.comps {
			rows = append(rows, map[string]any{"botcomponentid": c.ID, "name": c.Name, "schemaname": c.Schema, "_parentbotid_value": c.Bot, "data": f.Description})
		}
		f.page(w, r, "botcomponents", rows)
	case strings.HasPrefix(r.URL.Path, api+"systemusers(") && strings.HasSuffix(r.URL.Path, ")"):
		asked := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, api+"systemusers("), ")")
		for id, e := range f.users { // the stored id is answered, never the text of the path
			if id == asked {
				_ = json.NewEncoder(w).Encode(map[string]any{"systemuserid": id, "internalemailaddress": e})
				return
			}
		}
		http.Error(w, `{"error":{"code":"0x80040217"}}`, http.StatusNotFound)
	default:
		http.NotFound(w, r)
	}
}

// page answers one page of rows of the entity set. The next link is built from the stored base URL, the
// constant set name and a server-side cursor: nothing the request carried is echoed.
func (f *Fake) page(w http.ResponseWriter, r *http.Request, set string, rows []map[string]any) {
	start := 0
	if c, ok := f.cursor(r.URL.Query().Get("cursor")); ok && c.set == set {
		start = c.skip
	}
	size := f.PageSize
	if size <= 0 {
		size = len(rows)
	}
	end := min(start+size, len(rows))
	if start > end {
		start = end
	}
	body := map[string]any{"value": append([]map[string]any{}, rows[start:end]...)}
	if end < len(rows) {
		base := f.Base
		if f.LeakLink {
			base = "https://evil.example"
		}
		body["@odata.nextLink"] = base + api + set + "?cursor=" + f.newCursor(set, end)
	}
	_ = json.NewEncoder(w).Encode(body)
}

type cursor struct {
	set  string
	skip int
}

func (f *Fake) cursor(id string) (cursor, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.cursors[id]
	return c, ok
}

func (f *Fake) newCursor(set string, skip int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cursors == nil {
		f.cursors = map[string]cursor{}
	}
	id := "cur" + strconv.Itoa(len(f.cursors))
	f.cursors[id] = cursor{set, skip}
	return id
}
