// Package copilotfake is an in-process Dataverse Web API with Copilot Studio tables (issue #562) and the Entra
// token endpoint, for tests: the client-credentials grant, bearer-checked OData reads of bots, botcomponents
// and systemusers with @odata.nextLink paging, and the faults a service shows.
package copilotfake

import (
	"encoding/json"
	"net/http"
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

	tenant, client, secret string
	mu                     sync.Mutex
	bots                   []Bot
	comps                  []Component
	users                  map[string]string // systemuser id -> e-mail address
	writes                 int
	selects                []string
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
		f.page(w, r, rows)
	case r.URL.Path == api+"botcomponents":
		var rows []map[string]any
		for _, c := range f.comps {
			rows = append(rows, map[string]any{"botcomponentid": c.ID, "name": c.Name, "schemaname": c.Schema, "_parentbotid_value": c.Bot, "data": f.Description})
		}
		f.page(w, r, rows)
	case strings.HasPrefix(r.URL.Path, api+"systemusers(") && strings.HasSuffix(r.URL.Path, ")"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, api+"systemusers("), ")")
		if e, ok := f.users[id]; ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"systemuserid": id, "internalemailaddress": e})
			return
		}
		http.Error(w, `{"error":{"code":"0x80040217"}}`, http.StatusNotFound)
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) page(w http.ResponseWriter, r *http.Request, rows []map[string]any) {
	start := 0
	if s := r.URL.Query().Get("skip"); s != "" {
		for _, c := range s {
			start = start*10 + int(c-'0')
		}
	}
	size := f.PageSize
	if size <= 0 {
		size = len(rows)
	}
	end := min(start+size, len(rows))
	body := map[string]any{"value": rows[start:end]}
	if rows == nil {
		body["value"] = []any{}
	}
	if end < len(rows) {
		host := "https://" + r.Host
		if f.LeakLink {
			host = "https://evil.example"
		}
		q := r.URL.Query()
		q.Set("skip", itoa(end))
		body["@odata.nextLink"] = host + r.URL.Path + "?" + q.Encode()
	}
	_ = json.NewEncoder(w).Encode(body)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
