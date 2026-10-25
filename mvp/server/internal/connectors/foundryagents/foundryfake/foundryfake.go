// Package foundryfake is an in-process Azure AI Foundry Agent Service (issue #562) and the Entra token
// endpoint, for tests: the client-credentials grant (client id, secret and scope are checked), and a
// bearer-checked, cursor-paged assistants list. Every answer is a fixed body or a stored value.
package foundryfake

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Token is the access token the fake issues.
const Token = "eyJ0eXAi.foundry-access-token" // #nosec G101 -- a fixed test token of an in-process fake, not a credential

// Agent is one agent.
type Agent struct {
	ID, Name  string
	CreatedAt int64
	Metadata  map[string]string
	// Tools are raw tool objects; Resources the tool_resources object.
	Tools     []map[string]any
	Resources map[string]any
	// Instructions is served so a test can prove the connector does not keep it.
	Instructions string
}

// Fake is one project plus its tenant's token endpoint.
type Fake struct {
	// PageSize is the agents per page (0: all in one).
	PageSize int
	// Deny makes the API answer 403; NotJSON a body that is no JSON; Endless makes every page claim more.
	Deny, NotJSON, Endless bool

	tenant, client, secret, project string
	mu                              sync.Mutex
	agents                          []Agent
	writes                          int
	scopes                          []string
}

// New returns a fake of the project "support".
func New(tenant, client, secret string, agents ...Agent) *Fake {
	return &Fake{tenant: tenant, client: client, secret: secret, project: "support", agents: agents}
}

// Writes counts requests other than GET and the token POST.
func (f *Fake) Writes() int { f.mu.Lock(); defer f.mu.Unlock(); return f.writes }

// Scopes are the scopes asked of the token endpoint.
func (f *Fake) Scopes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.scopes...)
}

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
		http.Error(w, `{"error":{"code":"method_not_allowed"}}`, http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+Token {
		http.Error(w, `{"error":{"code":"unauthorized"}}`, http.StatusUnauthorized)
		return
	}
	if f.Deny {
		http.Error(w, `{"error":{"code":"PermissionDenied"}}`, http.StatusForbidden)
		return
	}
	if r.URL.Path != "/api/projects/"+f.project+"/assistants" || r.URL.Query().Get("api-version") == "" {
		http.NotFound(w, r)
		return
	}
	if f.NotJSON {
		_, _ = w.Write([]byte("<html>not json</html>"))
		return
	}
	start := 0
	if after := r.URL.Query().Get("after"); after != "" {
		for i, a := range f.agents {
			if a.ID == after {
				start = i + 1
			}
		}
	}
	size := f.PageSize
	if size <= 0 {
		size = len(f.agents)
	}
	end := min(start+size, len(f.agents))
	data := []map[string]any{}
	last := ""
	for _, a := range f.agents[start:end] {
		data = append(data, map[string]any{"id": a.ID, "object": "assistant", "name": a.Name, "created_at": a.CreatedAt, "metadata": a.Metadata,
			"tools": a.Tools, "tool_resources": a.Resources, "instructions": a.Instructions, "model": "gpt-4o"})
		last = a.ID
	}
	more := end < len(f.agents) || f.Endless
	if f.Endless && last == "" {
		last = "asst_endless" + strconv.Itoa(start)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data, "has_more": more, "last_id": strings.TrimSpace(last)})
}
