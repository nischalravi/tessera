// Package mcpfake is an in-process MCP server (issue #562) for tests: the Streamable HTTP transport with
// initialize, the initialized notification and a paged tools/list, a bearer token or an API key header, an
// anonymous mode, session ids that must be echoed, event-stream answers, and the faults a server shows
// (a refused credential, a JSON-RPC error, a body that is not JSON, a cursor that never ends).
//
// Every answer is a fixed body or a stored value: nothing a request carried is echoed.
package mcpfake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Tool is one tool the fake lists.
type Tool struct {
	Name                  string
	ReadOnly, Destructive *bool
	// Description is served so a test can prove the connector does not keep it.
	Description string
}

// Fake is one server.
type Fake struct {
	// Token is the credential. Header names the header it is in; empty: Authorization: Bearer.
	Token, Header string
	// Anonymous makes initialize and tools/list work without the credential.
	Anonymous bool
	// SSE answers requests as an event stream.
	SSE bool
	// PageSize is the tools per page (0: all in one).
	PageSize int
	// Endless makes every page carry a next cursor.
	Endless bool
	// NoSession makes the server stateless: no Mcp-Session-Id is issued or required.
	NoSession bool
	// RPCError makes tools/list answer a JSON-RPC error.
	RPCError bool
	// NotJSON makes every answer a body that is not JSON.
	NotJSON bool
	// Name and Version are serverInfo.
	Name, Version string

	mu    sync.Mutex
	tools []Tool
	calls []string // JSON-RPC methods seen, in order
	anon  int      // requests seen without a valid credential
}

// New returns a fake with a bearer token.
func New(token string, tools ...Tool) *Fake {
	return &Fake{Token: token, Name: "acme-tools", Version: "1.2.3", tools: tools}
}

// Methods returns the JSON-RPC methods seen so far.
func (f *Fake) Methods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// Unauthenticated is how many requests arrived without a valid credential.
func (f *Fake) Unauthenticated() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.anon
}

const session = "sess-0123456789"

func (f *Fake) authorized(r *http.Request) bool {
	if f.Header != "" {
		return r.Header.Get(f.Header) == f.Token
	}
	return r.Header.Get("Authorization") == "Bearer "+f.Token
}

// ServeHTTP implements http.Handler.
func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ok := f.authorized(r)
	f.mu.Lock()
	if !ok {
		f.anon++
	}
	f.mu.Unlock()
	if !ok && !f.Anonymous {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="/.well-known/oauth-protected-resource"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		ID     *json.Number    `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.calls = append(f.calls, req.Method)
	tools := append([]Tool(nil), f.tools...)
	f.mu.Unlock()
	if req.Method != "initialize" && !f.NoSession && r.Header.Get("Mcp-Session-Id") != session {
		http.Error(w, "no session", http.StatusBadRequest)
		return
	}
	if req.ID == nil { // a notification
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if f.NotJSON {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("<html>not json</html>"))
		return
	}
	var result any
	switch req.Method {
	case "initialize":
		if !f.NoSession {
			w.Header().Set("Mcp-Session-Id", session)
		}
		result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{"name": f.Name, "version": f.Version}}
	case "tools/list":
		if f.RPCError {
			f.reply(w, req.ID, nil, map[string]any{"code": -32603, "message": "internal error"})
			return
		}
		var p struct {
			Cursor string `json:"cursor"`
		}
		_ = json.Unmarshal(req.Params, &p)
		start := 0
		if p.Cursor != "" {
			n, err := strconv.Atoi(strings.TrimPrefix(p.Cursor, "c"))
			if err != nil || n < 0 || n > len(tools) {
				f.reply(w, req.ID, nil, map[string]any{"code": -32602, "message": "invalid cursor"})
				return
			}
			start = n
		}
		end := len(tools)
		if f.PageSize > 0 && start+f.PageSize < end {
			end = start + f.PageSize
		}
		list := []map[string]any{}
		for _, t := range tools[start:end] {
			e := map[string]any{"name": t.Name, "description": t.Description, "inputSchema": map[string]any{"type": "object"}}
			ann := map[string]any{}
			if t.ReadOnly != nil {
				ann["readOnlyHint"] = *t.ReadOnly
			}
			if t.Destructive != nil {
				ann["destructiveHint"] = *t.Destructive
			}
			if len(ann) > 0 {
				e["annotations"] = ann
			}
			list = append(list, e)
		}
		out := map[string]any{"tools": list}
		if end < len(tools) || f.Endless {
			out["nextCursor"] = fmt.Sprintf("c%d", end)
		}
		result = out
	default:
		f.reply(w, req.ID, nil, map[string]any{"code": -32601, "message": "method not found"})
		return
	}
	f.reply(w, req.ID, result, nil)
}

func (f *Fake) reply(w http.ResponseWriter, id *json.Number, result any, rpcErr any) {
	msg := map[string]any{"jsonrpc": "2.0", "id": id}
	if rpcErr != nil {
		msg["error"] = rpcErr
	} else {
		msg["result"] = result
	}
	b, _ := json.Marshal(msg)
	if f.SSE {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", b)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}
