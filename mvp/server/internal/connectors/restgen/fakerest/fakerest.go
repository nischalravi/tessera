// Package fakerest is an in-process fake REST system for tests of the generic
// REST connector (internal/connectors/restgen). It serves one user/group
// dataset through every pagination style, accepts each authentication mode,
// can throttle, fail, answer too much or lead a client astray, and records
// every request. It is a test helper: nothing in the server imports it.
package fakerest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Credentials the fake accepts.
const (
	Bearer       = "bearer-secret-token"
	APIKey       = "api-key-secret-value"
	Password     = "basic-secret-password"
	ClientID     = "client-1"
	ClientSecret = "client-secret-value"
	Username     = "svc-tessera"
	OAuthToken   = "oauth-access-token"
)

// User is a record of the fake.
type User struct {
	ID       string `json:"id"`
	Login    string `json:"login"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	State    string `json:"state"`
	Dept     string `json:"dept"`
	Created  string `json:"created"`
	LastSeen int64  `json:"last_seen"`
}

// Group is a group, role or entitlement of the fake.
type Group struct {
	ID      string
	Name    string
	Admin   bool
	Members []string // user ids
}

// Req is one request the fake saw. Path is as sent (still escaped).
type Req struct {
	Method, Path, RawQuery string
	Header                 http.Header
	Body                   string
}

// Fake is the server. Set the fields before the first request; the mutable
// state is guarded by mu.
type Fake struct {
	*httptest.Server

	// Auth is what the API demands: "bearer", "api_key_header", "api_key_query", "basic", "oauth2" or "" (open).
	Auth string
	// Total users seeded by New.
	mu         sync.Mutex
	Users      map[string]*User
	Groups     map[string]*Group
	Reqs       []Req
	TokenCalls int
	// Throttle answers the next n API requests 429 with RetryAfter (seconds, "" for none).
	Throttle   int
	RetryAfter string
	// Fail answers the next n API requests with this status.
	Fail       int
	FailStatus int
	// Huge makes /huge/users answer this many bytes.
	Huge int
	// StuckCursor makes /cursor/users repeat its first cursor forever.
	StuckCursor bool
	// EvilNext makes the next_url and link styles point at this absolute URL.
	EvilNext string
	// PageSize caps every page of the next_url/link/cursor styles.
	PageSize int
	// RejectTokenOnce answers the next API request that carries the OAuth token with 401, as if the
	// token had been revoked; the client must fetch a new one.
	RejectTokenOnce bool
	nextID          int
}

// New starts a fake with n users (u001...), two groups and one entitlement,
// and auth mode "bearer".
func New(n int) *Fake {
	f := &Fake{Auth: "bearer", Users: map[string]*User{}, Groups: map[string]*Group{}, PageSize: 10}
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("u%03d", i)
		state := "active"
		if i%7 == 0 {
			state = "suspended"
		}
		f.Users[id] = &User{ID: id, Login: fmt.Sprintf("user%03d", i), Email: fmt.Sprintf("user%03d@example.com", i),
			Name: fmt.Sprintf("User %03d", i), State: state, Dept: "eng", Created: "2024-03-01T10:00:00Z", LastSeen: 1700000000 + int64(i)}
	}
	f.nextID = n
	f.Groups["g1"] = &Group{ID: "g1", Name: "Engineers", Members: []string{"u001", "u002", "u003"}}
	f.Groups["g2"] = &Group{ID: "g2", Name: "Admins", Admin: true, Members: []string{"u001"}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

// Requests returns a copy of the recorded requests.
func (f *Fake) Requests() []Req {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Req(nil), f.Reqs...)
}

// APIRequests are the recorded requests that are not token requests.
func (f *Fake) APIRequests() []Req {
	var out []Req
	for _, r := range f.Requests() {
		if r.Path != "/oauth/token" {
			out = append(out, r)
		}
	}
	return out
}

func (f *Fake) authorized(r *http.Request) bool {
	switch f.Auth {
	case "":
		return true
	case "bearer":
		return r.Header.Get("Authorization") == "Bearer "+Bearer
	case "api_key_header":
		return r.Header.Get("X-Api-Key") == APIKey
	case "api_key_query":
		return r.URL.Query().Get("api_key") == APIKey
	case "basic":
		u, p, ok := r.BasicAuth()
		return ok && u == Username && p == Password
	case "oauth2":
		if r.Header.Get("Authorization") != "Bearer "+OAuthToken {
			return false
		}
		if f.RejectTokenOnce {
			f.RejectTokenOnce = false
			return false
		}
		return true
	}
	return false
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	body := ""
	if r.Body != nil {
		b := make([]byte, 8192)
		n, _ := r.Body.Read(b)
		body = string(b[:n])
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Reqs = append(f.Reqs, Req{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Clone(), body})

	if r.URL.Path == "/oauth/token" {
		f.token(w, r, body)
		return
	}
	if !f.authorized(r) {
		writeJSON(w, 401, map[string]any{"error": "unauthorized", "message": "bad credential"})
		return
	}
	if f.Throttle > 0 {
		f.Throttle--
		if f.RetryAfter != "" {
			w.Header().Set("Retry-After", f.RetryAfter)
		}
		writeJSON(w, 429, map[string]any{"error": "rate limited"})
		return
	}
	if f.Fail > 0 {
		f.Fail--
		writeJSON(w, f.FailStatus, map[string]any{"message": "boom"})
		return
	}
	w.Header().Set("X-RateLimit-Limit", "1000")
	w.Header().Set("X-RateLimit-Remaining", "990")

	path := r.URL.Path
	switch {
	case path == "/" && r.Method == "GET":
		writeJSON(w, 200, map[string]any{"service": "fake"})
	case path == "/huge/users":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"id":"` + strings.Repeat("x", f.Huge) + `"}]}`))
	case strings.HasPrefix(path, "/page/users"):
		f.pageStyle(w, r)
	case strings.HasPrefix(path, "/offset/users"):
		f.offsetStyle(w, r)
	case strings.HasPrefix(path, "/cursor/users"):
		f.cursorStyle(w, r)
	case strings.HasPrefix(path, "/link/users"):
		f.linkStyle(w, r)
	case strings.HasPrefix(path, "/nexturl/users"):
		f.nextURLStyle(w, r)
	case path == "/groups" && r.Method == "GET":
		f.groups(w, false)
	case path == "/roles" && r.Method == "GET":
		f.groups(w, true)
	case strings.HasPrefix(path, "/groups/") && strings.HasSuffix(path, "/members") && r.Method == "GET":
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/groups/"), "/members")
		g := f.Groups[id]
		if g == nil {
			writeJSON(w, 404, map[string]any{"message": "no such group"})
			return
		}
		var out []map[string]any
		for _, m := range g.Members {
			out = append(out, map[string]any{"user": map[string]any{"id": m}})
		}
		writeJSON(w, 200, map[string]any{"data": out})
	case path == "/users" && r.Method == "POST":
		f.create(w, body)
	case strings.HasPrefix(path, "/users/"):
		f.userOps(w, r, body)
	case strings.HasPrefix(path, "/groups/") && strings.Contains(path, "/members/"):
		f.memberOps(w, r)
	default:
		writeJSON(w, 404, map[string]any{"message": "not found"})
	}
}

func (f *Fake) token(w http.ResponseWriter, r *http.Request, body string) {
	f.TokenCalls++
	id, secret, ok := r.BasicAuth()
	if !ok {
		q := parseForm(body)
		id, secret = q["client_id"], q["client_secret"]
	}
	if id != ClientID || secret != ClientSecret || parseForm(body)["grant_type"] != "client_credentials" {
		writeJSON(w, 401, map[string]any{"error": "invalid_client"})
		return
	}
	writeJSON(w, 200, map[string]any{"access_token": OAuthToken, "token_type": "Bearer", "expires_in": 3600})
}

func parseForm(body string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(body, "&") {
		k, v, _ := strings.Cut(kv, "=")
		out[unesc(k)] = unesc(v)
	}
	return out
}

func unesc(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (f *Fake) sorted() []*User {
	out := make([]*User, 0, len(f.Users))
	for _, u := range f.Users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func slice(all []*User, from, n int) []*User {
	if from >= len(all) {
		return nil
	}
	to := from + n
	if to > len(all) {
		to = len(all)
	}
	return all[from:to]
}

func atoi(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// page style: ?page=N&per_page=M (from 1); {"data":{"users":[...]}}.
func (f *Fake) pageStyle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	size, page := atoi(q.Get("per_page"), 10), atoi(q.Get("page"), 1)
	writeJSON(w, 200, map[string]any{"data": map[string]any{"users": slice(f.sorted(), (page-1)*size, size)}})
}

// offset style: ?offset=N&limit=M; a bare array.
func (f *Fake) offsetStyle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	writeJSON(w, 200, slice(f.sorted(), atoi(q.Get("offset"), 0), atoi(q.Get("limit"), 10)))
}

// cursor style: ?cursor=<last id>; {"items":[...],"meta":{"next":"<last id>"}}.
func (f *Fake) cursorStyle(w http.ResponseWriter, r *http.Request) {
	cursor := r.URL.Query().Get("cursor")
	all := f.sorted()
	start := 0
	if cursor != "" && !f.StuckCursor {
		for i, u := range all {
			if u.ID == cursor {
				start = i + 1
			}
		}
	}
	items := slice(all, start, f.PageSize)
	meta := map[string]any{}
	if start+len(items) < len(all) || f.StuckCursor {
		next := items[len(items)-1].ID
		if f.StuckCursor {
			next = "stuck"
		}
		meta["next"] = next
	}
	writeJSON(w, 200, map[string]any{"items": items, "meta": meta})
}

// link style: Link: <...?after=N>; rel="next".
func (f *Fake) linkStyle(w http.ResponseWriter, r *http.Request) {
	after := atoi(r.URL.Query().Get("after"), 0)
	items := slice(f.sorted(), after, f.PageSize)
	if after+len(items) < len(f.Users) {
		next := fmt.Sprintf("http://%s/link/users?after=%d", r.Host, after+len(items))
		if f.EvilNext != "" {
			next = f.EvilNext
		}
		w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next", <http://%s/link/users?after=0>; rel="first"`, next, r.Host))
	}
	writeJSON(w, 200, items)
}

// next_url style: {"results":[...],"next":"/nexturl/users?from=N"} (a relative link).
func (f *Fake) nextURLStyle(w http.ResponseWriter, r *http.Request) {
	from := atoi(r.URL.Query().Get("from"), 0)
	items := slice(f.sorted(), from, f.PageSize)
	out := map[string]any{"results": items, "next": nil}
	if from+len(items) < len(f.Users) {
		out["next"] = fmt.Sprintf("/nexturl/users?from=%d", from+len(items))
		if f.EvilNext != "" {
			out["next"] = f.EvilNext
		}
	}
	writeJSON(w, 200, out)
}

func (f *Fake) groups(w http.ResponseWriter, admin bool) {
	var out []map[string]any
	ids := make([]string, 0, len(f.Groups))
	for id := range f.Groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		g := f.Groups[id]
		if admin && !g.Admin {
			continue
		}
		out = append(out, map[string]any{"id": g.ID, "name": g.Name, "admin": g.Admin, "member_ids": g.Members})
	}
	writeJSON(w, 200, map[string]any{"groups": out})
}

func (f *Fake) create(w http.ResponseWriter, body string) {
	var in struct {
		Login string `json:"login"`
		Email string `json:"email"`
		Name  string `json:"name"`
		Extra string `json:"extra"`
	}
	if json.Unmarshal([]byte(body), &in) != nil || in.Login == "" {
		writeJSON(w, 400, map[string]any{"message": "login is required"})
		return
	}
	f.nextID++
	id := fmt.Sprintf("u%03d", f.nextID)
	f.Users[id] = &User{ID: id, Login: in.Login, Email: in.Email, Name: in.Name, State: "active", Created: "2025-01-01T00:00:00Z"}
	writeJSON(w, 201, map[string]any{"user": f.Users[id]})
}

func (f *Fake) find(key string) *User {
	if u := f.Users[key]; u != nil {
		return u
	}
	for _, u := range f.Users {
		if u.Login == key {
			return u
		}
	}
	return nil
}

func (f *Fake) userOps(w http.ResponseWriter, r *http.Request, body string) {
	key := strings.TrimPrefix(r.URL.Path, "/users/")
	u := f.find(key)
	if u == nil {
		writeJSON(w, 404, map[string]any{"message": "no such user"})
		return
	}
	switch r.Method {
	case "GET":
		writeJSON(w, 200, map[string]any{"user": u})
	case "PATCH":
		var in map[string]any
		_ = json.Unmarshal([]byte(body), &in)
		if v, ok := in["email"].(string); ok {
			u.Email = v
		}
		if v, ok := in["state"].(string); ok {
			u.State = v
		}
		if v, ok := in["dept"].(string); ok {
			u.Dept = v
		}
		writeJSON(w, 200, map[string]any{"user": u})
	case "DELETE":
		delete(f.Users, u.ID)
		w.WriteHeader(204)
	default:
		w.WriteHeader(405)
	}
}

func (f *Fake) memberOps(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/groups/")
	gid, uid, _ := strings.Cut(rest, "/members/")
	g := f.Groups[gid]
	if g == nil || f.Users[uid] == nil {
		writeJSON(w, 404, map[string]any{"message": "no such group or user"})
		return
	}
	idx := -1
	for i, m := range g.Members {
		if m == uid {
			idx = i
		}
	}
	switch r.Method {
	case "GET":
		if idx < 0 {
			writeJSON(w, 404, map[string]any{"message": "not a member"})
			return
		}
		w.WriteHeader(204)
	case "PUT":
		if idx < 0 {
			g.Members = append(g.Members, uid)
		}
		w.WriteHeader(204)
	case "DELETE":
		if idx >= 0 {
			g.Members = append(g.Members[:idx], g.Members[idx+1:]...)
		}
		w.WriteHeader(204)
	default:
		w.WriteHeader(405)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
