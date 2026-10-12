// Package fake is an in-process SCIM 2.0 server with state, used by tests and
// by the dev-mode fake target (TESSERA_DEV_FAKE_TARGET). It is never reachable
// in production: config refuses the setting, and only cmd/tessera in dev
// starts it.
//
// It models the behaviours that matter to a provisioning client: filtered and
// paginated lists, paginated group members, PATCH with add / replace / remove
// (operation names in any case), Entra-style string booleans, and faults:
// "fail_writes" answers every write 503; "drop_writes" acknowledges writes
// without applying them (the case a re-read exists to catch).
package fake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Fault modes.
const (
	FailWrites = "fail_writes"
	DropWrites = "drop_writes"
)

// Options configure a Server.
type Options struct {
	// Token, when set, is the bearer token the server requires.
	Token string
	// StringBooleans answers booleans as "True" / "False" (Entra style).
	StringBooleans bool
	// MemberPage, when > 0, caps the members returned by GET /Groups/{id}
	// per response: a large group needs several requests.
	MemberPage int
	// Lenient treats a user or group that is looked up but unknown as
	// pre-existing in the target (the dev demo; the target "was already
	// provisioned"), except for users the server deleted and for lookups made
	// by a create_account operation.
	Lenient bool
	// Fault is the fault mode for every request; a request's
	// X-Fake-Fault header overrides it.
	Fault string
}

type userRec struct {
	ID, UserName, ExternalID, DisplayName, Email string
	Active                                       bool
}

type groupRec struct {
	ID, DisplayName, ExternalID string
	Members                     []string
	lenient                     bool // created by a lookup, not pre-provisioned
}

// Server is the fake target.
type Server struct {
	opt Options

	mu      sync.Mutex
	seq     int
	users   map[string]*userRec
	groups  map[string]*groupRec
	deleted map[string]bool
	// Requests is every request received, "METHOD path" (tests assert on it).
	requests []string
	keys     []string
}

// New returns an empty server.
func New(o Options) *Server {
	return &Server{opt: o, users: map[string]*userRec{}, groups: map[string]*groupRec{}, deleted: map[string]bool{}}
}

// AddUser pre-provisions a user and returns its id.
func (s *Server) AddUser(userName, displayName string, active bool) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addUser(userName, displayName, active).ID
}

// AddGroup pre-provisions a group with members (user ids) and returns its id.
func (s *Server) AddGroup(displayName, externalID string, members ...string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.addGroup(displayName, externalID)
	g.Members = append(g.Members, members...)
	return g.ID
}

func (s *Server) nextID(prefix string) string {
	s.seq++
	return prefix + strconv.Itoa(s.seq)
}

func (s *Server) addUser(userName, displayName string, active bool) *userRec {
	u := &userRec{ID: s.nextID("u"), UserName: userName, DisplayName: displayName, Active: active}
	s.users[u.ID] = u
	return u
}

func (s *Server) addGroup(displayName, externalID string) *groupRec {
	g := &groupRec{ID: s.nextID("g"), DisplayName: displayName, ExternalID: externalID}
	s.groups[g.ID] = g
	return g
}

// SetFault changes the fault mode ("" for none).
func (s *Server) SetFault(mode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opt.Fault = mode
}

// Requests returns the requests received so far, as "METHOD /path".
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// IdempotencyKeys returns the Idempotency-Key of each write received.
func (s *Server) IdempotencyKeys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.keys...)
}

// Active reports whether a user exists and is active.
func (s *Server) Active(userName string) (exists, active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.UserName == userName {
			return true, u.Active
		}
	}
	return false, false
}

// Members returns the display names of a group's members' userNames.
func (s *Server) Members(displayName string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, g := range s.groups {
		if g.DisplayName == displayName {
			for _, id := range g.Members {
				if u := s.users[id]; u != nil {
					out = append(out, u.UserName)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// Handler serves the SCIM API under /scim/v2.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serve)
}

const prefix = "/scim/v2"

var filterRE = regexp.MustCompile(`^(\w+) eq "((?:[^"\\]|\\.)*)"$`)

func (s *Server) boolJSON(b bool) any {
	if s.opt.StringBooleans {
		if b {
			return "True"
		}
		return "False"
	}
	return b
}

func (s *Server) userJSON(u *userRec) map[string]any {
	m := map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "id": u.ID,
		"userName": u.UserName, "active": s.boolJSON(u.Active)}
	if u.ExternalID != "" {
		m["externalId"] = u.ExternalID
	}
	if u.DisplayName != "" {
		m["displayName"] = u.DisplayName
	}
	if u.Email != "" {
		m["emails"] = []map[string]any{{"value": u.Email, "type": "work", "primary": s.boolJSON(true)}}
	}
	return m
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func scimErr(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status": strconv.Itoa(status), "detail": detail})
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.Method+" "+r.URL.Path)
	if s.opt.Token != "" && r.Header.Get("Authorization") != "Bearer "+s.opt.Token {
		scimErr(w, http.StatusUnauthorized, "invalid token")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, prefix)
	if path == r.URL.Path {
		scimErr(w, http.StatusNotFound, "not a SCIM path")
		return
	}
	write := r.Method != http.MethodGet
	fault := s.opt.Fault
	if h := r.Header.Get("X-Fake-Fault"); h != "" && h != "none" {
		fault = h
	}
	if write {
		s.keys = append(s.keys, r.Header.Get("Idempotency-Key"))
		switch fault {
		case FailWrites:
			scimErr(w, http.StatusServiceUnavailable, "the target is unavailable")
			return
		case DropWrites:
			s.dropped(w, r, path)
			return
		}
	}
	segs := strings.Split(strings.Trim(path, "/"), "/")
	create := r.Header.Get("X-Tessera-Operation") == "create_account"
	switch {
	case segs[0] == "Users" && len(segs) == 1 && r.Method == http.MethodGet:
		s.listUsers(w, r, create)
	case segs[0] == "Users" && len(segs) == 1 && r.Method == http.MethodPost:
		s.createUser(w, r)
	case segs[0] == "Users" && len(segs) == 2:
		s.userByID(w, r, segs[1])
	case segs[0] == "Groups" && len(segs) == 1 && r.Method == http.MethodGet:
		s.listGroups(w, r)
	case segs[0] == "Groups" && len(segs) == 2:
		s.groupByID(w, r, segs[1])
	default:
		scimErr(w, http.StatusNotFound, "no such resource")
	}
}

// dropped acknowledges a write without applying it.
func (s *Server) dropped(w http.ResponseWriter, r *http.Request, path string) {
	switch r.Method {
	case http.MethodPost:
		writeJSON(w, http.StatusCreated, map[string]any{"id": "dropped"})
	case http.MethodDelete:
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"id": strings.TrimPrefix(path, "/")})
	}
}

func page(r *http.Request, n int) (start, count int) {
	start, _ = strconv.Atoi(r.URL.Query().Get("startIndex"))
	if start < 1 {
		start = 1
	}
	count = 100
	if c, err := strconv.Atoi(r.URL.Query().Get("count")); err == nil && c >= 0 {
		count = c
	}
	return start, count
}

func list(w http.ResponseWriter, r *http.Request, all []map[string]any) {
	start, count := page(r, len(all))
	var res []map[string]any
	if start-1 < len(all) {
		end := min(start-1+count, len(all))
		res = all[start-1 : end]
	}
	if res == nil {
		res = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(all), "startIndex": start, "itemsPerPage": len(res), "Resources": res})
}

func unquote(s string) string { return strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(s) }

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, create bool) {
	removal := r.Header.Get("X-Tessera-Operation") == "remove_entitlement"
	var all []map[string]any
	ids := make([]string, 0, len(s.users))
	for id := range s.users {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return num(ids[i]) < num(ids[j]) })
	m := filterRE.FindStringSubmatch(r.URL.Query().Get("filter"))
	if m != nil && m[1] == "userName" {
		name := unquote(m[2])
		found := false
		for _, id := range ids {
			if s.users[id].UserName == name {
				found = true
			}
		}
		if !found && s.opt.Lenient && !create && !s.deleted[name] {
			u := s.addUser(name, "", true)
			ids = append(ids, u.ID)
			if removal { // a user "already provisioned" holds the groups that were looked up before
				for _, g := range s.groups {
					if g.lenient {
						g.Members = append(g.Members, u.ID)
					}
				}
			}
		}
	}
	for _, id := range ids {
		u := s.users[id]
		if m != nil && (m[1] != "userName" || u.UserName != unquote(m[2])) {
			continue
		}
		all = append(all, s.userJSON(u))
	}
	list(w, r, all)
}

func num(id string) int { n, _ := strconv.Atoi(id[1:]); return n }

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var b struct {
		UserName, ExternalID, DisplayName string
		Active                            any
		Emails                            []struct{ Value string }
	}
	if json.NewDecoder(r.Body).Decode(&b) != nil || b.UserName == "" {
		scimErr(w, http.StatusBadRequest, "userName is required")
		return
	}
	for _, u := range s.users {
		if u.UserName == b.UserName {
			scimErr(w, http.StatusConflict, "userName is not unique")
			return
		}
	}
	u := s.addUser(b.UserName, b.DisplayName, truthy(b.Active, true))
	u.ExternalID = b.ExternalID
	if len(b.Emails) > 0 {
		u.Email = b.Emails[0].Value
	}
	delete(s.deleted, b.UserName)
	writeJSON(w, http.StatusCreated, s.userJSON(u))
}

// truthy reads a boolean sent as a JSON boolean or as "True" / "False".
func truthy(v any, def bool) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	}
	return def
}

type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

func readPatch(r *http.Request) ([]patchOp, error) {
	var b struct {
		Operations []patchOp
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		return nil, err
	}
	return b.Operations, nil
}

func (s *Server) userByID(w http.ResponseWriter, r *http.Request, id string) {
	u := s.users[id]
	if u == nil {
		scimErr(w, http.StatusNotFound, "no such user")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.userJSON(u))
	case http.MethodDelete:
		delete(s.users, id)
		s.deleted[u.UserName] = true
		for _, g := range s.groups {
			g.Members = without(g.Members, id)
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPatch:
		ops, err := readPatch(r)
		if err != nil {
			scimErr(w, http.StatusBadRequest, "malformed PatchOp")
			return
		}
		for _, op := range ops {
			if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
				scimErr(w, http.StatusBadRequest, "unsupported op "+op.Op)
				return
			}
			var v any
			_ = json.Unmarshal(op.Value, &v)
			switch op.Path {
			case "active":
				u.Active = truthy(v, u.Active)
			case "displayName":
				u.DisplayName, _ = v.(string)
			case "":
				if obj, ok := v.(map[string]any); ok {
					if a, ok := obj["active"]; ok {
						u.Active = truthy(a, u.Active)
					}
				}
			default:
				scimErr(w, http.StatusBadRequest, "unsupported path "+op.Path)
				return
			}
		}
		writeJSON(w, http.StatusOK, s.userJSON(u))
	default:
		scimErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func without(ids []string, id string) []string {
	out := ids[:0:0]
	for _, x := range ids {
		if x != id {
			out = append(out, x)
		}
	}
	return out
}

func (s *Server) groupJSON(g *groupRec, members []string) map[string]any {
	ms := make([]map[string]any, 0, len(members))
	for _, id := range members {
		ms = append(ms, map[string]any{"value": id})
	}
	m := map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "id": g.ID,
		"displayName": g.DisplayName, "members": ms}
	if g.ExternalID != "" {
		m["externalId"] = g.ExternalID
	}
	return m
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	m := filterRE.FindStringSubmatch(r.URL.Query().Get("filter"))
	if m != nil && m[1] != "externalId" && m[1] != "displayName" {
		scimErr(w, http.StatusBadRequest, "unsupported filter")
		return
	}
	match := func(g *groupRec) bool {
		if m == nil {
			return true
		}
		if m[1] == "externalId" {
			return g.ExternalID == unquote(m[2])
		}
		return g.DisplayName == unquote(m[2])
	}
	if m != nil && s.opt.Lenient {
		found := false
		for _, g := range s.groups {
			found = found || match(g)
		}
		if !found {
			ext, name := "", unquote(m[2])
			if m[1] == "externalId" {
				ext = name
			}
			// An external id lookup creates the group only when the display
			// name lookup that follows it would not: the client tries the id
			// first and the name second, so create on the name.
			if m[1] == "displayName" {
				g := s.addGroup(name, ext)
				g.lenient = true
				if r.Header.Get("X-Tessera-Operation") == "remove_entitlement" {
					// the user being removed "already" held this group
					for id := range s.users {
						g.Members = append(g.Members, id)
					}
					sort.Slice(g.Members, func(i, j int) bool { return num(g.Members[i]) < num(g.Members[j]) })
				}
			}
		}
	}
	ids := make([]string, 0, len(s.groups))
	for id := range s.groups {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return num(ids[i]) < num(ids[j]) })
	var all []map[string]any
	for _, id := range ids {
		if g := s.groups[id]; match(g) {
			all = append(all, s.groupJSON(g, g.Members))
		}
	}
	list(w, r, all)
}

func (s *Server) groupByID(w http.ResponseWriter, r *http.Request, id string) {
	g := s.groups[id]
	if g == nil {
		scimErr(w, http.StatusNotFound, "no such group")
		return
	}
	switch r.Method {
	case http.MethodGet:
		members := g.Members
		if s.opt.MemberPage > 0 {
			start, count := page(r, len(members))
			count = min(count, s.opt.MemberPage)
			switch {
			case start-1 >= len(members):
				members = nil
			default:
				members = members[start-1 : min(start-1+count, len(members))]
			}
		}
		writeJSON(w, http.StatusOK, s.groupJSON(g, members))
	case http.MethodPatch:
		ops, err := readPatch(r)
		if err != nil {
			scimErr(w, http.StatusBadRequest, "malformed PatchOp")
			return
		}
		for _, op := range ops {
			if err := s.patchGroup(g, op); err != nil {
				scimErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		writeJSON(w, http.StatusOK, s.groupJSON(g, g.Members))
	default:
		scimErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

var removeRE = regexp.MustCompile(`^members\[value eq "([^"]+)"\]$`)

func (s *Server) patchGroup(g *groupRec, op patchOp) error {
	switch strings.ToLower(op.Op) {
	case "add":
		if op.Path != "members" {
			return fmt.Errorf("unsupported path %q", op.Path)
		}
		var ms []member
		if err := json.Unmarshal(op.Value, &ms); err != nil {
			return fmt.Errorf("members must be a list")
		}
		for _, m := range ms {
			if s.users[m.Value] == nil {
				return fmt.Errorf("no such user %q", m.Value)
			}
			if !contains(g.Members, m.Value) {
				g.Members = append(g.Members, m.Value)
			}
		}
	case "remove":
		m := removeRE.FindStringSubmatch(op.Path)
		if m == nil {
			return fmt.Errorf("unsupported path %q", op.Path)
		}
		g.Members = without(g.Members, m[1])
	default:
		return fmt.Errorf("unsupported op %q", op.Op)
	}
	return nil
}

type member struct {
	Value string `json:"value"`
}

func contains(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}
