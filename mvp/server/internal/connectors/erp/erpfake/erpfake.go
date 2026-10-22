// Package erpfake is an in-process SAP authorization service or Oracle Fusion
// security service (issue #304), with the faults an ERP shows: a refused token,
// throttling, server errors, malformed answers, writes that fail and writes
// accepted and dropped. The state is in neutral form; each vendor's handlers
// render and parse their own JSON, so the contract tests prove the readers.
package erpfake

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Auth is an authorization object.
type Auth struct {
	Object string
	Fields map[string][]string
}

// Role is a role.
type Role struct {
	ID, Name string
	Children []string
	TCodes   []string
	Auth     []Auth
}

// Assign is a role held by a user; From and To are YYYY-MM-DD or empty.
type Assign struct{ Role, From, To string }

// User is a user.
type User struct {
	ID, Name, Email string
	Locked          bool
	ValidTo         string
	Roles           []Assign
}

// Faults to inject.
type Faults struct {
	TokenStatus int
	ReadStatus  int
	Throttle    int
	WriteStatus int
	DropWrites  bool
	Malformed   bool
}

// Fake is one ERP.
type Fake struct {
	System, ClientID, Secret string

	mu       sync.Mutex
	roles    []Role
	users    []User
	faults   Faults
	throttle int
	Tokens   int
	Reads    int
	Writes   int
}

// New returns a fake of system ("sap" or "oracle") that accepts the credential.
func New(system, id, secret string) *Fake { return &Fake{System: system, ClientID: id, Secret: secret} }

// Set replaces the roles and users.
func (f *Fake) Set(roles []Role, users []User) {
	f.mu.Lock()
	f.roles, f.users = append([]Role(nil), roles...), append([]User(nil), users...)
	f.mu.Unlock()
}

// SetFaults replaces the faults.
func (f *Fake) SetFaults(x Faults) { f.mu.Lock(); f.faults, f.throttle = x, x.Throttle; f.mu.Unlock() }

// UserRoles returns the role ids a user holds.
func (f *Fake) UserRoles(id string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, u := range f.users {
		if u.ID == id {
			for _, a := range u.Roles {
				out = append(out, a.Role)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Counts returns token requests, reads and writes seen.
func (f *Fake) Counts() (tokens, reads, writes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Tokens, f.Reads, f.Writes
}

const token = "tok-erp-fake" // #nosec G101 -- a fixed test token of a fake

func (f *Fake) tokenPath() string {
	if f.System == "oracle" {
		return "/oauth2/v1/token"
	}
	return "/oauth/token"
}

func (f *Fake) root() string {
	if f.System == "oracle" {
		return "/fscmRestApi/security/v1"
	}
	return "/sap/opu/odata4/tessera/authz/v1"
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == f.tokenPath() && r.Method == http.MethodPost {
		f.Tokens++
		id, secret, ok := r.BasicAuth()
		switch {
		case f.faults.TokenStatus != 0:
			w.WriteHeader(f.faults.TokenStatus)
		case !ok || id != f.ClientID || secret != f.Secret || r.FormValue("grant_type") != "client_credentials":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid_client"}`)
		default:
			writeJSON(w, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
		}
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	write := r.Method != http.MethodGet
	if write {
		f.Writes++
	} else {
		f.Reads++
	}
	switch {
	case !write && f.throttle > 0:
		f.throttle--
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	case !write && f.faults.ReadStatus != 0:
		w.WriteHeader(f.faults.ReadStatus)
		fmt.Fprint(w, `{"error":"server_error","description":"leaky-body-should-never-surface"}`)
		return
	case !write && f.faults.Malformed:
		fmt.Fprint(w, `<html>maintenance</html>`)
		return
	case write && f.faults.WriteStatus != 0:
		w.WriteHeader(f.faults.WriteStatus)
		return
	case write && f.faults.DropWrites:
		w.WriteHeader(http.StatusNoContent)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, f.root())
	if p == r.URL.Path {
		http.NotFound(w, r)
		return
	}
	if f.System == "oracle" {
		f.oracle(w, r, p)
	} else {
		f.sap(w, r, p)
	}
}

func window(r *http.Request, offKey, limKey string, n int) (lo, hi int) {
	off, _ := strconv.Atoi(r.URL.Query().Get(offKey))
	lim, err := strconv.Atoi(r.URL.Query().Get(limKey))
	if err != nil || lim <= 0 || lim > 1000 {
		lim = 100
	}
	if off < 0 || off > n {
		off = n
	}
	return off, min(off+lim, n)
}

func (f *Fake) user(id string) *User {
	for i := range f.users {
		if f.users[i].ID == id {
			return &f.users[i]
		}
	}
	return nil
}

func (f *Fake) hasRole(id string) bool {
	for _, r := range f.roles {
		if r.ID == id {
			return true
		}
	}
	return false
}

func readJSON(r *http.Request, v any) bool {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	return err == nil && (len(b) == 0 || json.Unmarshal(b, v) == nil)
}

// ---------------------------------------------------------------- SAP

func (f *Fake) sapUser(u User) map[string]any {
	roles := []map[string]string{}
	for _, a := range u.Roles {
		roles = append(roles, map[string]string{"role": a.Role, "validFrom": a.From, "validTo": a.To})
	}
	return map[string]any{"user": u.ID, "name": u.Name, "email": u.Email, "locked": u.Locked, "validTo": u.ValidTo, "roles": roles}
}

func (f *Fake) sap(w http.ResponseWriter, r *http.Request, p string) {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	switch {
	case p == "/roles" && r.Method == http.MethodGet:
		lo, hi := window(r, "$skip", "$top", len(f.roles))
		out := []map[string]any{}
		for _, ro := range f.roles[lo:hi] {
			auth := []map[string]any{}
			for _, a := range ro.Auth {
				auth = append(auth, map[string]any{"object": a.Object, "fields": a.Fields})
			}
			out = append(out, map[string]any{"role": ro.ID, "description": ro.Name, "composite": len(ro.Children) > 0, "children": ro.Children,
				"tcodes": ro.TCodes, "authObjects": auth})
		}
		writeJSON(w, map[string]any{"value": out})
	case p == "/users" && r.Method == http.MethodGet:
		lo, hi := window(r, "$skip", "$top", len(f.users))
		out := []map[string]any{}
		for _, u := range f.users[lo:hi] {
			out = append(out, f.sapUser(u))
		}
		writeJSON(w, map[string]any{"value": out})
	case len(parts) == 2 && parts[0] == "users" && r.Method == http.MethodGet:
		u := f.user(parts[1])
		if u == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, f.sapUser(*u))
	case len(parts) == 4 && parts[0] == "users" && parts[2] == "roles":
		f.assign(w, r.Method, parts[1], parts[3])
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) assign(w http.ResponseWriter, method, user, role string) {
	u := f.user(user)
	if u == nil || (method != http.MethodDelete && !f.hasRole(role)) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	idx := -1
	for i, a := range u.Roles {
		if a.Role == role {
			idx = i
		}
	}
	switch method {
	case http.MethodPut, http.MethodPost:
		if idx < 0 {
			u.Roles = append(u.Roles, Assign{Role: role})
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		if idx >= 0 {
			u.Roles = append(u.Roles[:idx], u.Roles[idx+1:]...)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------- Oracle

func (f *Fake) oraUser(u User) map[string]any {
	roles := []map[string]string{}
	for _, a := range u.Roles {
		roles = append(roles, map[string]string{"roleCode": a.Role, "startDate": a.From, "endDate": a.To})
	}
	return map[string]any{"username": u.ID, "displayName": u.Name, "email": u.Email, "active": !u.Locked, "roleAssignments": roles}
}

func (f *Fake) oracle(w http.ResponseWriter, r *http.Request, p string) {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	switch {
	case p == "/roles" && r.Method == http.MethodGet:
		lo, hi := window(r, "offset", "limit", len(f.roles))
		out := []map[string]any{}
		for _, ro := range f.roles[lo:hi] {
			data := []map[string]any{}
			for _, a := range ro.Auth {
				cond := ""
				if c := a.Fields["CONDITION"]; len(c) > 0 {
					cond = c[0]
				}
				data = append(data, map[string]any{"object": a.Object, "condition": cond, "actions": a.Fields["ACTVT"]})
			}
			out = append(out, map[string]any{"roleCode": ro.ID, "roleName": ro.Name, "dutyRoles": ro.Children, "privileges": ro.TCodes, "dataSecurity": data})
		}
		writeJSON(w, map[string]any{"items": out, "hasMore": hi < len(f.roles)})
	case p == "/users" && r.Method == http.MethodGet:
		lo, hi := window(r, "offset", "limit", len(f.users))
		out := []map[string]any{}
		for _, u := range f.users[lo:hi] {
			out = append(out, f.oraUser(u))
		}
		writeJSON(w, map[string]any{"items": out, "hasMore": hi < len(f.users)})
	case len(parts) == 2 && parts[0] == "users" && r.Method == http.MethodGet:
		u := f.user(parts[1])
		if u == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, f.oraUser(*u))
	case len(parts) == 3 && parts[0] == "users" && parts[2] == "roleAssignments" && r.Method == http.MethodPost:
		var b struct {
			Role string `json:"roleCode"`
		}
		if !readJSON(r, &b) || b.Role == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.assign(w, http.MethodPost, parts[1], b.Role)
	case len(parts) == 4 && parts[0] == "users" && parts[2] == "roleAssignments":
		f.assign(w, r.Method, parts[1], parts[3])
	default:
		http.NotFound(w, r)
	}
}
