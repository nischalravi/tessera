// Package atfake is an in-process Atlassian Cloud (issue #559) for tests: the Jira Cloud REST API of a site
// (HTTP basic: users, group bulk and member reads, group membership writes, project roles and their actors) and
// the organization admin API (bearer key: organization users with product access, paged by a cursor link), with
// the faults a real site shows: refused credentials, expired sessions, throttling, server errors, malformed
// answers, a page link to another host, and writes that fail or are accepted and dropped.
//
// Every answer is a fixed body or stored data: nothing a request carried is echoed.
package atfake

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// User is a Jira user.
type User struct {
	AccountID, Type, Email, Name string
	Active                       bool
}

// Group is a Jira group.
type Group struct{ ID, Name string }

// Role is a project role of one project: its actors.
type Role struct {
	Name   string
	Admin  bool
	Users  []string // account ids
	Groups []string // group ids
}

// Product is a product an organization user can use.
type Product struct{ Key, Name string }

// AdminUser is an organization-managed account.
type AdminUser struct {
	AccountID, Email, Status string
	Products                 []Product
}

// Faults to inject.
type Faults struct {
	Unauthorized int // answer this many API calls with 401
	Throttle     int // answer this many API calls with 429
	ReadStatus   int
	WriteStatus  int
	DropWrites   bool
	Malformed    bool
	BadNext      bool // the admin API's next link points at another host
	AdminStatus  int  // answer admin API calls with this status
}

// Fake is one site and its organization.
type Fake struct {
	Email, Token string
	OrgID        string
	AdminKey     string
	PageSize     int // users per page of every list (0: 1000); the admin API uses it too

	mu     sync.Mutex
	faults Faults
	Users  []User
	Groups []Group
	// Members maps a group id to the account ids in it.
	Members map[string][]string
	// Access maps a group id to its access type (site-admin or admin).
	Access map[string]string
	// Projects maps a project key to its roles by role id.
	Projects   map[string]map[string]*Role
	AdminUsers []AdminUser

	Reads, Writes, AdminReads int
}

// New returns a fake that accepts basic credentials email:token and the admin key.
func New(email, token, orgID, adminKey string) *Fake {
	return &Fake{Email: email, Token: token, OrgID: orgID, AdminKey: adminKey, Members: map[string][]string{}, Access: map[string]string{},
		Projects: map[string]map[string]*Role{}}
}

// SetFaults replaces the faults.
func (f *Fake) SetFaults(x Faults) { f.mu.Lock(); f.faults = x; f.mu.Unlock() }

// MembersOf returns a copy of a group's member account ids.
func (f *Fake) MembersOf(group string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.Members[group]...)
}

// RoleOf returns a copy of a project role.
func (f *Fake) RoleOf(key, id string) Role {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r := f.Projects[key][id]; r != nil {
		c := *r
		c.Users = append([]string(nil), r.Users...)
		return c
	}
	return Role{}
}

// Counts returns the site reads, writes and admin reads seen.
func (f *Fake) Counts() (reads, writes, admin int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Reads, f.Writes, f.AdminReads
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int) {
	writeJSON(w, status, map[string]any{"errorMessages": []string{"fake failure"}, "errors": map[string]string{}})
}

func (f *Fake) pageSize(def int) int {
	if f.PageSize > 0 && f.PageSize < def {
		return f.PageSize
	}
	return def
}

func ints(q url.Values, k string, def int) int {
	if n, err := strconv.Atoi(q.Get(k)); err == nil && n >= 0 {
		return n
	}
	return def
}

func slice[T any](all []T, start, size int) []T {
	if start > len(all) {
		start = len(all)
	}
	return all[start:min(start+size, len(all))]
}

func (f *Fake) userJSON(u User) map[string]any {
	m := map[string]any{"accountId": u.AccountID, "accountType": u.Type, "displayName": u.Name, "active": u.Active}
	if u.Email != "" {
		m["emailAddress"] = u.Email
	}
	return m
}

// ServeHTTP implements http.Handler.
func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, "/admin/") {
		f.admin(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(f.Email+":"+f.Token)) {
		fail(w, http.StatusUnauthorized)
		return
	}
	if f.faults.Unauthorized > 0 {
		f.faults.Unauthorized--
		fail(w, http.StatusUnauthorized)
		return
	}
	if f.faults.Throttle > 0 {
		f.faults.Throttle--
		w.Header().Set("Retry-After", "0")
		fail(w, http.StatusTooManyRequests)
		return
	}
	if r.Method == http.MethodGet {
		f.Reads++
		if f.faults.ReadStatus != 0 {
			fail(w, f.faults.ReadStatus)
			return
		}
		if f.faults.Malformed {
			fmt.Fprint(w, `{"values": [`)
			return
		}
		f.read(w, r)
		return
	}
	f.Writes++
	if f.faults.WriteStatus != 0 {
		fail(w, f.faults.WriteStatus)
		return
	}
	f.write(w, r)
}

func (f *Fake) read(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	path := r.URL.Path
	switch {
	case path == "/rest/api/3/myself":
		writeJSON(w, http.StatusOK, map[string]any{"accountId": "5b10ac8d82e05b22cc7d4ef5", "accountType": "atlassian", "active": true})
	case path == "/rest/api/3/users/search":
		size := f.pageSize(ints(q, "maxResults", 50))
		out := []map[string]any{}
		for _, u := range slice(f.Users, ints(q, "startAt", 0), size) {
			out = append(out, f.userJSON(u))
		}
		writeJSON(w, http.StatusOK, out)
	case path == "/rest/api/3/user/search":
		needle := strings.ToLower(q.Get("query"))
		out := []map[string]any{}
		for _, u := range f.Users {
			if needle != "" && (strings.Contains(strings.ToLower(u.Email), needle) || strings.Contains(strings.ToLower(u.Name), needle)) && u.Active {
				out = append(out, f.userJSON(u))
			}
		}
		writeJSON(w, http.StatusOK, out)
	case path == "/rest/api/3/user":
		for _, u := range f.Users {
			if u.AccountID == q.Get("accountId") {
				m := f.userJSON(u)
				items := []map[string]string{}
				for _, g := range f.Groups {
					for _, a := range f.Members[g.ID] {
						if a == u.AccountID {
							items = append(items, map[string]string{"groupId": g.ID, "name": g.Name})
						}
					}
				}
				m["groups"] = map[string]any{"size": len(items), "items": items}
				writeJSON(w, http.StatusOK, m)
				return
			}
		}
		fail(w, http.StatusNotFound)
	case path == "/rest/api/3/group/bulk":
		var all []map[string]string
		for _, g := range f.Groups {
			if t := q.Get("accessType"); t != "" && f.Access[g.ID] != t {
				continue
			}
			all = append(all, map[string]string{"groupId": g.ID, "name": g.Name})
		}
		f.pageOut(w, q, all, 50)
	case path == "/rest/api/3/group/member":
		var all []map[string]any
		for _, id := range f.Members[q.Get("groupId")] {
			for _, u := range f.Users {
				if u.AccountID == id {
					all = append(all, f.userJSON(u))
				}
			}
		}
		f.pageOut(w, q, all, 50)
	default:
		f.project(w, r)
	}
}

func pageOf[T any](f *Fake, q url.Values, all []T, def int) (vals []T, start, size int, last bool) {
	size = f.pageSize(ints(q, "maxResults", def))
	start = ints(q, "startAt", 0)
	vals = slice(all, start, size)
	return vals, start, size, start+len(vals) >= len(all)
}

func (f *Fake) pageOut(w http.ResponseWriter, q url.Values, all any, def int) {
	switch a := all.(type) {
	case []map[string]string:
		v, s, n, last := pageOf(f, q, a, def)
		writeJSON(w, http.StatusOK, map[string]any{"values": nonNil(v), "startAt": s, "maxResults": n, "isLast": last, "total": len(a)})
	case []map[string]any:
		v, s, n, last := pageOf(f, q, a, def)
		writeJSON(w, http.StatusOK, map[string]any{"values": nonNil(v), "startAt": s, "maxResults": n, "isLast": last, "total": len(a)})
	}
}

func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

// project serves /rest/api/3/project/{key}/role[/{id}].
func (f *Fake) project(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/rest/api/3/project/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[1] != "role" {
		fail(w, http.StatusNotFound)
		return
	}
	for key, roles := range f.Projects { // what is written back is the stored key and id, never the request's
		if key != parts[0] {
			continue
		}
		if len(parts) == 2 {
			out := map[string]string{}
			for id, ro := range roles {
				out[ro.Name] = "https://example.atlassian.net/rest/api/3/project/" + key + "/role/" + id
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		for id, ro := range roles {
			if len(parts) == 3 && id == parts[2] {
				writeJSON(w, http.StatusOK, f.roleJSON(id, ro))
				return
			}
		}
	}
	fail(w, http.StatusNotFound)
}

func (f *Fake) roleJSON(id string, ro *Role) map[string]any {
	n, _ := strconv.Atoi(id)
	actors := []map[string]any{}
	for _, a := range ro.Users {
		actors = append(actors, map[string]any{"type": "atlassian-user-role-actor", "actorUser": map[string]string{"accountId": a}})
	}
	for _, g := range ro.Groups {
		actors = append(actors, map[string]any{"type": "atlassian-group-role-actor", "actorGroup": map[string]string{"groupId": g}})
	}
	return map[string]any{"id": n, "name": ro.Name, "admin": ro.Admin, "actors": actors}
}

func remove(s []string, v string) []string {
	out := s[:0:0]
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func has(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// activeUser returns the stored account id of an active user the request names. Writes record the stored id,
// never the request's text, so nothing a request carried is kept or echoed.
func (f *Fake) activeUser(v any) (string, bool) {
	id, _ := v.(string)
	for _, u := range f.Users {
		if u.AccountID == id && u.Active {
			return u.AccountID, true
		}
	}
	return "", false
}

func (f *Fake) write(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var body map[string]any
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			fail(w, http.StatusBadRequest)
			return
		}
	}
	if r.URL.Path == "/rest/api/3/group/user" {
		gid := q.Get("groupId")
		if !f.groupExists(gid) {
			fail(w, http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPost {
			acct, ok := f.activeUser(body["accountId"])
			if !ok {
				fail(w, http.StatusNotFound)
				return
			}
			if !f.faults.DropWrites && !has(f.Members[gid], acct) {
				f.Members[gid] = append(f.Members[gid], acct)
			}
			writeJSON(w, http.StatusCreated, map[string]string{"name": "group"})
			return
		}
		if r.Method == http.MethodDelete {
			acct, ok := f.activeUser(q.Get("accountId"))
			if !ok {
				fail(w, http.StatusNotFound)
				return
			}
			if !f.faults.DropWrites {
				f.Members[gid] = remove(f.Members[gid], acct)
			}
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	if rest, ok := strings.CutPrefix(r.URL.Path, "/rest/api/3/project/"); ok {
		parts := strings.Split(rest, "/")
		if len(parts) == 3 && parts[1] == "role" && f.Projects[parts[0]][parts[2]] != nil {
			ro := f.Projects[parts[0]][parts[2]]
			switch r.Method {
			case http.MethodPost:
				users, _ := body["user"].([]any)
				for _, u := range users {
					acct, ok := f.activeUser(u)
					if !ok {
						fail(w, http.StatusNotFound)
						return
					}
					if !f.faults.DropWrites && !has(ro.Users, acct) {
						ro.Users = append(ro.Users, acct)
					}
				}
				writeJSON(w, http.StatusOK, f.roleJSON(parts[2], ro))
				return
			case http.MethodDelete:
				if !f.faults.DropWrites {
					if acct, ok := f.activeUser(q.Get("user")); ok {
						ro.Users = remove(ro.Users, acct)
					}
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
	}
	http.NotFound(w, r)
}

func (f *Fake) groupExists(id string) bool {
	for _, g := range f.Groups {
		if g.ID == id {
			return true
		}
	}
	return false
}

// admin serves the organization admin API: /admin/v1/orgs/{orgId}/users with a cursor.
func (f *Fake) admin(w http.ResponseWriter, r *http.Request) {
	f.AdminReads++
	if r.Header.Get("Authorization") != "Bearer "+f.AdminKey || f.AdminKey == "" {
		fail(w, http.StatusUnauthorized)
		return
	}
	if f.faults.AdminStatus != 0 {
		fail(w, f.faults.AdminStatus)
		return
	}
	if r.URL.Path != "/admin/v1/orgs/"+f.OrgID+"/users" {
		fail(w, http.StatusNotFound)
		return
	}
	size := f.pageSize(1000)
	start := 0
	if c := r.URL.Query().Get("cursor"); c != "" {
		n, err := strconv.Atoi(c)
		if err != nil || n < 0 {
			fail(w, http.StatusBadRequest)
			return
		}
		start = n
	}
	rows := slice(f.AdminUsers, start, size)
	data := []map[string]any{}
	for _, u := range rows {
		prods := []map[string]string{}
		for _, p := range u.Products {
			prods = append(prods, map[string]string{"key": p.Key, "name": p.Name})
		}
		m := map[string]any{"account_id": u.AccountID, "account_type": "atlassian", "account_status": u.Status, "name": "User", "product_access": prods}
		if u.Email != "" {
			m["email"] = u.Email
		}
		data = append(data, m)
	}
	links := map[string]string{}
	if start+len(rows) < len(f.AdminUsers) {
		host := "https://" + r.Host
		if f.faults.BadNext {
			host = "https://evil.example.com"
		}
		links["next"] = host + r.URL.Path + "?cursor=" + strconv.Itoa(start+len(rows))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data, "links": links, "meta": map[string]int{"total": len(f.AdminUsers)}})
}

// SortedGroupIDs returns the group ids in order, for a stable test.
func (f *Fake) SortedGroupIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, g := range f.Groups {
		out = append(out, g.ID)
	}
	sort.Strings(out)
	return out
}
