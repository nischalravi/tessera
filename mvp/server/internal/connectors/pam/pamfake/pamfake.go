// Package pamfake is an in-process CyberArk, Delinea Secret Server or
// BeyondTrust Password Safe (issue #304). It keeps each vendor's own state
// (CyberArk permission flags, Delinea role names, BeyondTrust role ids), so
// the contract tests prove the readers' translation, and has switches for the
// faults a vault shows: a refused login, throttling, server errors, writes
// that fail or are silently dropped, and malformed answers.
package pamfake

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Member is a safe member in the vendor's own terms.
type Member struct {
	Name, Type string   // Type: User | Group
	Perms      []string // CyberArk permission names (camelCase)
	Folder     string   // Delinea folder role
	Secret     string   // Delinea secret role
	Roles      []string // BeyondTrust role names
}

// Account is a vaulted account.
type Account struct {
	ID, Name, User, Address, Platform string
	Auto                              bool
	Created, Rotated                  time.Time
}

// Safe is a safe, folder or smart rule.
type Safe struct {
	ID       string
	Name     string
	Members  []Member
	Accounts []Account
}

// Faults to inject.
type Faults struct {
	LoginStatus int  // refuse the login with this status
	ReadStatus  int  // answer every read with this status
	Throttle    int  // answer this many reads with 429 first
	WriteStatus int  // answer every write with this status
	DropWrites  bool // accept writes (2xx) and change nothing
	Malformed   bool // answer reads with text that is not JSON
}

// Fake is one vault.
type Fake struct {
	Vendor, User, Secret string

	mu       sync.Mutex
	safes    []Safe
	faults   Faults
	throttle int
	nextID   int64
	Logins   int
	Writes   int
	Reads    int
	Users    []string // Delinea and BeyondTrust principals the vault knows
	Groups   []string
}

// New returns a fake of vendor that accepts the credential.
func New(vendor, user, secret string) *Fake {
	return &Fake{Vendor: vendor, User: user, Secret: secret, nextID: 1000}
}

// Set replaces the safes.
func (f *Fake) Set(s ...Safe) { f.mu.Lock(); f.safes = append([]Safe(nil), s...); f.mu.Unlock() }

// SetFaults replaces the faults.
func (f *Fake) SetFaults(x Faults) { f.mu.Lock(); f.faults, f.throttle = x, x.Throttle; f.mu.Unlock() }

// SafeState returns a copy of one safe.
func (f *Fake) SafeState(id string) (Safe, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.safes {
		if s.ID == id {
			c := s
			c.Members = append([]Member(nil), s.Members...)
			return c, true
		}
	}
	return Safe{}, false
}

// Counts returns logins, reads and writes seen.
func (f *Fake) Counts() (logins, reads, writes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Logins, f.Reads, f.Writes
}

const token = "tok-pam-fake"

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch f.Vendor {
	case "cyberark":
		f.cyberark(w, r)
	case "delinea":
		f.delinea(w, r)
	case "beyondtrust":
		f.beyondtrust(w, r)
	default:
		http.NotFound(w, r)
	}
}

// gate applies the read and write faults; it reports whether the request was answered.
func (f *Fake) gate(w http.ResponseWriter, r *http.Request, authOK bool) bool {
	if !authOK {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
		return true
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
	case !write && f.faults.ReadStatus != 0:
		w.WriteHeader(f.faults.ReadStatus)
		fmt.Fprint(w, `{"error":"server_error","description":"leaky-body-should-never-surface"}`)
	case write && f.faults.WriteStatus != 0:
		w.WriteHeader(f.faults.WriteStatus)
	case !write && f.faults.Malformed:
		fmt.Fprint(w, `<html>maintenance</html>`)
	case write && f.faults.DropWrites:
		w.WriteHeader(http.StatusNoContent)
	default:
		return false
	}
	return true
}

func (f *Fake) safe(id string) *Safe {
	for i := range f.safes {
		if f.safes[i].ID == id {
			return &f.safes[i]
		}
	}
	return nil
}

func page(r *http.Request, offKey, limKey string, n int) (lo, hi int) {
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

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func readBody(r *http.Request, v any) bool {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	return err == nil && json.Unmarshal(b, v) == nil
}

func sortedMembers(ms []Member) []Member {
	out := append([]Member(nil), ms...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---------------------------------------------------------------- CyberArk

func (f *Fake) cyberark(w http.ResponseWriter, r *http.Request) {
	const root = "/PasswordVault/API"
	if r.URL.Path == root+"/auth/Cyberark/Logon" && r.Method == http.MethodPost {
		f.Logins++
		var b struct{ Username, Password string }
		if f.faults.LoginStatus != 0 {
			w.WriteHeader(f.faults.LoginStatus)
			return
		}
		if !readBody(r, &b) || b.Username != f.User || b.Password != f.Secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, token)
		return
	}
	if f.gate(w, r, r.Header.Get("Authorization") == token) {
		return
	}
	p := strings.TrimPrefix(r.URL.Path, root)
	parts := strings.Split(strings.Trim(p, "/"), "/")
	switch {
	case p == "/Safes" && r.Method == http.MethodGet:
		lo, hi := page(r, "offset", "limit", len(f.safes))
		var out []map[string]string
		for _, s := range f.safes[lo:hi] {
			out = append(out, map[string]string{"safeUrlId": s.ID, "safeName": s.Name})
		}
		writeJSON(w, map[string]any{"value": out, "count": len(f.safes)})
	case p == "/Accounts" && r.Method == http.MethodGet:
		name := strings.TrimPrefix(r.URL.Query().Get("filter"), "safeName eq ")
		var all []map[string]any
		for _, s := range f.safes {
			if s.Name != name {
				continue
			}
			for _, a := range s.Accounts {
				all = append(all, map[string]any{"id": a.ID, "name": a.Name, "userName": a.User, "address": a.Address, "safeName": s.Name,
					"platformId": a.Platform, "createdTime": a.Created.Unix(),
					"secretManagement": map[string]any{"automaticManagementEnabled": a.Auto, "lastModifiedTime": a.Rotated.Unix()}})
			}
		}
		lo, hi := page(r, "offset", "limit", len(all))
		writeJSON(w, map[string]any{"value": all[lo:hi]})
	case len(parts) >= 3 && parts[0] == "Safes" && parts[2] == "Members":
		s := f.safe(parts[1])
		if s == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f.caMembers(w, r, s, parts[3:])
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) caMembers(w http.ResponseWriter, r *http.Request, s *Safe, rest []string) {
	switch {
	case r.Method == http.MethodGet && len(rest) == 0:
		ms := sortedMembers(s.Members)
		lo, hi := page(r, "offset", "limit", len(ms))
		var out []map[string]any
		for _, m := range ms[lo:hi] {
			perms := map[string]bool{}
			for _, p := range m.Perms {
				perms[p] = true
			}
			out = append(out, map[string]any{"memberName": m.Name, "memberType": m.Type, "permissions": perms})
		}
		writeJSON(w, map[string]any{"value": out})
	case r.Method == http.MethodPost || r.Method == http.MethodPut:
		var b struct {
			Name  string          `json:"memberName"`
			Type  string          `json:"memberType"`
			Perms map[string]bool `json:"permissions"`
		}
		if !readBody(r, &b) || b.Name == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		m := Member{Name: b.Name, Type: b.Type}
		for k, on := range b.Perms {
			if on {
				m.Perms = append(m.Perms, k)
			}
		}
		sort.Strings(m.Perms)
		for i := range s.Members {
			if s.Members[i].Name == b.Name {
				if r.Method == http.MethodPost {
					w.WriteHeader(http.StatusConflict)
					return
				}
				s.Members[i] = m
				writeJSON(w, map[string]bool{"ok": true}) // fixed, never request input
				return
			}
		}
		s.Members = append(s.Members, m)
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]bool{"ok": true}) // fixed, never request input
	case r.Method == http.MethodDelete && len(rest) == 1:
		for i := range s.Members {
			if s.Members[i].Name == rest[0] {
				s.Members = append(s.Members[:i], s.Members[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------- Delinea

func (f *Fake) delinea(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oauth2/token" && r.Method == http.MethodPost {
		f.Logins++
		if f.faults.LoginStatus != 0 {
			w.WriteHeader(f.faults.LoginStatus)
			return
		}
		if r.FormValue("grant_type") != "password" || r.FormValue("username") != f.User || r.FormValue("password") != f.Secret {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		writeJSON(w, map[string]any{"access_token": token, "token_type": "bearer", "expires_in": 1200})
		return
	}
	if f.gate(w, r, r.Header.Get("Authorization") == "Bearer "+token) {
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/api/v1")
	q := r.URL.Query()
	paged := func(n int) (int, int, bool) {
		lo, hi := page(r, "skip", "take", n)
		return lo, hi, hi < n
	}
	switch {
	case p == "/folders" && r.Method == http.MethodGet:
		lo, hi, more := paged(len(f.safes))
		var out []map[string]any
		for _, s := range f.safes[lo:hi] {
			id, _ := strconv.Atoi(s.ID)
			out = append(out, map[string]any{"id": id, "folderName": s.Name, "folderPath": "\\" + s.Name})
		}
		writeJSON(w, map[string]any{"records": out, "hasNext": more})
	case p == "/secrets" && r.Method == http.MethodGet:
		s := f.safe(q.Get("filter.folderId"))
		var all []map[string]any
		if s != nil {
			for _, a := range s.Accounts {
				id, _ := strconv.Atoi(a.ID)
				all = append(all, map[string]any{"id": id, "name": a.Name, "secretTemplateName": a.Platform})
			}
		}
		lo, hi, more := paged(len(all))
		writeJSON(w, map[string]any{"records": all[lo:hi], "hasNext": more})
	case p == "/folder-permissions" && r.Method == http.MethodGet:
		s := f.safe(q.Get("filter.folderId"))
		var all []map[string]any
		if s != nil {
			for i, m := range sortedMembers(s.Members) {
				rec := map[string]any{"id": permID(s.ID, i), "folderAccessRoleName": m.Folder, "secretAccessRoleName": m.Secret}
				if m.Type == "Group" {
					rec["groupName"] = m.Name
				} else {
					rec["userName"] = m.Name
				}
				all = append(all, rec)
			}
		}
		lo, hi, more := paged(len(all))
		writeJSON(w, map[string]any{"records": all[lo:hi], "hasNext": more})
	case (p == "/users" || p == "/groups") && r.Method == http.MethodGet:
		names, field := f.Users, "userName"
		if p == "/groups" {
			names, field = f.Groups, "name"
		}
		var out []map[string]any
		for i, n := range names {
			if strings.Contains(strings.ToLower(n), strings.ToLower(q.Get("filter.searchText"))) {
				out = append(out, map[string]any{"id": 500 + i, field: n})
			}
		}
		writeJSON(w, map[string]any{"records": out, "hasNext": false})
	case p == "/folder-permissions" && r.Method == http.MethodPost:
		var b struct {
			FolderID int    `json:"folderId"`
			UserID   int    `json:"userId"`
			GroupID  int    `json:"groupId"`
			Folder   string `json:"folderAccessRoleName"`
			Secret   string `json:"secretAccessRoleName"`
		}
		if !readBody(r, &b) || f.safe(strconv.Itoa(b.FolderID)) == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s := f.safe(strconv.Itoa(b.FolderID))
		m := Member{Folder: b.Folder, Secret: b.Secret, Type: "User"}
		if b.GroupID != 0 && b.GroupID-500 < len(f.Groups) {
			m.Name, m.Type = f.Groups[b.GroupID-500], "Group"
		} else if b.UserID != 0 && b.UserID-500 < len(f.Users) {
			m.Name = f.Users[b.UserID-500]
		} else {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.Members = append(s.Members, m)
		w.WriteHeader(http.StatusOK)
		writeJSON(w, map[string]any{"id": permID(s.ID, len(s.Members)-1)})
	case strings.HasPrefix(p, "/folder-permissions/"):
		id, err := strconv.Atoi(strings.TrimPrefix(p, "/folder-permissions/"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for si := range f.safes {
			s := &f.safes[si]
			for i, m := range sortedMembers(s.Members) {
				if permID(s.ID, i) != id {
					continue
				}
				for j := range s.Members {
					if s.Members[j].Name != m.Name {
						continue
					}
					switch r.Method {
					case http.MethodDelete:
						s.Members = append(s.Members[:j], s.Members[j+1:]...)
					case http.MethodPut:
						var b struct{ Folder, Secret string }
						var raw map[string]string
						if !readBody(r, &raw) {
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						b.Folder, b.Secret = raw["folderAccessRoleName"], raw["secretAccessRoleName"]
						s.Members[j].Folder, s.Members[j].Secret = b.Folder, b.Secret
					}
					writeJSON(w, map[string]any{"id": id})
					return
				}
			}
		}
		w.WriteHeader(http.StatusNotFound)
	default:
		http.NotFound(w, r)
	}
}

func permID(safeID string, i int) int {
	n, _ := strconv.Atoi(safeID)
	return n*1000 + i
}

// ---------------------------------------------------------------- BeyondTrust

// BeyondTrust role ids; groups are users of the fake named Groups.
var btRoles = map[string]int{"Read Only": 1, "Requestor": 2, "Approver": 3}

func (f *Fake) beyondtrust(w http.ResponseWriter, r *http.Request) {
	const root = "/BeyondTrust/api/public/v3"
	want := "PS-Auth key=" + f.Secret + "; runas=" + f.User + ";"
	if r.URL.Path == root+"/Auth/SignAppin" && r.Method == http.MethodPost {
		f.Logins++
		if f.faults.LoginStatus != 0 {
			w.WriteHeader(f.faults.LoginStatus)
			return
		}
		if r.Header.Get("Authorization") != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "ASP.NET_SessionId", Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		writeJSON(w, map[string]string{"UserName": f.User})
		return
	}
	cookie, err := r.Cookie("ASP.NET_SessionId")
	if f.gate(w, r, r.Header.Get("Authorization") == want && err == nil && cookie.Value == token) {
		return
	}
	p := strings.TrimPrefix(r.URL.Path, root)
	parts := strings.Split(strings.Trim(p, "/"), "/")
	switch {
	case p == "/SmartRules" && r.Method == http.MethodGet:
		lo, hi := page(r, "offset", "limit", len(f.safes))
		var out []map[string]any
		for _, s := range f.safes[lo:hi] {
			id, _ := strconv.Atoi(s.ID)
			out = append(out, map[string]any{"SmartRuleID": id, "Title": s.Name})
		}
		writeJSON(w, out)
	case len(parts) == 3 && parts[0] == "SmartRules" && parts[2] == "ManagedAccounts":
		var out []map[string]any
		if s := f.safe(parts[1]); s != nil {
			for _, a := range s.Accounts {
				id, _ := strconv.Atoi(a.ID)
				out = append(out, map[string]any{"ManagedAccountID": id, "AccountName": a.Name, "SystemName": a.Address,
					"AutoManagementFlag": a.Auto, "LastChangeDate": a.Rotated.Format(time.RFC3339), "CreateDate": a.Created.Format(time.RFC3339)})
			}
		}
		writeJSON(w, out)
	case p == "/UserGroups" && r.Method == http.MethodGet:
		lo, hi := page(r, "offset", "limit", len(f.Groups))
		var out []map[string]any
		for i := lo; i < hi; i++ {
			out = append(out, map[string]any{"GroupID": 700 + i, "GroupName": f.Groups[i], "GroupType": "BeyondInsight"})
		}
		writeJSON(w, out)
	case p == "/Roles":
		var out []map[string]any
		for n, id := range btRoles {
			out = append(out, map[string]any{"RoleID": id, "Name": n})
		}
		writeJSON(w, out)
	case len(parts) >= 3 && parts[0] == "UserGroups" && parts[2] == "SmartRules":
		gi, err := strconv.Atoi(parts[1])
		if err != nil || gi < 700 || gi-700 >= len(f.Groups) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		g := f.Groups[gi-700]
		f.btRules(w, r, g, parts[3:])
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) btRules(w http.ResponseWriter, r *http.Request, group string, rest []string) {
	switch {
	case r.Method == http.MethodGet && len(rest) == 0:
		out := []map[string]any{}
		for _, s := range f.safes {
			for _, m := range s.Members {
				if m.Name != group {
					continue
				}
				id, _ := strconv.Atoi(s.ID)
				var roles []map[string]any
				for _, n := range m.Roles {
					roles = append(roles, map[string]any{"RoleID": btRoles[n], "Name": n})
				}
				out = append(out, map[string]any{"SmartRuleID": id, "Roles": roles})
			}
		}
		writeJSON(w, out)
	case len(rest) == 2 && rest[1] == "Roles":
		s := f.safe(rest[0])
		if s == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		idx := -1
		for i := range s.Members {
			if s.Members[i].Name == group {
				idx = i
			}
		}
		switch r.Method {
		case http.MethodPost:
			var body []map[string]int
			if !readBody(r, &body) || len(body) == 0 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var roles []string
			for _, b := range body {
				for n, id := range btRoles {
					if id == b["RoleID"] {
						roles = append(roles, n)
					}
				}
			}
			if idx < 0 {
				s.Members = append(s.Members, Member{Name: group, Type: "Group", Roles: roles})
			} else {
				s.Members[idx].Roles = roles
			}
			w.WriteHeader(http.StatusCreated)
		case http.MethodDelete:
			if idx >= 0 {
				s.Members = append(s.Members[:idx], s.Members[idx+1:]...)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
