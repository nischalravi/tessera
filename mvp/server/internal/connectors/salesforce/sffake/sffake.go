// Package sffake is an in-process Salesforce REST API (issue #555) for tests: the JWT bearer token
// endpoint (it checks the assertion's signature, issuer, subject, audience and expiry), SOQL queries
// with equality filters and paging, and sobject create, update and delete, with the faults a real org
// shows: a refused token, expired sessions, throttling, server errors, malformed answers, a bad paging
// link, and writes that fail or are accepted and dropped.
package sffake

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Row is one record.
type Row = map[string]any

// Faults to inject.
type Faults struct {
	TokenStatus  int
	Unauthorized int // answer this many API calls with 401 (an expired session)
	Throttle     int // answer this many API calls with 429
	ReadStatus   int
	WriteStatus  int
	DropWrites   bool
	Malformed    bool
	BadNext      bool // the first page links to another host
}

// Fake is one org.
type Fake struct {
	ClientID, Username string
	Key                *rsa.PublicKey
	Version            string
	PageSize           int
	// Now is the clock an assertion's expiry is judged against (default time.Now).
	Now func() time.Time

	mu         sync.Mutex
	objects    map[string][]Row
	faults     Faults
	n          int
	cursors    map[string][]Row
	Tokens     int
	Reads      int
	Writes     int
	Assertions []string
}

// New returns a fake that accepts assertions from clientID for username signed with the key matching pub.
func New(clientID, username string, pub *rsa.PublicKey) *Fake {
	return &Fake{ClientID: clientID, Username: username, Key: pub, Version: "v61.0", objects: map[string][]Row{}, cursors: map[string][]Row{}}
}

// Set replaces the rows of an sobject.
func (f *Fake) Set(object string, rows ...Row) {
	f.mu.Lock()
	f.objects[object] = append([]Row(nil), rows...)
	f.mu.Unlock()
}

// SetFaults replaces the faults.
func (f *Fake) SetFaults(x Faults) { f.mu.Lock(); f.faults = x; f.mu.Unlock() }

// Rows returns a copy of the rows of an sobject that match field=value pairs (none: all).
func (f *Fake) Rows(object string, kv ...string) []Row {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Row
	for _, r := range f.objects[object] {
		if matches(r, kv) {
			out = append(out, r)
		}
	}
	return out
}

// Counts returns token requests, reads and writes seen.
func (f *Fake) Counts() (tokens, reads, writes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Tokens, f.Reads, f.Writes
}

func matches(r Row, kv []string) bool {
	for i := 0; i+1 < len(kv); i += 2 {
		if fmt.Sprint(r[kv[i]]) != kv[i+1] {
			return false
		}
	}
	return true
}

const token = "tok-sf-fake" // #nosec G101 -- a fixed test token of a fake

var prefixes = map[string]string{"User": "005", "UserLogin": "0Yw", "PermissionSetAssignment": "0Pa"}

func (f *Fake) newID(object string) string {
	f.n++
	p := prefixes[object]
	if p == "" {
		p = "0XX"
	}
	return fmt.Sprintf("%s%015d", p, f.n)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, []map[string]string{{"message": "fake failure", "errorCode": code}})
}

func (f *Fake) checkAssertion(a, aud string) bool {
	parts := strings.Split(a, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(f.Key, crypto.SHA256, sum[:], sig) != nil {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var c struct {
		Iss, Sub, Aud string
		Exp           int64
	}
	if json.Unmarshal(raw, &c) != nil {
		return false
	}
	now := time.Now()
	if f.Now != nil {
		now = f.Now()
	}
	// a short-lived assertion: expiring within the next five minutes, not already expired
	return c.Iss == f.ClientID && c.Sub == f.Username && c.Aud == aud && c.Exp > now.Unix() && c.Exp <= now.Add(5*time.Minute).Unix()
}

var (
	selectRE = regexp.MustCompile(`(?is)^SELECT\s+(.+?)\s+FROM\s+(\w+)(?:\s+WHERE\s+(.+))?$`)
	condRE   = regexp.MustCompile(`^\s*(\w+)\s*=\s*'([^']*)'\s*$`)
)

// ServeHTTP implements http.Handler.
func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/services/oauth2/token" && r.Method == http.MethodPost {
		f.Tokens++
		a := r.FormValue("assertion")
		f.Assertions = append(f.Assertions, a)
		switch {
		case f.faults.TokenStatus != 0:
			w.WriteHeader(f.faults.TokenStatus)
		case r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || !f.checkAssertion(a, "https://"+r.Host) && !f.checkAssertion(a, "http://"+r.Host):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "audience or signature is invalid"})
		default:
			// instance_url is deliberately another host: the client must not follow it.
			writeJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "instance_url": "https://evil.example.com", "scope": "api"})
		}
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+token {
		fail(w, http.StatusUnauthorized, "INVALID_SESSION_ID")
		return
	}
	if f.faults.Unauthorized > 0 {
		f.faults.Unauthorized--
		fail(w, http.StatusUnauthorized, "INVALID_SESSION_ID")
		return
	}
	if f.faults.Throttle > 0 {
		f.faults.Throttle--
		w.Header().Set("Retry-After", "0")
		fail(w, http.StatusTooManyRequests, "REQUEST_LIMIT_EXCEEDED")
		return
	}
	root := "/services/data/" + f.Version
	switch {
	case r.Method == http.MethodGet && r.URL.Path == root+"/query":
		f.Reads++
		f.query(w, r.URL.Query().Get("q"))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, root+"/query/"):
		f.Reads++
		f.page(w, strings.TrimPrefix(r.URL.Path, root+"/query/"))
	case strings.HasPrefix(r.URL.Path, root+"/sobjects/"):
		f.Writes++
		if f.faults.WriteStatus != 0 {
			fail(w, f.faults.WriteStatus, "FAKE_WRITE_FAILURE")
			return
		}
		f.write(w, r, strings.Split(strings.TrimPrefix(r.URL.Path, root+"/sobjects/"), "/"))
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) query(w http.ResponseWriter, q string) {
	if f.faults.ReadStatus != 0 {
		fail(w, f.faults.ReadStatus, "FAKE_READ_FAILURE")
		return
	}
	if f.faults.Malformed {
		fmt.Fprint(w, `{"records": [`)
		return
	}
	m := selectRE.FindStringSubmatch(strings.TrimSpace(q))
	if m == nil {
		fail(w, http.StatusBadRequest, "MALFORMED_QUERY")
		return
	}
	var kv []string
	if m[3] != "" {
		for _, c := range regexp.MustCompile(`(?i)\s+AND\s+`).Split(m[3], -1) {
			cm := condRE.FindStringSubmatch(c)
			if cm == nil {
				fail(w, http.StatusBadRequest, "MALFORMED_QUERY")
				return
			}
			kv = append(kv, cm[1], cm[2])
		}
	}
	var rows []Row
	for _, r := range f.objects[m[2]] {
		if matches(r, kv) {
			rows = append(rows, r)
		}
	}
	f.respond(w, rows, 0)
}

func (f *Fake) respond(w http.ResponseWriter, rows []Row, offset int) {
	out := map[string]any{"totalSize": len(rows) + offset, "done": true}
	if f.PageSize > 0 && len(rows) > f.PageSize {
		id := fmt.Sprintf("01g%d", len(f.cursors)+1)
		f.cursors[id] = rows[f.PageSize:]
		rows = rows[:f.PageSize]
		out["done"] = false
		out["nextRecordsUrl"] = "/services/data/" + f.Version + "/query/" + id
		if f.faults.BadNext {
			out["nextRecordsUrl"] = "https://evil.example.com/services/data/" + f.Version + "/query/" + id
		}
	}
	if rows == nil {
		rows = []Row{}
	}
	out["records"] = rows
	writeJSON(w, http.StatusOK, out)
}

func (f *Fake) page(w http.ResponseWriter, id string) {
	rows, ok := f.cursors[id]
	if !ok {
		fail(w, http.StatusNotFound, "NOT_FOUND")
		return
	}
	delete(f.cursors, id)
	f.respond(w, rows, 0)
}

func (f *Fake) find(object, id string) int {
	for i, r := range f.objects[object] {
		if r["Id"] == id {
			return i
		}
	}
	return -1
}

func (f *Fake) write(w http.ResponseWriter, r *http.Request, parts []string) {
	object := parts[0]
	var body Row
	if r.Method != http.MethodDelete {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			fail(w, http.StatusBadRequest, "JSON_PARSER_ERROR")
			return
		}
	}
	switch {
	case r.Method == http.MethodPost && len(parts) == 1:
		if f.faults.DropWrites {
			writeJSON(w, http.StatusCreated, map[string]any{"id": f.newID(object), "success": true, "errors": []string{}})
			return
		}
		f.create(w, object, body)
	case r.Method == http.MethodPatch && len(parts) == 2:
		i := f.find(object, parts[1])
		if i < 0 {
			fail(w, http.StatusNotFound, "NOT_FOUND")
			return
		}
		if !f.faults.DropWrites {
			for k, v := range body {
				f.objects[object][i][k] = v
			}
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete && len(parts) == 2:
		i := f.find(object, parts[1])
		if i < 0 {
			fail(w, http.StatusNotFound, "ENTITY_IS_DELETED")
			return
		}
		row := f.objects[object][i]
		if object == "PermissionSetAssignment" && row["PermissionSetGroupId"] != nil && !f.isGroupRow(row) {
			fail(w, http.StatusBadRequest, "DELETE_FAILED")
			return
		}
		if !f.faults.DropWrites {
			f.objects[object] = append(f.objects[object][:i:i], f.objects[object][i+1:]...)
			if object == "PermissionSetAssignment" && row["PermissionSetGroupId"] != nil {
				f.dropGroupRows(row)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

// isGroupRow: the assignment of a group's own generated set, as opposed to a component's row.
func (f *Fake) isGroupRow(a Row) bool {
	for _, ps := range f.objects["PermissionSet"] {
		if ps["Id"] == a["PermissionSetId"] && ps["Type"] == "Group" && ps["PermissionSetGroupId"] == a["PermissionSetGroupId"] {
			return true
		}
	}
	return false
}

func (f *Fake) dropGroupRows(a Row) {
	keep := f.objects["PermissionSetAssignment"][:0:0]
	for _, x := range f.objects["PermissionSetAssignment"] {
		if !(x["AssigneeId"] == a["AssigneeId"] && x["PermissionSetGroupId"] == a["PermissionSetGroupId"]) {
			keep = append(keep, x)
		}
	}
	f.objects["PermissionSetAssignment"] = keep
}

func (f *Fake) create(w http.ResponseWriter, object string, body Row) {
	row := Row{"Id": f.newID(object)}
	for k, v := range body {
		row[k] = v
	}
	switch object {
	case "User":
		for _, req := range []string{"Username", "LastName", "Alias", "Email", "ProfileId", "TimeZoneSidKey", "LocaleSidKey", "EmailEncodingKey", "LanguageLocaleKey"} {
			if row[req] == nil || row[req] == "" {
				fail(w, http.StatusBadRequest, "REQUIRED_FIELD_MISSING")
				return
			}
		}
		for _, u := range f.objects["User"] {
			if u["Username"] == row["Username"] {
				fail(w, http.StatusBadRequest, "DUPLICATE_USERNAME")
				return
			}
		}
		row["IsActive"] = true
		f.objects["UserLogin"] = append(f.objects["UserLogin"], Row{"Id": f.newID("UserLogin"), "UserId": row["Id"], "IsFrozen": false})
	case "PermissionSetAssignment":
		if row["AssigneeId"] == nil || (row["PermissionSetId"] == nil && row["PermissionSetGroupId"] == nil) {
			fail(w, http.StatusBadRequest, "REQUIRED_FIELD_MISSING")
			return
		}
		for _, a := range f.objects[object] {
			if a["AssigneeId"] == row["AssigneeId"] && a["PermissionSetId"] == row["PermissionSetId"] && row["PermissionSetId"] != nil {
				fail(w, http.StatusBadRequest, "DUPLICATE_VALUE")
				return
			}
		}
		if g, ok := row["PermissionSetGroupId"]; ok {
			// the group's generated set, then one row per component set
			for _, ps := range f.objects["PermissionSet"] {
				if ps["Type"] == "Group" && ps["PermissionSetGroupId"] == g {
					row["PermissionSetId"] = ps["Id"]
				}
			}
			for _, c := range f.objects["PermissionSetGroupComponent"] {
				if c["PermissionSetGroupId"] == g {
					f.objects[object] = append(f.objects[object], Row{"Id": f.newID(object), "AssigneeId": row["AssigneeId"], "PermissionSetId": c["PermissionSetId"], "PermissionSetGroupId": g})
				}
			}
		}
	}
	f.objects[object] = append(f.objects[object], row)
	writeJSON(w, http.StatusCreated, map[string]any{"id": row["Id"], "success": true, "errors": []string{}})
}
