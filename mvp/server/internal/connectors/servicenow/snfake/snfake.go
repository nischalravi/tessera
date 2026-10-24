// Package snfake is an in-process ServiceNow Table API (issue #559) for tests: HTTP basic and the OAuth client
// credentials token endpoint (/oauth_token.do), GET with equality conditions of sysparm_query, sysparm_fields,
// sysparm_limit and sysparm_offset and the Link header, and POST, PATCH and DELETE on a table, with the faults
// an instance shows: a refused token, expired sessions, throttling, server errors, malformed answers, a paging
// link to another host, pages shorter than the limit while more remain (the limit is applied before ACLs), and
// writes that fail or are accepted and dropped.
//
// Every answer is a fixed body, a stored row or a generated id: nothing a request carried is echoed.
package snfake

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Row is one record. Values are strings, as the Table API returns them (booleans too).
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
	BadLink      bool // the Link header points at another host
	NoLink       bool // no Link header: the client pages by offset
}

// Fake is one instance.
type Fake struct {
	// Username and Password are the basic credentials; ClientID and ClientSecret the OAuth client's.
	Username, Password, ClientID, ClientSecret string
	// PageSize caps sysparm_limit. ShortPage, when set, makes a page that many rows even when more are allowed
	// and more remain (rows the caller may not see are dropped after the limit, as on a real instance).
	PageSize, ShortPage int

	mu      sync.Mutex
	tables  map[string][]Row
	faults  Faults
	n       int
	Tokens  int
	Reads   int
	Writes  int
	Created []string // table names created, in order
}

// New returns a fake with basic credentials and an OAuth client.
func New(username, password, clientID, clientSecret string) *Fake {
	return &Fake{Username: username, Password: password, ClientID: clientID, ClientSecret: clientSecret, tables: map[string][]Row{}}
}

// Set replaces the rows of a table.
func (f *Fake) Set(table string, rows ...Row) {
	f.mu.Lock()
	f.tables[table] = append([]Row(nil), rows...)
	f.mu.Unlock()
}

// SetFaults replaces the faults.
func (f *Fake) SetFaults(x Faults) { f.mu.Lock(); f.faults = x; f.mu.Unlock() }

// Rows returns a copy of the rows of a table that match field=value pairs (none: all).
func (f *Fake) Rows(table string, kv ...string) []Row {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Row
	for _, r := range f.tables[table] {
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

const token = "tok-sn-fake" // #nosec G101 -- a fixed test token of a fake

var hostRE = regexp.MustCompile(`^[A-Za-z0-9.:\[\]-]{1,255}$`)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"message": "fake failure", "detail": "fake failure"}, "status": "failure"})
}

func (f *Fake) authorized(r *http.Request) bool {
	a := r.Header.Get("Authorization")
	if a == "Bearer "+token {
		return true
	}
	if f.Username != "" {
		return a == "Basic "+base64.StdEncoding.EncodeToString([]byte(f.Username+":"+f.Password))
	}
	return false
}

// ServeHTTP implements http.Handler.
func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/oauth_token.do" && r.Method == http.MethodPost {
		f.Tokens++
		if f.faults.TokenStatus != 0 {
			writeJSON(w, f.faults.TokenStatus, map[string]string{"error": "access_denied"})
			return
		}
		if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "client_credentials" ||
			f.ClientID == "" || r.PostForm.Get("client_id") != f.ClientID || r.PostForm.Get("client_secret") != f.ClientSecret {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "access_denied"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 1799, "scope": "useraccount"})
		return
	}
	if !f.authorized(r) {
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
	rest, ok := strings.CutPrefix(r.URL.Path, "/api/now/table/")
	if !ok || rest == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(rest, "/")
	if r.Method == http.MethodGet && len(parts) == 1 {
		f.Reads++
		f.read(w, r, parts[0])
		return
	}
	f.Writes++
	if f.faults.WriteStatus != 0 {
		fail(w, f.faults.WriteStatus)
		return
	}
	f.write(w, r, parts)
}

// conditions parses the equality conditions of an encoded query; ORDERBY clauses are ignored.
func conditions(q string) (kv []string, ok bool) {
	for _, c := range strings.Split(q, "^") {
		if c == "" || strings.HasPrefix(c, "ORDERBY") {
			continue
		}
		k, v, found := strings.Cut(c, "=")
		if !found || k == "" || strings.HasSuffix(k, "!") || strings.ContainsAny(k, "<>") {
			return nil, false
		}
		kv = append(kv, k, v)
	}
	return kv, true
}

func (f *Fake) read(w http.ResponseWriter, r *http.Request, table string) {
	if f.faults.ReadStatus != 0 {
		fail(w, f.faults.ReadStatus)
		return
	}
	if f.faults.Malformed {
		fmt.Fprint(w, `{"result": [`)
		return
	}
	q := r.URL.Query()
	kv, ok := conditions(q.Get("sysparm_query"))
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"result": []Row{}})
		return
	}
	var rows []Row
	for _, row := range f.tables[table] {
		if matches(row, kv) {
			rows = append(rows, row)
		}
	}
	limit, _ := strconv.Atoi(q.Get("sysparm_limit"))
	offset, _ := strconv.Atoi(q.Get("sysparm_offset"))
	if limit <= 0 || (f.PageSize > 0 && limit > f.PageSize) {
		limit = f.PageSize
		if limit <= 0 {
			limit = 10000
		}
	}
	if offset < 0 || offset > len(rows) {
		offset = len(rows)
	}
	end := min(offset+limit, len(rows))
	page := rows[offset:end]
	if f.ShortPage > 0 && len(page) > f.ShortPage {
		page = page[:f.ShortPage]
	}
	next := offset + len(page)
	if next < len(rows) && !f.faults.NoLink {
		host := "https://invalid.example" // a request header is never echoed unchecked
		if hostRE.MatchString(r.Host) {
			host = "https://" + r.Host
		}
		if f.faults.BadLink {
			host = "https://evil.example.com"
		}
		nq := url.Values{"sysparm_offset": {strconv.Itoa(next)}, "sysparm_limit": {strconv.Itoa(limit)}}
		for _, k := range []string{"sysparm_query", "sysparm_fields", "sysparm_exclude_reference_link", "sysparm_display_value", "sysparm_no_count"} {
			if v := q.Get(k); v != "" {
				nq.Set(k, v)
			}
		}
		w.Header().Set("Link", `<`+host+`/api/now/table/`+table+`?`+nq.Encode()+`>;rel="next"`)
	}
	want := map[string]bool{}
	for _, c := range strings.Split(q.Get("sysparm_fields"), ",") {
		if c != "" {
			want[c] = true
		}
	}
	out := make([]Row, 0, len(page))
	for _, row := range page {
		o := Row{}
		for k, v := range row { // stored keys came from request bodies: escaped like the values
			if len(want) == 0 || want[k] {
				o[html.EscapeString(k)] = esc(v)
			}
		}
		out = append(out, o)
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": out})
}

// esc HTML-escapes a stored string on the way out: a row can hold what a POST body carried, and the fake never
// writes request-derived text back unescaped.
func esc(v any) any {
	if s, ok := v.(string); ok {
		return html.EscapeString(s)
	}
	return v
}

func (f *Fake) newID() string {
	f.n++
	return fmt.Sprintf("%032x", 0xab0000+f.n)
}

func (f *Fake) find(table, id string) int {
	for i, r := range f.tables[table] {
		if r["sys_id"] == id {
			return i
		}
	}
	return -1
}

// text stores a JSON value the way the Table API shows it: as a string.
func text(v any) any {
	switch x := v.(type) {
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return v
}

var required = map[string][]string{"sys_user": {"user_name"}, "sys_user_grmember": {"user", "group"}, "sys_user_has_role": {"user", "role"}, "incident": {"short_description"}}

func (f *Fake) write(w http.ResponseWriter, r *http.Request, parts []string) {
	table := parts[0]
	var body Row
	if r.Method != http.MethodDelete {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			fail(w, http.StatusBadRequest)
			return
		}
	}
	switch {
	case r.Method == http.MethodPost && len(parts) == 1:
		id := f.newID()
		if f.faults.DropWrites {
			writeJSON(w, http.StatusCreated, map[string]any{"result": Row{"sys_id": id}})
			return
		}
		row := Row{"sys_id": id}
		for k, v := range body {
			if k != "sys_id" { // the instance assigns the id; the body cannot set it
				row[k] = text(v)
			}
		}
		for _, req := range required[table] {
			if row[req] == nil || row[req] == "" {
				fail(w, http.StatusBadRequest)
				return
			}
		}
		if table == "sys_user" {
			for _, u := range f.tables[table] {
				if u["user_name"] == row["user_name"] {
					fail(w, http.StatusBadRequest)
					return
				}
			}
			row["active"], row["locked_out"] = "true", "false"
		}
		if table == "sys_user_has_role" {
			row["inherited"], row["state"] = "false", "active"
		}
		if table == "incident" {
			row["number"], row["state"] = fmt.Sprintf("INC%07d", 10000+f.n), "1"
		}
		f.tables[table] = append(f.tables[table], row)
		f.Created = append(f.Created, table)
		writeJSON(w, http.StatusCreated, map[string]any{"result": Row{"sys_id": id}})
	case r.Method == http.MethodPatch && len(parts) == 2:
		i := f.find(table, parts[1])
		if i < 0 {
			fail(w, http.StatusNotFound)
			return
		}
		if !f.faults.DropWrites {
			for k, v := range body {
				if k != "sys_id" {
					f.tables[table][i][k] = text(v)
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"result": Row{}}) // a fixed body: the path id is never echoed
	case r.Method == http.MethodDelete && len(parts) == 2:
		i := f.find(table, parts[1])
		if i < 0 {
			fail(w, http.StatusNotFound)
			return
		}
		if !f.faults.DropWrites {
			f.tables[table] = append(f.tables[table][:i:i], f.tables[table][i+1:]...)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}
