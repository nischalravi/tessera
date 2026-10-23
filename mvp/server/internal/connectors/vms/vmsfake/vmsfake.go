// Package vmsfake is an in-process Fieldglass or Beeline: an http.Handler that
// answers the token and listing requests of internal/connectors/vms with a
// configurable set of workers, pages and faults. Tests and the dev server use
// it in place of a real vendor tenant (issue #304); like oauthfake, it keeps
// the contract the reader relies on in one place.
package vmsfake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Worker is one assignment, in vendor-neutral form.
type Worker struct {
	ID, First, Last, Email  string
	Status                  string // the vendor's own text (Fieldglass "Active", Beeline "active")
	Start, End              string // YYYY-MM-DD
	Supplier, Role          string
	ManagerEmail, ManagerID string
	Modified                time.Time
	// Custom is sent as the worker's "custom_fields" object (both vendors), for field-mapping tests.
	Custom map[string]any
}

// Faults to inject.
type Faults struct {
	TokenStatus    int  // answer the token request with this status
	ListStatus     int  // answer every listing with this status
	Throttle       int  // answer this many listings with 429 first
	Malformed      bool // answer a listing with text that is not JSON
	NextOffOrigin  bool // point the next-page link at another host
	LoopForever    bool // every page links to itself
	WrongTokenType bool
}

// Fake is a vendor tenant.
type Fake struct {
	Vendor       string // fieldglass | beeline
	ClientID     string
	ClientSecret string
	PageSize     int

	mu       sync.Mutex
	workers  []Worker
	faults   Faults
	tokens   int
	lists    int
	queries  []string
	issued   string
	throttle int
}

// New returns a fake of the vendor with the credential it accepts.
func New(vendor, clientID, clientSecret string) *Fake {
	return &Fake{Vendor: vendor, ClientID: clientID, ClientSecret: clientSecret, PageSize: 2, issued: "tok-" + vendor}
}

// Set replaces the workers.
func (f *Fake) Set(ws ...Worker) {
	f.mu.Lock()
	f.workers = append([]Worker(nil), ws...)
	f.mu.Unlock()
}

// SetFaults replaces the injected faults.
func (f *Fake) SetFaults(x Faults) {
	f.mu.Lock()
	f.faults, f.throttle = x, x.Throttle
	f.mu.Unlock()
}

// Counts returns the token and listing requests seen.
func (f *Fake) Counts() (tokens, lists int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens, f.lists
}

// Queries returns the raw query of every listing request.
func (f *Fake) Queries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

func (f *Fake) listPath() string {
	if f.Vendor == "beeline" {
		return "/api/v2/assignments"
	}
	return "/api/v1/workers"
}

// ServeHTTP implements http.Handler.
func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/api/oauth2/v2.0/token" && r.Method == http.MethodPost:
		f.token(w, r)
	case r.URL.Path == f.listPath() && r.Method == http.MethodGet:
		f.list(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) token(w http.ResponseWriter, r *http.Request) {
	f.tokens++
	if f.faults.TokenStatus != 0 {
		w.WriteHeader(f.faults.TokenStatus)
		fmt.Fprint(w, `{"error":"invalid_client"}`)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok || id != f.ClientID || secret != f.ClientSecret || r.FormValue("grant_type") != "client_credentials" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_client"}`)
		return
	}
	typ := "Bearer"
	if f.faults.WrongTokenType {
		typ = "MAC"
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token":%q,"token_type":%q,"expires_in":3600}`, f.issued, typ)
}

func (f *Fake) list(w http.ResponseWriter, r *http.Request) {
	f.lists++
	f.queries = append(f.queries, r.URL.RawQuery)
	if r.Header.Get("Authorization") != "Bearer "+f.issued {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_token"}`)
		return
	}
	switch {
	case f.throttle > 0:
		f.throttle--
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	case f.faults.ListStatus != 0:
		w.WriteHeader(f.faults.ListStatus)
		fmt.Fprint(w, `{"error":"server_error","error_description":"leaky-body-should-never-surface"}`)
		return
	case f.faults.Malformed:
		fmt.Fprint(w, `<html>maintenance</html>`)
		return
	}
	q := r.URL.Query()
	var since time.Time
	for _, k := range []string{"modified_after", "modified_since"} {
		if v := q.Get(k); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			since = t
		}
	}
	var sel []Worker
	for _, x := range f.workers {
		if since.IsZero() || x.Modified.After(since) {
			sel = append(sel, x)
		}
	}
	page, err := strconv.Atoi(q.Get("page"))
	if q.Get("page") != "" && (err != nil || page < 0 || page > 10000) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	size := f.PageSize
	if size <= 0 {
		size = 2
	}
	lo, hi := page*size, min((page+1)*size, len(sel))
	if lo > len(sel) {
		lo = len(sel)
	}
	next := ""
	host := r.Host
	if !hostRE.MatchString(host) {
		host = "invalid.example" // a request header is never echoed unchecked
	}
	if f.faults.NextOffOrigin {
		host = "evil.example"
	}
	// the link is built from the fixed path and numbers, never from request text
	link := func(p int) string {
		nq := url.Values{"page": {strconv.Itoa(p)}}
		for _, k := range []string{"modified_after", "modified_since"} {
			if t, err := time.Parse(time.RFC3339, q.Get(k)); err == nil {
				nq.Set(k, t.UTC().Format(time.RFC3339))
			}
		}
		return "https://" + host + f.listPath() + "?" + nq.Encode()
	}
	switch {
	case f.faults.LoopForever:
		next = link(page)
	case hi < len(sel):
		next = link(page + 1)
	}
	w.Header().Set("Content-Type", "application/json")
	if f.Vendor == "beeline" {
		f.beeline(w, sel[lo:hi], next)
		return
	}
	f.fieldglass(w, sel[lo:hi], next)
}

func (f *Fake) fieldglass(w http.ResponseWriter, ws []Worker, next string) {
	out := make([]map[string]any, 0, len(ws))
	for _, x := range ws {
		m := map[string]any{"worker_id": x.ID, "first_name": x.First, "last_name": x.Last, "email": x.Email,
			"status": x.Status, "start_date": x.Start, "end_date": x.End, "supplier_name": x.Supplier, "job_title": x.Role,
			"buyer_manager_email": x.ManagerEmail, "buyer_manager_id": x.ManagerID, "modified_at": x.Modified.UTC().Format(time.RFC3339)}
		if x.Custom != nil {
			m["custom_fields"] = x.Custom
		}
		out = append(out, m)
	}
	var n any
	if next != "" {
		n = next
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"workers": out, "next_page": n})
}

func (f *Fake) beeline(w http.ResponseWriter, ws []Worker, next string) {
	out := make([]map[string]any, 0, len(ws))
	for _, x := range ws {
		m := map[string]any{"id": x.ID, "state": strings.ToLower(x.Status), "start": x.Start, "end": x.End,
			"vendor": x.Supplier, "position": x.Role, "updated": x.Modified.UTC().Format(time.RFC3339),
			"worker":  map[string]string{"first_name": x.First, "last_name": x.Last, "email": x.Email},
			"manager": map[string]string{"email": x.ManagerEmail, "employee_id": x.ManagerID}}
		if x.Custom != nil {
			m["custom_fields"] = x.Custom
		}
		out = append(out, m)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": out, "links": map[string]string{"next": next}})
}

var hostRE = regexp.MustCompile(`^[A-Za-z0-9.:\[\]-]{1,255}$`)
