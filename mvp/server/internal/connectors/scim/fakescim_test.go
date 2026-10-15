package scim_test

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/scim"
)

const (
	testToken = "tok-0123456789abcdef-SENTINEL"
	basePath  = "/scim/v2"
)

// fakeSCIM is an in-process SCIM 2.0 service (RFC 7643, 7644) with switches
// that make it misbehave in the ways real applications do. The zero value of
// every switch is the healthy behaviour. It serves reads only and records
// every request so tests can prove the prober sent nothing but GET.
type fakeSCIM struct {
	// ---- switches
	Missing               map[string]bool // discovery path ("Schemas") answers 404
	NoGroupResourceType   bool            // ResourceTypes lists User only
	TotalDelta            int             // added to every totalResults
	IgnoreStartIndex      bool            // always serves from the first resource
	IgnoreCount           bool            // serves 100 per page whatever count says
	NoStartIndexEcho      bool            // startIndex in the reply is always 1
	TruncateListMembers   int             // members capped at N on group list calls
	TruncateGetMembers    int             // members capped at N on group GET (0 = no cap)
	OmitListMembers       bool            // list calls return groups without members
	UsersWithoutGroups    bool            // users carry no groups attribute
	NoGroups              bool            // the application has no groups
	Endless               bool            // a collection that never ends (huge totalResults)
	Throttle              int             // the first N requests answer 429
	AlwaysThrottle        bool            // every request answers 429
	RetryAfter            string          // Retry-After of a 429 ("" omits the header)
	Delay                 time.Duration   // every response is this slow
	RateLimit, RateRemain int             // X-RateLimit-* headers (0 omits)
	UserCount             int             // default 120
	Token                 string          // required bearer token (default testToken)

	mu       sync.Mutex
	requests int
	methods  []string
	auth     []string
	paths    []string
}

type member struct {
	Value string `json:"value"`
	Type  string `json:"type,omitempty"`
}

func userID(i int) string  { return fmt.Sprintf("u%03d", i) }
func groupID(i int) string { return fmt.Sprintf("g%d", i) }

// membership: g1 has 30 users, g2 has 5, g3 has 2 (an admin group).
func (f *fakeSCIM) groupMembers(g int) []member {
	n := map[int]int{1: 30, 2: 5, 3: 2}[g]
	out := make([]member, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, member{Value: userID(i), Type: "User"})
	}
	return out
}

func (f *fakeSCIM) users() int {
	if f.UserCount > 0 {
		return f.UserCount
	}
	return 120
}

func (f *fakeSCIM) userGroups(i int) []member {
	var gs []member
	for g := 1; g <= 3; g++ {
		for _, m := range f.groupMembers(g) {
			if m.Value == userID(i) {
				gs = append(gs, member{Value: groupID(g)})
			}
		}
	}
	return gs
}

func (f *fakeSCIM) user(i int) map[string]any {
	u := map[string]any{"id": userID(i), "userName": fmt.Sprintf("user%d@example.org", i), "active": true}
	if !f.UsersWithoutGroups {
		u["groups"] = f.userGroups(i)
	}
	return u
}

func (f *fakeSCIM) group(g int, list bool) map[string]any {
	out := map[string]any{"id": groupID(g), "displayName": fmt.Sprintf("Group %d", g)}
	if list && f.OmitListMembers {
		return out
	}
	ms := f.groupMembers(g)
	cap := 0
	if list {
		cap = f.TruncateListMembers
	} else {
		cap = f.TruncateGetMembers
	}
	if cap > 0 && len(ms) > cap {
		ms = ms[:cap]
	}
	out["members"] = ms
	return out
}

// Requests returns a copy of what the server saw.
func (f *fakeSCIM) seen() (n int, methods, auth, paths []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests, append([]string(nil), f.methods...), append([]string(nil), f.auth...), append([]string(nil), f.paths...)
}

func (f *fakeSCIM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests++
	n := f.requests
	f.methods = append(f.methods, r.Method)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()

	if f.Delay > 0 {
		time.Sleep(f.Delay)
	}
	if f.RateLimit > 0 {
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(f.RateLimit))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(f.RateRemain))
	}
	if f.AlwaysThrottle || n <= f.Throttle {
		if f.RetryAfter != "" {
			w.Header().Set("Retry-After", f.RetryAfter)
		}
		http.Error(w, `{"status":"429"}`, http.StatusTooManyRequests)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "read only in this test", http.StatusMethodNotAllowed)
		return
	}
	token := f.Token
	if token == "" {
		token = testToken
	}
	if r.Header.Get("Authorization") != "Bearer "+token {
		http.Error(w, `{"status":"401"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/scim+json")
	path := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, basePath), "/")
	first, rest, _ := strings.Cut(path, "/")
	if f.Missing[first] {
		http.NotFound(w, r)
		return
	}
	switch first {
	case "ServiceProviderConfig":
		f.json(w, map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
			"patch": map[string]any{"supported": true}, "bulk": map[string]any{"supported": false},
			"filter": map[string]any{"supported": true, "maxResults": 100}, "etag": map[string]any{"supported": true},
			"sort": map[string]any{"supported": false}, "changePassword": map[string]any{"supported": false}})
	case "ResourceTypes":
		types := []map[string]any{{"id": "User", "name": "User"}, {"id": "Group", "name": "Group"}}
		if f.NoGroupResourceType {
			types = types[:1]
		}
		f.list(w, 1, 1, f.TotalDelta+len(types), anySlice(types))
	case "Schemas":
		f.list(w, 1, 1, 2+f.TotalDelta, anySlice([]map[string]any{{"id": "urn:ietf:params:scim:schemas:core:2.0:User"}, {"id": "urn:ietf:params:scim:schemas:core:2.0:Group"}}))
	case "Users":
		if rest != "" {
			http.NotFound(w, r)
			return
		}
		f.collection(w, r, f.users(), func(i int) any { return f.user(i) })
	case "Groups":
		if rest != "" {
			for g := 1; g <= 3; g++ {
				if groupID(g) == rest && !f.NoGroups {
					f.json(w, f.group(g, false))
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		total := 3
		if f.NoGroups {
			total = 0
		}
		f.collection(w, r, total, func(i int) any { return f.group(i, true) })
	default:
		http.NotFound(w, r)
	}
}

func anySlice[T any](in []T) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func (f *fakeSCIM) json(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }

func (f *fakeSCIM) list(w http.ResponseWriter, start, per, total int, res []any) {
	f.json(w, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": total, "startIndex": start, "itemsPerPage": per, "Resources": res})
}

// collection pages a 1-based collection of total resources, with the switches applied.
func (f *fakeSCIM) collection(w http.ResponseWriter, r *http.Request, total int, at func(i int) any) {
	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	count, err := strconv.Atoi(r.URL.Query().Get("count"))
	if start < 1 {
		start = 1
	}
	if err != nil || count > 100 {
		count = 100
	}
	if f.IgnoreCount {
		count = 100
	}
	if f.Endless {
		total = 1_000_000
	}
	from := start
	if f.IgnoreStartIndex {
		from = 1
	}
	res := []any{}
	for i := from; i < from+count && i <= total; i++ {
		res = append(res, at(i))
	}
	echo := start
	if f.NoStartIndexEcho {
		echo = 1
	}
	f.list(w, echo, len(res), total+f.TotalDelta, res)
}

// serve starts the fake behind TLS and returns it with a safehttp-backed
// client that trusts it (dev mode, loopback allowed: the dev exception the
// production guard refuses).
func serve(t *testing.T, f *fakeSCIM) (srv *httptest.Server, baseURL string, rootCAs *x509.CertPool) {
	t.Helper()
	srv = httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	rootCAs = x509.NewCertPool()
	rootCAs.AddCert(srv.Certificate())
	return srv, srv.URL + basePath, rootCAs
}

func devClient(t *testing.T, rootCAs *x509.CertPool, timeout time.Duration) *http.Client {
	t.Helper()
	hc, err := scim.NewClient(scim.ClientOptions{Env: config.Dev, AllowLoopback: true, RootCAs: rootCAs, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return hc
}
