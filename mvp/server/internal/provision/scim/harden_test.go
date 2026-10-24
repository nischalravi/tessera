package scim_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/scim"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

// quirkServer is a small in-memory SCIM service whose behaviour is switched by
// flags: what its ServiceProviderConfig advertises and which PATCH dialect it
// insists on. It records the methods it saw.
type quirkServer struct {
	mu        sync.Mutex
	patch     bool // advertise and accept PATCH
	filter    bool // advertise and honour filters
	etag      bool
	maxResult int
	strictCap bool // reject lower-case op names (400 invalidValue)
	strBool   bool // reject JSON booleans for active (400 invalidValue)
	noValFilt bool // reject PATCH paths with a [value filter] (400 invalidPath)
	users     map[string]map[string]any
	groups    map[string]map[string]any
	methods   []string
	ifMatch   []string
	version   int
}

func newQuirkServer() *quirkServer {
	return &quirkServer{
		patch: true, filter: true,
		users: map[string]map[string]any{
			"u1": {"id": "u1", "userName": alice, "active": true},
			"u2": {"id": "u2", "userName": bob, "active": true},
		},
		groups: map[string]map[string]any{
			"g1": {"id": "g1", "displayName": "engineering", "externalId": "eng", "members": []any{map[string]any{"value": "u2"}}},
		},
	}
}

func (q *quirkServer) scimErr(w http.ResponseWriter, code int, typ, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": strconv.Itoa(code), "scimType": typ, "detail": detail})
}

func (q *quirkServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q.mu.Lock()
	defer q.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/scim/v2")
	q.methods = append(q.methods, r.Method+" "+path)
	w.Header().Set("Content-Type", "application/scim+json")
	if path == "/ResourceTypes" {
		_ = json.NewEncoder(w).Encode(map[string]any{"Resources": []any{map[string]any{"name": "User"}}})
		return
	}
	if path == "/ServiceProviderConfig" {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"patch":  map[string]any{"supported": q.patch},
			"bulk":   map[string]any{"supported": true, "maxOperations": 50},
			"filter": map[string]any{"supported": q.filter, "maxResults": q.maxResult},
			"etag":   map[string]any{"supported": q.etag},
		})
		return
	}
	var coll map[string]map[string]any
	var id string
	switch {
	case strings.HasPrefix(path, "/Users"):
		coll, id = q.users, strings.TrimPrefix(strings.TrimPrefix(path, "/Users"), "/")
	case strings.HasPrefix(path, "/Groups"):
		coll, id = q.groups, strings.TrimPrefix(strings.TrimPrefix(path, "/Groups"), "/")
	default:
		http.NotFound(w, r)
		return
	}
	switch {
	case r.Method == http.MethodGet && id == "":
		q.list(w, r, coll)
	case r.Method == http.MethodGet:
		doc, ok := coll[id]
		if !ok {
			q.scimErr(w, 404, "", "no such resource")
			return
		}
		if q.etag {
			w.Header().Set("ETag", fmt.Sprintf(`W/"%d"`, q.version))
		}
		_ = json.NewEncoder(w).Encode(doc)
	case r.Method == http.MethodPatch || r.Method == http.MethodPut || r.Method == http.MethodDelete:
		q.write(w, r, coll, id)
	default:
		http.Error(w, "unsupported", http.StatusMethodNotAllowed)
	}
}

func (q *quirkServer) list(w http.ResponseWriter, r *http.Request, coll map[string]map[string]any) {
	f := r.URL.Query().Get("filter")
	if f != "" && !q.filter {
		q.scimErr(w, 400, "invalidFilter", "filtering is not supported")
		return
	}
	var all []map[string]any
	for _, k := range []string{"g1", "u1", "u2"} { // stable order
		d, ok := coll[k]
		if !ok {
			continue
		}
		if f != "" {
			_, val, _ := strings.Cut(f, ` eq "`)
			val = strings.TrimSuffix(val, `"`)
			if d["userName"] != val && d["displayName"] != val && d["externalId"] != val {
				continue
			}
		}
		all = append(all, d)
	}
	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	if q.maxResult > 0 && count > q.maxResult {
		count = q.maxResult
	}
	if start < 1 {
		start = 1
	}
	end := start - 1 + count
	if end > len(all) {
		end = len(all)
	}
	page := []map[string]any{}
	if start-1 < len(all) {
		page = all[start-1 : end]
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"totalResults": len(all), "startIndex": start, "itemsPerPage": len(page), "Resources": page})
}

func (q *quirkServer) write(w http.ResponseWriter, r *http.Request, coll map[string]map[string]any, id string) {
	doc, ok := coll[id]
	if !ok {
		q.scimErr(w, 404, "", "no such resource")
		return
	}
	if im := r.Header.Get("If-Match"); im != "" {
		q.ifMatch = append(q.ifMatch, im)
		if im != fmt.Sprintf(`W/"%d"`, q.version) {
			q.scimErr(w, 412, "", "stale")
			return
		}
	} else if q.etag && r.Method != http.MethodDelete {
		q.scimErr(w, 428, "", "If-Match required")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		delete(coll, id)
	case http.MethodPut:
		var nd map[string]any
		_ = json.NewDecoder(r.Body).Decode(&nd)
		coll[id] = nd
	case http.MethodPatch:
		if !q.patch {
			q.scimErr(w, 501, "", "PATCH not implemented")
			return
		}
		var body struct {
			Operations []map[string]any `json:"Operations"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, o := range body.Operations {
			op, _ := o["op"].(string)
			path, _ := o["path"].(string)
			if q.strictCap && op != strings.ToUpper(op[:1])+op[1:] {
				q.scimErr(w, 400, "invalidSyntax", "op must be capitalised")
				return
			}
			if q.noValFilt && strings.Contains(path, "[") {
				q.scimErr(w, 400, "invalidPath", "filter paths unsupported")
				return
			}
			if _, isBool := o["value"].(bool); q.strBool && isBool {
				q.scimErr(w, 400, "invalidValue", "booleans are strings")
				return
			}
			switch {
			case strings.HasPrefix(path, "members"):
				cur, _ := doc["members"].([]any)
				var keep []any
				switch strings.ToLower(op) {
				case "add":
					keep = append(keep, cur...)
					keep = append(keep, o["value"].([]any)...)
				case "remove":
					drop := ""
					if v, ok := o["value"].([]any); ok && len(v) > 0 {
						drop, _ = v[0].(map[string]any)["value"].(string)
					} else if _, rest, ok := strings.Cut(path, `value eq "`); ok {
						drop = strings.TrimSuffix(rest, `"]`)
					}
					for _, m := range cur {
						if m.(map[string]any)["value"] != drop {
							keep = append(keep, m)
						}
					}
				}
				doc["members"] = keep
			case path == "active":
				switch v := o["value"].(type) {
				case string:
					doc["active"] = strings.EqualFold(v, "true")
				default:
					doc["active"] = v
				}
			default:
				doc[path] = o["value"]
			}
		}
	}
	q.version++
	w.WriteHeader(http.StatusNoContent)
}

func (q *quirkServer) client(t *testing.T) *scim.Client {
	t.Helper()
	srv := httptest.NewServer(q)
	t.Cleanup(srv.Close)
	return &scim.Client{HTTP: httpClient(t), BaseURL: srv.URL + "/scim/v2", Token: "tok"}
}

func (q *quirkServer) saw(prefix string) int {
	n := 0
	for _, m := range q.methods {
		if strings.HasPrefix(m, prefix) {
			n++
		}
	}
	return n
}

func TestQuirks_PatchDialects(t *testing.T) {
	tests := []struct {
		name    string
		srv     func(*quirkServer)
		quirks  scim.Quirks
		wantErr bool
	}{
		{"standard server, unknown quirks", func(*quirkServer) {}, scim.UnknownQuirks(), false},
		{"capitalised ops needed, title quirk", func(q *quirkServer) { q.strictCap = true }, scim.Quirks{OpCase: scim.CaseTitle}, false},
		{"capitalised ops needed, quirk unknown", func(q *quirkServer) { q.strictCap = true }, scim.UnknownQuirks(), true},
		{"string booleans needed, quirk set", func(q *quirkServer) { q.strBool = true }, scim.Quirks{BoolAsString: scim.Yes}, false},
		{"string booleans needed, quirk unknown", func(q *quirkServer) { q.strBool = true }, scim.UnknownQuirks(), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := newQuirkServer()
			tc.srv(q)
			c := q.client(t)
			c.Quirks = tc.quirks
			err := c.Apply(context.Background(), req(target.DisableAccount, alice))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if !tc.wantErr && q.users["u1"]["active"] != false {
				t.Fatalf("user not disabled: %v", q.users["u1"])
			}
		})
	}
}

func TestQuirks_MemberRemoveStyles(t *testing.T) {
	tests := []struct {
		name       string
		noValFilt  bool
		quirks     scim.Quirks
		wantFilter bool // a PATCH was sent with a filter path first
	}{
		{"unknown: filter first, falls back to value list", true, scim.UnknownQuirks(), true},
		{"value_filter_ok=no goes straight to the value list", true, scim.Quirks{ValueFilterOK: scim.No}, false},
		{"member_remove=value goes straight to the value list", true, scim.Quirks{MemberRemove: scim.RemoveByValue}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := newQuirkServer()
			q.noValFilt = tc.noValFilt
			c := q.client(t)
			c.Quirks = tc.quirks
			if err := c.Apply(context.Background(), member(target.RemoveEntitlement, bob)); err != nil {
				t.Fatal(err)
			}
			if m, _ := q.groups["g1"]["members"].([]any); len(m) != 0 {
				t.Fatalf("members = %v", m)
			}
			if got := q.saw("PATCH /Groups/g1"); (got == 2) != tc.wantFilter {
				t.Fatalf("PATCH count = %d, wantFilter %v", got, tc.wantFilter)
			}
		})
	}
}

func TestDiscover_Capabilities(t *testing.T) {
	q := newQuirkServer()
	q.patch, q.filter, q.etag, q.maxResult = false, false, true, 25
	c := q.client(t)
	d, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := scim.Capabilities{Patch: scim.No, Bulk: scim.Yes, Filter: scim.No, ETag: scim.Yes, BulkMaxOperations: 50, FilterMaxResults: 25}
	if d.Capabilities == nil || *d.Capabilities != want {
		t.Fatalf("capabilities = %+v, want %+v", d.Capabilities, want)
	}
}

func TestHardening_PutWhenPatchUnsupported(t *testing.T) {
	q := newQuirkServer()
	q.patch = false
	c := q.client(t)
	ctx := context.Background()
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, req(target.DisableAccount, alice)); err != nil {
		t.Fatal(err)
	}
	if q.users["u1"]["active"] != false {
		t.Fatalf("user not disabled via PUT: %v", q.users["u1"])
	}
	if err := c.Apply(ctx, member(target.AddEntitlement, alice)); err != nil {
		t.Fatal(err)
	}
	if q.saw("PATCH") != 0 || q.saw("PUT /Users/u1") != 1 || q.saw("PUT /Groups/g1") != 1 {
		t.Fatalf("methods = %v", q.methods)
	}
	v, err := c.Verify(ctx, member(target.AddEntitlement, alice))
	if err != nil || !v.OK {
		t.Fatalf("verify = %+v, %v", v, err)
	}
	if err := c.Apply(ctx, member(target.RemoveEntitlement, bob)); err != nil {
		t.Fatal(err)
	}
	if m := q.groups["g1"]["members"].([]any); len(m) != 1 {
		t.Fatalf("members after remove = %v", m)
	}
}

func TestHardening_PutAfterUnadvertisedNotImplemented(t *testing.T) {
	// The document says PATCH works; the service answers 501 anyway.
	q := newQuirkServer()
	c := q.client(t)
	q.patch = true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusNotImplemented)
			return
		}
		q.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	c.BaseURL = srv.URL + "/scim/v2"
	if err := c.Apply(context.Background(), req(target.DisableAccount, alice)); err != nil {
		t.Fatal(err)
	}
	if q.users["u1"]["active"] != false || q.saw("PUT /Users/u1") != 1 {
		t.Fatalf("state %v methods %v", q.users["u1"], q.methods)
	}
}

func TestHardening_NoFilterListsWholeCollection(t *testing.T) {
	q := newQuirkServer()
	q.filter, q.maxResult = false, 1 // one resource a page
	c := q.client(t)
	ctx := context.Background()
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, member(target.AddEntitlement, bob)); err != nil { // already a member: no write
		t.Fatal(err)
	}
	if err := c.Apply(ctx, req(target.DisableAccount, bob)); err != nil {
		t.Fatal(err)
	}
	if q.users["u2"]["active"] != false {
		t.Fatalf("bob not disabled: %v", q.users["u2"])
	}
	// Walked page by page (count capped at 1), never sent a filter.
	if q.saw("GET /Users") < 2 {
		t.Fatalf("methods = %v", q.methods)
	}
}

func TestHardening_ETag(t *testing.T) {
	q := newQuirkServer()
	q.etag = true
	c := q.client(t)
	ctx := context.Background()
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, req(target.DisableAccount, alice)); err != nil {
		t.Fatal(err)
	}
	if len(q.ifMatch) != 1 || q.users["u1"]["active"] != false {
		t.Fatalf("If-Match = %v, user %v", q.ifMatch, q.users["u1"])
	}
	// Without discovery no tag is read, and a server that demands one answers 428.
	c2 := q.client(t)
	err := c2.Apply(ctx, req(target.DisableAccount, bob))
	if err == nil {
		t.Fatal("expected 428 without ETag support discovered")
	}
}

func TestHardening_PreconditionFailedIsRetryable(t *testing.T) {
	q := newQuirkServer()
	q.etag = true
	c := q.client(t)
	ctx := context.Background()
	if _, err := c.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	// A proxy that bumps the version between the tag read and the write.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			q.mu.Lock()
			q.version++
			q.mu.Unlock()
		}
		q.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	c.BaseURL = srv.URL + "/scim/v2"
	err := c.Apply(ctx, req(target.DisableAccount, alice))
	te, ok := err.(*target.Error)
	if !ok || te.Status != http.StatusPreconditionFailed || !te.Retryable {
		t.Fatalf("err = %#v", err)
	}
}

func TestErrors_ScimTypeMapping(t *testing.T) {
	tests := []struct {
		scimType string
		wantSub  string
	}{
		{"invalidPath", "PATCH path was refused"},
		{"invalidValue", "boolean quirk"},
		{"mutability", "read-only"},
		{"madeUpType", "service said"},
	}
	for _, tc := range tests {
		t.Run(tc.scimType, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					_, _ = w.Write([]byte(`{"totalResults":1,"Resources":[{"id":"u1","userName":"` + alice + `","active":true}]}`))
					return
				}
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"scimType":"` + tc.scimType + `","detail":"service said no"}`))
			}))
			t.Cleanup(srv.Close)
			c := &scim.Client{HTTP: httpClient(t), BaseURL: srv.URL}
			err := c.Apply(context.Background(), req(target.DisableAccount, alice))
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantSub)
			}
		})
	}
}
