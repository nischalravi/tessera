package api

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

type v1Err struct {
	Error struct {
		Code    string         `json:"code"`
		Message string         `json:"message"`
		Field   string         `json:"field"`
		Details map[string]any `json:"details"`
	} `json:"error"`
}

func TestV1ErrorBody(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		status               int
		body                 string
		code, message, field string
		details              []string
	}{
		{"detail only", 404, `{"detail":"identity not found"}`, "not_found", "identity not found", "", nil},
		{"error and detail", 409, `{"error":"already_exists","detail":"a group with that name exists"}`, "already_exists", "a group with that name exists", "", nil},
		{"code only", 429, `{"error":"rate_limited"}`, "rate_limited", "Too Many Requests", "", nil},
		{"denial keeps its fields", 403, `{"error":"forbidden","permission":"graph.read"}`, "forbidden", "Forbidden", "", []string{"permission"}},
		{"step-up challenge", 401, `{"error":"step_up_required","acr":"phr","max_age":300,"step_up_url":"/x"}`, "step_up_required", "Unauthorized", "", []string{"acr", "max_age", "step_up_url"}},
		{"validation list", 422, `{"detail":[{"loc":["body","name"],"msg":"Field required","type":"missing"}]}`, "validation_error", "Field required", "name", []string{"errors"}},
		{"validation nested", 422, `{"detail":[{"loc":["query","limit"],"msg":"bad","type":"x"},{"loc":["body","a"],"msg":"y","type":"x"}]}`, "validation_error", "bad", "limit", []string{"errors"}},
		{"route names the field", 422, `{"error":"invalid_name","detail":"name is required","field":"name"}`, "invalid_name", "name is required", "name", nil},
		{"plain text", 500, "Internal Server Error\n", "internal_error", "Internal Server Error", "", nil},
		{"html is never echoed", 400, "<script>alert(1)</script>", "bad_request", "Bad Request", "", nil},
		{"empty", 503, "", "service_unavailable", "Service Unavailable", "", nil},
		{"unknown status", 418, `{}`, "client_error", "I'm a teapot", "", nil},
	} {
		var e v1Err
		if err := json.Unmarshal(v1ErrorBody(tc.status, []byte(tc.body)), &e); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if e.Error.Code != tc.code || e.Error.Message != tc.message || e.Error.Field != tc.field || len(e.Error.Details) != len(tc.details) {
			t.Errorf("%s: %+v, want %s / %s / %s / %v", tc.name, e.Error, tc.code, tc.message, tc.field, tc.details)
		}
		for _, k := range tc.details {
			if _, ok := e.Error.Details[k]; !ok {
				t.Errorf("%s: details lack %s", tc.name, k)
			}
		}
	}
}

func TestV1ListBody(t *testing.T) {
	pg := v1Page{offset: 0, limit: 2, fp: "abc"}
	var got struct {
		Items []int   `json:"items"`
		Next  *string `json:"next_cursor"`
	}
	// an array is cut, with a cursor while rows remain
	if err := json.Unmarshal(v1ListBody([]byte(`[1,2,3,4,5]`), pg), &got); err != nil || len(got.Items) != 2 || got.Next == nil {
		t.Fatalf("first page: %+v %v", got, err)
	}
	if off, ok := v1DecodeCursor(*got.Next, "abc"); !ok || off != 2 {
		t.Errorf("cursor = %d %v", off, ok)
	}
	pg.offset = 4
	got.Next = nil
	if err := json.Unmarshal(v1ListBody([]byte(`[1,2,3,4,5]`), pg), &got); err != nil || len(got.Items) != 1 || got.Next != nil {
		t.Errorf("last page: %+v %v", got, err)
	}
	pg.offset = 9 // past the end
	if string(v1ListBody([]byte(`[1]`), pg)) != `{"items":[],"next_cursor":null}` {
		t.Errorf("past the end: %s", v1ListBody([]byte(`[1]`), pg))
	}
	if string(v1ListBody([]byte(`[]`), v1Page{limit: 2})) != `{"items":[],"next_cursor":null}` {
		t.Error("empty list")
	}
	// a native page keeps its shape and gains next_cursor
	pg = v1Page{limit: 2, fp: "abc"}
	var nat struct {
		Items  []int   `json:"items"`
		Total  int     `json:"total"`
		Offset int     `json:"offset"`
		Next   *string `json:"next_cursor"`
	}
	out := v1ListBody([]byte(`{"items":[1,2],"limit":2,"offset":0,"total":5}`), pg)
	if err := json.Unmarshal(out, &nat); err != nil || nat.Next == nil || nat.Total != 5 {
		t.Fatalf("native: %s %v", out, err)
	}
	if off, _ := v1DecodeCursor(*nat.Next, "abc"); off != 2 {
		t.Errorf("native cursor offset %d", off)
	}
	for body, wantNext := range map[string]string{
		`{"items":[5],"limit":2,"offset":4,"total":5}`: "null",
		`{"items":[1,2],"limit":2,"offset":0}`:         "",
		`{"items":[1],"limit":2,"offset":0}`:           "null",
		`{"items":[],"limit":2,"offset":0}`:            "null",
	} {
		out := string(v1ListBody([]byte(body), pg))
		if (wantNext == "null") != strings.HasSuffix(out, `"next_cursor":null}`) {
			t.Errorf("%s -> %s", body, out)
		}
	}
	// anything else is untouched
	for _, b := range []string{`{"total":3}`, `"text"`, `{"items":[1]}`, ``} {
		if string(v1ListBody([]byte(b), pg)) != b {
			t.Errorf("%q was changed", b)
		}
	}
}

func TestV1Cursor(t *testing.T) {
	fp := v1Fingerprint("/api/x", url.Values{"filter": {"a"}, "limit": {"5"}})
	if fp != v1Fingerprint("/api/x", url.Values{"filter": {"a"}, "limit": {"9"}, "cursor": {"zzz"}}) {
		t.Error("paging parameters changed the fingerprint")
	}
	if fp == v1Fingerprint("/api/x", url.Values{"filter": {"b"}}) || fp == v1Fingerprint("/api/y", url.Values{"filter": {"a"}}) {
		t.Error("a different filter or route kept the fingerprint")
	}
	c := v1EncodeCursor(40, fp)
	if off, ok := v1DecodeCursor(c, fp); !ok || off != 40 {
		t.Errorf("round trip = %d %v", off, ok)
	}
	for _, bad := range []string{"", "!!!", v1EncodeCursor(1, "other"), "MQ", "LTEuYWJj" /* -1.abc */} {
		if _, ok := v1DecodeCursor(bad, fp); ok {
			t.Errorf("cursor %q accepted", bad)
		}
	}
}

// TestV1_ErrorEnvelope: errors on /api/v1 use the envelope, the same requests
// on /api/ keep their shape.
func TestV1_ErrorEnvelope(t *testing.T) {
	t.Parallel()
	f, srv := v1Fixture(t)
	h := srv.Handler()
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	anon := newIsolationServer(f).Handler()
	for _, tc := range []struct {
		name, method, path, body string
		h                        func(method, path, body string) (int, string)
		status                   int
		code                     string
		old                      string // the unversioned body
	}{
		{"unknown route", "GET", "/api/no-such", "", func(m, p, b string) (int, string) { r := serveOnce(h, m, p, b); return r.Code, r.Body.String() }, 404, "not_found", `{"detail":"Not Found"}`},
		{"no session", "GET", "/api/summary", "", func(m, p, b string) (int, string) { r := serveOnce(anon, m, p, b); return r.Code, r.Body.String() }, 401, "login_required", `{"error":"login_required"}`},
		{"forbidden", "GET", "/api/admin/api-clients", "", func(m, p, b string) (int, string) {
			r := reqDo(h, viewer, m, p, b)
			return r.Code, r.Body.String()
		}, 403, "forbidden", ""},
		{"missing identity", "GET", "/api/identities/99999999", "", func(m, p, b string) (int, string) { r := serveOnce(h, m, p, b); return r.Code, r.Body.String() }, 404, "not_found", `{"detail":"identity not found"}`},
	} {
		st, raw := tc.h(tc.method, strings.Replace(tc.path, "/api/", "/api/v1/", 1), tc.body)
		var e v1Err
		if err := json.Unmarshal([]byte(raw), &e); err != nil || st != tc.status || e.Error.Code != tc.code || e.Error.Message == "" {
			t.Errorf("%s v1: %d %s", tc.name, st, raw)
		}
		ost, oraw := tc.h(tc.method, tc.path, tc.body)
		if ost != tc.status || (tc.old != "" && strings.TrimSpace(oraw) != tc.old) || strings.Contains(oraw, `"message"`) {
			t.Errorf("%s unversioned changed: %d %s", tc.name, ost, oraw)
		}
	}
}

// TestV1_Pagination walks a list by cursor and reads the same rows as the
// unversioned array; bad limits and cursors are refused (and audited).
func TestV1_Pagination(t *testing.T) {
	t.Parallel()
	f, srv := v1Fixture(t)
	h := srv.Handler()
	var all []struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal(serveOnce(h, "GET", "/api/identities", "").Body.Bytes(), &all); err != nil || len(all) < 5 {
		t.Fatalf("identities: %d rows, %v", len(all), err)
	}
	type page struct {
		Items []struct {
			ID int `json:"id"`
		} `json:"items"`
		Next *string `json:"next_cursor"`
	}
	for _, path := range []string{"/api/v1/identities?limit=2", "/api/v1/identities?limit=2&sort=name"} {
		var seen []int
		cursor, pages := "", 0
		for {
			p := path
			if cursor != "" {
				p += "&cursor=" + url.QueryEscape(cursor)
			}
			rec := serveOnce(h, "GET", p, "")
			var pg page
			if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &pg) != nil || len(pg.Items) == 0 || len(pg.Items) > 2 {
				t.Fatalf("%s: %d %.200s", p, rec.Code, rec.Body)
			}
			for _, it := range pg.Items {
				seen = append(seen, it.ID)
			}
			pages++
			if pg.Next == nil {
				break
			}
			cursor = *pg.Next
			if pages > 100 {
				t.Fatal("no end")
			}
		}
		if len(seen) != len(all) || pages != (len(all)+1)/2 {
			t.Errorf("%s: %d rows in %d pages, want %d", path, len(seen), pages, len(all))
		}
		for i, id := range seen {
			if id != all[i].ID {
				t.Fatalf("%s: row %d is %d, want %d", path, i, id, all[i].ID)
			}
		}
	}
	// default limit: everything fits
	var pg page
	if err := json.Unmarshal(serveOnce(h, "GET", "/api/v1/identities", "").Body.Bytes(), &pg); err != nil || len(pg.Items) != len(all) || pg.Next != nil {
		t.Errorf("default page: %d items, next %v, %v", len(pg.Items), pg.Next, err)
	}
	// a route that takes no paging parameters is not refused by them
	if rec := serveOnce(h, "GET", "/api/v1/policies?limit=2", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"items"`) {
		t.Errorf("policies: %d %.200s", rec.Code, rec.Body)
	}
	// the audit log is windowed: pages do not overlap
	var a1, a2 struct {
		Items []struct {
			ID int `json:"id"`
		} `json:"items"`
		Next *string `json:"next_cursor"`
	}
	if err := json.Unmarshal(serveOnce(h, "GET", "/api/v1/audit?limit=3", "").Body.Bytes(), &a1); err != nil || len(a1.Items) != 3 || a1.Next == nil {
		t.Fatalf("audit page 1: %+v %v", a1, err)
	}
	if err := json.Unmarshal(serveOnce(h, "GET", "/api/v1/audit?limit=3&cursor="+url.QueryEscape(*a1.Next), "").Body.Bytes(), &a2); err != nil || len(a2.Items) == 0 {
		t.Fatalf("audit page 2: %+v %v", a2, err)
	}
	for _, x := range a2.Items {
		for _, y := range a1.Items {
			if x.ID == y.ID {
				t.Errorf("audit row %d on both pages", x.ID)
			}
		}
	}
	// refusals: bad limits and cursors, a cursor of another list, all in the envelope and audited
	other := *a1.Next
	for name, p := range map[string]string{"limit 0": "/api/v1/identities?limit=0", "limit 501": "/api/v1/identities?limit=501",
		"limit text": "/api/v1/identities?limit=x", "cursor junk": "/api/v1/identities?cursor=junk",
		"cursor of another list": "/api/v1/identities?cursor=" + url.QueryEscape(other)} {
		before := len(httpEvents(ledger(t, f.DB, f.B.ID)))
		rec := serveOnce(h, "GET", p, "")
		var e v1Err
		if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || rec.Code != 400 || !strings.HasPrefix(e.Error.Code, "invalid_") || e.Error.Field == "" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
		if strings.Contains(rec.Body.String(), "junk") {
			t.Errorf("%s: input echoed: %s", name, rec.Body)
		}
		if n := len(httpEvents(ledger(t, f.DB, f.B.ID))); n != before+1 {
			t.Errorf("%s: %d events written, want 1", name, n-before)
		}
	}
	// the unversioned list is untouched by all of it
	if rec := serveOnce(h, "GET", "/api/identities?limit=2", ""); !strings.HasPrefix(rec.Body.String(), "[") && rec.Code == 200 {
		t.Errorf("unversioned identities changed: %.100s", rec.Body)
	}
	_ = fmt.Sprint
}
