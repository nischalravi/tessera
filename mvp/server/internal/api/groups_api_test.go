package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	grpapi "github.com/nischalravi/tessera/mvp/server/internal/groups/api"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The groups REST API (issue #48, GR-5): member filters, trace, batches with
// idempotency keys, the groups of an identity, the OpenAPI document and the
// isolation of all of it. Simulation is in groups_simulate_test.go and SCIM in
// scim_test.go.

// post sends a request with headers and decodes the JSON object answer.
func (c grpClient) post(method, path, body string, want int, hdr ...string) (map[string]any, *httptest.ResponseRecorder) {
	c.t.Helper()
	rec := c.do(method, path, body, hdr...)
	if rec.Code != want {
		c.t.Fatalf("%s %s %s: status %d, want %d: %.400s", method, path, body, rec.Code, want, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		c.t.Fatalf("%s %s: %v: %s", method, path, err, rec.Body.String())
	}
	return out, rec
}

func items(t *testing.T, got map[string]any) []map[string]any {
	t.Helper()
	raw, _ := got["items"].([]any)
	out := make([]map[string]any, len(raw))
	for i, r := range raw {
		out[i] = r.(map[string]any)
	}
	return out
}

// names lists a field of the items, in order.
func names(t *testing.T, got map[string]any, field string) []string {
	t.Helper()
	var out []string
	for _, it := range items(t, got) {
		out = append(out, fmt.Sprint(it[field]))
	}
	return out
}

func eq(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

func sorted(s []string) []string {
	slices.Sort(s)
	return s
}

func TestMembers_FiltersSearchSortAndPaging(t *testing.T) {
	c, f := newGrp(t)
	alice, bob, carol, dave := f.B.IDs["alice"], f.B.IDs["bob"], f.B.IDs["carol"], f.B.IDs["dave"]
	app := c.folder("", "app")
	team, staff, all := c.group(app, "team"), c.group(app, "staff"), c.group(app, "all")
	c.member(team, alice)
	c.member(team, bob)
	c.call("POST", "/api/groups/"+staff+"/members", `{"group":"`+team+`"}`, 201)
	c.member(staff, carol)
	c.member(staff, alice) // alice is both direct and nested in staff
	// a row that does not count yet: enabled in the future
	later := storetest.Now.Add(48 * time.Hour).Format(time.RFC3339)
	c.call("POST", "/api/groups/"+staff+"/members", fmt.Sprintf(`{"identity":%d,"enabled_from":%q}`, dave, later), 201)
	c.call("POST", "/api/groups/"+all+"/members", `{"group":"`+staff+`"}`, 201)

	list := func(group, qs string) map[string]any {
		return c.call("GET", "/api/groups/"+group+"/members"+qs, "", 200)
	}
	// direct: the rows (a group row and three identity rows)
	d := list(staff, "")
	if d["filter"] != "direct" || d["total"] != float64(4) {
		t.Fatalf("direct = %v", d)
	}
	// effective: alice, bob, carol (dave's row is not active yet)
	if got := list(staff, "?filter=effective"); got["total"] != float64(3) || !eq(names(t, got, "name"), []string{"Alice", "Bob", "Carol"}) {
		t.Errorf("effective = %v", got)
	}
	// indirect: only what arrives through nesting; alice also has a direct row, so she is not indirect
	if got := list(staff, "?filter=indirect"); got["total"] != float64(1) || !eq(names(t, got, "name"), []string{"Bob"}) {
		t.Errorf("indirect = %v", got)
	}
	if got := list(all, "?filter=indirect"); got["total"] != float64(3) {
		t.Errorf("indirect of a group with no direct identity rows = %v", got)
	}
	// composite: none for a basic group
	if got := list(staff, "?filter=composite"); got["total"] != nil && len(items(t, got)) != 0 {
		t.Errorf("composite of a basic group = %v", got)
	}
	// enabled: the row that counts and the one that does not
	if got := list(staff, "?enabled=true"); got["total"] != float64(3) {
		t.Errorf("enabled=true = %v", got)
	}
	if got := list(staff, "?enabled=false"); got["total"] != float64(1) || items(t, got)[0]["identity_id"] != float64(dave) ||
		items(t, got)[0]["active"] != false {
		t.Errorf("enabled=false = %v", got)
	}
	// q: a substring of the member's name (or email), without case
	if got := list(staff, "?filter=effective&q=ARO"); got["total"] != float64(1) || names(t, got, "name")[0] != "Carol" {
		t.Errorf("q = %v", got)
	}
	if got := list(staff, "?filter=effective&q=bob@"); got["total"] != float64(1) {
		t.Errorf("q by email = %v", got)
	}
	if got := list(staff, "?q=team"); got["total"] != float64(1) || items(t, got)[0]["type"] != "group" {
		t.Errorf("q finds a nested group by its name = %v", got)
	}
	// sort and paging: page 2 of size 2 of the names in descending order
	if got := list(staff, "?filter=effective&sort=-name"); !eq(names(t, got, "name"), []string{"Carol", "Bob", "Alice"}) {
		t.Errorf("sort=-name = %v", names(t, got, "name"))
	}
	pg := list(staff, "?filter=effective&sort=-name&limit=2&page=2")
	if pg["total"] != float64(3) || !eq(names(t, pg, "name"), []string{"Alice"}) {
		t.Errorf("page 2 = %v", pg)
	}
	if got := list(staff, "?filter=effective&sort=since&limit=1"); len(items(t, got)) != 1 {
		t.Errorf("sort=since = %v", got)
	}
	// list names the built-in list only
	list(staff, "?list=members")
	// a composite: its members come from its factors
	comp := c.group(app, "comp")
	c.call("POST", "/api/groups/"+comp+"/convert-to-composite", `{"op":"union","factors":["`+team+`","`+staff+`"]}`, 200)
	if got := list(comp, "?filter=composite"); got["total"] != float64(3) {
		t.Errorf("composite filter of a composite = %v", got)
	}

	for _, qs := range []string{"?filter=bogus", "?sort=size", "?enabled=maybe", "?filter=effective&enabled=true", "?list=other",
		"?page=0", "?page=x", "?page=2&offset=1", "?q=" + strings.Repeat("x", 256),
		"?as_of=" + storetest.Now.Format(time.RFC3339) + "&q=a", "?as_of=" + storetest.Now.Format(time.RFC3339) + "&sort=name"} {
		if rec := c.do("GET", "/api/groups/"+staff+"/members"+qs, ""); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("GET members%s = %d %.100s, want 422", qs, rec.Code, rec.Body.String())
		}
	}
}

func TestMembers_Trace(t *testing.T) {
	c, f := newGrp(t)
	alice, bob, carol := f.B.IDs["alice"], f.B.IDs["bob"], f.B.IDs["carol"]
	app := c.folder("", "app")
	team, staff, other, un, inter, minus := c.group(app, "team"), c.group(app, "staff"), c.group(app, "other"),
		c.group(app, "un"), c.group(app, "inter"), c.group(app, "minus")
	c.member(team, alice)
	c.member(team, bob)
	c.call("POST", "/api/groups/"+staff+"/members", `{"group":"`+team+`"}`, 201)
	c.member(staff, alice)
	c.member(other, alice)
	c.member(other, carol)
	c.call("POST", "/api/groups/"+un+"/convert-to-composite", `{"op":"union","factors":["`+staff+`","`+other+`"]}`, 200)
	c.call("POST", "/api/groups/"+inter+"/convert-to-composite", `{"op":"intersection","factors":["`+staff+`","`+other+`"]}`, 200)
	c.call("POST", "/api/groups/"+minus+"/convert-to-composite", `{"op":"complement","factors":["`+staff+`","`+other+`"]}`, 200)

	trace := func(group string, identity int64) map[string]any {
		return c.call("GET", fmt.Sprintf("/api/groups/%s/members/%d?trace=true", group, identity), "", 200)
	}
	paths := func(got map[string]any) [][]string {
		var out [][]string
		for _, p := range got["paths"].([]any) {
			var steps []string
			for _, s := range p.(map[string]any)["steps"].([]any) {
				m := s.(map[string]any)
				steps = append(steps, fmt.Sprintf("%s(%s)", m["name"], m["via"]))
			}
			out = append(out, steps)
		}
		return out
	}
	// without trace the answer has no paths
	if got := c.call("GET", fmt.Sprintf("/api/groups/%s/members/%d", staff, alice), "", 200); got["paths"] != nil || got["member"] != true {
		t.Errorf("no trace = %v", got)
	}
	// alice is in staff directly and through team: two paths
	got := trace(staff, alice)
	if p := paths(got); got["member"] != true || len(p) != 2 || got["truncated"] != false ||
		fmt.Sprint(p) != "[[app:staff(start)] [app:staff(start) app:team(nested)]]" {
		t.Errorf("alice in staff = %v", p)
	}
	// bob only through team
	if p := paths(trace(staff, bob)); fmt.Sprint(p) != "[[app:staff(start) app:team(nested)]]" {
		t.Errorf("bob in staff = %v", p)
	}
	// a union: through each factor that holds her
	if p := paths(trace(un, alice)); fmt.Sprint(p) != "[[app:un(start) app:staff(factor)] [app:un(start) app:staff(factor) app:team(nested)] [app:un(start) app:other(factor)]]" {
		t.Errorf("alice in the union = %v", p)
	}
	// an intersection needs both factors
	if p := paths(trace(inter, alice)); len(p) != 3 {
		t.Errorf("alice in the intersection = %v", p)
	}
	got = trace(inter, bob)
	if got["member"] != false || len(got["paths"].([]any)) != 0 {
		t.Errorf("bob in the intersection = %v", got)
	}
	// a complement is explained by its left factor
	if p := paths(trace(minus, bob)); fmt.Sprint(p) != "[[app:minus(start) app:staff(factor) app:team(nested)]]" {
		t.Errorf("bob in the complement = %v", p)
	}
	if got := trace(minus, alice); got["member"] != false {
		t.Errorf("alice is removed by the right factor: %v", got)
	}
	// a non-member has no paths, and a bad value is refused
	if got := trace(staff, carol); got["member"] != false || len(got["paths"].([]any)) != 0 {
		t.Errorf("carol = %v", got)
	}
	if rec := c.do("GET", fmt.Sprintf("/api/groups/%s/members/%d?trace=maybe", staff, alice), ""); rec.Code != 422 {
		t.Errorf("trace=maybe = %d", rec.Code)
	}
	if rec := c.do("GET", fmt.Sprintf("/api/groups/%s/members/%d?trace=true", staff, f.B.IDs["svc-etl"]+9999), ""); rec.Code != 404 {
		t.Errorf("trace of an unknown identity = %d", rec.Code)
	}
}

func decodeObj(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	return out
}

// actionCount counts the ledger's events with the action (the http.request events are separate).
func actionCount(t *testing.T, f *storetest.Fixture, action string) int {
	t.Helper()
	n := 0
	for _, e := range ledger(t, f.DB, f.B.ID) {
		if e.Action == action {
			n++
		}
	}
	return n
}

// TestBatch_AtomicAndIdempotent is the contract of the batch: by default it is
// all or nothing, and a retry with the same Idempotency-Key replays the first
// answer and changes nothing.
func TestBatch_AtomicAndIdempotent(t *testing.T) {
	e := newPrivEnv(t)
	c := e.admin
	alice, bob, carol := e.ident("alice"), e.ident("bob"), e.ident("carol")
	app := c.folder("", "app")
	team := c.group(app, "team")
	path := "/api/groups/" + team + "/members:batch"
	members := func() int {
		return int(c.call("GET", "/api/groups/"+team+"/members?filter=effective", "", 200)["total"].(float64))
	}

	// atomic by default: the last operation is refused (carol is not a member), so nothing is applied
	body := fmt.Sprintf(`{"add":[{"identity":%d},{"identity":%d}],"remove":["%d"]}`, alice, bob, carol)
	bad, _ := c.post("POST", path, body, 404)
	if bad["error"] != "not_found" || bad["index"] != float64(2) {
		t.Errorf("atomic failure = %v", bad)
	}
	if n := members(); n != 0 {
		t.Fatalf("%d members after a refused atomic batch, want 0", n)
	}
	if n := actionCount(t, e.f, "groups.member.added"); n != 0 {
		t.Errorf("%d member events after a refused atomic batch, want 0", n)
	}
	// the same batch without the bad operation
	body = fmt.Sprintf(`{"add":[{"identity":%d,"reason":"x"},{"identity":%d}],"reason":"onboarding"}`, alice, bob)
	first, rec := c.post("POST", path, body, 200, "Idempotency-Key", "key-1")
	if first["created"] != float64(2) || first["failed"] != float64(0) || first["atomic"] != true || first["effective"] != "applied" ||
		rec.Header().Get("Idempotent-Replayed") != "" {
		t.Fatalf("batch = %v", first)
	}
	res := first["results"].([]any)
	if len(res) != 2 || res[0].(map[string]any)["status"] != "created" || res[0].(map[string]any)["member_type"] != "identity" ||
		res[1].(map[string]any)["member"] != fmt.Sprint(bob) {
		t.Errorf("results = %v", res)
	}
	if n := members(); n != 2 {
		t.Fatalf("%d members after the batch, want 2", n)
	}
	added, batches, stored := actionCount(t, e.f, "groups.member.added"), actionCount(t, e.f, "groups.member.batch"), idemCount(t, e.f)
	if added != 2 || batches != 1 || stored != 1 {
		t.Errorf("events added=%d batch=%d, stored keys=%d; want 2, 1, 1", added, batches, stored)
	}

	// a retry with the same key and request replays the first answer, writes nothing
	again, rec := c.post("POST", path, body, 200, "Idempotency-Key", "key-1")
	if rec.Header().Get("Idempotent-Replayed") != "true" || fmt.Sprint(again) != fmt.Sprint(first) {
		t.Errorf("replay = %v (replayed %q)", again, rec.Header().Get("Idempotent-Replayed"))
	}
	if n := actionCount(t, e.f, "groups.member.added"); n != added {
		t.Errorf("a replay wrote member events: %d", n)
	}
	if n := actionCount(t, e.f, "groups.member.batch"); n != batches {
		t.Errorf("a replay wrote a batch event: %d", n)
	}
	if n := idemCount(t, e.f); n != stored {
		t.Errorf("a replay stored another key: %d", n)
	}
	// without the key the same batch runs again (and updates the rows)
	if again, _ := c.post("POST", path, body, 200); again["updated"] != float64(2) || again["created"] != float64(0) {
		t.Errorf("no key = %v", again)
	}

	// the same key with another request is refused, not replayed
	other, _ := c.post("POST", path, fmt.Sprintf(`{"add":[{"identity":%d}]}`, carol), 422, "Idempotency-Key", "key-1")
	if other["error"] != "idempotency_key_reused" {
		t.Errorf("reused key = %v", other)
	}
	if n := members(); n != 2 {
		t.Errorf("a refused reuse changed the members: %d", n)
	}
	// ... and so is the same key on another group
	team2 := c.group(app, "team2")
	if other, _ := c.post("POST", "/api/groups/"+team2+"/members:batch", body, 422, "Idempotency-Key", "key-1"); other["error"] != "idempotency_key_reused" {
		t.Errorf("reused key on another group = %v", other)
	}

	// keys are private to the caller: another admin's key-1 is its own
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	mine, rec := admin2.post("POST", path, body, 200, "Idempotency-Key", "key-1")
	if rec.Header().Get("Idempotent-Replayed") != "" || mine["updated"] != float64(2) {
		t.Errorf("another caller's key was replayed or refused: %v", mine)
	}
	if n := idemCount(t, e.f); n != 2 {
		t.Errorf("%d stored keys, want one per caller", n)
	}

	// a refused request stores nothing, so the retry is evaluated again
	before := idemCount(t, e.f)
	c.post("POST", path, `{"remove":["`+fmt.Sprint(carol)+`"]}`, 404, "Idempotency-Key", "key-2")
	if n := idemCount(t, e.f); n != before {
		t.Errorf("a refused request stored its answer: %d keys", n)
	}
	// a bad key is refused
	for _, k := range []string{"has space", strings.Repeat("k", 256), "ü"} {
		if rec := c.do("POST", path, body, "Idempotency-Key", k); rec.Code != 422 {
			t.Errorf("Idempotency-Key %q = %d, want 422", k, rec.Code)
		}
	}
}

func idemCount(t *testing.T, f *storetest.Fixture) int {
	t.Helper()
	var n int
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		var err error
		n, err = tx.GrpIdempotencyCount()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// The single membership writes accept the key too.
func TestIdempotency_SingleMembershipRoutes(t *testing.T) {
	c, f := newGrp(t)
	alice := f.B.IDs["alice"]
	g := c.group(c.folder("", "app"), "g")
	add := "/api/groups/" + g + "/members"
	body := fmt.Sprintf(`{"identity":%d}`, alice)
	first, _ := c.post("POST", add, body, 201, "Idempotency-Key", "a-1")
	again, rec := c.post("POST", add, body, 201, "Idempotency-Key", "a-1") // not 200: the first answer, replayed
	if rec.Header().Get("Idempotent-Replayed") != "true" || fmt.Sprint(first) != fmt.Sprint(again) {
		t.Errorf("replayed add = %v", again)
	}
	del := fmt.Sprintf("%s/%d", add, alice)
	c.post("DELETE", del, "", 200, "Idempotency-Key", "d-1")
	// the member is gone, so a repeat without the key is a 404, but with the key it replays the 200
	if rec := c.do("DELETE", del, ""); rec.Code != 404 {
		t.Errorf("second delete = %d", rec.Code)
	}
	if _, rec := c.post("DELETE", del, "", 200, "Idempotency-Key", "d-1"); rec.Header().Get("Idempotent-Replayed") != "true" {
		t.Error("the delete was not replayed")
	}
}

func TestBatch_NonAtomicReportsEachOperation(t *testing.T) {
	c, f := newGrp(t)
	alice, bob, carol, dave := f.B.IDs["alice"], f.B.IDs["bob"], f.B.IDs["carol"], f.B.IDs["dave"]
	app := c.folder("", "app")
	team, staff := c.group(app, "team"), c.group(app, "staff")
	c.call("POST", "/api/groups/"+team+"/members", `{"group":"`+staff+`"}`, 201) // staff is in team: adding team to staff is a cycle
	c.member(team, carol)
	c.member(staff, dave)
	path := "/api/groups/" + staff + "/members:batch"
	body := fmt.Sprintf(`{"atomic":false,"add":[{"identity":%d},{"group":"%s"},{"identity":%d},{"identity":99999999}],"remove":["%d","%d"]}`,
		alice, team, bob, carol, dave)
	got, _ := c.post("POST", path, body, 200)
	res := got["results"].([]any)
	status := func(i int) string { return res[i].(map[string]any)["status"].(string) }
	code := func(i int) any {
		if e, ok := res[i].(map[string]any)["error"].(map[string]any); ok {
			return e["error"]
		}
		return nil
	}
	if len(res) != 6 || got["atomic"] != false || got["created"] != float64(2) || got["removed"] != float64(1) || got["failed"] != float64(3) {
		t.Fatalf("batch = %v", got)
	}
	// alice, bob added; the cycle, the unknown identity and carol's missing row failed; dave removed
	want := []string{"created", "failed", "created", "failed", "failed", "removed"}
	for i, w := range want {
		if status(i) != w {
			t.Errorf("result %d = %v, want %s", i, res[i], w)
		}
	}
	if code(1) != "cycle" || code(3) != "unknown_identity" || code(4) != "not_found" {
		t.Errorf("errors = %v %v %v", code(1), code(3), code(4))
	}
	// what stands: alice and bob (dave is gone), and the failed operations left nothing behind
	m := c.call("GET", "/api/groups/"+staff+"/members?filter=effective", "", 200)
	if m["total"] != float64(2) || !eq(names(t, m, "name"), []string{"Alice", "Bob"}) {
		t.Errorf("members after the batch = %v", m)
	}
	if d := c.call("GET", "/api/groups/"+staff+"/members", "", 200); d["total"] != float64(2) {
		t.Errorf("direct rows after the batch = %v", d)
	}
}

func TestBatch_Validation(t *testing.T) {
	c, f := newGrp(t)
	alice := f.B.IDs["alice"]
	app := c.folder("", "app")
	g, comp := c.group(app, "g"), c.group(app, "comp")
	c.call("POST", "/api/groups/"+comp+"/convert-to-composite", `{"op":"union","factors":["`+g+`", "`+c.group(app, "h")+`"]}`, 200)
	path := "/api/groups/" + g + "/members:batch"
	many := strings.Repeat(fmt.Sprintf(`{"identity":%d},`, alice), 1000) + fmt.Sprintf(`{"identity":%d}`, alice)
	for name, tc := range map[string]struct {
		path, body string
		status     int
		code       string
	}{
		"empty":              {path, `{}`, 422, "empty_batch"},
		"too many":           {path, `{"add":[` + many + `]}`, 422, "batch_too_large"},
		"unknown field":      {path, `{"add":[],"bogus":1}`, 422, "invalid_body"},
		"identity and group": {path, fmt.Sprintf(`{"add":[{"identity":%d,"group":"%s"}]}`, alice, g), 422, "invalid_member"},
		"neither":            {path, `{"add":[{}]}`, 422, "invalid_member"},
		"bad identity":       {path, `{"add":[{"identity":0}]}`, 422, "invalid_identity"},
		"bad group":          {path, `{"add":[{"group":"nope"}]}`, 422, "invalid_group"},
		"bad date":           {path, fmt.Sprintf(`{"add":[{"identity":%d,"disabled_at":"x"}]}`, alice), 422, "invalid_disabled_at"},
		"bad remove":         {path, `{"remove":["x"]}`, 422, "invalid_member"},
		"both lists":         {path, fmt.Sprintf(`{"add":[{"identity":%d}],"remove":["%d"]}`, alice, alice), 422, "conflicting_operations"},
		"past disable":       {path, fmt.Sprintf(`{"add":[{"identity":%d,"disabled_at":"2000-01-01T00:00:00Z"}]}`, alice), 422, "invalid_dates"},
		"composite":          {"/api/groups/" + comp + "/members:batch", fmt.Sprintf(`{"add":[{"identity":%d}]}`, alice), 409, "composite_no_members"},
		"unknown group":      {"/api/groups/00000000-0000-4000-8000-00000000d00d/members:batch", fmt.Sprintf(`{"add":[{"identity":%d}]}`, alice), 404, "not_found"},
		"not a uuid":         {"/api/groups/x/members:batch", fmt.Sprintf(`{"add":[{"identity":%d}]}`, alice), 404, "not_found"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := c.do("POST", tc.path, tc.body)
			got := decodeObj(t, rec)
			if rec.Code != tc.status || got["error"] != tc.code {
				t.Errorf("%d %v, want %d %s", rec.Code, got, tc.status, tc.code)
			}
		})
	}
	// the index names the offending operation, and the op its kind
	got := decodeObj(t, c.do("POST", path, fmt.Sprintf(`{"add":[{"identity":%d},{}]}`, alice)))
	if got["index"] != float64(1) || got["op"] != "add" {
		t.Errorf("validation names the operation: %v", got)
	}
}

func TestBatch_QueuedRecomputeAnswers202(t *testing.T) {
	c, f, _ := newGrpEngine(t, 1)
	alice, bob := f.B.IDs["alice"], f.B.IDs["bob"]
	app := c.folder("", "app")
	team, staff := c.group(app, "team"), c.group(app, "staff")
	c.call("POST", "/api/groups/"+staff+"/members", `{"group":"`+team+`"}`, 201)
	got, _ := c.post("POST", "/api/groups/"+team+"/members:batch", fmt.Sprintf(`{"add":[{"identity":%d},{"identity":%d}]}`, alice, bob), 202)
	ops := got["ops"].([]any)
	if got["effective"] != "pending" || len(ops) == 0 {
		t.Fatalf("queued batch = %v", got)
	}
	r0 := got["results"].([]any)[0].(map[string]any)
	if r0["effective"] != "pending" || r0["op_id"] == nil || r0["status"] != "created" {
		t.Errorf("result = %v", r0)
	}
}

func TestBatch_PrivilegesPerOperation(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	g, other := e.admin.group(app, "g"), e.admin.group(app, "other")
	bob, alice := e.user("bob", "bob"), e.user("alice", "alice")
	path := "/api/groups/" + g + "/members:batch"
	body := fmt.Sprintf(`{"add":[{"identity":%d}]}`, e.ident("carol"))
	// no privilege at all: 403 (atomic or not)
	denied(t, bob, "POST", path, body, "update")
	denied(t, bob, "POST", path, `{"atomic":false,"add":[{"identity":`+fmt.Sprint(e.ident("carol"))+`}]}`, "update")
	// optin is enough for oneself, not for another
	e.grant("/api/groups/"+g, "optin", "bob", "")
	bob.call("POST", path, fmt.Sprintf(`{"add":[{"identity":%d}]}`, e.ident("bob")), 200)
	denied(t, bob, "POST", path, body, "update")
	got := bob.call("POST", path, fmt.Sprintf(`{"atomic":false,"add":[{"identity":%d},{"identity":%d}]}`, e.ident("bob"), e.ident("carol")), 200)
	res := got["results"].([]any)
	if got["failed"] != float64(1) || res[0].(map[string]any)["status"] != "updated" || res[1].(map[string]any)["status"] != "failed" ||
		res[1].(map[string]any)["error"].(map[string]any)["error"] != "privilege_required" {
		t.Errorf("mixed batch = %v", got)
	}
	// removing oneself needs optout
	denied(t, bob, "POST", path, fmt.Sprintf(`{"remove":["%d"]}`, e.ident("bob")), "optout")
	// nesting a group needs read on it
	e.grant("/api/groups/"+g, "update", "alice", "")
	denied(t, alice, "POST", path, `{"add":[{"group":"`+other+`"}]}`, "read")
	e.grant("/api/groups/"+other, "read", "alice", "")
	alice.call("POST", path, `{"add":[{"group":"`+other+`"}]}`, 200)
}

func TestIdentityGroups(t *testing.T) {
	e := newPrivEnv(t)
	c := e.admin
	alice, bob := e.ident("alice"), e.ident("bob")
	app := c.folder("", "app")
	team, staff, secret := c.group(app, "team"), c.group(app, "staff"), c.group(app, "secret")
	c.member(team, alice)
	c.call("POST", "/api/groups/"+staff+"/members", `{"group":"`+team+`"}`, 201)
	c.member(staff, bob)
	c.member(secret, alice)
	path := fmt.Sprintf("/api/identities/%d/groups", alice)

	got := c.call("GET", path, "", 200)
	if got["filter"] != "effective" || !eq(names(t, got, "name"), []string{"app:secret", "app:staff", "app:team"}) {
		t.Fatalf("groups of alice = %v", got)
	}
	it := items(t, got)[2]
	if it["group_id"] != team || it["type"] != "group" || it["definition"] != "basic" || it["status"] != "active" {
		t.Errorf("item = %v", it)
	}
	if got := c.call("GET", path+"?filter=direct", "", 200); !eq(names(t, got, "name"), []string{"app:secret", "app:team"}) {
		t.Errorf("direct = %v", got)
	}
	if got := c.call("GET", path+"?filter=indirect", "", 200); !eq(names(t, got, "name"), []string{"app:staff"}) {
		t.Errorf("indirect = %v", got)
	}
	if got := c.call("GET", path+"?limit=1&offset=1", "", 200); !eq(names(t, got, "name"), []string{"app:staff"}) {
		t.Errorf("page = %v", got)
	}
	// as of now, and an hour ago (before the groups existed)
	now := storetest.Now.Format(time.RFC3339)
	// (a point-in-time page is in group id order)
	if got := c.call("GET", path+"?as_of="+now, "", 200); got["as_of"] == nil || !eq(sorted(names(t, got, "name")), []string{"app:secret", "app:staff", "app:team"}) {
		t.Errorf("as_of now = %v", got)
	}
	if got := c.call("GET", path+"?as_of="+storetest.Now.Add(-time.Hour).Format(time.RFC3339), "", 200); len(items(t, got)) != 0 {
		t.Errorf("as_of before = %v", got)
	}
	// a removed membership leaves the present, not the past
	c.call("DELETE", fmt.Sprintf("/api/groups/%s/members/%d", secret, alice), "", 200)
	if got := c.call("GET", path, "", 200); !eq(names(t, got, "name"), []string{"app:staff", "app:team"}) {
		t.Errorf("after the removal = %v", got)
	}
	// only the groups the caller may read: a user who reads team sees team
	reader := e.user("reader", "carol")
	if got := reader.call("GET", path, "", 200); len(items(t, got)) != 0 {
		t.Errorf("a caller with no privilege sees %v", got)
	}
	e.grant("/api/groups/"+team, "read", "carol", "")
	if got := reader.call("GET", path, "", 200); !eq(names(t, got, "name"), []string{"app:team"}) {
		t.Errorf("a caller who reads team sees %v", got)
	}
	e.grant("/api/groups/"+staff, "view", "carol", "") // view alone does not tell who is a member
	if got := reader.call("GET", path, "", 200); !eq(names(t, got, "name"), []string{"app:team"}) {
		t.Errorf("view alone shows %v", got)
	}
	// refusals
	for p, want := range map[string]int{
		"/api/identities/999999999/groups": 404, "/api/identities/x/groups": 404, "/api/identities/0/groups": 404,
		path + "?filter=bogus": 422, path + "?list=other": 422, path + "?as_of=nope": 422, path + "?between=" + now + "," + now: 422,
		path + "?as_of=" + now + "&filter=direct": 422, path + "?limit=0": 422,
	} {
		if rec := c.do("GET", p, ""); rec.Code != want {
			t.Errorf("GET %s = %d %.100s, want %d", p, rec.Code, rec.Body.String(), want)
		}
	}
}

func TestGroupsOpenAPI_CoversRoutes(t *testing.T) {
	c, f := newGrp(t)
	srv := newIsolationServer(f)
	doc := c.call("GET", "/api/openapi/groups.json", "", 200)
	if doc["openapi"] != "3.1.0" {
		t.Fatalf("document = %v", doc["openapi"])
	}
	paths := doc["paths"].(map[string]any)
	covered := map[string]bool{}
	for _, rt := range srv.Routes() {
		if !grpapi.Covers(rt.Method, rt.Pattern) {
			continue
		}
		key := rt.Method + " " + rt.Pattern
		covered[key] = true
		op, ok := paths[rt.Pattern].(map[string]any)[strings.ToLower(rt.Method)].(map[string]any)
		if !ok {
			t.Errorf("%s is not documented", key)
			continue
		}
		if op["x-tessera-permission"] != string(rt.Perm) || op["summary"] == "" {
			t.Errorf("%s: %v", key, op)
		}
	}
	for _, key := range grpapi.Documented() {
		if !covered[key] {
			t.Errorf("%s is documented but no such route is registered", key)
		}
	}
	if len(covered) < 45 {
		t.Errorf("%d routes covered", len(covered))
	}
	// the idempotent writes say so, and the SCIM routes show their filter
	batch := paths["/api/groups/{id}/members:batch"].(map[string]any)["post"].(map[string]any)
	if !strings.Contains(fmt.Sprint(batch["parameters"]), "Idempotency-Key") || batch["requestBody"] == nil {
		t.Errorf("batch operation = %v", batch)
	}
	if !strings.Contains(fmt.Sprint(paths["/scim/v2/Users"]), "filter") {
		t.Error("the SCIM users route does not document filter")
	}
	// a signed-in user of any role may read it; anonymous may not
	if rec := serve(srv.Handler(), httptest.NewRequest("GET", "/api/openapi/groups.json", nil)); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous = %d", rec.Code)
	}
	// deterministic
	a, b := c.do("GET", "/api/openapi/groups.json", ""), c.do("GET", "/api/openapi/groups.json", "")
	if a.Body.String() != b.Body.String() {
		t.Error("the document changes between requests")
	}
}

// TestGroupsAPI_Isolation: at the API layer, tenant A's groups, identities and
// keys do not exist for tenant B.
func TestGroupsAPI_Isolation(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	a := grpClient{client{t, asAdmin(t, srv, f.DB, f.A.ID, storetest.Now).Handler()}}
	b := grpClient{client{t, asAdmin(t, srv, f.DB, f.B.ID, storetest.Now).Handler()}}
	aAlice, bAlice := f.A.IDs["alice"], f.B.IDs["alice"]
	gA := a.group(a.folder("", "secret"+"-a"), "g")
	a.member(gA, aAlice)
	gB := b.group(b.folder("", "app"), "g")
	b.member(gB, bAlice)

	// B cannot see, trace, write, batch, simulate or list A's group
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/groups/" + gA + "/members", ""},
		{"GET", "/api/groups/" + gA + "/members?filter=indirect&q=a&sort=name", ""},
		{"GET", fmt.Sprintf("/api/groups/%s/members/%d?trace=true", gA, aAlice), ""},
		{"GET", "/api/groups/" + gA + "/members?as_of=" + storetest.Now.Format(time.RFC3339), ""},
		{"POST", "/api/groups/" + gA + "/members:batch", fmt.Sprintf(`{"add":[{"identity":%d}]}`, bAlice)},
		{"POST", "/api/groups:simulate", fmt.Sprintf(`{"changes":[{"kind":"add_member","group":%q,"identity":%d}]}`, gA, bAlice)},
		{"GET", "/scim/v2/Groups/" + gA, ""},
		{"GET", fmt.Sprintf("/api/identities/%d/groups", aAlice), ""},
		{"GET", fmt.Sprintf("/scim/v2/Users/%d", aAlice), ""},
	} {
		rec := b.do(tc.method, tc.path, tc.body)
		if rec.Code != http.StatusNotFound && !(strings.HasPrefix(tc.path, "/api/groups:simulate") && rec.Code == http.StatusNotFound) {
			t.Errorf("B: %s %s = %d %.150s, want 404", tc.method, tc.path, rec.Code, rec.Body.String())
		}
		if leaks(rec.Body.String()) {
			t.Errorf("B: %s %s leaks tenant A: %s", tc.method, tc.path, rec.Body.String())
		}
	}
	// A's identity cannot be put into B's group, by batch or by simulation
	rec := b.do("POST", "/api/groups/"+gB+"/members:batch", fmt.Sprintf(`{"add":[{"identity":%d}]}`, f.A.IDs["bob"]))
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "unknown_identity") {
		t.Errorf("batch with another tenant's identity = %d %s", rec.Code, rec.Body.String())
	}
	// B's listings and SCIM hold nothing of A
	for _, p := range []string{"/scim/v2/Users?count=200", "/scim/v2/Groups?count=200", "/api/groups/" + gB + "/members?filter=effective",
		fmt.Sprintf("/api/identities/%d/groups", bAlice), "/api/groups/native"} {
		if rec := b.do("GET", p, ""); rec.Code != 200 || leaks(rec.Body.String()) || strings.Contains(rec.Body.String(), gA) {
			t.Errorf("B: GET %s = %d, leaks tenant A: %.200s", p, rec.Code, rec.Body.String())
		}
	}
	if u := b.do("GET", "/scim/v2/Users?count=200", ""); decodeObj(t, u)["totalResults"] != float64(6) {
		t.Errorf("B's users = %s", u.Body.String())
	}
	// the same key in both tenants is two keys: neither replays the other's answer
	bodyA, bodyB := fmt.Sprintf(`{"add":[{"identity":%d}]}`, f.A.IDs["bob"]), fmt.Sprintf(`{"add":[{"identity":%d}]}`, f.B.IDs["bob"])
	ra, hdrA := a.post("POST", "/api/groups/"+gA+"/members:batch", bodyA, 200, "Idempotency-Key", "same-key")
	rb, hdrB := b.post("POST", "/api/groups/"+gB+"/members:batch", bodyB, 200, "Idempotency-Key", "same-key")
	if hdrA.Header().Get("Idempotent-Replayed") != "" || hdrB.Header().Get("Idempotent-Replayed") != "" ||
		ra["group_id"] != gA || rb["group_id"] != gB || fmt.Sprint(ra) == fmt.Sprint(rb) {
		t.Errorf("keys crossed tenants: %v %v", ra, rb)
	}
	// A's replay is A's
	if again, rec := a.post("POST", "/api/groups/"+gA+"/members:batch", bodyA, 200, "Idempotency-Key", "same-key"); rec.Header().Get("Idempotent-Replayed") != "true" ||
		again["group_id"] != gA {
		t.Errorf("A's replay = %v", again)
	}
}
