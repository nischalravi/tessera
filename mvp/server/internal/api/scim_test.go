package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	grpapi "github.com/nischalravi/tessera/mvp/server/internal/groups/api"
)

// The read-only SCIM server (issue #48, GR-5): conformance of the read side of
// RFC 7644 (resources, ListResponse, filter, paging, attribute selection,
// errors), and who may read what.

const scimType = "application/scim+json"

// scimGet sends a GET and decodes the answer; it checks the status and media type.
func scimGet(t *testing.T, c grpClient, path string, want int) map[string]any {
	t.Helper()
	rec := c.do("GET", path, "")
	if rec.Code != want {
		t.Fatalf("GET %s = %d, want %d: %.400s", path, rec.Code, want, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != scimType {
		t.Errorf("GET %s: Content-Type %q, want %s", path, ct, scimType)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("GET %s: %v: %s", path, err, rec.Body.String())
	}
	return out
}

func resources(t *testing.T, got map[string]any) []map[string]any {
	t.Helper()
	raw, ok := got["Resources"].([]any)
	if !ok {
		t.Fatalf("no Resources array in %v", got)
	}
	out := make([]map[string]any, len(raw))
	for i, r := range raw {
		out[i] = r.(map[string]any)
	}
	return out
}

func resField(t *testing.T, got map[string]any, field string) []string {
	t.Helper()
	var out []string
	for _, r := range resources(t, got) {
		out = append(out, fmt.Sprint(r[field]))
	}
	return out
}

func filterQ(filter string, extra ...string) string {
	v := url.Values{"filter": {filter}}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return "?" + v.Encode()
}

func TestSCIM_UsersConformance(t *testing.T) {
	c, f := newGrp(t)
	alice := f.B.IDs["alice"]
	// the tenant's six identities, as ListResponse
	all := scimGet(t, c, "/scim/v2/Users", 200)
	if all["totalResults"] != float64(6) || all["startIndex"] != float64(1) || all["itemsPerPage"] != float64(6) ||
		fmt.Sprint(all["schemas"]) != "["+grpapi.SchemaListResponse+"]" {
		t.Fatalf("list = %v", all)
	}
	users := resources(t, all)
	u := users[0]
	if u["id"] != fmt.Sprint(alice) || u["userName"] == "" || u["displayName"] != "Alice" || u["active"] != true || u["userType"] != "human" ||
		fmt.Sprint(u["schemas"]) != "["+grpapi.SchemaUser+"]" || u["externalId"] != "alice" {
		t.Errorf("user = %v", u)
	}
	if emails := u["emails"].([]any); len(emails) != 1 || emails[0].(map[string]any)["primary"] != true ||
		emails[0].(map[string]any)["value"] != u["userName"] {
		t.Errorf("emails = %v", u["emails"])
	}
	if m := u["meta"].(map[string]any); m["resourceType"] != "User" || m["location"] != "/scim/v2/Users/"+fmt.Sprint(alice) || m["created"] == nil {
		t.Errorf("meta = %v", m)
	}
	// ids ascend; paging: startIndex is 1-based
	ids := resField(t, all, "id")
	pg := scimGet(t, c, "/scim/v2/Users?startIndex=3&count=2", 200)
	if pg["totalResults"] != float64(6) || pg["startIndex"] != float64(3) || pg["itemsPerPage"] != float64(2) ||
		!eq(resField(t, pg, "id"), ids[2:4]) {
		t.Errorf("page = %v", pg)
	}
	if last := scimGet(t, c, "/scim/v2/Users?startIndex=6&count=10", 200); last["itemsPerPage"] != float64(1) || !eq(resField(t, last, "id"), ids[5:]) {
		t.Errorf("last page = %v", last)
	}
	if past := scimGet(t, c, "/scim/v2/Users?startIndex=50", 200); past["itemsPerPage"] != float64(0) || past["totalResults"] != float64(6) ||
		len(resources(t, past)) != 0 {
		t.Errorf("past the end = %v", past)
	}
	// count=0 only counts; a negative count is 0, startIndex below 1 is 1 (RFC 7644 §3.4.2.4)
	if z := scimGet(t, c, "/scim/v2/Users?count=0", 200); z["totalResults"] != float64(6) || len(resources(t, z)) != 0 {
		t.Errorf("count=0 = %v", z)
	}
	if n := scimGet(t, c, "/scim/v2/Users?count=-3&startIndex=-4", 200); len(resources(t, n)) != 0 || n["startIndex"] != float64(1) {
		t.Errorf("negative = %v", n)
	}
	if big := scimGet(t, c, "/scim/v2/Users?count=100000", 200); big["itemsPerPage"] != float64(6) {
		t.Errorf("a large count = %v", big)
	}

	// filters, every operator
	for _, tc := range []struct {
		filter string
		want   []string // displayName
	}{
		{`displayName eq "alice"`, []string{"Alice"}}, // without case
		{`userName eq "` + fmt.Sprint(u["userName"]) + `"`, []string{"Alice"}},
		{`displayName ne "Alice" and userType eq "human"`, []string{"Bob", "Carol", "Dave"}},
		{`displayName co "ar"`, []string{"Carol"}},
		{`displayName sw "B"`, []string{"Bob"}},
		{`displayName ew "e"`, []string{"Alice", "Dave"}},
		{`displayName gt "Carol" and userType eq "human"`, []string{"Dave"}},
		{`displayName le "Alice"`, []string{"Alice"}},
		{`active eq false`, []string{"Dave"}},
		{`not (active eq true)`, []string{"Dave"}},
		{`userType eq "service" or userType eq "ai_agent"`, []string{"svc-etl", "Helper Bot"}},
		{`(userType eq "service" or userType eq "ai_agent") and displayName co "bot"`, []string{"Helper Bot"}},
		{`emails.value pr and active eq true and displayName sw "A"`, []string{"Alice"}},
		{`title pr`, nil},
		{`externalId eq "svc-etl"`, []string{"svc-etl"}},
		{`id eq "` + fmt.Sprint(alice) + `"`, []string{"Alice"}},
		{`id eq "99999999"`, nil},
		{`displayName EQ "alice" AND ACTIVE EQ true`, []string{"Alice"}}, // keywords and attributes are case-insensitive
	} {
		got := scimGet(t, c, "/scim/v2/Users"+filterQ(tc.filter), 200)
		if g := resField(t, got, "displayName"); !eq(g, tc.want) || got["totalResults"] != float64(len(tc.want)) {
			t.Errorf("filter %s = %v (total %v), want %v", tc.filter, g, got["totalResults"], tc.want)
		}
	}
	// a filtered page counts all matches
	got := scimGet(t, c, "/scim/v2/Users"+filterQ(`userType pr`, "count", "2", "startIndex", "2"), 200)
	if got["totalResults"] != float64(6) || got["itemsPerPage"] != float64(2) || !eq(resField(t, got, "id"), ids[1:3]) {
		t.Errorf("filtered page = %v", got)
	}
	got = scimGet(t, c, "/scim/v2/Users"+filterQ(`active eq true`, "count", "2", "startIndex", "5"), 200)
	if got["totalResults"] != float64(5) || got["itemsPerPage"] != float64(1) {
		t.Errorf("filtered last page = %v", got)
	}

	// attribute selection
	one := scimGet(t, c, "/scim/v2/Users/"+fmt.Sprint(alice)+"?attributes=userName,displayName", 200)
	if _, has := one["emails"]; has || one["userName"] == nil || one["displayName"] != "Alice" || one["id"] == nil || one["meta"] == nil || one["schemas"] == nil {
		t.Errorf("attributes = %v", one)
	}
	one = scimGet(t, c, "/scim/v2/Users/"+fmt.Sprint(alice)+"?excludedAttributes=emails,id", 200)
	if _, has := one["emails"]; has || one["id"] == nil || one["userName"] == nil {
		t.Errorf("excludedAttributes = %v", one)
	}
	if lst := scimGet(t, c, "/scim/v2/Users?attributes=userName", 200); len(resources(t, lst)[0]) != 4 { // schemas, id, meta, userName
		t.Errorf("attributes on a list = %v", resources(t, lst)[0])
	}

	// errors are SCIM errors
	for _, tc := range []struct {
		path, scimType string
		status         int
	}{
		{"/scim/v2/Users" + filterQ(`bogus eq "x"`), "invalidFilter", 400},
		{"/scim/v2/Users" + filterQ(`displayName eq`), "invalidFilter", 400},
		{"/scim/v2/Users" + filterQ(`displayName eq "x`), "invalidFilter", 400},
		{"/scim/v2/Users" + filterQ(`displayName xx "x"`), "invalidFilter", 400},
		{"/scim/v2/Users" + filterQ(`(displayName eq "x"`), "invalidFilter", 400},
		{"/scim/v2/Users" + filterQ(`displayName eq "x" displayName eq "y"`), "invalidFilter", 400},
		{"/scim/v2/Users" + filterQ(`displayName eq x`), "invalidFilter", 400},
		{"/scim/v2/Users" + filterQ(strings.Repeat("a", 2000)), "invalidFilter", 400},
		{"/scim/v2/Users" + filterQ(strings.Repeat("not (", 40)+`active eq true`+strings.Repeat(")", 40)), "invalidFilter", 400},
		{"/scim/v2/Users?startIndex=x", "invalidValue", 400},
		{"/scim/v2/Users?count=x", "invalidValue", 400},
		{"/scim/v2/Users/0", "", 404},
		{"/scim/v2/Users/x", "", 404},
		{"/scim/v2/Users/99999999", "", 404},
	} {
		got := scimGet(t, c, tc.path, tc.status)
		if got["status"] != fmt.Sprint(tc.status) || got["scimType"] != nilIfEmpty(tc.scimType) || got["detail"] == "" ||
			fmt.Sprint(got["schemas"]) != "["+grpapi.SchemaError+"]" {
			t.Errorf("GET %.60s = %v", tc.path, got)
		}
	}
	// no writes
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if rec := c.do(m, "/scim/v2/Users/"+fmt.Sprint(alice), `{}`); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /scim/v2/Users = %d, want 405", m, rec.Code)
		}
		if rec := c.do(m, "/scim/v2/Groups", `{}`); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /scim/v2/Groups = %d, want 405", m, rec.Code)
		}
	}
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func TestSCIM_GroupsConformance(t *testing.T) {
	c, f := newGrp(t)
	alice, bob, carol := f.B.IDs["alice"], f.B.IDs["bob"], f.B.IDs["carol"]
	app := c.folder("", "app")
	team, staff, empty := c.group(app, "team"), c.group(app, "staff"), c.group(app, "empty")
	gone := c.group(app, "gone")
	c.member(team, alice)
	c.member(team, bob)
	c.call("POST", "/api/groups/"+staff+"/members", `{"group":"`+team+`"}`, 201)
	c.member(staff, carol)
	c.call("DELETE", "/api/groups/"+gone, "", 200)

	all := scimGet(t, c, "/scim/v2/Groups", 200)
	if all["totalResults"] != float64(3) || !eq(resField(t, all, "displayName"), []string{"app:empty", "app:staff", "app:team"}) ||
		fmt.Sprint(all["schemas"]) != "["+grpapi.SchemaListResponse+"]" {
		t.Fatalf("groups = %v", all)
	}
	var st map[string]any
	for _, g := range resources(t, all) {
		if g["displayName"] == "app:staff" {
			st = g
		}
	}
	members := st["members"].([]any)
	if len(members) != 3 || st["id"] != staff || fmt.Sprint(st["schemas"]) != "["+grpapi.SchemaGroup+" "+grpapi.SchemaGroupExt+"]" {
		t.Fatalf("staff = %v", st)
	}
	if m := members[0].(map[string]any); m["value"] != fmt.Sprint(alice) || m["display"] != "Alice" || m["type"] != "User" ||
		m["$ref"] != "/scim/v2/Users/"+fmt.Sprint(alice) {
		t.Errorf("member = %v", m)
	}
	ext := st[grpapi.SchemaGroupExt].(map[string]any)
	if ext["memberCount"] != float64(3) || ext["membersTruncated"] != false || ext["type"] != "group" || ext["definition"] != "basic" || ext["status"] != "active" {
		t.Errorf("extension = %v", ext)
	}
	if m := st["meta"].(map[string]any); m["resourceType"] != "Group" || m["location"] != "/scim/v2/Groups/"+staff {
		t.Errorf("meta = %v", m)
	}
	// filter and paging
	for _, tc := range []struct {
		filter string
		want   []string
	}{
		{`displayName eq "APP:TEAM"`, []string{"app:team"}},
		{`displayName co "ea"`, []string{"app:team"}},
		{`displayName sw "app:s"`, []string{"app:staff"}},
		{`displayName ew "y"`, []string{"app:empty"}},
		{`displayName sw "app:" and not (displayName eq "app:team")`, []string{"app:empty", "app:staff"}},
		{`displayName eq "app:team" or displayName eq "app:empty"`, []string{"app:empty", "app:team"}},
		{`id eq "` + staff + `"`, []string{"app:staff"}},
		{`displayName eq "nothing"`, nil},
		{`displayName eq "app:gone"`, nil}, // deleted groups are not listed
	} {
		got := scimGet(t, c, "/scim/v2/Groups"+filterQ(tc.filter), 200)
		if g := resField(t, got, "displayName"); !eq(g, tc.want) || got["totalResults"] != float64(len(tc.want)) {
			t.Errorf("filter %s = %v, want %v", tc.filter, g, tc.want)
		}
	}
	pg := scimGet(t, c, "/scim/v2/Groups?startIndex=2&count=1", 200)
	if pg["totalResults"] != float64(3) || pg["startIndex"] != float64(2) || !eq(resField(t, pg, "displayName"), []string{"app:staff"}) {
		t.Errorf("page = %v", pg)
	}
	if z := scimGet(t, c, "/scim/v2/Groups?count=0", 200); z["totalResults"] != float64(3) || len(resources(t, z)) != 0 {
		t.Errorf("count=0 = %v", z)
	}
	// excludedAttributes / attributes
	if lst := scimGet(t, c, "/scim/v2/Groups?excludedAttributes=members", 200); resources(t, lst)[0]["members"] != nil {
		t.Errorf("excludedAttributes = %v", resources(t, lst)[0])
	}
	if lst := scimGet(t, c, "/scim/v2/Groups?attributes=displayName", 200); len(resources(t, lst)[0]) != 4 {
		t.Errorf("attributes = %v", resources(t, lst)[0])
	}
	// one group; an empty one has an empty members array, not null
	one := scimGet(t, c, "/scim/v2/Groups/"+empty, 200)
	if ms, ok := one["members"].([]any); !ok || len(ms) != 0 || one["displayName"] != "app:empty" {
		t.Errorf("empty group = %v", one)
	}
	if one := scimGet(t, c, "/scim/v2/Groups/"+staff+"?excludedAttributes=members", 200); one["members"] != nil || one["displayName"] != "app:staff" {
		t.Errorf("one without members = %v", one)
	}
	for _, p := range []string{"/scim/v2/Groups/00000000-0000-4000-8000-00000000d00d", "/scim/v2/Groups/x", "/scim/v2/Groups/" + gone} {
		if got := scimGet(t, c, p, 404); got["status"] != "404" || got["detail"] == "" {
			t.Errorf("GET %s = %v", p, got)
		}
	}
	if got := scimGet(t, c, "/scim/v2/Groups"+filterQ(`members.value eq "1"`), 400); got["scimType"] != "invalidFilter" {
		t.Errorf("unsupported attribute = %v", got)
	}
	// a user carries the groups the caller may read
	u := scimGet(t, c, "/scim/v2/Users/"+fmt.Sprint(alice), 200)
	gs := u["groups"].([]any)
	if len(gs) != 2 || gs[0].(map[string]any)["display"] != "app:staff" || gs[1].(map[string]any)["display"] != "app:team" ||
		gs[0].(map[string]any)["type"] != "Group" || gs[0].(map[string]any)["value"] != staff {
		t.Errorf("groups of alice = %v", gs)
	}
	// a group's members are capped on a list, a single group lists more
	big := c.group(app, "big")
	for _, id := range []int64{alice, bob, carol} {
		c.member(big, id)
	}
	if got := scimGet(t, c, "/scim/v2/Groups/"+big, 200); got[grpapi.SchemaGroupExt].(map[string]any)["membersTruncated"] != false {
		t.Errorf("big = %v", got)
	}
}

func TestSCIM_ServiceProviderConfigAndResourceTypes(t *testing.T) {
	c, _ := newGrp(t)
	spc := scimGet(t, c, "/scim/v2/ServiceProviderConfig", 200)
	if fmt.Sprint(spc["schemas"]) != "["+grpapi.SchemaSPC+"]" || spc["patch"].(map[string]any)["supported"] != false ||
		spc["filter"].(map[string]any)["supported"] != true || spc["filter"].(map[string]any)["maxResults"] != float64(grpapi.MaxCount) ||
		spc["sort"].(map[string]any)["supported"] != false || spc["bulk"].(map[string]any)["supported"] != false {
		t.Errorf("ServiceProviderConfig = %v", spc)
	}
	rt := scimGet(t, c, "/scim/v2/ResourceTypes", 200)
	if rt["totalResults"] != float64(2) || !eq(resField(t, rt, "endpoint"), []string{"/Users", "/Groups"}) {
		t.Errorf("ResourceTypes = %v", rt)
	}
}

// TestSCIM_PrivilegeAndAuth: the SCIM server is authenticated like the rest of
// the API, needs groups.read, and shows only the groups the caller may read.
func TestSCIM_PrivilegeAndAuth(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	open, hidden := e.admin.group(app, "open"), e.admin.group(app, "hidden")
	e.admin.member(open, e.ident("alice"))
	e.admin.member(hidden, e.ident("bob"))
	nobody := e.user("nobody", "carol") // operator: groups.read, holds no privilege
	paths := []string{"/scim/v2/Groups", "/scim/v2/Groups/" + open, "/scim/v2/Users", "/scim/v2/Users/1", "/scim/v2/ServiceProviderConfig",
		"/scim/v2/ResourceTypes"}

	// never anonymous, whatever is sent: not a cookie, a bearer token or a header naming a tenant
	h := e.srv.Handler()
	for _, p := range paths {
		for _, hdr := range [][2]string{{}, {"Authorization", "Bearer abc"}, {"X-Tessera-Tenant", "tenant-b"}, {"Cookie", "x=y"}} {
			req := httptest.NewRequest("GET", p, nil)
			if hdr[0] != "" {
				req.Header.Set(hdr[0], hdr[1])
			}
			if rec := serve(h, req); rec.Code != http.StatusUnauthorized {
				t.Errorf("anonymous GET %s %v = %d, want 401", p, hdr, rec.Code)
			}
		}
	}
	// a role without groups.read: 403
	bg := e.as("auditless", []auth.Role{auth.RoleBreakGlass}, nil)
	for _, p := range paths {
		if rec := bg.do("GET", p, ""); rec.Code != http.StatusForbidden {
			t.Errorf("a role without groups.read: GET %s = %d, want 403", p, rec.Code)
		}
	}
	// no privilege: no groups listed, a group is 403 in SCIM's format
	if got := scimGet(t, nobody, "/scim/v2/Groups", 200); got["totalResults"] != float64(0) || len(resources(t, got)) != 0 {
		t.Errorf("groups of a caller with no privilege = %v", got)
	}
	got := scimGet(t, nobody, "/scim/v2/Groups/"+open, 403)
	if got["status"] != "403" || fmt.Sprint(got["schemas"]) != "["+grpapi.SchemaError+"]" || got["detail"] == "" {
		t.Errorf("403 = %v", got)
	}
	// view is not read: the members are what a Group carries
	e.grant("/api/groups/"+open, "view", "carol", "")
	scimGet(t, nobody, "/scim/v2/Groups/"+open, 403)
	if got := scimGet(t, nobody, "/scim/v2/Groups", 200); got["totalResults"] != float64(0) {
		t.Errorf("view shows %v", got)
	}
	// read on one group shows that group, and only that
	e.grant("/api/groups/"+open, "read", "carol", "")
	if got := scimGet(t, nobody, "/scim/v2/Groups", 200); got["totalResults"] != float64(1) || !eq(resField(t, got, "displayName"), []string{"app:open"}) {
		t.Errorf("read shows %v", got)
	}
	scimGet(t, nobody, "/scim/v2/Groups/"+open, 200)
	scimGet(t, nobody, "/scim/v2/Groups/"+hidden, 403)
	if got := scimGet(t, nobody, "/scim/v2/Groups"+filterQ(`displayName pr`), 200); got["totalResults"] != float64(1) {
		t.Errorf("a filter does not widen what is shown: %v", got)
	}
	// a user's groups are the ones the caller may read
	if u := scimGet(t, nobody, fmt.Sprintf("/scim/v2/Users/%d", e.ident("bob")), 200); u["groups"] != nil {
		t.Errorf("bob's groups = %v", u["groups"])
	}
	if u := scimGet(t, nobody, fmt.Sprintf("/scim/v2/Users/%d", e.ident("alice")), 200); len(u["groups"].([]any)) != 1 {
		t.Errorf("alice's groups = %v", u["groups"])
	}
	// the tenant admin reads everything
	if got := scimGet(t, e.admin, "/scim/v2/Groups", 200); got["totalResults"] != float64(2) {
		t.Errorf("admin = %v", got)
	}
	// every call is audited, with the route
	if n := len(httpEvents(ledger(t, e.f.DB, e.f.B.ID))); n == 0 {
		t.Error("no http.request events")
	}
}
