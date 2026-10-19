package api

import (
	"encoding/json"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/orgs"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// The seeded larkspur company has departments, so the Organizations page is
// not empty: a root, one organization per department, owners and members.
func TestOrgsAPI_DemoCompany(t *testing.T) {
	c := client{t, testServer(t, testkit.Demo(t))}
	rec := c.do("GET", "/api/orgs", "")
	var list []orgs.Org
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != 200 || len(list) < 5 {
		t.Fatalf("list: %d %.400s", rec.Code, rec.Body)
	}
	root := list[0]
	if root.ID != orgs.RootID || root.Kind != orgs.KindRoot || root.Name == "" || root.Children != len(list)-1 || root.Members < 20 {
		t.Errorf("root = %+v", root)
	}
	owned := 0
	sum := 0
	for _, o := range list[1:] {
		sum += o.Members
		if o.ParentID == nil || *o.ParentID != orgs.RootID || o.Members == 0 {
			t.Errorf("department %+v", o)
		}
		if o.Owner != nil {
			owned++
		}
	}
	if sum != root.Members || owned == 0 {
		t.Errorf("departments hold %d of the root's %d people; %d have an owner", sum, root.Members, owned)
	}
	// a department's detail names its owners, members and their managers
	dept := list[1]
	rec = c.do("GET", "/api/orgs/"+dept.ID, "")
	var d orgs.Detail
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil || rec.Code != 200 || d.ID != dept.ID || d.Parent == nil || d.Parent.ID != orgs.RootID ||
		len(d.People) != dept.Members {
		t.Fatalf("detail: %d %.400s", rec.Code, rec.Body)
	}
	rec = c.do("GET", "/api/orgs/root", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil || rec.Code != 200 || len(d.Children) != root.Children {
		t.Errorf("root detail: %d %.300s", rec.Code, rec.Body)
	}
	for _, id := range []string{"nope", "dept-zzzzzzzzzz", "dept-0123456789", "../x", "ROOT"} {
		if rec := c.do("GET", "/api/orgs/"+id, ""); rec.Code != 404 {
			t.Errorf("GET /api/orgs/%s = %d", id, rec.Code)
		}
	}
}

// Another tenant sees only its own people: tenant B's organizations carry none
// of tenant A's (the fixture marks A's names with a sentinel), and the page
// needs graph.read.
func TestOrgsAPI_TenantScopedAndPermission(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	viewerB := reqLogin(t, f, "v@b.example", []auth.Role{auth.RoleViewer}, "")
	breakGlass := reqLogin(t, f, "bg@b.example", []auth.Role{auth.RoleBreakGlass}, "")

	rec := reqDo(h, viewerB, "GET", "/api/orgs", "")
	var list []orgs.Org
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != 200 || len(list) < 2 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if leaks(rec.Body.String()) {
		t.Error("tenant B's organizations carry tenant A's data")
	}
	for _, o := range list {
		rec := reqDo(h, viewerB, "GET", "/api/orgs/"+o.ID, "")
		if rec.Code != 200 || leaks(rec.Body.String()) {
			t.Errorf("org %s: %d, leaks=%v", o.ID, rec.Code, leaks(rec.Body.String()))
		}
	}
	// the count is B's own people
	var want int
	for _, o := range list[1:] {
		want += o.Members
	}
	if list[0].Members != want || want == 0 {
		t.Errorf("root counts %d people, departments %d", list[0].Members, want)
	}
	for _, p := range []string{"/api/orgs", "/api/orgs/root"} {
		if rec := reqDo(h, breakGlass, "GET", p, ""); rec.Code != 403 {
			t.Errorf("break-glass GET %s = %d, want 403", p, rec.Code)
		}
	}
}
