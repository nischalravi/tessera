package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func TestDatasetsAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	now := storetest.Now
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now)
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "pa@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, now)
	other := signIn(t, f.DB, f.A.ID, authtest.User{Email: "pa@a.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, now)

	if rec := reqDo(h, viewer, "POST", "/api/datasets", `{"name":"x"}`); rec.Code != 403 {
		t.Errorf("viewer create: %d", rec.Code)
	}
	rec := reqDo(h, admin, "POST", "/api/datasets", `{"name":"Cost centers","description":"d","values":["cc-1"]}`)
	var d datasetView
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil || rec.Code != 201 || d.Count != 1 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	base := "/api/datasets/" + d.ID
	if rec := reqDo(h, admin, "POST", "/api/datasets", `{"name":"Cost centers"}`); rec.Code != 409 {
		t.Errorf("duplicate: %d", rec.Code)
	}
	if rec := reqDo(h, admin, "POST", "/api/datasets", `{"name":"bad/name"}`); rec.Code != 422 || strings.Contains(rec.Body.String(), "bad/name") {
		t.Errorf("bad name: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", base+"/values", `{"add":["cc-2","cc-3"],"remove":["cc-1"]}`); rec.Code != 200 ||
		!strings.Contains(rec.Body.String(), `"added":2`) || !strings.Contains(rec.Body.String(), `"removed":1`) {
		t.Errorf("edit values: %d %s", rec.Code, rec.Body)
	}
	csvReq := func(l authtest.Login, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Content-Type", "text/csv")
		l.Apply(req)
		return serve(h, req)
	}
	if rec := csvReq(admin, base+"/upload?header=true", "v\ncc-9\ncc-2\n"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"added":1`) {
		t.Errorf("upload: %d %s", rec.Code, rec.Body)
	}
	if rec := csvReq(viewer, base+"/upload", "a\n"); rec.Code != 403 {
		t.Errorf("viewer upload: %d", rec.Code)
	}
	if rec := csvReq(admin, base+"/upload?mode=bogus", "a\n"); rec.Code != 422 {
		t.Errorf("bad mode: %d", rec.Code)
	}
	if rec := csvReq(admin, base+"/upload?mode=replace", "only\n"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"count":1`) {
		t.Errorf("replace: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, viewer, "GET", base+"/contains?value=only", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"contains":true`) {
		t.Errorf("contains: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, viewer, "GET", base+"?limit=10", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"values":["only"]`) {
		t.Errorf("get: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "PUT", base, `{"version":1,"name":"Renamed","description":""}`); rec.Code != 409 {
		t.Errorf("stale rename: %d", rec.Code)
	}
	if rec := reqDo(h, admin, "GET", "/api/datasets/not-an-id", ""); rec.Code != 404 {
		t.Errorf("bad id: %d", rec.Code)
	}
	// another tenant sees and touches nothing
	if rec := reqDo(h, other, "GET", "/api/datasets", ""); rec.Code != 200 || strings.Contains(rec.Body.String(), "Cost centers") {
		t.Errorf("tenant A lists B's datasets: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, other, "GET", base, ""); rec.Code != 404 {
		t.Errorf("tenant A reads B's dataset: %d", rec.Code)
	}
	if rec := reqDo(h, other, "DELETE", base, ""); rec.Code != 404 {
		t.Errorf("tenant A deletes B's dataset: %d", rec.Code)
	}
	if rec := reqDo(h, admin, "DELETE", base, ""); rec.Code != 200 {
		t.Errorf("delete: %d %s", rec.Code, rec.Body)
	}
	got := reqAuditActions(t, f, f.B.ID)
	for _, a := range []string{"dataset.created", "dataset.values.changed", "dataset.uploaded", "dataset.deleted"} {
		if got[a] == 0 {
			t.Errorf("no %s audit event: %v", a, got)
		}
	}
}
