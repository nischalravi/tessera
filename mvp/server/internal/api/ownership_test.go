package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func ownDo(h http.Handler, l authtest.Login, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	l.Apply(req)
	return serve(h, req)
}

func TestOwnershipAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	op := signIn(t, f.DB, f.B.ID, authtest.User{Email: "op@b.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, storetest.Now)
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	ids := f.B.IDs
	group := ids["group:okta:payments-approvers"]
	body := fmt.Sprintf(`{"primary_owner_id":%d,"backup_owner_id":%d,"purpose":"approve payments"}`, ids["alice"], ids["carol"])
	path := fmt.Sprintf("/api/ownership/group/%d", group)

	if rec := ownDo(h, viewer, "PUT", path, body); rec.Code != 403 {
		t.Errorf("viewer sets: %d", rec.Code)
	}
	rec := ownDo(h, op, "PUT", path, body)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"source":"tessera"`) || !strings.Contains(rec.Body.String(), `"purpose":"approve payments"`) {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	if rec := ownDo(h, op, "PUT", "/api/ownership/account/1", "{}"); rec.Code != 422 {
		t.Errorf("bad kind: %d %s", rec.Code, rec.Body)
	}
	same := fmt.Sprintf(`{"primary_owner_id":%d,"backup_owner_id":%d}`, ids["alice"], ids["alice"])
	if rec := ownDo(h, op, "PUT", path, same); rec.Code != 422 || !strings.Contains(rec.Body.String(), "same_owner") {
		t.Errorf("same owner: %d %s", rec.Code, rec.Body)
	}
	if rec := ownDo(h, op, "PUT", path, `{"owner":1}`); rec.Code != 422 {
		t.Errorf("unknown field: %d %s", rec.Code, rec.Body)
	}

	rec = ownDo(h, viewer, "GET", "/api/ownership?kind=group&unowned=false", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"backup_owner":{"id":`) || strings.Count(rec.Body.String(), `"key":`) != 1 {
		t.Errorf("owned groups: %d %s", rec.Code, rec.Body)
	}
	rec = ownDo(h, viewer, "GET", "/api/ownership?kind=identity", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"source":"connector"`) || !strings.Contains(rec.Body.String(), `"counts":{`) {
		t.Errorf("identities: %d %s", rec.Code, rec.Body)
	}
	if rec := ownDo(h, viewer, "GET", "/api/ownership?kind=account", ""); rec.Code != 422 {
		t.Errorf("bad kind query: %d", rec.Code)
	}

	bulk := fmt.Sprintf(`{"objects":[{"kind":"identity","key":"%d"},{"kind":"app","key":"okta"}],"primary_owner_id":%d}`, ids["svc-etl"], ids["carol"])
	rec = ownDo(h, op, "POST", "/api/ownership/bulk", bulk)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"updated":2`) {
		t.Fatalf("bulk: %d %s", rec.Code, rec.Body)
	}
	rec = ownDo(h, viewer, "GET", fmt.Sprintf("/api/identities/%d", ids["svc-etl"]), "")
	if !strings.Contains(rec.Body.String(), fmt.Sprintf(`"owner":{"id":%d,`, ids["carol"])) {
		t.Errorf("svc-etl owner not carol: %s", rec.Body)
	}
	if rec := ownDo(h, op, "POST", "/api/ownership/bulk", `{"objects":[],"primary_owner_id":null}`); rec.Code != 422 {
		t.Errorf("empty bulk: %d", rec.Code)
	}
}
