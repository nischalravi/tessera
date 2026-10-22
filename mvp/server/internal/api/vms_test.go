package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/vms/vmsfake"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func TestVmsAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	fk := vmsfake.New("fieldglass", "client-1", "s3cret-value")
	fk.Set(vmsfake.Worker{ID: "W-1", First: "Casey", Last: "Contractor", Email: "casey@agency.example", Status: "Active",
		Start: "2026-09-01", End: now.AddDate(0, 0, 60).Format("2006-01-02"), Supplier: "Acme", ManagerEmail: "dana@corp.example",
		Modified: now.Add(-time.Hour)},
		vmsfake.Worker{ID: "W-2", First: "Sam", Last: "NoBoss", Email: "sam@agency.example", Status: "Active",
			Start: "2026-09-01", End: now.AddDate(0, 0, 60).Format("2006-01-02"), Supplier: "Acme", Modified: now.Add(-time.Hour)})
	fgSrv := connsynctest.New(t, fk)
	hc, err := safehttp.NewForTest(t, fgSrv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	srv := newIsolationServerWith(f, func(c *Config) { c.Sealer = testSealer() })
	srv.vms.HTTP, srv.vms.RT = hc, connsynctest.Runtime
	h := srv.Handler()
	// the sponsor
	if err := f.DB.InTenant(t.Context(), f.B.ID, func(c *store.TenantTx) error {
		m := "dana@corp.example"
		_, err := c.InsertIdentity(&store.Identity{ExternalID: "emp-1", Name: "Dana", Email: &m, Type: "human", Status: "active", CreatedAt: now})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	adminA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	pa := signIn(t, f.DB, f.B.ID, authtest.User{Email: "pa@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, now)
	paA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "pa@a.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, now)
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now)
	auditor := signIn(t, f.DB, f.B.ID, authtest.User{Email: "au@b.example", Roles: []auth.Role{auth.RoleAuditor}}, authtest.Phr, now)

	create := jsonStr(map[string]any{"vendor": "fieldglass", "name": "Fieldglass EU", "base_url": fgSrv.URL, "credential": "client-1:s3cret-value"})
	if rec := reqDo(h, viewer, "POST", "/api/vms/sources", create); rec.Code != 403 {
		t.Errorf("viewer POST: %d", rec.Code)
	}
	if rec := reqDo(h, auditor, "GET", "/api/vms/sources", ""); rec.Code != 403 && rec.Code != 200 {
		t.Errorf("auditor GET: %d", rec.Code)
	}
	rec := reqDo(h, admin, "POST", "/api/vms/sources", create)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "s3cret") {
		t.Error("the credential is in the response")
	}
	var src vmsSourceView
	_ = json.Unmarshal(rec.Body.Bytes(), &src)
	if src.ID == "" || !src.HasCredential || src.Status != "active" || src.Vendor != "fieldglass" {
		t.Fatalf("source = %+v", src)
	}

	bad := map[string]string{
		"unknown vendor":        `{"vendor":"workday","name":"x","base_url":"https://a.example.com"}`,
		"bad name":              `{"vendor":"csv","name":"<script>"}`,
		"no credential":         `{"vendor":"beeline","name":"Beeline","base_url":"https://bl.example.com"}`,
		"a bare token":          `{"vendor":"beeline","name":"Beeline","base_url":"https://bl.example.com","credential":"abc"}`,
		"no base url":           `{"vendor":"fieldglass","name":"FG2","credential":"a:b"}`,
		"http in a base url":    `{"vendor":"fieldglass","name":"FG2","base_url":"http://fg.example.com","credential":"a:b"}`,
		"a traversal path":      `{"vendor":"fieldglass","name":"FG2","base_url":"https://fg.example.com","credential":"a:b","settings":{"workers_path":"/a/../b"}}`,
		"csv with half a fetch": `{"vendor":"csv","name":"File","base_url":"https://files.example.com"}`,
		"unknown field":         `{"vendor":"csv","name":"File","extra":1}`,
	}
	for name, body := range bad {
		if rec := reqDo(h, admin, "POST", "/api/vms/sources", body); rec.Code != 422 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := reqDo(h, admin, "POST", "/api/vms/sources", create); rec.Code != 409 {
		t.Errorf("duplicate name: %d", rec.Code)
	}

	// edits: the credential is kept unless the origin moves
	edit := func(m map[string]any) *httptest.ResponseRecorder {
		return reqDo(h, admin, "PUT", "/api/vms/sources/"+src.ID, jsonStr(m))
	}
	if rec := edit(map[string]any{"name": "Fieldglass EU", "base_url": fgSrv.URL, "status": "paused"}); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"paused"`) {
		t.Errorf("pause: %d %s", rec.Code, rec.Body)
	}
	if rec := edit(map[string]any{"name": "Fieldglass EU", "base_url": "https://other.example.com"}); rec.Code != 422 || !strings.Contains(rec.Body.String(), "credential_required") {
		t.Errorf("moved origin without a credential: %d %s", rec.Code, rec.Body)
	}
	if rec := edit(map[string]any{"vendor": "beeline", "name": "x", "base_url": fgSrv.URL}); rec.Code != 422 {
		t.Errorf("vendor change: %d", rec.Code)
	}
	if rec := edit(map[string]any{"name": "Fieldglass EU", "base_url": fgSrv.URL, "status": "active"}); rec.Code != 200 {
		t.Errorf("resume: %d %s", rec.Code, rec.Body)
	}

	// another tenant sees and changes none of it
	if rec := reqDo(h, adminA, "GET", "/api/vms/sources", ""); rec.Code != 200 || strings.Contains(rec.Body.String(), src.ID) {
		t.Errorf("tenant A list: %d %s", rec.Code, rec.Body)
	}
	for _, c := range [][2]string{{"PUT", "/api/vms/sources/" + src.ID}, {"DELETE", "/api/vms/sources/" + src.ID},
		{"POST", "/api/vms/sources/" + src.ID + "/import"}} {
		body := `{"name":"x"}`
		if strings.HasSuffix(c[1], "/import") {
			body = "worker_id,name,email\n"
		}
		who := adminA
		if strings.HasSuffix(c[1], "/import") {
			who = paA // import needs lifecycle.manage
		}
		req := httptest.NewRequest(c[0], c[1], strings.NewReader(body))
		req.Header.Set("Content-Type", map[bool]string{true: "text/csv", false: "application/json"}[strings.HasSuffix(c[1], "/import")])
		who.Apply(req)
		if rec := serve(h, req); rec.Code != 404 {
			t.Errorf("tenant A %s %s: %d", c[0], c[1], rec.Code)
		}
	}
	if rec := reqDo(h, paA, "POST", "/api/vms/sync", jsonStr(map[string]any{"source_id": src.ID})); rec.Code != 404 {
		t.Errorf("tenant A sync of B's source: %d", rec.Code)
	}

	// sync: one contractor is created, the one with no sponsor is held
	if rec := reqDo(h, viewer, "POST", "/api/vms/sync", ""); rec.Code != 403 {
		t.Errorf("viewer sync: %d", rec.Code)
	}
	if rec := reqDo(h, admin, "POST", "/api/vms/sync", ""); rec.Code != 403 {
		t.Errorf("tenant admin sync (it creates and ends people): %d", rec.Code)
	}
	rec = reqDo(h, pa, "POST", "/api/vms/sync", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"created":1`) || !strings.Contains(rec.Body.String(), `"review":1`) {
		t.Fatalf("sync: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, admin, "GET", "/api/vms/records?limit=10", "")
	var recs struct {
		Records []vmsRecordView `json:"records"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &recs)
	if rec.Code != 200 || len(recs.Records) != 2 {
		t.Fatalf("records: %d %s", rec.Code, rec.Body)
	}
	reasons := map[string]string{}
	for _, r := range recs.Records {
		reasons[r.Outcome] = r.Reason
		if r.Source != "fieldglass" {
			t.Errorf("record source = %q", r.Source)
		}
	}
	if reasons["review"] != "sponsor_required" || reasons["created"] != "" {
		t.Errorf("outcomes = %v", reasons)
	}
	for _, l := range []string{"0", "501", "-1", "9223372036854775807", "99999999999999999999", "x"} {
		if rec := reqDo(h, admin, "GET", "/api/vms/records?limit="+l, ""); rec.Code != 422 {
			t.Errorf("limit %s: %d", l, rec.Code)
		}
	}
	if rec := reqDo(h, adminA, "GET", "/api/vms/records", ""); rec.Code != 200 || strings.Contains(rec.Body.String(), `"fieldglass"`) {
		t.Errorf("tenant A records: %d %s", rec.Code, rec.Body)
	}

	// a CSV source takes an uploaded file
	rec = reqDo(h, admin, "POST", "/api/vms/sources", `{"vendor":"csv","name":"Agency file"}`)
	var file vmsSourceView
	_ = json.Unmarshal(rec.Body.Bytes(), &file)
	if rec.Code != 201 || file.HasCredential {
		t.Fatalf("csv create: %d %s", rec.Code, rec.Body)
	}
	csv := "worker_id,name,email,sponsor_email,end_date\nC-1,Kim Lo,kim@agency.example,dana@corp.example," + now.AddDate(0, 0, 20).Format("2006-01-02") + "\n"
	up := func(id, ct, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/vms/sources/"+id+"/import", strings.NewReader(body))
		req.Header.Set("Content-Type", ct)
		pa.Apply(req)
		return serve(h, req)
	}
	if rec := up(file.ID, "text/csv", csv); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"created":1`) {
		t.Errorf("import: %d %s", rec.Code, rec.Body)
	}
	if rec := up(file.ID, "text/csv", "junk"); rec.Code != 422 {
		t.Errorf("bad file: %d %s", rec.Code, rec.Body)
	}
	if rec := up(file.ID, "application/json", "{}"); rec.Code != http.StatusUnsupportedMediaType && rec.Code != 415 {
		t.Errorf("json as a file: %d", rec.Code)
	}
	if rec := up(src.ID, "text/csv", csv); rec.Code != 422 {
		t.Errorf("file for a REST source: %d", rec.Code)
	}

	// removing a feed keeps the contractors it brought
	if rec := reqDo(h, admin, "DELETE", "/api/vms/sources/"+src.ID, ""); rec.Code != 200 {
		t.Errorf("delete: %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "DELETE", "/api/vms/sources/"+src.ID, ""); rec.Code != 404 {
		t.Errorf("second delete: %d", rec.Code)
	}
	acts := reqAuditActions(t, f, f.B.ID)
	for _, a := range []string{"vms.source_created", "vms.source_updated", "vms.source_removed", "vms.sync", "intake.vms.created", "intake.vms.review", "lifecycle.set"} {
		if acts[a] == 0 {
			t.Errorf("no %s audit event: %v", a, acts)
		}
	}
	// the sealed credential is never in an audit event
	if err := f.DB.ReadTenant(t.Context(), f.B.ID, func(c *store.TenantTx) error {
		log, err := c.AuditLog(-1)
		for _, e := range log {
			if strings.Contains(string(e.Detail), "s3cret") {
				t.Errorf("audit %s carries the secret", e.Action)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
