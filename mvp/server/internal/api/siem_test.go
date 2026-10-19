package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/siem"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// seedSiemSink adds a webhook sink in tenant tn and returns its id.
func seedSiemSink(t *testing.T, db *store.DB, tn tenancy.ID, tag string) string {
	t.Helper()
	id := "sink-" + tag
	if err := db.InTenant(context.Background(), tn, func(tx *store.TenantTx) error {
		return tx.InsertSiemSink(&store.SiemSink{ID: id, Name: "SIEM " + tag, Kind: "webhook", Format: "json", Target: "https://siem.example/x?token=abc",
			Flavor: "json", Enabled: true, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func siemDo(h http.Handler, l authtest.Login, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	l.Apply(req)
	return serve(h, req)
}

func siemServer(t *testing.T, f *storetest.Fixture, snd siem.Sender) http.Handler {
	t.Helper()
	sealer, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	srv := newIsolationServer(f)
	srv.cfg.Siem = &siem.Service{DB: f.DB, Sealer: sealer,
		NewSender: func(*store.SiemSink, string, string) (siem.Sender, error) { return snd, nil }}
	return srv.Handler()
}

type okSender struct{ n int }

func (o *okSender) Send(_ context.Context, b []siem.Record) error { o.n += len(b); return nil }

func TestSiemAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	snd := &okSender{}
	h := siemServer(t, f, snd)
	now := storetest.Now
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	auditor := signIn(t, f.DB, f.B.ID, authtest.User{Email: "au@b.example", Roles: []auth.Role{auth.RoleAuditor}}, authtest.Phr, now)
	op := signIn(t, f.DB, f.B.ID, authtest.User{Email: "op@b.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, now)

	body := `{"name":"Splunk","kind":"webhook","format":"ocsf","target":"https://splunk.example:8088/services/collector?channel=x","flavor":"hec","token":"hec-123"}`
	if rec := siemDo(h, op, "POST", "/api/siem/sinks", body); rec.Code != 403 {
		t.Errorf("operator creates: %d", rec.Code)
	}
	if rec := siemDo(h, auditor, "POST", "/api/siem/sinks", body); rec.Code != 403 {
		t.Errorf("auditor creates: %d", rec.Code)
	}
	rec := siemDo(h, admin, "POST", "/api/siem/sinks", body)
	if rec.Code != 201 || strings.Contains(rec.Body.String(), "hec-123") || strings.Contains(rec.Body.String(), "channel=x") ||
		!strings.Contains(rec.Body.String(), `"has_token":true`) || !strings.Contains(rec.Body.String(), `"status":"healthy"`) {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var v sinkView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if rec := siemDo(h, admin, "POST", "/api/siem/sinks", `{"name":"x","kind":"syslog","format":"json","target":"10.1.2.3:6514"}`); rec.Code != 422 {
		t.Errorf("private syslog target: %d %s", rec.Code, rec.Body)
	}
	if rec := siemDo(h, admin, "POST", "/api/siem/sinks", `{"name":"x","kind":"webhook","format":"json","target":"https://x.example","flavor":"hec"}`); rec.Code != 422 || !strings.Contains(rec.Body.String(), "token_required") {
		t.Errorf("HEC without a token: %d %s", rec.Code, rec.Body)
	}
	// the auditor sees health and lag
	rec = siemDo(h, auditor, "GET", "/api/siem/sinks", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"health":{"status":"healthy"`) || !strings.Contains(rec.Body.String(), `"head_seq":`) {
		t.Errorf("list: %d %s", rec.Code, rec.Body)
	}
	// update keeps the token and target when omitted
	rec = siemDo(h, admin, "PUT", "/api/siem/sinks/"+v.ID, `{"name":"Splunk prod","include_http":true,"enabled":false}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"has_token":true`) || !strings.Contains(rec.Body.String(), `"status":"paused"`) ||
		!strings.Contains(rec.Body.String(), "splunk.example:8088") {
		t.Errorf("update: %d %s", rec.Code, rec.Body)
	}
	if rec := siemDo(h, admin, "POST", "/api/siem/sinks/"+v.ID+"/rewind", `{"seq":0}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"cursor_seq":0`) {
		t.Errorf("rewind: %d %s", rec.Code, rec.Body)
	}
	if rec := siemDo(h, admin, "POST", "/api/siem/sinks/"+v.ID+"/rewind", `{}`); rec.Code != 422 {
		t.Errorf("rewind without seq: %d", rec.Code)
	}
	rec = siemDo(h, admin, "POST", "/api/siem/sinks/"+v.ID+"/test", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":true`) || snd.n != 1 {
		t.Errorf("test: %d %s (sent %d)", rec.Code, rec.Body, snd.n)
	}
	if rec := siemDo(h, auditor, "GET", "/api/siem/sinks/"+v.ID+"/dead-letters", ""); rec.Code != 200 || rec.Body.String() != "[]" {
		t.Errorf("dead letters: %d %s", rec.Code, rec.Body)
	}
	acts := map[string]int{}
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{})
		for _, e := range evs {
			acts[e.Action]++
			if strings.Contains(string(e.Detail), "hec-123") {
				t.Errorf("token in the audit log: %s", e.Detail)
			}
		}
		return err
	})
	for _, a := range []string{"siem.sink.created", "siem.sink.updated", "siem.sink.rewound", "siem.sink.tested"} {
		if acts[a] != 1 {
			t.Errorf("%s audited %d times", a, acts[a])
		}
	}
}

// TestSiemAPI_CrossTenant: tenant A's sinks answer like ids that do not exist.
func TestSiemAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := siemServer(t, f, &okSender{})
	aSink := seedSiemSink(t, f.DB, f.A.ID, "a")
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	before := storetest.Dump(t, f.DB, f.A.ID)
	for _, c := range []struct{ method, path, body string }{
		{"PUT", "/api/siem/sinks/%s", `{"name":"x"}`},
		{"POST", "/api/siem/sinks/%s/rewind", `{"seq":0}`},
		{"POST", "/api/siem/sinks/%s/test", ""},
		{"GET", "/api/siem/sinks/%s/dead-letters", ""},
	} {
		got := siemDo(h, admin, c.method, strings.Replace(c.path, "%s", aSink, 1), c.body)
		want := siemDo(h, admin, c.method, strings.Replace(c.path, "%s", "nope", 1), c.body)
		if got.Code != want.Code || got.Code == 200 || got.Body.String() != want.Body.String() {
			t.Errorf("%s %s: %d %s; missing: %d %s", c.method, c.path, got.Code, got.Body, want.Code, want.Body)
		}
	}
	if rec := siemDo(h, admin, "GET", "/api/siem/sinks", ""); strings.Contains(rec.Body.String(), aSink) {
		t.Error("A's sink listed for B")
	}
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("tenant A changed")
	}
}
