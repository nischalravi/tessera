package api

import (
	"context"
	"encoding/json"
	"fmt"
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

// TestSiemAPI_S3AndEventFilter: an S3 sink keeps its region and access key id, seals the secret access key and
// never returns it; an event filter is normalised, validated and kept when an edit leaves it out.
func TestSiemAPI_S3AndEventFilter(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := siemServer(t, f, &okSender{})
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	body := `{"name":"Bucket","kind":"s3","format":"json","target":"https://s3.eu-west-1.amazonaws.com/audit/tessera?x=1","region":"eu-west-1",` +
		`"access_key_id":"AKIAIOSFODNN7EXAMPLE","token":"` + secret + `"}`
	if rec := siemDo(h, admin, "POST", "/api/siem/sinks", body); rec.Code != 422 || !strings.Contains(rec.Body.String(), "invalid_target") {
		t.Errorf("a bucket URL with a query: %d %s", rec.Code, rec.Body)
	}
	body = strings.Replace(body, "?x=1", "", 1)
	if rec := siemDo(h, admin, "POST", "/api/siem/sinks", strings.Replace(body, `"token":"`+secret+`"`, `"token":""`, 1)); rec.Code != 422 || !strings.Contains(rec.Body.String(), "token_required") {
		t.Errorf("an S3 sink without its secret: %d %s", rec.Code, rec.Body)
	}
	if rec := siemDo(h, admin, "POST", "/api/siem/sinks", strings.Replace(body, `"region":"eu-west-1"`, `"region":""`, 1)); rec.Code != 422 || !strings.Contains(rec.Body.String(), "invalid_region") {
		t.Errorf("an S3 sink without a region: %d %s", rec.Code, rec.Body)
	}
	if rec := siemDo(h, admin, "POST", "/api/siem/sinks", strings.Replace(body, `"format":"json"`, `"format":"json","event_filter":["auth login"]`, 1)); rec.Code != 422 || !strings.Contains(rec.Body.String(), "invalid_filter") {
		t.Errorf("a bad filter: %d %s", rec.Code, rec.Body)
	}
	rec := siemDo(h, admin, "POST", "/api/siem/sinks", strings.Replace(body, `"format":"json"`, `"format":"json","event_filter":["Auth.*","grant.revoke","auth.*"]`, 1))
	if rec.Code != 201 || strings.Contains(rec.Body.String(), secret) || !strings.Contains(rec.Body.String(), `"event_filter":["auth.*","grant.revoke"]`) ||
		!strings.Contains(rec.Body.String(), `"region":"eu-west-1"`) || !strings.Contains(rec.Body.String(), `"access_key_id":"AKIAIOSFODNN7EXAMPLE"`) ||
		!strings.Contains(rec.Body.String(), `"has_token":true`) {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var v sinkView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	// an edit that leaves the filter out keeps it; [] clears it
	if rec := siemDo(h, admin, "PUT", "/api/siem/sinks/"+v.ID, `{"name":"Bucket 2"}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"event_filter":["auth.*","grant.revoke"]`) {
		t.Errorf("update keeps the filter: %d %s", rec.Code, rec.Body)
	}
	if rec := siemDo(h, admin, "PUT", "/api/siem/sinks/"+v.ID, `{"name":"Bucket 2","event_filter":[]}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"event_filter":[]`) {
		t.Errorf("update clears the filter: %d %s", rec.Code, rec.Body)
	}
	// the secret is sealed and never in the audit log
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{})
		for _, e := range evs {
			if strings.Contains(string(e.Detail), secret) {
				t.Errorf("secret in the audit log: %s", e.Detail)
			}
		}
		k, err2 := tx.SiemSink(v.ID)
		if err2 != nil || strings.Contains(string(k.SecretSealed), secret) || len(k.SecretSealed) == 0 {
			t.Errorf("secret storage: %v", err2)
		}
		return err
	})
}

// TestSiemAPI_NarrowingTheFilterNeedsTwoAdmins (issue #511): one admin cannot narrow a sink's event filter through
// the PUT; the change request that does it needs a second admin, widening needs none, and the change's own audit
// events always match the sink.
func TestSiemAPI_NarrowingTheFilterNeedsTwoAdmins(t *testing.T) {
	e := newPrivEnv(t)
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil)
	sink := e.admin.call("POST", "/api/siem/sinks", `{"name":"splunk","kind":"webhook","format":"json","flavor":"json","target":"https://siem.example.com/hook"}`, 201)
	id := sink["id"].(string)
	// narrowing from "every event", or to a subset, is refused at the PUT
	for _, f := range []string{`["grant.revoke"]`, `["auth.*"]`} {
		got := e.admin.call("PUT", "/api/siem/sinks/"+id, `{"name":"splunk","event_filter":`+f+`}`, 409)
		if got["error"] != "two_admin_change_required" && got["code"] != "two_admin_change_required" {
			t.Errorf("narrowing to %s: %v", f, got)
		}
	}
	// the request needs a second admin
	body := fmt.Sprintf(`{"type":"siem.sink.filter","payload":{"sink_id":%q,"event_filter":["grant.revoke"]}}`, id)
	ch := e.admin.call("POST", "/api/admin/change-requests", body, 201)
	if ch["status"] != "pending_approval" || ch["two_person"] != true {
		t.Fatalf("narrowing request = %v", ch)
	}
	approve := "/api/admin/change-requests/" + ch["id"].(string) + "/approve"
	if rec := e.admin.do("POST", approve, fmt.Sprintf(`{"payload_hash":%q}`, ch["payload_hash"])); rec.Code == 200 {
		t.Errorf("the requester approved their own narrowing: %s", rec.Body)
	}
	admin2.call("POST", approve, fmt.Sprintf(`{"payload_hash":%q}`, ch["payload_hash"]), 200)
	var filter []string
	var narrowedEvents int
	_ = e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		k, err := tx.SiemSink(id)
		if err != nil {
			t.Fatal(err)
		}
		filter = k.EventFilter
		evs, _ := tx.AuditEvents(store.AuditFilter{})
		for _, ev := range evs {
			if ev.Action == "siem.sink.filter_changed" {
				narrowedEvents++
				if !siem.EventMatches(k.EventFilter, ev.Action) {
					t.Error("the filter change does not reach the filtered sink")
				}
			}
		}
		return nil
	})
	if len(filter) != 1 || filter[0] != "grant.revoke" || narrowedEvents != 1 {
		t.Errorf("filter = %v, filter_changed events = %d", filter, narrowedEvents)
	}
	// widening is one admin, at the PUT or as a request that applies at once
	e.admin.call("PUT", "/api/siem/sinks/"+id, `{"name":"splunk","event_filter":["grant.revoke","auth.*"]}`, 200)
	wide := e.admin.call("POST", "/api/admin/change-requests", fmt.Sprintf(`{"type":"siem.sink.filter","payload":{"sink_id":%q,"event_filter":[]}}`, id), 201)
	if wide["status"] != "applied" || wide["two_person"] != false {
		t.Errorf("clearing the filter = %v", wide)
	}
}
