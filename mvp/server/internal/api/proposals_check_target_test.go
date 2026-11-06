package api

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// TestProposalsAPI_CheckTarget (issue #886): an approver checks the URL they expect against the one a proposal seals and
// learns only match / no-match; the check needs the approve permission and a fresh step-up, is bounded, and the sealed and
// submitted URLs appear in no response or audit event. The fingerprint is then on the live channel and sink.
func TestProposalsAPI_CheckTarget(t *testing.T) {
	e := newOAuthEnv(t)
	tenant := e.f.A
	login := func(email string, role auth.Role) authtest.Login {
		return signIn(t, e.f.DB, tenant.ID, authtest.User{Email: email, Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
	}
	a2 := login("ben@a.example", auth.RoleTenantAdmin)
	viewer := login("vic@a.example", auth.RoleViewer)
	stale := signIn(t, e.f.DB, tenant.ID, authtest.User{Email: "old@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-time.Hour)}, storetest.Now)
	b1 := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "bob@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	m := e.addMachine("tenant-a", []string{"viewer"}, []string{"tessera:read", "config.propose"}, true)
	tok := e.machineToken(m, "tenant-a", "tessera:read config.propose")

	const target = "https://hooks.example.com/services/PLAINTEXT-sealed-path"
	const guess = "https://hooks.example.com/services/PLAINTEXT-guess-path"
	rec := e.call(tok, "POST", "/api/proposals/alert-channels", `{"name":"soc","kind":"webhook","target":"`+target+`","signing_secret":"PLAINTEXT-signing-secret-1"}`)
	got := body(rec)
	cid, hash, fp := asString(got["change_id"]), asString(got["payload_hash"]), asString(got["target_fingerprint"])
	if rec.Code != 202 || fp == "" {
		t.Fatalf("proposal: %d %s", rec.Code, rec.Body)
	}
	path := "/api/admin/change-requests/" + cid + "/check-target"
	check := func(l authtest.Login, url string) (int, map[string]any, string) {
		r := serve(e.h, authed(l, "POST", path, fmt.Sprintf(`{"url":%q}`, url)))
		return r.Code, body(r), r.Body.String()
	}

	if code, _, _ := check(viewer, target); code != 403 {
		t.Errorf("a viewer checking: %d", code)
	}
	if code, v, _ := check(stale, target); code != 401 || v["error"] != "step_up_required" {
		t.Errorf("a stale step-up: %d %v", code, v)
	}
	if r := e.call(tok, "POST", path, `{"url":"`+target+`"}`); r.Code != 403 {
		t.Errorf("the proposing client checking: %d %s", r.Code, r.Body)
	}
	if code, _, _ := check(b1, target); code != 404 {
		t.Errorf("another tenant's admin checking: %d", code)
	}
	if code, v, _ := check(a2, target); code != 200 || v["match"] != true {
		t.Errorf("matching URL: %d %v", code, v)
	}
	code, v, raw := check(a2, guess)
	if code != 200 || v["match"] != false || strings.Contains(raw, "PLAINTEXT") || strings.Contains(raw, "hooks.example.com") {
		t.Errorf("non-matching URL: %d %s", code, raw)
	}
	if code, _, _ := check(a2, "not a url"); code != 422 {
		t.Errorf("a malformed URL: %d", code)
	}
	for i := 0; i < admin.MaxTargetChecksPerRequest-2; i++ {
		check(a2, guess)
	}
	if code, v, _ := check(a2, target); code != 429 || v["error"] != admin.ReasonTargetCheckLocked {
		t.Errorf("after the limit: %d %v", code, v)
	}
	for _, ev := range ledger(t, e.f.DB, tenant.ID) {
		if d := string(ev.Detail); strings.Contains(d, "PLAINTEXT") || strings.Contains(d, "hooks.example.com") {
			t.Errorf("%s carries a URL: %s", ev.Action, d)
		}
	}

	// the fingerprint on the live channel is the one the approver compared
	if r := serve(e.h, authed(a2, "POST", "/api/admin/change-requests/"+cid+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash))); r.Code != 200 {
		t.Fatalf("approve: %d %s", r.Code, r.Body)
	}
	r := serve(e.h, authed(a2, "GET", "/api/alerts/channels", ""))
	if !strings.Contains(r.Body.String(), `"target_fingerprint":"`+fp+`"`) || !strings.Contains(r.Body.String(), `"target_origin":"https://hooks.example.com:443"`) ||
		strings.Contains(r.Body.String(), "PLAINTEXT-sealed") {
		t.Errorf("channel list: %s", r.Body)
	}
	rec = e.call(tok, "POST", "/api/proposals/siem-sinks", `{"name":"splunk","kind":"webhook","format":"json","flavor":"hec","target":"https://splunk.example.com:8088/collector","token":"PLAINTEXT-hec-token-0001"}`)
	sink := body(rec)
	if rec.Code != 202 {
		t.Fatalf("sink proposal: %d %s", rec.Code, rec.Body)
	}
	if r := serve(e.h, authed(a2, "POST", "/api/admin/change-requests/"+asString(sink["change_id"])+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, asString(sink["payload_hash"])))); r.Code != 200 {
		t.Fatalf("approve sink: %d %s", r.Code, r.Body)
	}
	r = serve(e.h, authed(a2, "GET", "/api/siem/sinks", ""))
	if !strings.Contains(r.Body.String(), `"target_fingerprint":"`+asString(sink["target_fingerprint"])+`"`) || strings.Contains(r.Body.String(), "PLAINTEXT") {
		t.Errorf("sink list: %s", r.Body)
	}
}
