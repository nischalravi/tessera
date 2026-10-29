package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Config proposals by machine clients (issue #721): the scope arrives only through a two-admin change, a proposal is
// a 202 that waits for a human with a step-up, the client polls only its own proposals, and nothing the client holds
// lets it approve.

const proposedRule = `{"enabled":true,"severity":"critical","threshold":2,"window_minutes":30}`

func TestProposalsAPI_Flow(t *testing.T) {
	e := newOAuthEnv(t)
	tenant := e.f.A
	login := func(email string, role auth.Role) authtest.Login {
		return signIn(t, e.f.DB, tenant.ID, authtest.User{Email: email, Display: strings.Split(email, "@")[0], Roles: []auth.Role{role}},
			authtest.Phr, storetest.Now)
	}
	a1, a2 := login("ada@a.example", auth.RoleTenantAdmin), login("ben@a.example", auth.RoleTenantAdmin)
	person := func(l authtest.Login, method, path, payload string) (int, map[string]any) {
		rec := serve(e.h, authed(l, method, path, payload))
		return rec.Code, body(rec)
	}

	// a client its admin created (ApprovedBy is that admin: the config.propose grant must not trip the #522 check)
	id := "tsc_proposer"
	key := seedClient(t, e.f.DB, tenant.ID, id, "terraform", func(c *store.APIClient) {
		c.AllowedScopes, c.ApprovedBy = []string{"tessera:read"}, a1.UserID.String()
	})
	m := machineClient{id: id, key: key}
	other := e.addMachine("tenant-a", []string{"viewer"}, []string{"tessera:read", "config.propose"}, true)

	// 1. without the scope: 403, whatever else the token holds
	plain := e.machineToken(m, "tenant-a", "tessera:read")
	if rec := e.call(plain, "POST", "/api/proposals/alert-rules/signin_failures", proposedRule); rec.Code != 403 || body(rec)["permission"] != "config.propose" {
		t.Fatalf("a client without the scope: %d %s", rec.Code, rec.Body)
	}
	// a person never holds it: a tenant admin's session is refused too
	if code, _ := person(a1, "POST", "/api/proposals/alert-rules/signin_failures", proposedRule); code != 403 {
		t.Errorf("an admin proposing with a session: %d", code)
	}

	// 2. the grant needs two admins and a step-up; the admin API refuses the client as either
	grant := fmt.Sprintf(`{"type":"api_client.propose.grant","payload":{"client_id":%q}}`, id)
	if rec := e.call(plain, "POST", "/api/admin/change-requests", grant); rec.Code != 403 {
		t.Errorf("a client filing its own grant: %d", rec.Code)
	}
	code, ch := person(a1, "POST", "/api/admin/change-requests", grant)
	if code != 201 || ch["status"] != "pending_approval" {
		t.Fatalf("grant request: %d %v", code, ch)
	}
	gid, ghash := asString(ch["id"]), asString(ch["payload_hash"])
	approve := func(l authtest.Login, cid, hash string) (int, map[string]any) {
		return person(l, "POST", "/api/admin/change-requests/"+cid+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash))
	}
	if code, v := approve(a1, gid, ghash); code != 403 || v["error"] != "self_approval_refused" {
		t.Errorf("the requesting admin approving the grant: %d %v", code, v)
	}
	if code, v := approve(a2, gid, ghash); code != 200 || v["status"] != "applied" {
		t.Fatalf("second admin approves the grant: %d %v", code, v)
	}

	// 3. the proposal: 202, a change id and a URL; nothing is written yet
	tok := e.machineToken(m, "tenant-a", "tessera:read config.propose")
	rec := e.call(tok, "POST", "/api/proposals/alert-rules/signin_failures", proposedRule)
	got := body(rec)
	cid, hash := asString(got["change_id"]), asString(got["payload_hash"])
	if rec.Code != http.StatusAccepted || got["status"] != "pending_approval" || cid == "" || len(hash) != 64 ||
		!strings.Contains(asString(got["url"]), "/admin/change-requests?id="+cid) {
		t.Fatalf("proposal: %d %s", rec.Code, rec.Body)
	}
	threshold := func() int {
		var th int
		if err := e.f.DB.ReadTenant(context.Background(), tenant.ID, func(tx *store.TenantTx) error {
			r, err := alerts.EffectiveRule(tx, "signin_failures")
			th = r.Threshold
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return th
	}
	if threshold() == 2 {
		t.Fatal("the rule changed before approval")
	}
	if rec := e.call(tok, "GET", "/api/proposals/"+cid, ""); rec.Code != 200 || body(rec)["status"] != "pending_approval" {
		t.Errorf("poll: %d %s", rec.Code, rec.Body)
	}
	// another client, even one holding the scope, sees nothing of it
	otherTok := e.machineToken(other, "tenant-a", "tessera:read config.propose")
	if rec := e.call(otherTok, "GET", "/api/proposals/"+cid, ""); rec.Code != 404 {
		t.Errorf("another client polling: %d %s", rec.Code, rec.Body)
	}
	if rec := e.call(tok, "GET", "/api/proposals/"+gid, ""); rec.Code != 404 {
		t.Errorf("polling a change a person filed: %d %s", rec.Code, rec.Body)
	}

	// 4. the client can approve nothing, with or without a hash
	for _, path := range []string{"approve", "apply", "reject"} {
		if rec := e.call(tok, "POST", "/api/admin/change-requests/"+cid+"/"+path, fmt.Sprintf(`{"payload_hash":%q}`, hash)); rec.Code != 403 {
			t.Errorf("the proposing client calling %s: %d %s", path, rec.Code, rec.Body)
		}
	}
	// the admin view names the client
	if code, v := person(a2, "GET", "/api/admin/change-requests/"+cid, ""); code != 200 || v["proposed_by_client"] != id ||
		v["type"] != "config.proposal" || !strings.Contains(asString(v["summary"]), "alert rule signin_failures") {
		t.Errorf("admin view: %d %v", code, v)
	}

	// 5. a human approves with a step-up and only then is it applied
	stale := signIn(t, e.f.DB, tenant.ID, authtest.User{Email: "old@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-time.Hour)}, storetest.Now)
	if code, v := approve(stale, cid, hash); code != 401 || v["error"] != "step_up_required" {
		t.Errorf("approval without a fresh step-up: %d %v", code, v)
	}
	if threshold() == 2 {
		t.Fatal("the rule changed without an approval")
	}
	if code, v := approve(a2, cid, hash); code != 200 || v["status"] != "applied" {
		t.Fatalf("approval: %d %v", code, v)
	}
	if threshold() != 2 {
		t.Fatal("the rule did not change after approval")
	}
	if rec := e.call(tok, "GET", "/api/proposals/"+cid, ""); rec.Code != 200 || body(rec)["status"] != "applied" || body(rec)["applied_at"] == nil {
		t.Errorf("poll after apply: %d %s", rec.Code, rec.Body)
	}

	// 6. every transition of the proposal names the client
	seen := map[string]bool{}
	for _, ev := range ledger(t, e.f.DB, tenant.ID) {
		if strings.HasPrefix(ev.Action, "admin.change.") && strings.Contains(string(ev.Detail), cid) {
			if !strings.Contains(string(ev.Detail), `"client_id":"`+id+`"`) {
				t.Errorf("%s has no client id: %s", ev.Action, ev.Detail)
			}
			seen[ev.Action] = true
		}
	}
	for _, a := range []string{"admin.change.submitted", "admin.change.approved", "admin.change.applied"} {
		if !seen[a] {
			t.Errorf("no %s event naming the client", a)
		}
	}

	// 7. bad proposals are refused before anything is filed
	for _, tc := range []struct {
		name, path, body string
		want             int
	}{
		{"no body", "/api/proposals/alert-rules/signin_failures", ``, 422},
		{"unknown rule", "/api/proposals/alert-rules/nope", proposedRule, 404},
		{"unknown field", "/api/proposals/alert-rules/signin_failures", `{"enabled":true,"severity":"high","threshold":2,"window_minutes":30,"x":1}`, 422},
		{"catalog group not a number", "/api/proposals/catalog-items/abc", `{"risk":"low"}`, 422},
		{"role without a name", "/api/proposals/roles", `{"risk":"low"}`, 422},
		{"ruleset without a name", "/api/proposals/sod-rulesets", `{}`, 422},
	} {
		if rec := e.call(tok, "POST", tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.name, rec.Code, rec.Body, tc.want)
		}
	}

	// 8. the other tenant's admin sees none of this
	b1 := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "bob@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	if code, _ := person(b1, "GET", "/api/admin/change-requests/"+cid, ""); code != 404 {
		t.Errorf("tenant B reading A's proposal: %d", code)
	}
}

// TestProposalsAPI_Kinds: each kind files a pending request that applies after a human approves it.
func TestProposalsAPI_Kinds(t *testing.T) {
	e := newOAuthEnv(t)
	tenant := e.f.A
	a1 := signIn(t, e.f.DB, tenant.ID, authtest.User{Email: "ada@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	a2 := signIn(t, e.f.DB, tenant.ID, authtest.User{Email: "ben@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	m := e.addMachine("tenant-a", []string{"viewer"}, []string{"tessera:read", "config.propose"}, true)
	tok := e.machineToken(m, "tenant-a", "tessera:read config.propose")
	_ = a1

	var groupID int64
	if err := e.f.DB.ReadTenant(context.Background(), tenant.ID, func(tx *store.TenantTx) error {
		gs, err := tx.Groups()
		if len(gs) > 0 {
			groupID = gs[0].ID
		}
		return err
	}); err != nil || groupID == 0 {
		t.Fatalf("no group in the fixture: %v", err)
	}
	for _, tc := range []struct{ name, path, body string }{
		{"catalog item", fmt.Sprintf("/api/proposals/catalog-items/%d", groupID), `{"requestable":true,"risk":"low","description":"proposed","default_hours":8,"max_hours":24}`},
		{"role", "/api/proposals/roles", fmt.Sprintf(`{"key":"proposed-role","name":"Proposed role","risk":"low","requestable":true,"description":"d","entitlement_group_ids":[%d]}`, groupID)},
		{"sod ruleset", "/api/proposals/sod-rulesets", `{"name":"Proposed ruleset","key":"proposed"}`},
		{"alert rule", "/api/proposals/alert-rules/signin_failures", proposedRule},
	} {
		rec := e.call(tok, "POST", tc.path, tc.body)
		got := body(rec)
		if rec.Code != 202 {
			t.Errorf("%s: %d %s", tc.name, rec.Code, rec.Body)
			continue
		}
		cid, hash := asString(got["change_id"]), asString(got["payload_hash"])
		rec = serve(e.h, authed(a2, "POST", "/api/admin/change-requests/"+cid+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash)))
		if rec.Code != 200 || body(rec)["status"] != "applied" {
			t.Errorf("%s approval: %d %s", tc.name, rec.Code, rec.Body)
		}
		rec = e.call(tok, "GET", "/api/proposals/"+cid, "")
		if body(rec)["status"] != "applied" {
			t.Errorf("%s poll: %d %s", tc.name, rec.Code, rec.Body)
		}
		// the poll names what a create made (a role or ruleset by its key), so the client can find it
		if asString(body(rec)["result_id"]) == "" {
			t.Errorf("%s poll has no result_id: %s", tc.name, rec.Body)
		}
	}
}

// TestProposalsAPI_ScopeIsNotRegistrable: no way to register a client hands out config.propose; only the two-admin change does.
func TestProposalsAPI_ScopeIsNotRegistrable(t *testing.T) {
	e := newOAuthEnv(t)
	admin := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "ada@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	owner := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "owner@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	_ = owner
	create := fmt.Sprintf(`{"name":"tf","owner":"owner@a.example","scopes":["tessera:read","config.propose"],"roles":["viewer"],"jwks":%s}`, pubJWKS(t, "k1"))
	rec := serve(e.h, authed(admin, "POST", "/api/admin/api-clients", create))
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "invalid_scopes") {
		t.Errorf("registering a client with config.propose: %d %s", rec.Code, rec.Body)
	}
	// a person cannot file a config.proposal: only a machine client does, through /api/proposals (issue #740)
	direct := `{"type":"config.proposal","payload":{"kind":"alert_rule","id":"mfa_bypass","body":{"enabled":false,"severity":"low","threshold":1,"window_minutes":60}}}`
	if rec := serve(e.h, authed(admin, "POST", "/api/admin/change-requests", direct)); rec.Code != 422 {
		t.Errorf("a person filing a config.proposal: %d %s", rec.Code, rec.Body)
	}
	// and the grant refuses a first-party client
	grant := `{"type":"api_client.propose.grant","payload":{"client_id":"tessera-cli"}}`
	if rec := serve(e.h, authed(admin, "POST", "/api/admin/change-requests", grant)); rec.Code != 404 && rec.Code != 409 && rec.Code != 422 {
		t.Errorf("granting config.propose to the CLI client: %d %s", rec.Code, rec.Body)
	}
}
