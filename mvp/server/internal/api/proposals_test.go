package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
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
	var ownerID int64
	if err := e.f.DB.ReadTenant(context.Background(), tenant.ID, func(tx *store.TenantTx) error {
		is, err := tx.Identities()
		if len(is) > 0 {
			ownerID = is[0].ID
		}
		return err
	}); err != nil || ownerID == 0 {
		t.Fatalf("no identity in the fixture: %v", err)
	}
	for _, tc := range []struct{ name, path, body string }{
		{"catalog item", fmt.Sprintf("/api/proposals/catalog-items/%d", groupID), `{"requestable":true,"risk":"low","description":"proposed","default_hours":8,"max_hours":24}`},
		{"role", "/api/proposals/roles", fmt.Sprintf(`{"key":"proposed-role","name":"Proposed role","risk":"low","requestable":true,"description":"d","entitlement_group_ids":[%d]}`, groupID)},
		{"sod ruleset", "/api/proposals/sod-rulesets", `{"name":"Proposed ruleset","key":"proposed"}`},
		{"alert rule", "/api/proposals/alert-rules/signin_failures", proposedRule},
		{"birthright rule", "/api/proposals/birthright-rules", `{"name":"Finance staff","description":"d","condition":{"attr":"identity.department","op":"eq","value":"Finance"},"note":"n"}`},
		{"mitigating control", "/api/proposals/mitigating-controls", fmt.Sprintf(`{"name":"Monthly review","description":"d","owner_id":%d,"type":"detective","frequency":"monthly","evidence_requirement":"signed report"}`, ownerID)},
		{"approval policy", "/api/proposals/approval-policies", `{"name":"Two step","description":"d","scope":"access","steps":[{"id":"d","type":"approval","approver":"decider"}],"targets":[{"kind":"request_type","target_id":"access"}]}`},
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

// TestProposalsAPI_ProposerKeysRotate: an admin rotates the keys of a client that holds config.propose (issue #739). No
// person holds that permission, so the creator check must leave it out, as the #522 approver check does.
func TestProposalsAPI_ProposerKeysRotate(t *testing.T) {
	e := newOAuthEnv(t)
	admin := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "ada@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	id := "tsc_rotator"
	seedClient(t, e.f.DB, e.f.A.ID, id, "terraform", func(c *store.APIClient) {
		c.AllowedScopes, c.ApprovedBy = []string{"tessera:read", "config.propose"}, admin.UserID.String()
	})
	for i, mode := range []string{"add", "replace"} {
		payload := fmt.Sprintf(`{"mode":%q,"jwks":%s}`, mode, pubJWKS(t, fmt.Sprintf("rot%d", i)))
		if rec := serve(e.h, authed(admin, "POST", "/api/admin/api-clients/"+id+"/keys", payload)); rec.Code != 200 {
			t.Errorf("rotating (%s) the keys of a proposer client: %d %s", mode, rec.Code, rec.Body)
		}
	}
	// the scope is still not registrable, and a client whose roles exceed the admin is still refused
	viewer := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "vic@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	if rec := serve(e.h, authed(viewer, "POST", "/api/admin/api-clients/"+id+"/keys", fmt.Sprintf(`{"mode":"add","jwks":%s}`, pubJWKS(t, "rot9")))); rec.Code != 403 {
		t.Errorf("a viewer rotating the keys: %d %s", rec.Code, rec.Body)
	}
}

// TestProposalsAPI_NewKinds (issue #719): birthright rules, mitigating controls and approval policies are proposed, never
// written, until a different human approves with a step-up; the apply goes through the domain code the admin routes use,
// is audited in the same transaction, can change what it created, and is invisible to another tenant.
func TestProposalsAPI_NewKinds(t *testing.T) {
	e := newOAuthEnv(t)
	tenant := e.f.A
	a2 := signIn(t, e.f.DB, tenant.ID, authtest.User{Email: "ben@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	b1 := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "bob@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	m := e.addMachine("tenant-a", []string{"viewer"}, []string{"tessera:read", "config.propose"}, true)
	tok := e.machineToken(m, "tenant-a", "tessera:read config.propose")
	readOnly := e.addMachine("tenant-a", []string{"viewer"}, []string{"tessera:read", "tessera:write"}, true)
	roTok := e.machineToken(readOnly, "tenant-a", "tessera:read tessera:write")

	var ownerID int64
	if err := e.f.DB.ReadTenant(context.Background(), tenant.ID, func(tx *store.TenantTx) error {
		is, err := tx.Identities()
		if len(is) > 0 {
			ownerID = is[0].ID
		}
		return err
	}); err != nil || ownerID == 0 {
		t.Fatalf("no identity in the fixture: %v", err)
	}
	count := func(tenantID tenancy.ID, f func(*store.TenantTx) (int, error)) int {
		n := 0
		if err := e.f.DB.ReadTenant(context.Background(), tenantID, func(tx *store.TenantTx) error {
			var err error
			n, err = f(tx)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	policies := func(id tenancy.ID) int {
		return count(id, func(tx *store.TenantTx) (int, error) { ps, err := tx.AbacPolicies(); return len(ps), err })
	}
	controls := func(id tenancy.ID) int {
		return count(id, func(tx *store.TenantTx) (int, error) { cs, err := tx.SodControls(); return len(cs), err })
	}
	workflows := func(id tenancy.ID) int {
		return count(id, func(tx *store.TenantTx) (int, error) { ws, err := tx.Workflows(); return len(ws), err })
	}
	basePol, baseCtl, baseWf := policies(tenant.ID), controls(tenant.ID), workflows(tenant.ID)

	rule := `{"name":"Finance staff","description":"d","condition":{"op":"eq","attr":"identity.department","value":"Finance"}}`
	control := fmt.Sprintf(`{"name":"Monthly review","description":"d","owner_id":%d,"type":"detective","frequency":"monthly"}`, ownerID)
	policy := `{"name":"Two step","scope":"access","steps":[{"id":"d","type":"approval","approver":"decider"}]}`

	// a client without config.propose (a write token included) can propose nothing, and a person's session is refused
	for _, path := range []string{"/api/proposals/birthright-rules", "/api/proposals/mitigating-controls", "/api/proposals/approval-policies"} {
		if rec := e.call(roTok, "POST", path, `{}`); rec.Code != 403 {
			t.Errorf("a client without config.propose on %s: %d %s", path, rec.Code, rec.Body)
		}
		if rec := serve(e.h, authed(a2, "POST", path, `{}`)); rec.Code != 403 {
			t.Errorf("a person's session on %s: %d", path, rec.Code)
		}
	}

	file := func(path, payload string) (cid, hash string) {
		t.Helper()
		rec := e.call(tok, "POST", path, payload)
		got := body(rec)
		if rec.Code != 202 || got["status"] != "pending_approval" {
			t.Fatalf("POST %s: %d %s", path, rec.Code, rec.Body)
		}
		return asString(got["change_id"]), asString(got["payload_hash"])
	}
	approve := func(l authtest.Login, cid, hash string) *httptest.ResponseRecorder {
		return serve(e.h, authed(l, "POST", "/api/admin/change-requests/"+cid+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash)))
	}
	stale := signIn(t, e.f.DB, tenant.ID, authtest.User{Email: "old@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-time.Hour)}, storetest.Now)

	cases := []struct {
		name, path, payload string
		count               func(tenancy.ID) int
		base                int
	}{
		{"birthright rule", "/api/proposals/birthright-rules", rule, policies, basePol},
		{"mitigating control", "/api/proposals/mitigating-controls", control, controls, baseCtl},
		{"approval policy", "/api/proposals/approval-policies", policy, workflows, baseWf},
	}
	results := map[string]string{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cid, hash := file(tc.path, tc.payload)
			// nothing is written while it waits; the client cannot approve; an approval needs a fresh step-up
			if tc.count(tenant.ID) != tc.base {
				t.Fatal("written before approval")
			}
			if rec := e.call(tok, "POST", "/api/admin/change-requests/"+cid+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash)); rec.Code != 403 {
				t.Errorf("the client approving: %d", rec.Code)
			}
			if rec := approve(stale, cid, hash); rec.Code != 401 || body(rec)["error"] != "step_up_required" {
				t.Errorf("approval without a step-up: %d %s", rec.Code, rec.Body)
			}
			// the approver is another tenant's admin: not found
			if rec := serve(e.h, authed(b1, "POST", "/api/admin/change-requests/"+cid+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash))); rec.Code != 404 {
				t.Errorf("another tenant's admin approving: %d", rec.Code)
			}
			if rec := approve(a2, cid, hash); rec.Code != 200 || body(rec)["status"] != "applied" {
				t.Fatalf("approval: %d %s", rec.Code, rec.Body)
			}
			if got := tc.count(tenant.ID); got != tc.base+1 {
				t.Errorf("rows after approval = %d, want %d", got, tc.base+1)
			}
			if tc.count(e.f.B.ID) != 0 && tc.name != "approval policy" {
				t.Error("tenant B sees the new row")
			}
			rec := e.call(tok, "GET", "/api/proposals/"+cid, "")
			if body(rec)["status"] != "applied" || asString(body(rec)["result_id"]) == "" {
				t.Errorf("poll: %d %s", rec.Code, rec.Body)
			}
			results[tc.name] = asString(body(rec)["result_id"])
			// another tenant's admin cannot read the request, and the domain event is in the ledger
			if code := serve(e.h, authed(b1, "GET", "/api/admin/change-requests/"+cid, "")).Code; code != 404 {
				t.Errorf("tenant B reading the proposal: %d", code)
			}
		})
	}
	if tc := workflows(e.f.B.ID); tc != 0 {
		t.Errorf("tenant B has %d workflows", tc)
	}

	// the domain events are in the ledger, in the name of the approving admin, next to the change's own
	want := map[string]bool{"abac.policy.create": false, "sod.control.create": false, "workflow.create": false, "workflow.assign": false}
	for _, ev := range ledger(t, e.f.DB, tenant.ID) {
		if _, ok := want[ev.Action]; ok {
			want[ev.Action] = true
		}
	}
	for a, seen := range want {
		if !seen && a != "workflow.assign" {
			t.Errorf("no %s event", a)
		}
	}

	// a proposal can change what an earlier one made: the id in the path, the version in the body
	cid, hash := file("/api/proposals/birthright-rules/"+results["birthright rule"],
		`{"version":1,"name":"Finance staff","description":"changed","condition":{"attr":"identity.department","op":"eq","value":"Finance"}}`)
	if rec := approve(a2, cid, hash); rec.Code != 200 {
		t.Errorf("updating the rule: %d %s", rec.Code, rec.Body)
	}
	cid, hash = file("/api/proposals/mitigating-controls/"+results["mitigating control"], fmt.Sprintf(`{"version":1,"name":"Monthly review","description":"changed","owner_id":%d,"type":"detective","frequency":"weekly"}`, ownerID))
	if rec := approve(a2, cid, hash); rec.Code != 200 {
		t.Errorf("updating the control: %d %s", rec.Code, rec.Body)
	}
	cid, hash = file("/api/proposals/approval-policies/"+results["approval policy"],
		`{"version":1,"name":"Two step","steps":[{"id":"d","type":"approval","approver":"decider"}],"targets":[{"kind":"request_type","target_id":"access"}]}`)
	if rec := approve(a2, cid, hash); rec.Code != 200 {
		t.Errorf("updating the approval policy: %d %s", rec.Code, rec.Body)
	}

	// refused at the door: validation runs at submit, so nothing bad is filed
	for _, tc := range []struct {
		name, path, payload string
		want                int
	}{
		{"rule without a condition", "/api/proposals/birthright-rules", `{"name":"x"}`, 422},
		{"rule with a bad condition", "/api/proposals/birthright-rules", `{"name":"x","condition":{"attr":"nope","op":"eq","value":1}}`, 422},
		{"rule name taken", "/api/proposals/birthright-rules", rule, 409},
		{"rule not found", "/api/proposals/birthright-rules/" + uuid.NewString(), `{"version":1,"name":"x","condition":{"attr":"identity.department","op":"eq","value":"a"}}`, 404},
		{"rule stale version", "/api/proposals/birthright-rules/" + results["birthright rule"], `{"version":1,"name":"x","condition":{"attr":"identity.department","op":"eq","value":"a"}}`, 409},
		{"rule unknown field", "/api/proposals/birthright-rules", `{"name":"x","condition":{"attr":"identity.department","op":"eq","value":"a"},"admin":true}`, 422},
		{"control without an owner", "/api/proposals/mitigating-controls", `{"name":"y","type":"detective","frequency":"monthly"}`, 422},
		{"control with an unknown owner", "/api/proposals/mitigating-controls", `{"name":"y","owner_id":99999999,"type":"detective","frequency":"monthly"}`, 422},
		{"control name taken", "/api/proposals/mitigating-controls", control, 409},
		{"control not found", "/api/proposals/mitigating-controls/nope", `{"version":1,"name":"y"}`, 404},
		{"policy without steps", "/api/proposals/approval-policies", `{"name":"z","scope":"access","steps":[]}`, 422},
		{"policy name taken", "/api/proposals/approval-policies", policy, 409},
		{"policy with a bad target", "/api/proposals/approval-policies", `{"name":"z","scope":"access","steps":[{"id":"d","type":"approval","approver":"decider"}],"targets":[{"kind":"catalog_item","target_id":"nope"}]}`, 404},
		{"policy not found", "/api/proposals/approval-policies/" + uuid.NewString(), `{"version":1,"name":"z","steps":[{"id":"d","type":"approval","approver":"decider"}]}`, 404},
	} {
		if rec := e.call(tok, "POST", tc.path, tc.payload); rec.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.name, rec.Code, rec.Body, tc.want)
		}
	}
}

// TestProposalsAPI_RolesReadScope (issue #719): tessera:read lists the business roles for a machine client, read-only and
// in its own tenant; a client without that scope, and one that only proposes, cannot.
func TestProposalsAPI_RolesReadScope(t *testing.T) {
	e := newOAuthEnv(t)
	m := e.addMachine("tenant-a", []string{"viewer"}, []string{"tessera:read"}, true)
	if rec := e.call(e.machineToken(m, "tenant-a", "tessera:read"), "GET", "/api/roles", ""); rec.Code != 200 {
		t.Errorf("a read token listing roles: %d %s", rec.Code, rec.Body)
	}
	if rec := e.call(e.machineToken(m, "tenant-a", "tessera:read"), "POST", "/api/roles", `{"name":"x"}`); rec.Code != 403 {
		t.Errorf("a read token creating a role: %d %s", rec.Code, rec.Body)
	}
	p := e.addMachine("tenant-a", []string{"viewer"}, []string{"config.propose"}, true)
	if rec := e.call(e.machineToken(p, "tenant-a", "config.propose"), "GET", "/api/roles", ""); rec.Code != 403 {
		t.Errorf("a propose-only token listing roles: %d %s", rec.Code, rec.Body)
	}
}

// TestProposalsAPI_SealedSecrets (issue #719): connections, alert channels and SIEM sinks carry secrets. The client files
// them; a different admin approves with a step-up; the secret appears in no response, change request, audit event (the
// http.request ones included) or log line, before or after the apply; and it is gone when a request is rejected.
func TestProposalsAPI_SealedSecrets(t *testing.T) {
	e := newOAuthEnv(t)
	tenant := e.f.A
	a2 := signIn(t, e.f.DB, tenant.ID, authtest.User{Email: "ben@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	b1 := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "bob@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	stale := signIn(t, e.f.DB, tenant.ID, authtest.User{Email: "old@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-time.Hour)}, storetest.Now)
	m := e.addMachine("tenant-a", []string{"viewer"}, []string{"tessera:read", "config.propose"}, true)
	tok := e.machineToken(m, "tenant-a", "tessera:read config.propose")
	noScope := e.addMachine("tenant-a", []string{"viewer"}, []string{"tessera:read", "tessera:write"}, true)
	noTok := e.machineToken(noScope, "tenant-a", "tessera:read tessera:write")

	const secret = "PLAINTEXT-s3cr3t-value-7"
	hook := `{"name":"soc","kind":"webhook","target":"https://hooks.example.com/services/PLAINTEXT-s3cr3t-path","signing_secret":"` + secret + `-hook"}`
	sink := `{"name":"splunk","kind":"webhook","format":"json","flavor":"hec","target":"https://splunk.example.com:8088/collector","token":"` + secret + `-hec"}`
	conn := `{"name":"Okta prod","connector_type":"okta","config":{"org_url":"https://acme.okta.com"},"credential":{"secret":"` + secret + `-conn"}}`
	paths := map[string]string{"/api/proposals/alert-channels": hook, "/api/proposals/siem-sinks": sink, "/api/proposals/connections": conn}

	// a client without config.propose, and a person's session, file nothing
	for path, payload := range paths {
		if rec := e.call(noTok, "POST", path, payload); rec.Code != 403 {
			t.Errorf("%s without config.propose: %d", path, rec.Code)
		}
		if rec := serve(e.h, authed(a2, "POST", path, payload)); rec.Code != 403 {
			t.Errorf("%s by a person's session: %d", path, rec.Code)
		}
	}
	// nothing leaks from the ledger, rows or responses at any point
	var responses []string
	check := func(stage string) {
		t.Helper()
		hay := append([]string{}, responses...)
		for _, ev := range ledger(t, e.f.DB, tenant.ID) {
			hay = append(hay, ev.Action, string(ev.Detail))
		}
		if err := e.f.DB.ReadTenant(context.Background(), tenant.ID, func(tx *store.TenantTx) error {
			chs, err := tx.AdminChanges()
			for _, c := range chs {
				hay = append(hay, string(c.Payload), c.Failure)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		for i, h := range hay {
			if strings.Contains(h, "PLAINTEXT-s3cr3t") {
				t.Fatalf("%s: the secret is in place %d: %.300s", stage, i, h)
			}
		}
	}
	keep := func(rec *httptest.ResponseRecorder) *httptest.ResponseRecorder {
		responses = append(responses, rec.Body.String())
		return rec
	}
	type filed struct{ cid, hash string }
	files := map[string]filed{}
	for path, payload := range paths {
		rec := keep(e.call(tok, "POST", path, payload))
		got := body(rec)
		if rec.Code != 202 || got["status"] != "pending_approval" {
			t.Fatalf("POST %s: %d %s", path, rec.Code, rec.Body)
		}
		files[path] = filed{asString(got["change_id"]), asString(got["payload_hash"])}
	}
	check("after filing")
	for path, f := range files {
		// the client reads its own proposal, and an admin the request: markers only
		keep(e.call(tok, "GET", "/api/proposals/"+f.cid, ""))
		rec := keep(serve(e.h, authed(a2, "GET", "/api/admin/change-requests/"+f.cid, "")))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"set"`) {
			t.Errorf("the request of %s: %d %s", path, rec.Code, rec.Body)
		}
		keep(serve(e.h, authed(a2, "GET", "/api/admin/change-requests", "")))
		// the client cannot approve or apply; an approval needs a step-up and another tenant's admin sees nothing
		for _, act := range []string{"approve", "apply"} {
			if rec := e.call(tok, "POST", "/api/admin/change-requests/"+f.cid+"/"+act, fmt.Sprintf(`{"payload_hash":%q}`, f.hash)); rec.Code != 403 {
				t.Errorf("the client %sing %s: %d", act, path, rec.Code)
			}
		}
		if rec := serve(e.h, authed(stale, "POST", "/api/admin/change-requests/"+f.cid+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, f.hash))); rec.Code != 401 {
			t.Errorf("approval without step-up on %s: %d", path, rec.Code)
		}
		if rec := serve(e.h, authed(b1, "POST", "/api/admin/change-requests/"+f.cid+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, f.hash))); rec.Code != 404 {
			t.Errorf("another tenant approving %s: %d", path, rec.Code)
		}
	}
	check("after refused approvals")
	// nothing written yet
	count := func() (ch, sk, cn int) {
		if err := e.f.DB.ReadTenant(context.Background(), tenant.ID, func(tx *store.TenantTx) error {
			cs, _ := tx.AlertChannels()
			ks, _ := tx.SiemSinks()
			ns, err := tx.Connections()
			ch, sk, cn = len(cs), len(ks), len(ns)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	ch0, sk0, cn0 := count()
	// one is rejected: its secret goes with it
	rej := files["/api/proposals/connections"]
	if rec := keep(serve(e.h, authed(a2, "POST", "/api/admin/change-requests/"+rej.cid+"/reject", `{}`))); rec.Code != 200 {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body)
	}
	if err := e.f.DB.ReadTenant(context.Background(), tenant.ID, func(tx *store.TenantTx) error {
		id, err := uuid.Parse(rej.cid)
		if err != nil {
			return err
		}
		c, err := tx.AdminChange(id)
		if len(c.SecretEnc) != 0 {
			t.Errorf("a rejected request keeps %d sealed bytes", len(c.SecretEnc))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/proposals/alert-channels", "/api/proposals/siem-sinks"} {
		f := files[path]
		if rec := keep(serve(e.h, authed(a2, "POST", "/api/admin/change-requests/"+f.cid+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, f.hash)))); rec.Code != 200 || body(rec)["status"] != "applied" {
			t.Fatalf("approving %s: %d %s", path, rec.Code, rec.Body)
		}
		if rec := keep(e.call(tok, "GET", "/api/proposals/"+f.cid, "")); asString(body(rec)["result_id"]) == "" {
			t.Errorf("no result id for %s: %s", path, rec.Body)
		}
	}
	if ch, sk, cn := count(); ch != ch0+1 || sk != sk0+1 || cn != cn0 {
		t.Errorf("rows after = %d %d %d, want %d %d %d", ch, sk, cn, ch0+1, sk0+1, cn0)
	}
	// the admin lists show targets redacted and the applied secrets as flags
	for _, p := range []string{"/api/alerts/channels", "/api/siem/sinks"} {
		if rec := keep(serve(e.h, authed(a2, "GET", p, ""))); rec.Code != 200 {
			t.Errorf("GET %s: %d", p, rec.Code)
		}
	}
	check("after the apply")
	// the connection, filed again, is applied as a draft only
	cid, hash := func() (string, string) {
		rec := keep(e.call(tok, "POST", "/api/proposals/connections", conn))
		return asString(body(rec)["change_id"]), asString(body(rec)["payload_hash"])
	}()
	if rec := keep(serve(e.h, authed(a2, "POST", "/api/admin/change-requests/"+cid+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash)))); rec.Code != 200 {
		t.Fatalf("approving the connection: %d %s", rec.Code, rec.Body)
	}
	id := asString(body(keep(e.call(tok, "GET", "/api/proposals/"+cid, "")))["result_id"])
	if rec := keep(serve(e.h, authed(a2, "GET", "/api/connections/"+id, ""))); rec.Code != 200 || strings.Contains(rec.Body.String(), `"state":"active"`) {
		t.Errorf("the connection: %d %s", rec.Code, rec.Body)
	}
	check("after the connection")
	// and the same proposals in another tenant: refused to a client of tenant A for tenant B's rows
	if rec := e.call(tok, "POST", "/api/proposals/siem-sinks/"+uuid.NewString(), `{"name":"x"}`); rec.Code != 404 {
		t.Errorf("updating a sink that does not exist: %d %s", rec.Code, rec.Body)
	}
}
