package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/match"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The identity rules page reports what the engines apply; it carries no second rule set.
func TestIdentityRulesAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	now := storetest.Now
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now)
	policy := signIn(t, f.DB, f.B.ID, authtest.User{Email: "pa@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, now)

	rec := reqDo(h, viewer, "GET", "/api/admin/identity-rules", "")
	var v identityRulesView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != 200 {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body)
	}
	if len(v.Matching.Rules) != len(match.Catalog()) || v.Matching.NameStrong != match.DefaultNameStrong ||
		v.Matching.Settings.UnmergeWindowDays != store180 || v.Matching.Settings.AutoLinkTierB {
		t.Errorf("matching: %+v", v.Matching)
	}
	if v.GroupNaming.MaxSegment != naming.MaxExtension || v.GroupNaming.Separator != ":" || !v.GroupNaming.CaseInsensitive {
		t.Errorf("group naming: %+v", v.GroupNaming)
	}
	if len(v.Dormancy) != 2 || v.Dormancy[0].Days != 30 || v.Dormancy[1].Days != 30 || len(v.NotConfigurable) == 0 || len(v.Correlation.Proposals) == 0 ||
		v.Rules.Version != 0 || v.Rules.CanManage || len(v.Rules.CorrelationOrder) != 2 || v.Rules.CorrelationOrder[0] != "external_id" {
		t.Errorf("dormancy, correlation or the not-configurable list: %+v", v)
	}

	// the settings it shows are the ones PUT /api/admin/matching changes
	if rec := reqDo(h, policy, "PUT", "/api/admin/matching", `{"auto_link_tier_b":true,"require_review_tier_a":true,"unmerge_window_days":30}`); rec.Code != 200 {
		t.Fatalf("PUT matching: %d %s", rec.Code, rec.Body)
	}
	rec = reqDo(h, viewer, "GET", "/api/admin/identity-rules", "")
	if !strings.Contains(rec.Body.String(), `"auto_link_tier_b":true`) || !strings.Contains(rec.Body.String(), `"unmerge_window_days":30`) {
		t.Errorf("the page does not show the saved settings: %s", rec.Body)
	}
	// another tenant is unaffected
	adminA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now)
	if rec := reqDo(h, adminA, "GET", "/api/admin/identity-rules", ""); !strings.Contains(rec.Body.String(), `"auto_link_tier_b":false`) {
		t.Errorf("tenant A sees B's settings: %s", rec.Body)
	}
}

const store180 = 180

// An administrator tunes the correlation order, the authoritative sources and the dormancy thresholds; the page then
// reports what the engines read, a stale version is a conflict, and another tenant keeps the defaults.
func TestIdentityRulesPUT(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	now := storetest.Now
	policy := signIn(t, f.DB, f.B.ID, authtest.User{Email: "pa@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, now)
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now)
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: now.Add(-20 * time.Minute)}, now)
	body := `{"version":0,"correlation_order":["email","external_id"],"authoritative":{},"dormant_service_days":45,"dormant_ai_agent_days":10}`

	if rec := reqDo(h, viewer, "PUT", "/api/admin/identity-rules", body); rec.Code != 403 {
		t.Errorf("viewer PUT: %d", rec.Code)
	}
	if rec := reqDo(h, stale, "PUT", "/api/admin/identity-rules", body); rec.Code != 401 && rec.Code != 403 {
		t.Errorf("PUT without a fresh sign-in: %d", rec.Code)
	}
	rec := reqDo(h, policy, "PUT", "/api/admin/identity-rules", body)
	var v identityRulesView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != 200 {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}
	if v.Rules.Version != 1 || v.Rules.CorrelationOrder[0] != "email" || v.Rules.DormantServiceDays != 45 || v.Dormancy[0].Days != 45 || v.Dormancy[1].Days != 10 || !v.Rules.CanManage {
		t.Errorf("after PUT: %+v", v.Rules)
	}
	for name, tc := range map[string]struct {
		body string
		code int
	}{
		"stale version":  {`{"version":0,"correlation_order":["email"],"authoritative":{},"dormant_service_days":45,"dormant_ai_agent_days":10}`, 409},
		"no keys":        {`{"version":1,"correlation_order":[],"authoritative":{},"dormant_service_days":45,"dormant_ai_agent_days":10}`, 422},
		"unknown source": {`{"version":1,"correlation_order":["email"],"authoritative":{"title":"nowhere"},"dormant_service_days":45,"dormant_ai_agent_days":10}`, 422},
		"bad attribute":  {`{"version":1,"correlation_order":["email"],"authoritative":{"salary":"okta"},"dormant_service_days":45,"dormant_ai_agent_days":10}`, 422},
		"zero days":      {`{"version":1,"correlation_order":["email"],"authoritative":{},"dormant_service_days":0,"dormant_ai_agent_days":10}`, 422},
		"unknown field":  {`{"version":1,"correlation_order":["email"],"authoritative":{},"dormant_service_days":5,"dormant_ai_agent_days":10,"x":1}`, 422},
	} {
		if rec := reqDo(h, policy, "PUT", "/api/admin/identity-rules", tc.body); rec.Code != tc.code {
			t.Errorf("%s: %d %s, want %d", name, rec.Code, rec.Body, tc.code)
		}
	}
	// the change is audited with the old values
	auditor := signIn(t, f.DB, f.B.ID, authtest.User{Email: "au@b.example", Roles: []auth.Role{auth.RoleAuditor}}, authtest.Phr, now)
	rec = reqDo(h, auditor, "GET", "/api/audit", "")
	if !strings.Contains(rec.Body.String(), "identity.rules.update") {
		t.Errorf("no identity.rules.update event: %.300s", rec.Body)
	}
	// another tenant is unaffected
	viewerA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "v@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now)
	rec = reqDo(h, viewerA, "GET", "/api/admin/identity-rules", "")
	var a identityRulesView
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil || a.Rules.Version != 0 || a.Rules.DormantServiceDays != 30 || a.Rules.CorrelationOrder[0] != "external_id" {
		t.Errorf("tenant A sees B's rules: %+v", a.Rules)
	}
}
