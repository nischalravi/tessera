package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/match"
	"github.com/nischalravi/tessera/mvp/server/internal/nhi"
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
	if len(v.Dormancy) != 1 || v.Dormancy[0].Days != nhi.DormantDays || len(v.NotConfigurable) == 0 || len(v.Correlation.Proposals) == 0 {
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
