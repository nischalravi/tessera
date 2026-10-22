package api

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/deprov"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Attestation and deprovisioning over the API (issue #57, GR-14).

func TestAttestationAPI_DecideRevokesThroughTheEngine(t *testing.T) {
	e := newPrivEnv(t)
	e.linkAdmin()
	app := e.admin.folder("", "app")
	g := e.admin.group(app, "g")
	for _, who := range []string{"alice", "bob"} {
		e.admin.call("POST", "/api/groups/"+g+"/members", fmt.Sprintf(`{"identity":%d}`, e.ident(who)), 201)
	}
	camp := e.admin.call("POST", "/api/groups/"+g+"/attestation/campaigns", "", 201)["id"].(string)
	detail := e.admin.call("GET", "/api/groups/attestation/campaigns/"+camp, "", 200)
	if detail["population_verified"] != true {
		t.Errorf("detail = %v", detail)
	}
	items := detail["items"].([]any)
	var aliceItem, bobItem string
	for _, it := range items {
		m := it.(map[string]any)
		if m["identity_id"] == float64(e.ident("alice")) {
			aliceItem = m["id"].(string)
		} else {
			bobItem = m["id"].(string)
		}
	}
	// someone who administers nothing may not decide
	stranger := e.user("stranger", "carol")
	denied(t, stranger, "POST", "/api/groups/attestation/campaigns/"+camp+"/items/"+aliceItem+"/decision", `{"decision":"revoke"}`, "admin")
	// a decision is keep or revoke
	if rec := e.admin.do("POST", "/api/groups/attestation/campaigns/"+camp+"/items/"+aliceItem+"/decision", `{"decision":"maybe"}`); rec.Code != 422 {
		t.Errorf("a bad decision = %d", rec.Code)
	}
	out := e.admin.call("POST", "/api/groups/attestation/campaigns/"+camp+"/items/"+aliceItem+"/decision", `{"decision":"revoke","comment":"left the team"}`, 200)
	if out["apply_state"] != "applied" {
		t.Errorf("revoke = %v", out)
	}
	e.admin.call("POST", "/api/groups/attestation/campaigns/"+camp+"/items/"+bobItem+"/decision", `{"decision":"keep"}`, 200)
	m := e.admin.call("GET", "/api/groups/"+g+"/members?filter=direct", "", 200)
	if m["total"] != float64(1) {
		t.Errorf("members after the revoke = %v", m)
	}
	if v := e.admin.call("GET", "/api/groups/attestation/campaigns/"+camp, "", 200)["campaign"].(map[string]any); v["status"] != "completed" {
		t.Errorf("campaign = %v", v)
	}
	// a decided campaign takes no more decisions
	if rec := e.admin.do("POST", "/api/groups/attestation/campaigns/"+camp+"/items/"+bobItem+"/decision", `{"decision":"keep"}`); rec.Code != 409 {
		t.Errorf("decision on a completed campaign = %d", rec.Code)
	}
}

func TestDeprovAPI_VetoNeedsAnOverrideByAnAdmin(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	g, aff := e.admin.group(app, "g"), e.admin.group(app, "aff")
	e.admin.call("PUT", "/api/groups/deprovisioning/settings", `{"affiliations":["`+aff+`"]}`, 200)
	carol := fmt.Sprintf(`{"identity":%d}`, e.ident("carol"))
	e.admin.call("POST", "/api/groups/"+aff+"/members", carol, 201)
	e.admin.call("DELETE", "/api/groups/"+aff+"/members/"+fmt.Sprint(e.ident("carol")), "", 200)
	if err := e.f.DB.InTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		_, err := deprov.Process(deprov.Env{Tx: tx, Now: storetest.Now}, 1000)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	bob := e.user("bob", "bob")
	e.grant("/api/groups/"+g, "update", "bob", "")
	rec := bob.do("POST", "/api/groups/"+g+"/members", carol)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"vetoed"`) {
		t.Fatalf("add of a deprovisioned identity = %d %s", rec.Code, rec.Body.String())
	}
	// update is not enough to override: admin is
	over := fmt.Sprintf(`{"identity":%d,"override_reason":"returning contractor"}`, e.ident("carol"))
	denied(t, bob, "POST", "/api/groups/"+g+"/members", over, "admin")
	e.admin.call("POST", "/api/groups/"+g+"/members", over, 201)
}

// Issues #439 and #440: a group attestation decision is refused like a review
// decision: 403 self_review for the subject, 403 reviewer_unlinked for an
// account with no linked identity, each audited, and the item stays open.
func TestAttestationAPI_RefusesSelfAndUnlinkedDeciders(t *testing.T) {
	e := newPrivEnv(t)
	g := e.admin.group(e.admin.folder("", "app"), "g")
	e.admin.call("POST", "/api/groups/"+g+"/members", fmt.Sprintf(`{"identity":%d}`, e.ident("alice")), 201)
	camp := e.admin.call("POST", "/api/groups/"+g+"/attestation/campaigns", "", 201)["id"].(string)
	item := e.admin.call("GET", "/api/groups/attestation/campaigns/"+camp, "", 200)["items"].([]any)[0].(map[string]any)["id"].(string)
	path := "/api/groups/attestation/campaigns/" + camp + "/items/" + item + "/decision"
	alice := e.ident("alice")
	admins := []auth.Role{auth.RoleTenantAdmin}
	for _, tc := range []struct {
		name, code string
		by         grpClient
	}{
		{"unlinked", "reviewer_unlinked", e.as("unlinked-admin", admins, nil)},
		{"subject", "self_review", e.as("alice-admin", admins, &alice)},
	} {
		before := auditCount(t, e.f, "review.decide.refused")
		if rec := tc.by.do("POST", path, `{"decision":"keep"}`); rec.Code != 403 || !strings.Contains(rec.Body.String(), `"`+tc.code+`"`) {
			t.Errorf("%s: %d %s, want 403 %s", tc.name, rec.Code, rec.Body, tc.code)
		}
		if n := auditCount(t, e.f, "review.decide.refused"); n != before+1 {
			t.Errorf("%s: %d review.decide.refused events, want %d", tc.name, n, before+1)
		}
	}
	if v := e.admin.call("GET", "/api/groups/attestation/campaigns/"+camp, "", 200)["campaign"].(map[string]any); v["status"] != "open" {
		t.Errorf("a refused decision changed the campaign: %v", v)
	}
}
