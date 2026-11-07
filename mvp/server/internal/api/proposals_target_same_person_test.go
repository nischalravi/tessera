package api

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The target_change flag of a proposal tells whether the URL it seals equals the object's live URL, so only an approver who
// is not the proposer may see it (#886). "The proposer" is the person, as in approve, cancel and check-target
// (store.SameActor): a second platform user of the same identity (one per IdP connection) must not see it either.
func TestProposalsAPI_TargetChangeHiddenFromTheProposersOtherAccount(t *testing.T) {
	e := newOAuthEnv(t)
	tenant := e.f.A
	e.srv.cfg.Alerts = &alerts.Service{DB: e.f.DB, Sealer: e.sealer, Mail: alerts.LogMailer{}}
	alice := tenant.IDs["alice"]
	owner := signIn(t, e.f.DB, tenant.ID, authtest.User{Email: "alice@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}, IdentityID: &alice},
		authtest.Phr, storetest.Now)
	otherAccount := signIn(t, e.f.DB, tenant.ID, authtest.User{Email: "alice.sso2@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}, IdentityID: &alice},
		authtest.Phr, storetest.Now)
	approver := signIn(t, e.f.DB, tenant.ID, authtest.User{Email: "ben@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)

	id := "tsc_samepersona01"
	key := seedClient(t, e.f.DB, tenant.ID, id, "proposer", func(c *store.APIClient) {
		c.Roles, c.AllowedScopes = []string{"viewer"}, []string{"tessera:read", "config.propose"}
		c.OwnerUserID = &owner.UserID
	})
	tok := e.machineToken(machineClient{id: id, key: key}, "tenant-a", "tessera:read config.propose")

	const live = "https://hooks.example.com/services/PLAINTEXT-live-path"
	r := serve(e.h, authed(approver, "POST", "/api/alerts/channels", `{"name":"live","kind":"webhook","target":"`+live+`","min_severity":"high"}`))
	if r.Code != 201 {
		t.Fatalf("channel: %d %s", r.Code, r.Body)
	}
	chID := asString(body(r)["id"])
	rec := e.call(tok, "POST", "/api/proposals/alert-channels/"+chID, `{"target":"`+live+`"}`) // the guess equals the live URL
	if rec.Code != 202 {
		t.Fatalf("proposal: %d %s", rec.Code, rec.Body)
	}
	change := asString(body(rec)["change_id"])

	if v := body(serve(e.h, authed(approver, "GET", "/api/admin/change-requests/"+change, ""))); v["target_change"] != "unchanged" {
		t.Fatalf("the other approver's flag = %v, want unchanged", v["target_change"])
	}
	for name, l := range map[string]authtest.Login{"the proposer's owner": owner, "the owner's other account": otherAccount} {
		if v := serve(e.h, authed(l, "GET", "/api/admin/change-requests/"+change, "")).Body.String(); strings.Contains(v, "target_change") {
			t.Errorf("%s sees how the sealed URL compares with the live one: %s", name, v)
		}
	}
	if r := serve(e.h, authed(otherAccount, "POST", "/api/admin/change-requests/"+change+"/check-target", `{"url":"`+live+`"}`)); r.Code != 403 {
		t.Errorf("check-target by the owner's other account: %d %s", r.Code, r.Body)
	}
}
