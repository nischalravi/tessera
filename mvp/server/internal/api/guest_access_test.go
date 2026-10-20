package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/access"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The real claim grants the bundle and joins the reference groups; the
// sponsorship view shows each item's state; the person's bundle and the
// reference groups are readable by those with the permission.
func TestGuestAccess_ClaimGrantsBundleAndJoinsRefGroups(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	var gid int64
	if err := e.db.InTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		gs, err := tx.Groups()
		if err != nil {
			return err
		}
		for _, g := range gs {
			if g.System == "okta" && !g.Privileged {
				gid = g.ID
				break
			}
		}
		return tx.PutCatalogItem(&store.CatalogItem{ID: uuid.NewString(), GroupID: gid, Requestable: true, Risk: "low",
			EligibleTypes: []string{"human"}, UpdatedAt: e.clk.now()})
	}); err != nil || gid == 0 {
		t.Fatal(gid, err)
	}
	const email = "bundle@guest.example"
	ends := e.clk.now().AddDate(0, 0, 10)
	rec := e.do(e.sponsor, "POST", "/api/guests/invitations", inviteJSON(email, "visitor", ends, fmt.Sprintf(`,"bundle":[%d]`, gid)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("invite: %d %s", rec.Code, rec.Body)
	}
	var v sponsorshipView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if len(v.Bundle) != 1 || v.Bundle[0].State != "pending" || !strings.Contains(v.Bundle[0].Detail, "claim") {
		t.Fatalf("bundle before the claim = %+v", v.Bundle)
	}
	_, token := e.lastLink(email)
	pg := e.newPage()
	pg.start(token)
	pg.verifyEmail(email)
	pg.post("existing-account", `{"answer":"no"}`)
	authURL, lc := e.loginURL(pg.post("credential", ""))
	ref := strings.TrimPrefix(e.identityOf(v.Guest.ID).ExternalID, "guest:")
	if cb := e.signInAtIdP(authURL, lc, "guest-"+ref, devidp.MethodPasskey); cb.Header().Get("Location") != "/claim?result=complete" {
		t.Fatalf("callback: %d %v", cb.Code, cb.Header())
	}
	// the sponsorship view says granted, expiring with the sponsorship
	rec = e.do(e.sponsor, "GET", "/api/sponsorships/"+v.ID, "")
	var after sponsorshipView
	_ = json.Unmarshal(rec.Body.Bytes(), &after)
	if len(after.Bundle) != 1 || after.Bundle[0].State != "granted" || after.Bundle[0].ExpiresAt == nil || !after.Bundle[0].ExpiresAt.Equal(ends) {
		t.Fatalf("bundle after the claim = %+v", after.Bundle)
	}
	// the guest is in the reference groups and Groups lists them
	admin := authtest.LoginAs(t, e.db, e.tenant, authtest.User{Email: "pa@larkspur.example", Display: "Pat", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, e.clk.now())
	rec = e.do(admin, "GET", "/api/refgroups", "")
	var rg refGroupsView
	if err := json.Unmarshal(rec.Body.Bytes(), &rg); err != nil || rec.Code != 200 {
		t.Fatalf("refgroups: %d %s", rec.Code, rec.Body)
	}
	in := func(key string) bool {
		for _, g := range rg.Groups {
			if g.Key == key {
				return slices.ContainsFunc(g.Members, func(p personRef) bool { return p.ID == v.Guest.ID })
			}
		}
		return false
	}
	if !in(access.RefGuestActive) || !in(access.RefGuestVisitor) || in(access.RefIAL2) {
		t.Errorf("reference groups after the claim: %+v", rg)
	}
	rec = e.do(admin, "GET", fmt.Sprintf("/api/identities/%d/access-bundle", v.Guest.ID), "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"state":"granted"`) {
		t.Errorf("access-bundle: %d %s", rec.Code, rec.Body)
	}
	// ending the sponsorship removes the membership and the reference groups
	if rec = e.do(e.sponsor, "POST", "/api/sponsorships/"+v.ID+"/end", `{"reason":"done"}`); rec.Code != 200 {
		t.Fatalf("end: %d %s", rec.Code, rec.Body)
	}
	rec = e.do(admin, "GET", "/api/refgroups", "")
	_ = json.Unmarshal(rec.Body.Bytes(), &rg)
	if in(access.RefGuestActive) {
		t.Error("an ended guest is still in ref:guest:active")
	}
	rec = e.do(e.sponsor, "GET", "/api/sponsorships/"+v.ID, "")
	_ = json.Unmarshal(rec.Body.Bytes(), &after)
	if after.Bundle[0].State != "removed" {
		t.Errorf("bundle after the end = %+v", after.Bundle)
	}
}
