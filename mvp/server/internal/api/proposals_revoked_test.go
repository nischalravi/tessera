package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// TestProposalsAPI_RevokedProposerIsCancelled: revoking a client, or removing its config.propose scope, cancels what it
// proposed and nobody approved yet (reason proposer_revoked, audited); an approval afterwards is refused with nothing
// applied (issue #743).
func TestProposalsAPI_RevokedProposerIsCancelled(t *testing.T) {
	e := newOAuthEnv(t)
	tenant := e.f.A
	login := func(email string) authtest.Login {
		return signIn(t, e.f.DB, tenant.ID, authtest.User{Email: email, Display: strings.Split(email, "@")[0], Roles: []auth.Role{auth.RoleTenantAdmin}},
			authtest.Phr, storetest.Now)
	}
	a1, a2 := login("ada@a.example"), login("ben@a.example")
	person := func(l authtest.Login, method, path, payload string) (int, map[string]any) {
		rec := serve(e.h, authed(l, method, path, payload))
		return rec.Code, body(rec)
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
	for _, how := range []string{"revoke", "scope_removal"} {
		t.Run(how, func(t *testing.T) {
			id := "tsc_" + how
			key := seedClient(t, e.f.DB, tenant.ID, id, "terraform", func(c *store.APIClient) {
				c.AllowedScopes, c.ApprovedBy = []string{"tessera:read", "config.propose"}, a1.UserID.String()
			})
			tok := e.machineToken(machineClient{id: id, key: key}, "tenant-a", "tessera:read config.propose")
			before := threshold()
			rec := e.call(tok, "POST", "/api/proposals/alert-rules/signin_failures", proposedRule)
			cid, hash := asString(body(rec)["change_id"]), asString(body(rec)["payload_hash"])
			if rec.Code != http.StatusAccepted || cid == "" {
				t.Fatalf("proposal: %d %s", rec.Code, rec.Body)
			}
			if how == "revoke" {
				if code, v := person(a1, "POST", "/api/admin/api-clients/"+id+"/revoke", `{}`); code != 200 || v["status"] != "disabled" {
					t.Fatalf("revoke: %d %v", code, v)
				}
			} else {
				if err := e.f.DB.InTenant(context.Background(), tenant.ID, func(tx *store.TenantTx) error {
					return e.srv.admin.SetClientScopes(tx, id, []string{"tessera:read"}, nil, "test")
				}); err != nil {
					t.Fatal(err)
				}
			}
			// the client cannot poll any more (its token no longer holds the scope), so the cancellation is read by the admin
			if rec := e.call(tok, "GET", "/api/proposals/"+cid, ""); rec.Code == 200 {
				t.Errorf("a client without the scope polled: %s", rec.Body)
			}
			if code, v := person(a2, "GET", "/api/admin/change-requests/"+cid, ""); code != 200 || v["status"] != "cancelled" || v["failure"] != "proposer_revoked" {
				t.Errorf("admin view: %d %v", code, v)
			}
			if code, v := person(a2, "POST", "/api/admin/change-requests/"+cid+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash)); code != 409 {
				t.Errorf("approving a cancelled proposal: %d %v", code, v)
			}
			if threshold() != before {
				t.Error("a revoked client's proposal was applied")
			}
			found := false
			for _, ev := range ledger(t, e.f.DB, tenant.ID) {
				found = found || ev.Action == "admin.change.cancelled" && strings.Contains(string(ev.Detail), cid) &&
					strings.Contains(string(ev.Detail), "proposer_revoked") && strings.Contains(string(ev.Detail), `"client_id":"`+id+`"`)
			}
			if !found {
				t.Error("no admin.change.cancelled event naming the client and the reason")
			}
		})
	}
}
