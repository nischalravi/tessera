package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// runLeaver files and executes an HRIS leaver for identity id (#331).
func runLeaver(t *testing.T, h http.Handler, l authtest.Login, id int64) {
	t.Helper()
	rec := corrDo(h, l, "POST", "/api/hris/events", fmt.Sprintf(`{"type":"leaver","identity_id":%d}`, id))
	var ev struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ev); err != nil || rec.Code != 200 || ev.ID == 0 {
		t.Fatalf("create leaver: %d %.300s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, l, "POST", fmt.Sprintf("/api/hris/events/%d/execute", ev.ID), ""); rec.Code != 200 {
		t.Fatalf("execute leaver: %d %.300s", rec.Code, rec.Body)
	}
}

func sessionRevokedReason(t *testing.T, f *storetest.Fixture, l authtest.Login) string {
	t.Helper()
	var reason string
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		s, err := c.Session(l.SessionID)
		if err == nil && s.RevokedReason != nil {
			reason = *s.RevokedReason
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return reason
}

// A leaver on a disabled identity must not lift the #316 block (#331).
func TestLeaverOnDisabledIdentityKeepsSignInBlocked(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := containServer(t, f).Handler()
	alice := f.A.IDs["alice"]
	linked := signIn(t, f.DB, f.A.ID, authtest.User{Email: "alice@a.example", Roles: []auth.Role{auth.RolePolicyAdmin},
		IdentityID: &alice}, authtest.Phr, storetest.Now)
	l := linkedPolicyAdmin(t, f, f.A.ID, "pa@a.example")
	if rec := corrDo(h, l, "POST", fmt.Sprintf("/api/identities/%d/disable", alice), `{"reason":"suspected insider activity"}`); rec.Code != 200 {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body)
	}
	runLeaver(t, h, l, alice)
	if st := identityStatus(t, h, l, alice); st != "terminated" {
		t.Fatalf("status after leaver = %s", st)
	}
	if rec := corrDo(h, linked, "GET", "/api/auth/session", ""); rec.Code != 401 {
		t.Errorf("old session after disable+leaver: %d", rec.Code)
	}
	if _, err := authtest.New(f.DB, f.A.ID, authtest.User{ID: linked.UserID, Email: "alice@a.example", IdentityID: &alice},
		authtest.Phr, storetest.Now); err == nil {
		t.Error("a session was issued to a user whose identity was disabled and then terminated")
	}
	// enable cannot bring a terminated identity back
	l2 := linkedPolicyAdmin(t, f, f.A.ID, "pa2@a.example")
	if rec := corrDo(h, l2, "POST", fmt.Sprintf("/api/identities/%d/enable", alice), `{"reason":"cleared by investigation"}`); rec.Code == 200 {
		t.Errorf("enable of a terminated identity succeeded: %s", rec.Body)
	}
	if st := identityStatus(t, h, l, alice); st != "terminated" {
		t.Errorf("status after refused enable = %s", st)
	}
}

// A leaver alone revokes the linked user's sessions in its transaction and
// blocks new ones (#331).
func TestLeaverRevokesLinkedUserSessions(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := containServer(t, f).Handler()
	alice := f.A.IDs["alice"]
	linked := signIn(t, f.DB, f.A.ID, authtest.User{Email: "alice@a.example", Roles: []auth.Role{auth.RolePolicyAdmin},
		IdentityID: &alice}, authtest.Phr, storetest.Now)
	l := linkedPolicyAdmin(t, f, f.A.ID, "pa@a.example")
	if rec := corrDo(h, linked, "GET", "/api/auth/session", ""); rec.Code != 200 {
		t.Fatalf("session before leaver: %d", rec.Code)
	}
	runLeaver(t, h, l, alice)
	// The leaver's containment step (RevokeLocal) revokes the sessions first,
	// with "containment: leaver"; TerminateIdentity then finds none active and
	// would write identity_terminated. Either way the sessions are revoked.
	if got := sessionRevokedReason(t, f, linked); got != auth.RevokedIdentityTerminated && got != "containment: leaver" {
		t.Errorf("revoked reason %q, want %q or the containment reason", got, auth.RevokedIdentityTerminated)
	}
	if rec := corrDo(h, linked, "GET", "/api/auth/session", ""); rec.Code != 401 {
		t.Errorf("session after leaver: %d", rec.Code)
	}
	if _, err := authtest.New(f.DB, f.A.ID, authtest.User{ID: linked.UserID, Email: "alice@a.example", IdentityID: &alice},
		authtest.Phr, storetest.Now); err == nil {
		t.Error("a session was issued to a user whose identity is terminated")
	}
	// the admin's own session is untouched
	if rec := corrDo(h, l, "GET", "/api/auth/session", ""); rec.Code != 200 {
		t.Errorf("unrelated session: %d", rec.Code)
	}
}

// The session middleware fails closed on every non-active identity status,
// even when no revocation ran (#331).
func TestSessionRefusedForInactiveIdentity(t *testing.T) {
	for _, st := range []string{"disabled", "terminated", store.IdentityStatusMerged, "unknown_status"} {
		t.Run(st, func(t *testing.T) {
			f := storetest.TwoTenants(t)
			h := containServer(t, f).Handler()
			alice := f.A.IDs["alice"]
			linked := signIn(t, f.DB, f.A.ID, authtest.User{Email: "alice@a.example", Roles: []auth.Role{auth.RolePolicyAdmin},
				IdentityID: &alice}, authtest.Phr, storetest.Now)
			if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
				return c.SetIdentityStatus(alice, st)
			}); err != nil {
				t.Fatal(err)
			}
			rec := corrDo(h, linked, "GET", "/api/auth/session", "")
			if rec.Code != 401 {
				t.Errorf("session with identity %s: %d %s", st, rec.Code, rec.Body)
			}
			if _, err := authtest.New(f.DB, f.A.ID, authtest.User{ID: linked.UserID, Email: "alice@a.example", IdentityID: &alice},
				authtest.Phr, storetest.Now); err == nil {
				t.Errorf("a session was issued with identity %s", st)
			}
		})
	}
}

// Merge never moves a sign-in: an identity bound to a Tessera user cannot be
// merged away, so its user cannot end up on a merged identity through the API
// (and the middleware blocks it if it did, above).
func TestMergeRefusesIdentityWithLinkedUser(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := containServer(t, f).Handler()
	alice, bob := f.A.IDs["alice"], f.A.IDs["bob"]
	linked := signIn(t, f.DB, f.A.ID, authtest.User{Email: "alice@a.example", Roles: []auth.Role{auth.RolePolicyAdmin},
		IdentityID: &alice}, authtest.Phr, storetest.Now)
	admin := linkedPolicyAdmin(t, f, f.A.ID, "pa@a.example")
	rec := corrDo(h, admin, "POST", fmt.Sprintf("/api/identities/%d/merge", alice), fmt.Sprintf(`{"into":%d,"reason":"duplicate person record"}`, bob))
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "merged_identity_signs_in") {
		t.Errorf("merge of a signed-in identity: %d %s", rec.Code, rec.Body)
	}
	if st := identityStatus(t, h, admin, alice); st != "active" {
		t.Errorf("alice status = %s", st)
	}
	if rec := corrDo(h, linked, "GET", "/api/auth/session", ""); rec.Code != 200 {
		t.Errorf("linked session after refused merge: %d", rec.Code)
	}
}

// An admin cannot disable the identity linked to their own user and lock
// themselves out; the refusal is audited and nothing changes (#335).
func TestDisableRefusesSelfDisable(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := containServer(t, f).Handler()
	alice := f.A.IDs["alice"]
	self := signIn(t, f.DB, f.A.ID, authtest.User{Email: "alice@a.example", Roles: []auth.Role{auth.RolePolicyAdmin},
		IdentityID: &alice}, authtest.Phr, storetest.Now)
	rec := corrDo(h, self, "POST", fmt.Sprintf("/api/identities/%d/disable", alice), `{"reason":"testing my own disable"}`)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), `"self_disable_not_allowed"`) {
		t.Fatalf("self disable: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, self, "GET", "/api/auth/session", ""); rec.Code != 200 {
		t.Errorf("session after refused self disable: %d", rec.Code)
	}
	if st := identityStatus(t, h, self, alice); st != "active" {
		t.Errorf("status after refused self disable = %s", st)
	}
	if got := auditActions(t, f, f.A.ID); got["identity.disable.refused"] != 1 || got["identity.disable"] != 0 {
		t.Errorf("audit actions %v", got)
	}
	if d := auditDetail(t, f, f.A.ID, "identity.disable.refused"); !strings.Contains(d, `"self_disable_not_allowed"`) {
		t.Errorf("identity.disable.refused detail %s", d)
	}
	// another admin may disable it
	l := linkedPolicyAdmin(t, f, f.A.ID, "pa@a.example")
	if rec := corrDo(h, l, "POST", fmt.Sprintf("/api/identities/%d/disable", alice), `{"reason":"suspected insider activity"}`); rec.Code != 200 {
		t.Errorf("disable by another admin: %d %s", rec.Code, rec.Body)
	}
}
