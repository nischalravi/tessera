package api

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// TestPrivs_AccountLinkFourEyes (#376): pinning a connector account to an
// identity and releasing the pin each need two admins. The first request
// answers 202 and changes nothing, the same admin (also from another session)
// gets 403 four_eyes_required, a different admin's identical request applies,
// a differing request does not apply the first one, a request expires, and
// another tenant's admin sees nothing (404).
func TestPrivs_AccountLinkFourEyes(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	var offset atomic.Int64 // seconds added to the frozen clock
	srv := newIsolationServerWith(f, func(c *Config) {
		c.Clock = func() time.Time { return storetest.Now.Add(time.Duration(offset.Load()) * time.Second) }
	})
	h := srv.Handler()
	ids := f.B.IDs
	acct, carol, bob := ids["acct:aws:dave-iam"], ids["carol"], ids["bob"]
	a1 := policyAdmin(t, f, f.B.ID, "pa1@b.example")
	a1again := policyAdmin(t, f, f.B.ID, "pa1@b.example") // another session, same admin
	a2 := policyAdmin(t, f, f.B.ID, "pa2@b.example")
	foreign := policyAdmin(t, f, f.A.ID, "pa@a.example")

	linkPath := fmt.Sprintf("/api/accounts/%d/link", acct)
	type resp struct {
		code int
		body string
	}
	pin := func(by authtest.Login, identity int64) resp {
		rec := corrDo(h, by, "POST", linkPath, fmt.Sprintf(`{"identity_id":%d,"reason":"AWS team confirmed"}`, identity))
		return resp{rec.Code, rec.Body.String()}
	}
	release := func(by authtest.Login) (int, string) {
		rec := corrDo(h, by, "DELETE", linkPath, "")
		return rec.Code, rec.Body.String()
	}
	decisions := func() string { return corrDo(h, a2, "GET", "/api/correlation/decisions", "").Body.String() }
	pinned := func() bool { return strings.Contains(decisions(), "AWS team confirmed") }
	pendingCount := func(by authtest.Login) string {
		rec := corrDo(h, by, "GET", "/api/correlation/link-requests", "")
		if rec.Code != 200 {
			t.Fatalf("list pending: %d %s", rec.Code, rec.Body)
		}
		return rec.Body.String()
	}

	// pin: one admin leaves it pending
	if r := pin(a1, carol); r.code != 202 || !strings.Contains(r.body, "pending_second_admin") {
		t.Fatalf("first admin: %d %s", r.code, r.body)
	}
	if pinned() {
		t.Fatal("the first admin pinned alone")
	}
	for name, by := range map[string]authtest.Login{"same session": a1, "another session": a1again} {
		if r := pin(by, carol); r.code != 403 || !strings.Contains(r.body, "four_eyes_required") {
			t.Fatalf("same admin, %s: %d %s", name, r.code, r.body)
		}
	}
	if pinned() {
		t.Fatal("the same admin confirmed their own request")
	}
	if body := pendingCount(a2); !strings.Contains(body, `"count":1`) || !strings.Contains(body, "pa1@b.example") {
		t.Fatalf("pending list: %s", body)
	}
	// another tenant's admin: the account does not exist for them, and they see nothing
	if r := pin(foreign, carol); r.code != 404 {
		t.Fatalf("other tenant's admin: %d %s", r.code, r.body)
	}
	if body := pendingCount(foreign); !strings.Contains(body, `"count":0`) {
		t.Fatalf("other tenant sees the request: %s", body)
	}
	if rec := corrDo(h, foreign, "DELETE", "/api/correlation/link-requests/"+fmt.Sprint(acct), ""); rec.Code != 404 {
		t.Fatalf("other tenant cancels: %d %s", rec.Code, rec.Body)
	}
	// a differing request from the second admin does not apply the first
	if r := pin(a2, bob); r.code != 202 {
		t.Fatalf("differing identity: %d %s", r.code, r.body)
	}
	if pinned() {
		t.Fatal("a differing request applied the first one")
	}
	// a1 now confirms nothing either: the pending request is a2's (bob), so carol is a new request
	if r := pin(a1, carol); r.code != 202 {
		t.Fatalf("a1 carol after a2's bob: %d %s", r.code, r.body)
	}
	if pinned() {
		t.Fatal("pinned after replaced requests")
	}
	// a different action does not match either
	if code, body := release(a2); code != 404 || !strings.Contains(body, "no_decision") {
		t.Fatalf("release of an unpinned account: %d %s", code, body)
	}
	if r := pin(a2, carol); r.code != 200 {
		t.Fatalf("second admin, identical request: %d %s", r.code, r.body)
	}
	if !pinned() {
		t.Fatal("the confirmed pin was not applied")
	}
	if body := pendingCount(a1); !strings.Contains(body, `"count":0`) {
		t.Fatalf("pending after apply: %s", body)
	}

	// release: the same flow
	if code, body := release(a1); code != 202 || !strings.Contains(body, "pending_second_admin") {
		t.Fatalf("release, first admin: %d %s", code, body)
	}
	for name, by := range map[string]authtest.Login{"same session": a1, "another session": a1again} {
		if code, body := release(by); code != 403 || !strings.Contains(body, "four_eyes_required") {
			t.Fatalf("release, same admin, %s: %d %s", name, code, body)
		}
	}
	if code, _ := release(foreign); code != 404 {
		t.Fatalf("release by other tenant's admin: %d", code)
	}
	if !pinned() {
		t.Fatal("one admin released")
	}
	// a pin request from the second admin is not a release
	if r := pin(a2, bob); r.code != 202 || !pinned() {
		t.Fatalf("a re-pin must not release: %d %s", r.code, r.body)
	}
	if code, _ := release(a1); code != 202 {
		t.Fatalf("release after the replaced request: %d", code)
	}
	if code, body := release(a2); code != 200 {
		t.Fatalf("release, second admin: %d %s", code, body)
	}
	if pinned() {
		t.Fatal("the confirmed release was not applied")
	}

	// cancel: only the requester
	if r := pin(a1, carol); r.code != 202 {
		t.Fatalf("pin for cancel: %d %s", r.code, r.body)
	}
	cancel := "/api/correlation/link-requests/" + fmt.Sprint(acct)
	if rec := corrDo(h, a2, "DELETE", cancel, ""); rec.Code != 403 || !strings.Contains(rec.Body.String(), "not_requester") {
		t.Fatalf("cancel by another admin: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, a1again, "DELETE", cancel, ""); rec.Code != 200 {
		t.Fatalf("cancel by the requester: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, a1, "DELETE", cancel, ""); rec.Code != 404 {
		t.Fatalf("cancel twice: %d %s", rec.Code, rec.Body)
	}
	if r := pin(a2, carol); r.code != 202 || pinned() {
		t.Fatalf("a cancelled request must not be confirmed: %d %s", r.code, r.body)
	}

	// expiry: after 72 hours the pending request (a2's) is ignored
	offset.Store(int64(73 * time.Hour / time.Second))
	later := storetest.Now.Add(73 * time.Hour)
	b1 := signIn(t, f.DB, f.B.ID, authtest.User{Email: "pa1@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, later)
	b2 := signIn(t, f.DB, f.B.ID, authtest.User{Email: "pa2@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, later)
	if body := pendingCount(b1); !strings.Contains(body, `"count":0`) {
		t.Fatalf("expired request listed: %s", body)
	}
	if r := pin(b1, carol); r.code != 202 {
		t.Fatalf("expired request confirmed: %d %s", r.code, r.body)
	}
	if pinned() {
		t.Fatal("an expired request was applied")
	}
	if r := pin(b2, carol); r.code != 200 {
		t.Fatalf("fresh request, second admin: %d %s", r.code, r.body)
	}

	acts := auditActions(t, f, f.B.ID)
	for action, want := range map[string]int{"identity.account.link": 2, "identity.account.release": 1,
		"identity.account.link_request_cancelled": 1} {
		if acts[action] != want {
			t.Errorf("audit %s = %d, want %d (%v)", action, acts[action], want, acts)
		}
	}
	if acts["identity.account.link_requested"] < 4 || acts["identity.account.release_requested"] < 2 {
		t.Errorf("request events missing: %v", acts)
	}
	if auditActions(t, f, f.A.ID)["identity.account.link_requested"] != 0 {
		t.Error("tenant A logged B's request")
	}
}

// One person with two sign-in users (one per IdP connection, both linked to
// the same identity) is one admin: the second user cannot confirm or cancel
// the first user's pin or release (#402).
func TestPrivs_AccountLinkFourEyesSamePerson(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	ids := f.B.IDs
	acct, carol, person := ids["acct:aws:dave-iam"], ids["carol"], ids["alice"]
	roles := []auth.Role{auth.RolePolicyAdmin}
	u1 := signIn(t, f.DB, f.B.ID, authtest.User{Email: "p1@b.example", Roles: roles, IdentityID: &person}, authtest.Phr, storetest.Now)
	u2 := signIn(t, f.DB, f.B.ID, authtest.User{Email: "p2@b.example", Roles: roles, IdentityID: &person}, authtest.Phr, storetest.Now)
	other := policyAdmin(t, f, f.B.ID, "other@b.example")
	path := fmt.Sprintf("/api/accounts/%d/link", acct)
	body := fmt.Sprintf(`{"identity_id":%d,"reason":"same person check"}`, carol)

	if rec := corrDo(h, u1, "POST", path, body); rec.Code != 202 {
		t.Fatalf("pin request: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, u2, "POST", path, body); rec.Code != 403 || !strings.Contains(rec.Body.String(), "four_eyes_required") {
		t.Fatalf("pin by the person's second user: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, u1, "GET", "/api/correlation/decisions", ""); strings.Contains(rec.Body.String(), "same person check") {
		t.Fatal("one person pinned alone")
	}
	if rec := corrDo(h, u2, "DELETE", fmt.Sprintf("/api/correlation/link-requests/%d", acct), ""); rec.Code != 200 {
		t.Fatalf("the person's second user cancels: %d %s", rec.Code, rec.Body)
	}
	corrDo(h, u1, "POST", path, body)
	if rec := corrDo(h, other, "POST", path, body); rec.Code != 200 {
		t.Fatalf("another person confirms: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, u1, "DELETE", path, ""); rec.Code != 202 {
		t.Fatalf("release request: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, u2, "DELETE", path, ""); rec.Code != 403 || !strings.Contains(rec.Body.String(), "four_eyes_required") {
		t.Fatalf("release by the person's second user: %d %s", rec.Code, rec.Body)
	}
}

// Listing needs identities.correlate; a viewer cannot read who asked for what.
func TestCorrelationAPI_LinkRequestsNeedPermission(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	v := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	if rec := corrDo(h, v, "GET", "/api/correlation/link-requests", ""); rec.Code != http.StatusForbidden {
		t.Errorf("viewer list: %d", rec.Code)
	}
	if rec := corrDo(h, v, "DELETE", "/api/correlation/link-requests/1", ""); rec.Code != http.StatusForbidden {
		t.Errorf("viewer cancel: %d", rec.Code)
	}
}
