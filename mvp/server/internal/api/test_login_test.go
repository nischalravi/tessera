package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// requestedConn adds a pending connection and the applied
// idp_connection.create request that created it, requested by user.
func (e *oidcEnv) requestedConn(user string) *store.IdPConnection {
	e.t.Helper()
	conn := e.addConn(func(c *store.IdPConnection) { c.Status = "pending" })
	now := e.clk.now()
	uid, err := uuid.Parse(user)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.db.InTenant(context.Background(), seed.LarkspurID, func(tx *store.TenantTx) error {
		ch := &store.AdminChange{Type: "idp_connection.create", Payload: json.RawMessage(`{"connection_id":"` + conn.ID.String() + `"}`),
			PayloadHash: "0000000000000000000000000000000000000000000000000000000000000000", Status: store.ChangeCoolingOff,
			CoolingOffSeconds: 86400, RequestedBy: uid, RequestedAt: now, ExpiresAt: now.Add(72 * time.Hour), EffectiveAt: &now,
			TargetID: conn.ID.String()}
		if err := tx.InsertAdminChange(ch); err != nil {
			return err
		}
		return tx.MarkAdminChangeApplied(ch.ID, now)
	}); err != nil {
		e.t.Fatal(err)
	}
	return conn
}

// signedIn signs sub in and returns the session cookie and the user's id.
func (e *oidcEnv) signedIn(sub string) (*http.Cookie, string) {
	e.t.Helper()
	sid := cookieNamed(e.signIn(sub, devidp.MethodPasskey, devidp.ProfileOkta), auth.CookieName)
	if sid == nil {
		e.t.Fatalf("%s did not sign in", sub)
	}
	return sid, at(e.session(sid), "user", "id").(string)
}

// testLogin starts a test login with the session cookie, signs in at the IdP
// as sub, and returns the start and callback responses (the callback carries
// the session cookie too unless cb is nil).
func (e *oidcEnv) testLogin(conn uuid.UUID, start, cb *http.Cookie, sub string) (*http.Cookie, *httptest.ResponseRecorder) {
	e.t.Helper()
	rec := e.get("/api/auth/login?tenant=larkspur&test=1&connection="+conn.String(), start)
	lc := cookieNamed(rec, LoginCookieName)
	if rec.Code != http.StatusFound || lc == nil {
		return nil, rec
	}
	cbURL := e.idp.NewBrowser(e.t).Authorize(e.t, rec.Header().Get("Location"), sub, devidp.MethodPasskey, devidp.ProfileOkta)
	return lc, e.get(cbURL.RequestURI(), lc, cb)
}

func (e *oidcEnv) testLoginAt(conn uuid.UUID) *time.Time {
	e.t.Helper()
	var at *time.Time
	if err := e.db.ReadTenant(context.Background(), seed.LarkspurID, func(tx *store.TenantTx) error {
		ch, err := tx.AppliedConnectionCreate(conn)
		if err == nil {
			at = ch.TestLoginAt
		}
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return at
}

// TestTestLogin_ActivatesConnection (§15.2): the requester's test sign-in
// through a pending connection records the test login without creating a
// session, a user or a role; then the connection activates.
func TestTestLogin_ActivatesConnection(t *testing.T) {
	e := newOIDCEnv(t)
	sid, uid := e.signedIn("00u-alice-admin")
	conn := e.requestedConn(uid)
	usersBefore := len(platformUsers(t, e.db))
	activate := "/api/admin/idp-connections/" + conn.ID.String() + "/activate"

	// not yet: activation needs the test login; a plain login never uses a pending connection
	if rec := e.post(activate, sid, ""); rec.Code != http.StatusConflict {
		t.Fatalf("activate before the test login: %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.get("/api/auth/login?tenant=larkspur&connection="+conn.ID.String(), sid); cookieNamed(rec, LoginCookieName) != nil {
		t.Error("a plain login started through a pending connection")
	}

	lc, rec := e.testLogin(conn.ID, sid, sid, "00u-alice-admin")
	if lc == nil || rec.Code != http.StatusFound || rec.Header().Get("Location") != "/?test_login=ok" {
		t.Fatalf("test login callback: %d %v", rec.Code, rec.Header())
	}
	if cookieNamed(rec, auth.CookieName) != nil {
		t.Error("a test login set a session cookie")
	}
	if e.testLoginAt(conn.ID) == nil {
		t.Fatal("the test login was not recorded")
	}
	// no session, user, external login or role came out of it
	if n := len(platformUsers(t, e.db)); n != usersBefore {
		t.Errorf("%d users, want %d", n, usersBefore)
	}
	if err := e.db.ReadTenant(context.Background(), seed.LarkspurID, func(tx *store.TenantTx) error {
		ls, err := tx.ExternalLoginsForUser(uuid.MustParse(uid))
		if err != nil {
			return err
		}
		for _, l := range ls {
			if l.IdPConnectionID == conn.ID {
				t.Error("a test login linked the identity to the pending connection")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, ev := range ledger(t, e.db, seed.LarkspurID) {
		if ev.Action == "auth.login.success" {
			var d map[string]any
			_ = json.Unmarshal(ev.Detail, &d)
			if d["connection_id"] == conn.ID.String() {
				t.Error("a test login wrote auth.login.success")
			}
		}
	}
	if len(e.events("idp_connection.test_login")) != 1 {
		t.Errorf("idp_connection.test_login events: %d", len(e.events("idp_connection.test_login")))
	}
	if rec := e.post(activate, sid, ""); rec.Code != http.StatusOK {
		t.Fatalf("activate after the test login: %d %s", rec.Code, rec.Body.String())
	}
}

// TestTestLogin_Refused: a test login needs the requesting admin's own live
// session, a pending connection, and records nothing otherwise.
func TestTestLogin_Refused(t *testing.T) {
	e := newOIDCEnv(t)
	alice, aliceID := e.signedIn("00u-alice-admin")
	ivan, _ := e.signedIn("00u-ivan-admin2")
	conn := e.requestedConn(aliceID)

	// no session: refused at the start
	if _, rec := e.testLogin(conn.ID, nil, nil, "00u-alice-admin"); rec.Code != http.StatusFound || cookieNamed(rec, LoginCookieName) != nil {
		t.Fatalf("anonymous test login: %d", rec.Code)
	}
	if got := e.lastFailure(seed.LarkspurID); got != "test_login_admin_required" {
		t.Errorf("reason %q", got)
	}
	// another admin did not request the connection
	if _, rec := e.testLogin(conn.ID, ivan, ivan, "00u-ivan-admin2"); cookieNamed(rec, LoginCookieName) != nil {
		t.Fatalf("another admin started a test login: %d", rec.Code)
	}
	if got := e.lastFailure(seed.LarkspurID); got != "test_login_not_requester" {
		t.Errorf("reason %q", got)
	}
	// an active connection is not tested
	active := devConnID(t, e.db, seed.LarkspurID)
	if _, rec := e.testLogin(active, alice, alice, "00u-alice-admin"); cookieNamed(rec, LoginCookieName) != nil {
		t.Fatalf("test login of an active connection: %d", rec.Code)
	}
	if got := e.lastFailure(seed.LarkspurID); got != "test_login_not_pending" {
		t.Errorf("reason %q", got)
	}
	// the callback without the admin's session records nothing
	if lc, rec := e.testLogin(conn.ID, alice, nil, "00u-alice-admin"); lc == nil || rec.Code != http.StatusFound ||
		cookieNamed(rec, auth.CookieName) != nil {
		t.Fatalf("callback without the session: %d %v", rec.Code, rec.Header())
	}
	if got := e.lastFailure(seed.LarkspurID); got != "test_login_session_mismatch" {
		t.Errorf("reason %q", got)
	}
	// another admin's session at the callback does not count either
	if lc, rec := e.testLogin(conn.ID, alice, ivan, "00u-alice-admin"); lc == nil || cookieNamed(rec, auth.CookieName) != nil {
		t.Fatalf("callback with another session: %d %v", rec.Code, rec.Header())
	}
	if e.testLoginAt(conn.ID) != nil {
		t.Error("a refused test login was recorded")
	}
	if rec := e.post("/api/admin/idp-connections/"+conn.ID.String()+"/activate", alice, ""); rec.Code != http.StatusConflict {
		t.Errorf("activate: %d", rec.Code)
	}
}
