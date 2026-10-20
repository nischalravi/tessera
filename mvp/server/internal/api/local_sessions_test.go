package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Containment ends Tessera's own sessions too (review of PR #222): a person
// with an active Tessera session loses it when a verified SSF event, a manual
// contain or a leaver execution names their identity, even when the identity
// has no other account for a provider step to act on.

// linkedViewer signs in a viewer of tenant A whose platform user is linked to
// identity; probe is a request the session may make while it lives.
func linkedViewer(t *testing.T, f *storetest.Fixture, email string, identity int64) (authtest.Login, string) {
	t.Helper()
	l := signIn(t, f.DB, f.A.ID, authtest.User{Email: email, Roles: []auth.Role{auth.RoleViewer}, IdentityID: &identity}, authtest.Phr, storetest.Now)
	return l, fmt.Sprintf("/api/identities/%d/containment", identity)
}

func sessionStatus(t *testing.T, f *storetest.Fixture, l authtest.Login) string {
	t.Helper()
	var st string
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		s, err := c.Session(l.SessionID)
		if err == nil {
			st = s.Status
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return st
}

func localAudit(t *testing.T, e *ssfEnv, trigger string, sessions float64) {
	t.Helper()
	got := e.audit("containment.local_sessions_revoked")
	if len(got) != 1 || got[0]["trigger"] != trigger || got[0]["sessions_revoked"] != sessions || got[0]["users"] != float64(1) {
		t.Errorf("containment.local_sessions_revoked: %v (want trigger %s, %v session(s))", got, trigger, sessions)
	}
}

func TestSSFEndsTesseraSessionWithNoDownstreamSteps(t *testing.T) {
	e := newSSFEnv(t)
	bob := e.f.A.IDs["bob"] // only an Okta account: the transmitter's own system, so zero downstream steps
	l, probe := linkedViewer(t, e.f, "bob@a.example", bob)
	other, _ := linkedViewer(t, e.f, "alice@a.example", e.f.A.IDs["alice"])
	if rec := corrDo(e.h, l, "GET", probe, ""); rec.Code != http.StatusOK {
		t.Fatalf("before the event the session works: %d %s", rec.Code, rec.Body)
	}

	rec := e.deliver(e.key.sign(t, sessionRevoked("jti-local-1", "bob", nil)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("push: %d %s", rec.Code, rec.Body)
	}

	if rec := corrDo(e.h, l, "GET", probe, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("after a verified session-revoked SET the Tessera session is refused with 401, got %d %s", rec.Code, rec.Body)
	}
	if st := sessionStatus(t, e.f, l); st != "revoked" {
		t.Errorf("session status %q", st)
	}
	if st := sessionStatus(t, e.f, other); st != "active" {
		t.Errorf("another identity's session was touched: %q", st)
	}
	if rec := corrDo(e.h, other, "GET", fmt.Sprintf("/api/identities/%d/containment", e.f.A.IDs["alice"]), ""); rec.Code != http.StatusOK {
		t.Errorf("another identity's session still works: %d", rec.Code)
	}
	evs := e.events(e.pa, "")
	if len(evs) != 1 || evs[0].Status != "actioned" || evs[0].Steps != 0 {
		t.Errorf("event %+v: want actioned with zero provider steps", evs)
	}
	if e.aws.Count("DescribeUser") != 0 {
		t.Error("no provider call was expected")
	}
	localAudit(t, e, "ssf", 1)
	if got := e.audit("containment.run"); len(got) != 0 {
		t.Errorf("no provider run was expected: %v", got)
	}
}

func TestManualContainEndsTesseraSession(t *testing.T) {
	e := newSSFEnv(t)
	bob := e.f.A.IDs["bob"]
	l, probe := linkedViewer(t, e.f, "bob@a.example", bob)
	if rec := corrDo(e.h, l, "GET", probe, ""); rec.Code != http.StatusOK {
		t.Fatalf("before: %d %s", rec.Code, rec.Body)
	}
	rec := corrDo(e.h, e.pa, "POST", fmt.Sprintf("/api/identities/%d/contain", bob), `{"reason":"suspected token theft"}`)
	if rec.Code != http.StatusOK && rec.Code != http.StatusBadGateway {
		t.Fatalf("contain: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(e.h, l, "GET", probe, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("after manual contain the Tessera session is refused with 401, got %d", rec.Code)
	}
	localAudit(t, e, "manual", 1)
}

func TestLeaverExecuteEndsTesseraSession(t *testing.T) {
	e := newSSFEnv(t)
	var leaver int64
	if err := e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
		ev, err := c.HrisEvent(e.f.A.IDs["hris:leaver"])
		if err == nil && ev.IdentityID != nil {
			leaver = *ev.IdentityID
		}
		return err
	}); err != nil || leaver == 0 {
		t.Fatalf("leaver event: %d, %v", leaver, err)
	}
	l, probe := linkedViewer(t, e.f, "leaver@a.example", leaver)
	if rec := corrDo(e.h, l, "GET", probe, ""); rec.Code != http.StatusOK {
		t.Fatalf("before: %d %s", rec.Code, rec.Body)
	}
	rec := corrDo(e.h, e.pa, "POST", fmt.Sprintf("/api/hris/events/%d/execute", e.f.A.IDs["hris:leaver"]), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("execute: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(e.h, l, "GET", probe, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("after the leaver executes the Tessera session is refused with 401, got %d", rec.Code)
	}
	localAudit(t, e, "leaver", 1)
}
