package api

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// requestRecovery puts larkspur into operator recovery for newbie and returns
// the invitation code and the recovery id.
func (e *oidcEnv) requestRecovery() (code, id string) {
	e.t.Helper()
	svc := &admin.Service{DB: e.db, Clock: e.clk.now}
	res, err := svc.RequestRecovery(context.Background(), admin.RecoveryRequest{Tenant: seed.LarkspurID,
		Operator: admin.Operator{ID: "op-1", PhishingResistant: true}, CoOperator: admin.Operator{ID: "op-2", PhishingResistant: true},
		Ticket: "SUP-305", ConnectionID: devConnID(e.t, e.db, seed.LarkspurID), Email: newbie.Email})
	if err != nil {
		e.t.Fatal(err)
	}
	return res.Code, res.Recovery.ID.String()
}

func (e *oidcEnv) tenantStatus() string {
	e.t.Helper()
	var st string
	if err := e.db.ReadSystem(context.Background(), "test tenant status", func(s *store.SystemTx) error {
		t, err := s.TenantByID(seed.LarkspurID)
		if err == nil {
			st = t.Status
		}
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return st
}

// TestRecoverySignIn (#305): a tenant in operator recovery still completes
// IdP sign-in: an existing admin signs in and cancels the recovery; the
// invitation redeems after not_before with a phishing-resistant sign-in and
// not before, nor without phishing resistance.
func TestRecoverySignIn(t *testing.T) {
	e := newOIDCEnv(t)
	code, id := e.requestRecovery()
	if got := e.tenantStatus(); got != "recovery" {
		t.Fatalf("tenant status %q", got)
	}

	// sign-in during recovery works
	rec := e.signIn("00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)
	sid := cookieNamed(rec, auth.CookieName)
	if rec.Code != http.StatusFound || sid == nil {
		t.Fatalf("sign-in during recovery: %d %v", rec.Code, rec.Header())
	}

	// redeeming before not_before is refused
	target := "/t/larkspur/bootstrap?code=" + url.QueryEscape(code)
	if rec := e.get(target); rec.Code != http.StatusFound || e.lastFailure(seed.LarkspurID) != admin.ReasonRecoveryNotYet {
		t.Fatalf("redeem before not_before: %d %q", rec.Code, e.lastFailure(seed.LarkspurID))
	}

	// after not_before: a password sign-in does not redeem, a passkey does
	e.clk.add(admin.RecoveryDelay + time.Minute)
	e.refused(e.finish(e.start(target, "00u-newbie", devidp.MethodPassword, devidp.ProfileOkta)), seed.LarkspurID, "bootstrap_requires_phr")
	if got := e.tenantStatus(); got != "recovery" {
		t.Fatalf("tenant status after a refused redemption %q", got)
	}
	rec = e.finish(e.start(target, "00u-newbie", devidp.MethodPasskey, devidp.ProfileOkta))
	nsid := cookieNamed(rec, auth.CookieName)
	if rec.Code != http.StatusFound || nsid == nil {
		t.Fatalf("redeem after not_before: %d %v", rec.Code, rec.Header())
	}
	if got := e.tenantStatus(); got != "active" {
		t.Errorf("tenant status after redemption %q, want active", got)
	}
	if rec := e.get("/api/auth/session", nsid); rec.Code != 200 {
		t.Errorf("redeemer session: %d", rec.Code)
	}
	_ = id
}

// TestRecoverySignIn_AdminCancels (#305): with the tenant in recovery, an
// admin signs in through the IdP and cancels it; the invitation is then spent.
func TestRecoverySignIn_AdminCancels(t *testing.T) {
	e := newOIDCEnv(t)
	code, id := e.requestRecovery()
	rec := e.signIn("00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)
	sid := cookieNamed(rec, auth.CookieName)
	if sid == nil {
		t.Fatalf("no session during recovery: %d %v", rec.Code, rec.Header())
	}
	// a step-up for the same tenant resolves too
	rec = e.stepUp(sid, "/api/auth/step-up?return_to=/", "00u-alice-admin", devidp.MethodPasskey)
	if fresh := cookieNamed(rec, auth.CookieName); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/?stepup=ok" || fresh == nil {
		t.Fatalf("step-up during recovery: %d %v", rec.Code, rec.Header())
	} else {
		sid = fresh
	}
	if rec := e.post("/api/admin/recovery/"+id+"/cancel", sid, ""); rec.Code != http.StatusOK {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body.String())
	}
	if got := e.tenantStatus(); got != "active" {
		t.Errorf("tenant status after cancel %q", got)
	}
	e.clk.add(admin.RecoveryDelay + time.Minute)
	if rec := e.get("/t/larkspur/bootstrap?code=" + url.QueryEscape(code)); rec.Code != http.StatusFound {
		t.Fatalf("redeem after cancel: %d", rec.Code)
	}
	if got := e.lastFailure(seed.LarkspurID); got == "" {
		t.Error("redeeming a cancelled recovery was not refused")
	}
}

// TestSuspendedTenantCallbackRefused (#305): only active and recovering
// tenants resolve a login transaction; a tenant suspended mid-sign-in is refused.
func TestSuspendedTenantCallbackRefused(t *testing.T) {
	e := newOIDCEnv(t)
	a := e.start("/api/auth/login?tenant=larkspur&return_to=/", "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)
	if err := e.db.SetTenantStatusForTest(context.Background(), seed.LarkspurID, "suspended"); err != nil {
		t.Fatal(err)
	}
	rec := e.finish(a)
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || cookieNamed(rec, auth.CookieName) != nil ||
		len(loc) < 22 || loc[:22] != "/login?error=login_fai" {
		t.Fatalf("suspended tenant callback: %d %v", rec.Code, rec.Header())
	}
	if rec := e.get("/api/auth/login?tenant=larkspur"); cookieNamed(rec, LoginCookieName) != nil {
		t.Error("a suspended tenant can start a sign-in")
	}
}
