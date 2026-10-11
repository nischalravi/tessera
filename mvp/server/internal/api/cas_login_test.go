package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/casclient"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp/devidptest"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// CAS 3.0 sign-in through the dev IdP's /cas server (#152).

func newCASEnv(t *testing.T) *oidcEnv {
	t.Helper()
	return newAuthEnv(t, authEnvOpts{cas: true})
}

func casConnID(t testing.TB, db *store.DB, tn tenancy.ID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.ReadTenant(context.Background(), tn, func(tx *store.TenantTx) error {
		cs, err := tx.IdPConnections()
		for _, c := range cs {
			if c.Protocol == "cas" {
				id = c.ID
			}
		}
		return err
	}); err != nil || id == uuid.Nil {
		t.Fatalf("no CAS connection: %v", err)
	}
	return id
}

func (e *oidcEnv) casLoginURL() string {
	return "/api/auth/login?tenant=larkspur&return_to=/jit&connection=" + casConnID(e.t, e.db, seed.LarkspurID).String()
}

// casStart starts at target and signs in at the CAS server with b (a fresh
// browser when nil).
func (e *oidcEnv) casStart(target, sub string, m devidp.Method, fault devidp.Fault, b *devidptest.Browser, cookies ...*http.Cookie) attempt {
	e.t.Helper()
	rec := e.get(target, cookies...)
	if rec.Code != http.StatusFound {
		e.t.Fatalf("%s: %d %s", target, rec.Code, rec.Body.String())
	}
	a := attempt{login: rec, cookie: cookieNamed(rec, LoginCookieName)}
	loc := rec.Header().Get("Location")
	if fault != devidp.FaultNone {
		loc += "&fault=" + string(fault)
	}
	if b == nil {
		b = e.idp.NewBrowser(e.t)
	}
	a.callback = b.Authorize(e.t, loc, sub, m, "")
	return a
}

func (e *oidcEnv) casSignIn(sub string, m devidp.Method, fault devidp.Fault) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.finish(e.casStart(e.casLoginURL(), sub, m, fault, nil))
}

// TestCASLogin_HardwareKeyAdmin: Ivan signs in with a security key; the
// released amr attribute matches the connection's phr_amr, so the session is
// phishing resistant (basis amr) and his tenant_admin role is active.
func TestCASLogin_HardwareKeyAdmin(t *testing.T) {
	e := newCASEnv(t)
	conn := casConnID(t, e.db, seed.LarkspurID)
	a := e.casStart(e.casLoginURL(), "00u-ivan-admin2", devidp.MethodHardwareKey, devidp.FaultNone, nil)
	login, _ := url.Parse(a.login.Header().Get("Location"))
	svc, _ := url.Parse(query(login).Get("service"))
	if !strings.HasPrefix(login.String(), e.idp.CASServerURL()+"/login?") || query(login).Has("renew") ||
		svc.Path != "/api/auth/cas/"+conn.String()+"/callback" || query(svc).Get("state") == "" {
		t.Errorf("CAS login URL %s", login)
	}
	rec := e.finish(a)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/jit" {
		t.Fatalf("callback: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	v := e.session(cookieNamed(rec, auth.CookieName))
	active, _ := json.Marshal(at(v, "active_roles"))
	if at(v, "authn", "phishing_resistant") != true || at(v, "authn", "phr_basis") != "amr" ||
		!strings.Contains(string(active), "tenant_admin") {
		t.Errorf("session %v", v)
	}
	ok := false
	for _, ev := range e.events("auth.login.success") {
		ok = ok || strings.Contains(string(ev.Detail), `"via":"cas"`)
	}
	if !ok {
		t.Error("no auth.login.success via cas")
	}
	e.refused(e.finish(a), seed.LarkspurID, "login_transaction_expired_or_used")
}

func TestCASLogin_Assurance(t *testing.T) {
	e := newCASEnv(t)
	for _, tc := range []struct {
		sub string
		m   devidp.Method
		phr bool
		aal float64
	}{
		{"00u-alice-admin", devidp.MethodPasskey, true, 2},
		{"00u-olu-operator", devidp.MethodPasswordOTP, false, 2},
		{"00u-vic-viewer", devidp.MethodPassword, false, 1},
	} {
		v := e.session(cookieNamed(e.casSignIn(tc.sub, tc.m, devidp.FaultNone), auth.CookieName))
		if at(v, "authn", "phishing_resistant") != tc.phr || at(v, "authn", "aal") != tc.aal {
			t.Errorf("%s %s: %v", tc.sub, tc.m, at(v, "authn"))
		}
	}
}

func TestCASLogin_FaultsRefused(t *testing.T) {
	e := newCASEnv(t)
	want := map[devidp.Fault]string{
		devidp.FaultCASFailure: casclient.ReasonFailure, devidp.FaultCASNoUser: casclient.ReasonUser,
		devidp.FaultCASTwoUsers: casclient.ReasonUser, devidp.FaultCASCommentUser: casclient.ReasonUser,
		devidp.FaultCASProxied: casclient.ReasonProxied, devidp.FaultCASStaleAuth: "auth_time_stale",
		devidp.FaultCASTicketReuse: "cas_ticket_replay",
	}
	for _, f := range devidp.CASFaults() {
		t.Run(string(f), func(t *testing.T) {
			e.t = t
			if f == devidp.FaultCASTicketReuse { // a first, valid ticket the faulty server then issues again
				if rec := e.casSignIn("00u-vic-viewer", devidp.MethodPassword, devidp.FaultNone); cookieNamed(rec, auth.CookieName) == nil {
					t.Fatalf("first sign-in: %d", rec.Code)
				}
			}
			e.refused(e.casSignIn("00u-vic-viewer", devidp.MethodPassword, f), seed.LarkspurID, want[f])
		})
	}
}

func TestCASLogin_TransactionChecks(t *testing.T) {
	e := newCASEnv(t)
	conn := casConnID(t, e.db, seed.LarkspurID)
	tamper := func(a attempt, k, v string) attempt {
		q := query(a.callback)
		q.Set(k, v)
		a.callback.RawQuery = q.Encode()
		return a
	}
	start := func() attempt {
		return e.casStart(e.casLoginURL(), "00u-vic-viewer", devidp.MethodPassword, devidp.FaultNone, nil)
	}
	e.refused(e.finish(tamper(start(), "state", "nope")), seed.LarkspurID, "state_mismatch")
	e.refused(e.finish(tamper(start(), "ticket", "ST-forged")), seed.LarkspurID, casclient.ReasonFailure)
	e.refused(e.finish(tamper(start(), "ticket", "PT-proxy")), seed.LarkspurID, casclient.ReasonTicket)
	// the ticket of another transaction's service (state) does not validate
	a, b := start(), start()
	a.callback.RawQuery = url.Values{"state": {query(a.callback).Get("state")}, "ticket": {query(b.callback).Get("ticket")}}.Encode()
	if rec := e.finish(a); cookieNamed(rec, auth.CookieName) != nil {
		t.Error("a ticket issued for another service URL signed in")
	}
	// other protocols' callbacks, another tenant's connection
	a = start()
	a.callback.Path = "/api/auth/oidc/" + conn.String() + "/callback"
	e.refused(e.finish(a), seed.LarkspurID, "connection_mismatch")
	a = start()
	a.callback.Path = "/api/auth/cas/" + casConnID(t, e.db, seed.GlobexID).String() + "/callback"
	e.refused(e.finish(a), seed.LarkspurID, "connection_mismatch")
	e.refused(e.casSignIn("00u-gina-globex", devidp.MethodPasskey, devidp.FaultNone), seed.LarkspurID, "unknown_subject")
}

// TestCASStepUp: a step-up of a CAS session asks for renew=true; the browser's
// CAS single sign-on session does not satisfy it, a new login does, and an
// old authenticationDate is refused.
func TestCASStepUp(t *testing.T) {
	e := newCASEnv(t)
	b := e.idp.NewBrowser(t) // keeps the CAS server's session cookie
	sid := cookieNamed(e.finish(e.casStart(e.casLoginURL(), "00u-pat-policy", devidp.MethodPasskey, devidp.FaultNone, b)), auth.CookieName)
	e.ageAuth(sid)
	if rec := e.post(approvePath, sid, ""); rec.Code != 401 {
		t.Fatalf("before step-up: %d", rec.Code)
	}
	target := "/api/auth/step-up?acr=urn:tessera:acr:phr&max_age=900&return_to=/access/jit"
	a := e.casStart(target, "00u-pat-policy", devidp.MethodPasskey, devidp.FaultNone, b, sid)
	if loc, _ := url.Parse(a.login.Header().Get("Location")); query(loc).Get("renew") != "true" {
		t.Errorf("step-up CAS URL %s", loc)
	}
	rec := e.get(a.callback.RequestURI(), a.cookie, sid)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/access/jit?stepup=ok" {
		t.Fatalf("step-up: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	fresh := cookieNamed(rec, auth.CookieName)
	if rec := e.post(approvePath, fresh, ""); rec.Code == 401 || rec.Code == 403 {
		t.Errorf("after step-up: %d %s", rec.Code, rec.Body.String())
	}
	// a server that answers renew with an old authentication is refused
	e.ageAuth(fresh)
	a = e.casStart(target, "00u-pat-policy", devidp.MethodPasskey, devidp.FaultCASStaleAuth, b, fresh)
	rec = e.get(a.callback.RequestURI(), a.cookie, fresh)
	if !strings.Contains(rec.Header().Get("Location"), "stepup=failed") || cookieNamed(rec, auth.CookieName) != nil {
		t.Errorf("stale step-up: %d %v", rec.Code, rec.Header())
	}
	if ev := e.events("auth.step_up.failure"); len(ev) != 1 || !strings.Contains(string(ev[0].Detail), "auth_time_stale") {
		t.Errorf("auth.step_up.failure %v", ev)
	}
}

// TestCASLogin_Bootstrap: a bootstrap invitation can be redeemed through a
// CAS connection with a phishing-resistant sign-in, as that email.
func TestCASLogin_Bootstrap(t *testing.T) {
	e := newCASEnv(t)
	code := e.invite(seed.LarkspurID, casConnID(t, e.db, seed.LarkspurID), "newbie@larkspur.example", time.Hour)
	rec := e.finish(e.casStart("/t/larkspur/bootstrap?code="+code, "00u-newbie", devidp.MethodPasskey, devidp.FaultNone, nil))
	v := e.session(cookieNamed(rec, auth.CookieName))
	active, _ := json.Marshal(at(v, "active_roles"))
	if !strings.Contains(string(active), "tenant_admin") {
		t.Errorf("bootstrap through CAS: %d %v", rec.Code, v)
	}
}
