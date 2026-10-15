package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The step-up tests (design §19 PR8, auth/stepup_test) drive
// /api/auth/step-up and the step_up callback through the in-process dev IdP.

// post sends an unsafe request as the session (cookie, Origin, CSRF token).
func (e *oidcEnv) post(path string, sid *http.Cookie, body string) *httptest.ResponseRecorder {
	e.t.Helper()
	csrf := at(e.session(sid), "csrf_token").(string)
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", oidcPublicURL)
	r.Header.Set(auth.CSRFHeader, csrf)
	r.AddCookie(sid)
	return serve(e.h, r)
}

// stepUp runs GET /api/auth/step-up and the IdP, and returns the callback
// response (sent with the login cookie and the session cookie).
func (e *oidcEnv) stepUp(sid *http.Cookie, target, sub string, m devidp.Method) *httptest.ResponseRecorder {
	e.t.Helper()
	rec := e.get(target, sid)
	if rec.Code != http.StatusFound {
		e.t.Fatalf("%s: %d %s", target, rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if q := query(loc); q.Get("prompt") != "login" || q.Get("max_age") != "0" || q.Get("acr_values") != "phr" {
		e.t.Errorf("step-up authorize URL %s", loc)
	}
	login := cookieNamed(rec, LoginCookieName)
	cb := e.idp.NewBrowser(e.t).Authorize(e.t, rec.Header().Get("Location"), sub, m, devidp.ProfileOkta)
	return e.get(cb.RequestURI(), login, sid)
}

func (e *oidcEnv) events(action string) []*store.AuditEvent {
	var out []*store.AuditEvent
	for _, ev := range ledger(e.t, e.db, seed.LarkspurID) {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}

const approvePath = "/api/jit/requests/1/approve"

// ageAuth makes the session's authentication 16 minutes old while keeping
// the session active (admin sessions end after 15 idle minutes).
func (e *oidcEnv) ageAuth(sid *http.Cookie) {
	e.t.Helper()
	e.clk.add(10 * time.Minute)
	e.session(sid)
	e.clk.add(6 * time.Minute)
}

// TestStepUp_Challenge: an approval with a phishing-resistant sign-in older
// than 15 minutes is 401 with the RFC 9470 challenge and a step_up_url.
func TestStepUp_Challenge(t *testing.T) {
	e := newOIDCEnv(t)
	sid := cookieNamed(e.signIn("00u-pat-policy", devidp.MethodPasskey, devidp.ProfileOkta), auth.CookieName)
	e.ageAuth(sid)
	rec := e.post(approvePath, sid, "")
	want := `Bearer error="insufficient_user_authentication", error_description="This action needs a phishing-resistant sign-in in the last 15 minutes", acr_values="urn:tessera:acr:phr", max_age=900`
	if rec.Code != 401 || rec.Header().Get("WWW-Authenticate") != want {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	v := decode(t, rec)
	if v["error"] != "step_up_required" || v["acr"] != "urn:tessera:acr:phr" || v["max_age"] != float64(900) ||
		v["step_up_url"] != "/api/auth/step-up?acr=urn%3Atessera%3Aacr%3Aphr&max_age=900" {
		t.Errorf("body %v", v)
	}
}

// TestStepUp_Flow: the step-up through the IdP rotates the session cookie,
// makes the approval pass, and records required vs presented.
func TestStepUp_Flow(t *testing.T) {
	e := newOIDCEnv(t)
	sid := cookieNamed(e.signIn("00u-pat-policy", devidp.MethodPasskey, devidp.ProfileOkta), auth.CookieName)
	e.ageAuth(sid)
	if rec := e.post(approvePath, sid, ""); rec.Code != 401 {
		t.Fatalf("before step-up: %d", rec.Code)
	}
	rec := e.stepUp(sid, "/api/auth/step-up?acr=urn:tessera:acr:phr&max_age=900&return_to=/access/jit", "00u-pat-policy",
		devidp.MethodPasskey)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/access/jit?stepup=ok" {
		t.Fatalf("step-up callback: %d %v", rec.Code, rec.Header())
	}
	fresh := cookieNamed(rec, auth.CookieName)
	if fresh == nil || fresh.Value == sid.Value {
		t.Fatal("the session cookie did not change")
	}
	if code := e.get("/api/auth/session", sid).Code; code != 401 {
		t.Errorf("the pre-step-up cookie still works: %d", code)
	}
	v := e.session(fresh)
	if at(v, "session", "id") == nil || at(v, "authn", "phishing_resistant") != true {
		t.Errorf("session after step-up %v", v)
	}
	// the approval now runs (request 1 is the seed's; whatever its state,
	// it is no longer a step-up refusal)
	if rec := e.post(approvePath, fresh, ""); rec.Code == 401 || rec.Code == 403 {
		t.Errorf("after step-up: %d %s", rec.Code, rec.Body.String())
	}
	ev := e.events("auth.step_up.success")
	if len(ev) != 1 || ev[0].ActorType != store.ActorUser {
		t.Fatalf("auth.step_up.success events %v", ev)
	}
	var d map[string]any
	_ = json.Unmarshal(ev[0].Detail, &d)
	if at(d, "required", "acr") != "urn:tessera:acr:phr" || at(d, "presented", "acr") != "urn:tessera:acr:phr" {
		t.Errorf("step-up detail %s", ev[0].Detail)
	}
}

// TestStepUp_Refusals: a different person at the IdP, an IdP that did not
// really re-authenticate, a weaker method and another browser's session are
// each refused, audited, and leave the session as it was.
func TestStepUp_Refusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fault  devidp.Fault
		sub    string
		method devidp.Method
		action string
		reason string
	}{
		{"another user at the IdP", devidp.FaultNone, "00u-alice-admin", devidp.MethodPasskey, "auth.step_up.subject_mismatch", "subject_mismatch"},
		{"sub_change_on_stepup", devidp.FaultSubChangeStepUp, "00u-pat-policy", devidp.MethodPasskey, "auth.step_up.subject_mismatch", "subject_mismatch"},
		{"stale_auth_time", devidp.FaultStaleAuthTime, "00u-pat-policy", devidp.MethodPasskey, "auth.step_up.failure", "auth_time_stale"},
		{"weaker method", devidp.FaultNone, "00u-pat-policy", devidp.MethodPasswordOTP, "auth.step_up.insufficient", "insufficient_authentication"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newOIDCEnv(t)
			sid := cookieNamed(e.signIn("00u-pat-policy", devidp.MethodPasskey, devidp.ProfileOkta), auth.CookieName)
			e.ageAuth(sid)
			if tc.fault != devidp.FaultNone {
				if err := e.idp.SetFault(tc.fault); err != nil {
					t.Fatal(err)
				}
			}
			rec := e.stepUp(sid, "/api/auth/step-up?return_to=/access/jit", tc.sub, tc.method)
			if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.HasPrefix(loc, "/access/jit?") ||
				!strings.Contains(loc, "stepup=failed") || cookieNamed(rec, auth.CookieName) != nil {
				t.Fatalf("%d %v", rec.Code, rec.Header())
			}
			ev := e.events(tc.action)
			if len(ev) != 1 || !strings.Contains(string(ev[0].Detail), `"reason":"`+tc.reason+`"`) {
				t.Errorf("%s events %v", tc.action, ev)
			}
			if len(e.events("auth.step_up.success")) != 0 {
				t.Error("a refused step-up recorded success")
			}
			// the session is unchanged: still signed in, still stale
			_ = e.idp.SetFault(devidp.FaultNone)
			if rec := e.post(approvePath, sid, ""); rec.Code != 401 {
				t.Errorf("after the refused step-up: %d", rec.Code)
			}
		})
	}
}

// TestStepUp_OtherBrowser: a step-up transaction finished by a browser that
// holds another session (or none) upgrades nothing.
func TestStepUp_OtherBrowser(t *testing.T) {
	e := newOIDCEnv(t)
	sid := cookieNamed(e.signIn("00u-pat-policy", devidp.MethodPasskey, devidp.ProfileOkta), auth.CookieName)
	rec := e.get("/api/auth/step-up?return_to=/access/jit", sid)
	login := cookieNamed(rec, LoginCookieName)
	cb := e.idp.NewBrowser(t).Authorize(t, rec.Header().Get("Location"), "00u-pat-policy", devidp.MethodPasskey, devidp.ProfileOkta)
	out := e.get(cb.RequestURI(), login) // no session cookie
	if !strings.Contains(out.Header().Get("Location"), "stepup=failed") || cookieNamed(out, auth.CookieName) != nil {
		t.Fatalf("%d %v", out.Code, out.Header())
	}
	if ev := e.events("auth.step_up.failure"); len(ev) != 1 || !strings.Contains(string(ev[0].Detail), "step_up_session_mismatch") {
		t.Errorf("failure events %v", ev)
	}
}

// TestStepUp_Validation: bad parameters are refused; a session that did not
// come from an IdP connection cannot step up; return_to stays on this site.
func TestStepUp_Validation(t *testing.T) {
	e := newOIDCEnv(t)
	sid := cookieNamed(e.signIn("00u-pat-policy", devidp.MethodPasskey, devidp.ProfileOkta), auth.CookieName)
	for target, code := range map[string]int{
		"/api/auth/step-up?acr=urn:x":      422,
		"/api/auth/step-up?max_age=901":    422,
		"/api/auth/step-up?max_age=-1":     422,
		"/api/auth/step-up?return_to=//ev": 302,
	} {
		rec := e.get(target, sid)
		if rec.Code != code {
			t.Errorf("%s: %d", target, rec.Code)
		}
	}
	if rec := e.get("/api/auth/step-up"); rec.Code != 401 {
		t.Errorf("without a session: %d", rec.Code)
	}
	// a session minted directly (no IdP connection behind it)
	l := signIn(t, e.db, seed.LarkspurID, testAdmin, authtest.Phr, e.clk.now())
	r := httptest.NewRequest("GET", "/api/auth/step-up", nil)
	l.Apply(r)
	if rec := serve(e.h, r); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "step_up_unavailable") {
		t.Errorf("session without a connection: %d %s", rec.Code, rec.Body.String())
	}
}
