package api

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/samlsp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp/devidptest"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// WS-Federation sign-in through the dev IdP's /wsfed endpoint (#153).

func newWSFedEnv(t *testing.T) *oidcEnv {
	t.Helper()
	return newAuthEnv(t, authEnvOpts{wsfed: true})
}

func wsfedConnID(t testing.TB, db *store.DB, tn tenancy.ID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.ReadTenant(context.Background(), tn, func(tx *store.TenantTx) error {
		cs, err := tx.IdPConnections()
		for _, c := range cs {
			if c.Protocol == "wsfed" {
				id = c.ID
			}
		}
		return err
	}); err != nil || id == uuid.Nil {
		t.Fatalf("no WS-Federation connection: %v", err)
	}
	return id
}

type wsfedAttempt struct {
	login  *httptest.ResponseRecorder
	cookie *http.Cookie
	post   devidptest.WSFedPost
}

func (e *oidcEnv) wsfedLoginURL() string {
	return "/api/auth/login?tenant=larkspur&return_to=/jit&connection=" + wsfedConnID(e.t, e.db, seed.LarkspurID).String()
}

func (e *oidcEnv) wsfedStart(target, sub string, m devidp.Method, fault devidp.Fault, cookies ...*http.Cookie) wsfedAttempt {
	e.t.Helper()
	rec := e.get(target, cookies...)
	if rec.Code != http.StatusFound {
		e.t.Fatalf("%s: %d %s", target, rec.Code, rec.Body.String())
	}
	a := wsfedAttempt{login: rec, cookie: cookieNamed(rec, LoginCookieName)}
	loc := rec.Header().Get("Location")
	if fault != devidp.FaultNone {
		loc += "&fault=" + url.QueryEscape(string(fault))
	}
	a.post = e.idp.NewBrowser(e.t).AuthorizeWSFed(e.t, loc, sub, m)
	return a
}

// wsfedPost posts the form (path only) with cookies.
func (e *oidcEnv) wsfedPost(p devidptest.WSFedPost, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()
	u, _ := url.Parse(p.Reply)
	if form == nil {
		form = url.Values{"wa": {"wsignin1.0"}, "wresult": {p.WResult}, "wctx": {p.WCtx}}
	}
	r := httptest.NewRequest("POST", u.Path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	return serve(e.h, r)
}

func (e *oidcEnv) wsfedSignIn(sub string, m devidp.Method, fault devidp.Fault) *httptest.ResponseRecorder {
	e.t.Helper()
	a := e.wsfedStart(e.wsfedLoginURL(), sub, m, fault)
	return e.wsfedPost(a.post, nil, a.cookie)
}

// TestWSFedLogin_PasskeyAdmin: Alice signs in with a passkey; Tessera
// requested the phr class ref (wauth), so the session is phishing resistant
// and tenant_admin is active. The IdP's cross-site POST is re-posted from
// Tessera's origin first.
func TestWSFedLogin_PasskeyAdmin(t *testing.T) {
	e := newWSFedEnv(t)
	conn := wsfedConnID(t, e.db, seed.LarkspurID)
	a := e.wsfedStart(e.wsfedLoginURL(), "00u-alice-admin", devidp.MethodPasskey, devidp.FaultNone)
	loc, _ := url.Parse(a.login.Header().Get("Location"))
	q := query(loc)
	if !strings.HasPrefix(loc.String(), e.idp.WSFedURL()+"?") || q.Get("wa") != "wsignin1.0" ||
		q.Get("wtrealm") != WSFedRealm(oidcPublicURL, conn) || q.Get("wreply") != WSFedReply(oidcPublicURL, conn) ||
		q.Get("wctx") == "" || q.Get("wauth") != "urn:devidp:ac:phr" || q.Has("wfresh") {
		t.Errorf("sign-in URL %s", loc)
	}
	rec := e.wsfedPost(a.post, nil) // cross-site: no cookie
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `action="`+WSFedReply(oidcPublicURL, conn)+`"`) ||
		!strings.Contains(rec.Header().Get("Content-Security-Policy"), "form-action 'self'") {
		t.Fatalf("bounce: %d %s", rec.Code, rec.Body.String())
	}
	form := url.Values{}
	for _, m := range regexpHidden.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	if form.Get("wresult") != a.post.WResult || form.Get("bounce") != "1" || form.Get("wa") != "wsignin1.0" {
		t.Fatalf("bounce form %v", form)
	}
	rec = e.wsfedPost(a.post, form, a.cookie)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/jit" {
		t.Fatalf("callback: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	v := e.session(cookieNamed(rec, auth.CookieName))
	active, _ := json.Marshal(at(v, "active_roles"))
	if at(v, "authn", "phishing_resistant") != true || at(v, "authn", "phr_basis") != "acr" || !strings.Contains(string(active), "tenant_admin") {
		t.Errorf("session %v", v)
	}
	ok := false
	for _, ev := range e.events("auth.login.success") {
		ok = ok || strings.Contains(string(ev.Detail), `"via":"wsfed"`)
	}
	if !ok {
		t.Error("no auth.login.success via wsfed")
	}
	e.refused(e.wsfedPost(a.post, nil, a.cookie), seed.LarkspurID, "login_transaction_expired_or_used")
}

func TestWSFedLogin_FaultsRefused(t *testing.T) {
	e := newWSFedEnv(t)
	wrap := map[string]bool{samlsp.ReasonAssertionCount: true, samlsp.ReasonUnsignedAssert: true, samlsp.ReasonSignature: true}
	want := map[devidp.Fault]string{
		devidp.FaultWSFedSAML11: samlsp.ReasonAssertionCount, devidp.FaultWSFedWrongAppliesTo: samlsp.ReasonAppliesTo,
		devidp.FaultWSFedTampered: samlsp.ReasonSignature, devidp.FaultUnsignedAssertion: samlsp.ReasonUnsignedAssert,
		devidp.FaultSignedResponseOnly: samlsp.ReasonUnsignedAssert, devidp.FaultCommentInNameID: samlsp.ReasonNameIDComment,
		devidp.FaultWrongAudience: samlsp.ReasonAudience, devidp.FaultWrongRecipient: samlsp.ReasonRecipient,
		devidp.FaultSAMLExpired: samlsp.ReasonExpired, devidp.FaultReplay: samlsp.ReasonReplay,
	}
	for _, f := range devidp.WSFedFaults() {
		t.Run(string(f), func(t *testing.T) {
			e.t = t
			if f == devidp.FaultReplay {
				if rec := e.wsfedSignIn("00u-alice-admin", devidp.MethodPasskey, devidp.FaultNone); cookieNamed(rec, auth.CookieName) == nil {
					t.Fatalf("first sign-in: %d", rec.Code)
				}
			}
			rec := e.wsfedSignIn("00u-alice-admin", devidp.MethodPasskey, f)
			got := e.lastFailure(seed.LarkspurID)
			if w, ok := want[f]; (ok && got != w) || (!ok && !wrap[got]) {
				t.Errorf("reason %q, want %q", got, want[f])
			}
			e.refused(rec, seed.LarkspurID, got)
		})
	}
}

func TestWSFedLogin_TransactionChecks(t *testing.T) {
	e := newWSFedEnv(t)
	start := func() wsfedAttempt {
		return e.wsfedStart(e.wsfedLoginURL(), "00u-vic-viewer", devidp.MethodPassword, devidp.FaultNone)
	}
	a := start()
	e.refused(e.wsfedPost(a.post, url.Values{"wa": {"wsignin1.0"}, "wresult": {a.post.WResult}, "wctx": {"forged"}}, a.cookie),
		seed.LarkspurID, "wctx_mismatch")
	a = start()
	e.refused(e.wsfedPost(a.post, url.Values{"wa": {"wsignout1.0"}, "wresult": {a.post.WResult}, "wctx": {a.post.WCtx}}, a.cookie),
		seed.LarkspurID, "wsfed_action_unsupported")
	// another transaction's token with this transaction's cookie and wctx is
	// still bound only by wctx: the token itself carries no request ID, so
	// the replay cache stops it from being used twice
	a, b := start(), start()
	if rec := e.wsfedPost(a.post, url.Values{"wa": {"wsignin1.0"}, "wresult": {b.post.WResult}, "wctx": {a.post.WCtx}}, a.cookie); cookieNamed(rec, auth.CookieName) == nil {
		t.Fatalf("a's transaction with b's token: %d", rec.Code)
	}
	e.refused(e.wsfedPost(b.post, nil, b.cookie), seed.LarkspurID, samlsp.ReasonReplay)
	// another tenant's connection, an expired transaction, size
	a = start()
	a.post.Reply = WSFedReply(oidcPublicURL, wsfedConnID(t, e.db, seed.GlobexID))
	e.refused(e.wsfedPost(a.post, nil, a.cookie), seed.LarkspurID, "connection_mismatch")
	a = start()
	e.clk.add(11 * time.Minute)
	e.refused(e.wsfedPost(a.post, nil, a.cookie), seed.LarkspurID, "login_transaction_expired_or_used")
	a = start()
	e.refused(e.wsfedPost(a.post, url.Values{"wa": {"wsignin1.0"}, "wresult": {strings.Repeat("A", maxWSFedBody)}, "wctx": {a.post.WCtx}}, a.cookie),
		tenancy.Platform, samlsp.ReasonTooLarge)
	e.refused(e.wsfedSignIn("00u-gina-globex", devidp.MethodPasskey, devidp.FaultNone), seed.LarkspurID, "unknown_subject")
}

// TestWSFedStepUp: a step-up of a WS-Federation session sends wfresh=0; a
// fresh AuthnInstant passes, an authentication from before it is refused.
func TestWSFedStepUp(t *testing.T) {
	e := newWSFedEnv(t)
	sid := cookieNamed(e.wsfedSignIn("00u-pat-policy", devidp.MethodPasskey, devidp.FaultNone), auth.CookieName)
	e.ageAuth(sid)
	target := "/api/auth/step-up?acr=urn:tessera:acr:phr&max_age=900&return_to=/access/jit"
	a := e.wsfedStart(target, "00u-pat-policy", devidp.MethodPasskey, devidp.FaultNone, sid)
	if loc, _ := url.Parse(a.login.Header().Get("Location")); query(loc).Get("wfresh") != "0" {
		t.Errorf("step-up URL %s", loc)
	}
	rec := e.wsfedPost(a.post, nil, a.cookie, sid)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/access/jit?stepup=ok" {
		t.Fatalf("step-up: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	fresh := cookieNamed(rec, auth.CookieName)
	if rec := e.post(approvePath, fresh, ""); rec.Code == 401 || rec.Code == 403 {
		t.Errorf("after step-up: %d", rec.Code)
	}
	e.ageAuth(fresh)
	rec = e.get(target, fresh)
	login := cookieNamed(rec, LoginCookieName)
	e.clk.add(-time.Minute) // the IdP signs in "a minute ago"
	post := e.idp.NewBrowser(t).AuthorizeWSFed(t, rec.Header().Get("Location"), "00u-pat-policy", devidp.MethodPasskey)
	e.clk.add(time.Minute)
	rec = e.wsfedPost(post, nil, login, fresh)
	if !strings.Contains(rec.Header().Get("Location"), "stepup=failed") || cookieNamed(rec, auth.CookieName) != nil {
		t.Errorf("stale step-up: %d %v", rec.Code, rec.Header())
	}
}

var regexpHidden = regexp.MustCompile(`name="(wa|wresult|wctx|bounce)" value="([^"]*)"`)
