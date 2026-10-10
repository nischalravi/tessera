package api

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
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

// SAML sign-in through the in-process dev IdP (design §9.2, PR9).

func newSAMLEnv(t *testing.T) *oidcEnv {
	t.Helper()
	return newAuthEnv(t, true)
}

// samlConnID is the tenant's seeded dev_mock SAML connection.
func samlConnID(t testing.TB, db *store.DB, tn tenancy.ID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.ReadTenant(context.Background(), tn, func(tx *store.TenantTx) error {
		cs, err := tx.IdPConnections()
		for _, c := range cs {
			if c.Protocol == "saml" {
				id = c.ID
			}
		}
		return err
	}); err != nil || id == uuid.Nil {
		t.Fatalf("no SAML connection: %v", err)
	}
	return id
}

// samlAttempt is one SAML sign-in: the login start and the IdP's form.
type samlAttempt struct {
	login  *httptest.ResponseRecorder
	cookie *http.Cookie
	post   devidptest.SAMLPost
}

func (e *oidcEnv) samlLoginURL(extra string) string {
	return "/api/auth/login?tenant=larkspur&return_to=/jit&connection=" + samlConnID(e.t, e.db, seed.LarkspurID).String() + extra
}

// samlStart begins a SAML sign-in at target and signs in at the IdP (with
// fault, if set).
func (e *oidcEnv) samlStart(target, sub string, m devidp.Method, fault devidp.Fault, cookies ...*http.Cookie) samlAttempt {
	e.t.Helper()
	rec := e.get(target, cookies...)
	if rec.Code != http.StatusFound {
		e.t.Fatalf("%s: %d %s", target, rec.Code, rec.Body.String())
	}
	a := samlAttempt{login: rec, cookie: cookieNamed(rec, LoginCookieName)}
	if a.cookie == nil {
		e.t.Fatalf("%s set no login cookie", target)
	}
	sso := rec.Header().Get("Location")
	if fault != devidp.FaultNone {
		sso += "&fault=" + url.QueryEscape(string(fault))
	}
	a.post = e.idp.NewBrowser(e.t).AuthorizeSAML(e.t, sso, sub, m)
	return a
}

// acs posts the IdP's form to the ACS (path only) with cookies.
func (e *oidcEnv) acs(p devidptest.SAMLPost, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()
	u, err := url.Parse(p.ACS)
	if err != nil {
		e.t.Fatal(err)
	}
	if form == nil {
		form = url.Values{"SAMLResponse": {p.SAMLResponse}, "RelayState": {p.RelayState}}
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

func (e *oidcEnv) samlSignIn(sub string, m devidp.Method, fault devidp.Fault) *httptest.ResponseRecorder {
	e.t.Helper()
	a := e.samlStart(e.samlLoginURL(""), sub, m, fault)
	return e.acs(a.post, nil, a.cookie)
}

var bounceField = regexp.MustCompile(`name="(SAMLResponse|RelayState|bounce)" value="([^"]*)"`)

// TestSAMLLogin_PasskeyAdmin: Alice signs in with a passkey; Tessera
// requested the dev IdP's phr class ref, so it is phishing resistance (basis
// acr). The IdP's cross-site POST comes without the Lax login cookie, so the
// ACS re-posts it from Tessera's origin first.
func TestSAMLLogin_PasskeyAdmin(t *testing.T) {
	e := newSAMLEnv(t)
	conn := samlConnID(t, e.db, seed.LarkspurID)
	a := e.samlStart(e.samlLoginURL(""), "00u-alice-admin", devidp.MethodPasskey, devidp.FaultNone)
	sso, _ := url.Parse(a.login.Header().Get("Location"))
	if q := query(sso); !strings.HasPrefix(sso.String(), e.idp.SAMLSSOURL()+"?") || q.Get("SAMLRequest") == "" ||
		q.Get("Signature") == "" || q.Get("RelayState") == "" {
		t.Errorf("SSO URL %s", sso)
	}
	if c := a.cookie; !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 600 {
		t.Errorf("login cookie %+v", c)
	}
	if a.post.ACS != ACSURL(oidcPublicURL, conn) {
		t.Errorf("posted to %s", a.post.ACS)
	}
	// 1. the cross-site POST: no cookie, so a same-origin re-post page
	rec := e.acs(a.post, nil)
	csp := rec.Header().Get("Content-Security-Policy")
	if rec.Code != 200 || !strings.Contains(csp, "script-src 'nonce-") || !strings.Contains(csp, "form-action 'self'") ||
		rec.Header().Get("Cache-Control") != "no-store" || cookieNamed(rec, auth.CookieName) != nil ||
		!strings.Contains(rec.Body.String(), `action="`+ACSURL(oidcPublicURL, conn)+`"`) {
		t.Fatalf("bounce: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	form := url.Values{}
	for _, m := range bounceField.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	if form.Get("SAMLResponse") != a.post.SAMLResponse || form.Get("bounce") != "1" {
		t.Fatalf("bounce form %v", form)
	}
	// a bounced POST without the cookie is refused, not bounced again
	e.refused(e.acs(a.post, form), tenancy.Platform, "login_cookie_missing")
	// 2. the same-origin POST with the cookie
	rec = e.acs(a.post, form, a.cookie)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/jit" {
		t.Fatalf("ACS: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	sid := cookieNamed(rec, auth.CookieName)
	v := e.session(sid)
	active, _ := json.Marshal(at(v, "active_roles"))
	if !strings.Contains(string(active), "tenant_admin") || at(v, "authn", "phishing_resistant") != true ||
		at(v, "authn", "phr_basis") != "acr" || at(v, "authn", "aal") != float64(2) {
		t.Errorf("session %v", v)
	}
	ok := false
	for _, ev := range e.events("auth.login.success") {
		ok = ok || (ev.ActorType == store.ActorUser && strings.Contains(string(ev.Detail), `"via":"saml"`))
	}
	if !ok {
		t.Error("no auth.login.success via saml")
	}
	// the transaction is single use
	e.refused(e.acs(a.post, nil, a.cookie), seed.LarkspurID, "login_transaction_expired_or_used")
}

// TestSAMLLogin_Assurance: password sign-ins are not phishing resistant and
// leave admin roles inactive; a class ref Tessera did not request is not
// trusted.
func TestSAMLLogin_Assurance(t *testing.T) {
	e := newSAMLEnv(t)
	for _, tc := range []struct {
		sub      string
		m        devidp.Method
		phr      bool
		aal      float64
		activeTA bool
	}{
		{"00u-alice-admin", devidp.MethodPasswordOTP, false, 2, false},
		{"00u-vic-viewer", devidp.MethodPassword, false, 1, false},
		{"00u-ivan-admin2", devidp.MethodHardwareKey, true, 3, true}, // phrh
	} {
		rec := e.samlSignIn(tc.sub, tc.m, devidp.FaultNone)
		if rec.Code != http.StatusFound {
			t.Fatalf("%s: %d %s", tc.m, rec.Code, rec.Body.String())
		}
		v := e.session(cookieNamed(rec, auth.CookieName))
		active, _ := json.Marshal(at(v, "active_roles"))
		if at(v, "authn", "phishing_resistant") != tc.phr || at(v, "authn", "aal") != tc.aal ||
			strings.Contains(string(active), "tenant_admin") != tc.activeTA {
			t.Errorf("%s %s: authn %v active %s", tc.sub, tc.m, at(v, "authn"), active)
		}
	}
	// the login asks for aal2 only: a phr class ref was not requested
	if err := e.db.InSystem(context.Background(), "test", func(st *store.SystemTx) error {
		return st.SetTenantSettings(seed.LarkspurID, `{"login_acr":"urn:tessera:acr:aal2"}`)
	}); err != nil {
		t.Fatal(err)
	}
	v := e.session(cookieNamed(e.samlSignIn("00u-alice-admin", devidp.MethodPasskey, devidp.FaultNone), auth.CookieName))
	if at(v, "authn", "phishing_resistant") != false {
		t.Errorf("an unrequested phr class ref was trusted: %v", at(v, "authn"))
	}
}

// TestSAMLLogin_FaultsRefused: every SAML fault of the dev IdP is refused
// at the ACS with its reason and no session; the replay fault (the previous
// assertion ID, re-signed for the new request) is caught by replay_cache.
func TestSAMLLogin_FaultsRefused(t *testing.T) {
	e := newSAMLEnv(t)
	wrap := map[string]bool{samlsp.ReasonAssertionCount: true, samlsp.ReasonUnsignedAssert: true, samlsp.ReasonSignature: true}
	for _, f := range devidp.SAMLFaults() {
		t.Run(string(f), func(t *testing.T) {
			e.t = t
			if f == devidp.FaultReplay {
				if rec := e.samlSignIn("00u-alice-admin", devidp.MethodPasskey, devidp.FaultNone); rec.Code != http.StatusFound ||
					cookieNamed(rec, auth.CookieName) == nil {
					t.Fatalf("first sign-in: %d", rec.Code)
				}
			}
			rec := e.samlSignIn("00u-alice-admin", devidp.MethodPasskey, f)
			if cookieNamed(rec, auth.CookieName) != nil {
				t.Fatalf("a session for fault %s", f)
			}
			got := e.lastFailure(seed.LarkspurID)
			want := map[devidp.Fault]string{devidp.FaultUnsignedAssertion: samlsp.ReasonUnsignedAssert,
				devidp.FaultSignedResponseOnly: samlsp.ReasonUnsignedAssert, devidp.FaultCommentInNameID: samlsp.ReasonNameIDComment,
				devidp.FaultWrongAudience: samlsp.ReasonAudience, devidp.FaultWrongRecipient: samlsp.ReasonRecipient,
				devidp.FaultSAMLExpired: samlsp.ReasonExpired, devidp.FaultUnsolicited: samlsp.ReasonUnsolicited,
				devidp.FaultWrongInResponseTo: samlsp.ReasonInResponseTo, devidp.FaultReplay: samlsp.ReasonReplay}[f]
			if (want != "" && got != want) || (want == "" && !wrap[got]) {
				t.Errorf("reason %q, want %q", got, want)
			}
			e.refused(rec, seed.LarkspurID, got)
		})
	}
}

// TestSAMLLogin_TransactionChecks: the response must come with the
// transaction's cookie and RelayState, within its lifetime, under its
// connection; oversized and malformed posts are refused.
func TestSAMLLogin_TransactionChecks(t *testing.T) {
	e := newSAMLEnv(t)
	start := func() samlAttempt {
		return e.samlStart(e.samlLoginURL(""), "00u-alice-admin", devidp.MethodPasskey, devidp.FaultNone)
	}
	a := start()
	e.refused(e.acs(a.post, url.Values{"SAMLResponse": {a.post.SAMLResponse}, "RelayState": {uuid.NewString()}}, a.cookie),
		seed.LarkspurID, "relay_state_mismatch")
	// another transaction's cookie (login CSRF): RelayState names another txn
	a, b := start(), start()
	e.refused(e.acs(a.post, nil, b.cookie), seed.LarkspurID, "relay_state_mismatch")
	// expired transaction
	a = start()
	e.clk.add(11 * time.Minute)
	e.refused(e.acs(a.post, nil, a.cookie), seed.LarkspurID, "login_transaction_expired_or_used")
	// an unknown cookie
	e.refused(e.acs(start().post, nil, &http.Cookie{Name: LoginCookieName, Value: "nope"}), tenancy.Platform, "login_transaction_unknown")
	// an OIDC callback cannot finish a SAML transaction
	a = start()
	conn := samlConnID(t, e.db, seed.LarkspurID)
	e.refused(e.get("/api/auth/oidc/"+conn.String()+"/callback?state=x&code=y", a.cookie), seed.LarkspurID, "state_mismatch")
	// too large and malformed
	a = start()
	big := url.Values{"SAMLResponse": {strings.Repeat("A", maxACSBody)}, "RelayState": {a.post.RelayState}}
	e.refused(e.acs(a.post, big, a.cookie), tenancy.Platform, samlsp.ReasonTooLarge)
	a = start()
	e.refused(e.acs(a.post, url.Values{"SAMLResponse": {"%%%"}, "RelayState": {a.post.RelayState}}, a.cookie),
		seed.LarkspurID, samlsp.ReasonMalformed)
}

// TestIsolation_SAMLCrossTenant: a larkspur transaction cannot finish at
// globex's ACS, Gina (globex) has no larkspur account, and each metadata
// document is its own connection's.
func TestIsolation_SAMLCrossTenant(t *testing.T) {
	e := newSAMLEnv(t)
	a := e.samlStart(e.samlLoginURL(""), "00u-alice-admin", devidp.MethodPasskey, devidp.FaultNone)
	p := a.post
	p.ACS = ACSURL(oidcPublicURL, samlConnID(t, e.db, seed.GlobexID))
	e.refused(e.acs(p, nil, a.cookie), seed.LarkspurID, "connection_mismatch")
	e.refused(e.samlSignIn("00u-gina-globex", devidp.MethodPasskey, devidp.FaultNone), seed.LarkspurID, "unknown_subject")
	for _, tn := range []tenancy.ID{seed.LarkspurID, seed.GlobexID} {
		id := samlConnID(t, e.db, tn)
		rec := e.get("/api/auth/saml/" + id.String() + "/metadata")
		if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/samlmetadata+xml" ||
			!strings.Contains(rec.Body.String(), `entityID="`+SPEntityID(oidcPublicURL, id)+`"`) {
			t.Fatalf("metadata %s: %d %s", tn, rec.Code, rec.Body.String())
		}
	}
	for _, id := range []string{uuid.NewString(), "not-a-uuid", devConnID(t, e.db, seed.LarkspurID).String()} {
		if rec := e.get("/api/auth/saml/" + id + "/metadata"); rec.Code != 404 {
			t.Errorf("metadata for %s: %d", id, rec.Code)
		}
	}
}

// TestSAMLLogin_ConnectionAttestation: a connection attested phishing
// resistant (assume_phishing_resistant) makes a password sign-in phr, and
// says so: phr_basis connection_attestation.
func TestSAMLLogin_ConnectionAttestation(t *testing.T) {
	e := newSAMLEnv(t)
	base := samlConnID(t, e.db, seed.LarkspurID)
	id := uuid.New()
	if err := e.db.InTenant(context.Background(), seed.LarkspurID, func(tx *store.TenantTx) error {
		c, err := tx.IdPConnection(base)
		if err != nil {
			return err
		}
		key, err := e.sealer.Open(c.SPKeyEnc, auth.SPKeyAAD(seed.LarkspurID, base))
		if err != nil {
			return err
		}
		c.ID, c.Name, c.AssumePhishingResistant, c.JITProvisioning = id, "Attested SAML", true, true
		if c.SPKeyEnc, err = e.sealer.Seal(key, auth.SPKeyAAD(seed.LarkspurID, id)); err != nil {
			return err
		}
		return tx.InsertIdPConnection(c)
	}); err != nil {
		t.Fatal(err)
	}
	a := e.samlStart("/api/auth/login?tenant=larkspur&connection="+id.String(), "00u-alice-admin", devidp.MethodPassword,
		devidp.FaultNone)
	v := e.session(cookieNamed(e.acs(a.post, nil, a.cookie), auth.CookieName))
	if at(v, "authn", "phishing_resistant") != true || at(v, "authn", "phr_basis") != "connection_attestation" {
		t.Errorf("authn %v", at(v, "authn"))
	}
}

// TestSAMLStepUp: a step-up of a SAML session goes back to its IdP with
// ForceAuthn and the phr class ref; the fresh AuthnInstant updates the
// session's auth_time. An assertion from before the step-up is refused.
func TestSAMLStepUp(t *testing.T) {
	e := newSAMLEnv(t)
	sid := cookieNamed(e.samlSignIn("00u-pat-policy", devidp.MethodPasskey, devidp.FaultNone), auth.CookieName)
	before := at(e.session(sid), "authn", "auth_time")
	e.ageAuth(sid)
	if rec := e.post(approvePath, sid, ""); rec.Code != 401 {
		t.Fatalf("before step-up: %d", rec.Code)
	}
	a := e.samlStart("/api/auth/step-up?acr=urn:tessera:acr:phr&max_age=900&return_to=/access/jit", "00u-pat-policy",
		devidp.MethodPasskey, devidp.FaultNone, sid)
	sso, _ := url.Parse(a.login.Header().Get("Location"))
	req := samlRequestXML(t, query(sso).Get("SAMLRequest"))
	if !strings.Contains(req, `ForceAuthn="true"`) || !strings.Contains(req, "urn:devidp:ac:phr<") {
		t.Errorf("step-up AuthnRequest %s", req)
	}
	rec := e.acs(a.post, nil, a.cookie, sid)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/access/jit?stepup=ok" {
		t.Fatalf("step-up ACS: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	fresh := cookieNamed(rec, auth.CookieName)
	v := e.session(fresh)
	if after := at(v, "authn", "auth_time"); after == before || at(v, "authn", "phishing_resistant") != true {
		t.Errorf("auth_time %v -> %v, authn %v", before, after, at(v, "authn"))
	}
	if rec := e.post(approvePath, fresh, ""); rec.Code == 401 || rec.Code == 403 {
		t.Errorf("after step-up: %d %s", rec.Code, rec.Body.String())
	}
	if len(e.events("auth.step_up.success")) != 1 {
		t.Error("no auth.step_up.success")
	}
	// an IdP that answers with an authentication from before the step-up
	// started is refused (ForceAuthn is only a request)
	e.ageAuth(fresh)
	rec = e.get("/api/auth/step-up?acr=urn:tessera:acr:phr&max_age=900", fresh)
	login := cookieNamed(rec, LoginCookieName)
	e.clk.add(-time.Minute) // the IdP signs in "a minute ago"
	post := e.idp.NewBrowser(t).AuthorizeSAML(t, rec.Header().Get("Location"), "00u-pat-policy", devidp.MethodPasskey)
	e.clk.add(time.Minute)
	rec = e.acs(post, nil, login, fresh)
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.Contains(loc, "stepup=failed") ||
		cookieNamed(rec, auth.CookieName) != nil {
		t.Errorf("stale step-up: %d %v", rec.Code, rec.Header())
	}
	if ev := e.events("auth.step_up.failure"); len(ev) != 1 || !strings.Contains(string(ev[0].Detail), "auth_time_stale") {
		t.Errorf("auth.step_up.failure %v", ev)
	}
}

// samlRequestXML inflates a Redirect-binding SAMLRequest.
func samlRequestXML(t *testing.T, v string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// FuzzSAMLACS (§19 PR9): mutated responses posted to the ACS handler never
// panic and never create a session. Each input gets a fresh transaction,
// which no response answers (the seeds were issued for another one).
func FuzzSAMLACS(f *testing.F) {
	e := newAuthEnv(f, true)
	a := e.samlStart(e.samlLoginURL(""), "00u-alice-admin", devidp.MethodPasskey, devidp.FaultNone)
	raw, _ := base64.StdEncoding.DecodeString(a.post.SAMLResponse)
	f.Add(raw)
	f.Add([]byte(strings.Replace(string(raw), "00u-alice-admin", "00u-ivan-admin2", 1)))
	f.Add([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`))
	target := e.samlLoginURL("")
	f.Fuzz(func(t *testing.T, b []byte) {
		e.t = t
		rec := e.get(target)
		cookie := cookieNamed(rec, LoginCookieName)
		sso, _ := url.Parse(rec.Header().Get("Location"))
		form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(b)}, "RelayState": {query(sso).Get("RelayState")}}
		if got := e.acs(a.post, form, cookie); cookieNamed(got, auth.CookieName) != nil || got.Code == 200 {
			t.Fatalf("ACS answered %d with a session or a page", got.Code)
		}
	})
}
