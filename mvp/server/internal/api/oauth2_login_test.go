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
	"github.com/nischalravi/tessera/mvp/server/internal/auth/oauth2rp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Sign-in through the dev IdP's GitHub-style OAuth 2.0 emulation (#151).

func newGitHubEnv(t *testing.T) *oidcEnv {
	t.Helper()
	return newAuthEnv(t, authEnvOpts{github: true})
}

func githubConnID(t testing.TB, db *store.DB, tn tenancy.ID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.ReadTenant(context.Background(), tn, func(tx *store.TenantTx) error {
		cs, err := tx.IdPConnections()
		for _, c := range cs {
			if c.Protocol == "oauth2" {
				id = c.ID
			}
		}
		return err
	}); err != nil || id == uuid.Nil {
		t.Fatalf("no OAuth 2.0 connection: %v", err)
	}
	return id
}

func (e *oidcEnv) githubLoginURL(conn uuid.UUID) string {
	return "/api/auth/login?tenant=larkspur&return_to=/jit&connection=" + conn.String()
}

// githubStart begins a GitHub sign-in (with fault) and signs in at the IdP.
func (e *oidcEnv) githubStart(target, sub string, fault devidp.Fault) attempt {
	e.t.Helper()
	rec := e.get(target)
	if rec.Code != http.StatusFound {
		e.t.Fatalf("%s: %d %s", target, rec.Code, rec.Body.String())
	}
	a := attempt{login: rec, cookie: cookieNamed(rec, LoginCookieName)}
	authz := rec.Header().Get("Location")
	if fault != devidp.FaultNone {
		authz += "&fault=" + string(fault)
	}
	a.callback = e.idp.NewBrowser(e.t).Authorize(e.t, authz, sub, devidp.MethodPasskey, "")
	return a
}

func (e *oidcEnv) githubSignIn(sub string, fault devidp.Fault) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.finish(e.githubStart(e.githubLoginURL(githubConnID(e.t, e.db, seed.LarkspurID)), sub, fault))
}

// TestOAuth2Login_GitHub: Alice signs in through GitHub-style OAuth 2.0.
// She is found by her numeric GitHub id; the session is AAL1 and not
// phishing resistant, so her tenant_admin role stays inactive.
func TestOAuth2Login_GitHub(t *testing.T) {
	e := newGitHubEnv(t)
	conn := githubConnID(t, e.db, seed.LarkspurID)
	a := e.githubStart(e.githubLoginURL(conn), "00u-alice-admin", devidp.FaultNone)
	authz, _ := url.Parse(a.login.Header().Get("Location"))
	q := query(authz)
	if !strings.HasPrefix(authz.String(), e.idp.GitHubAuthorizeURL()+"?") || q.Get("code_challenge_method") != "S256" ||
		q.Get("state") == "" || q.Get("nonce") != "" || q.Get("redirect_uri") != oidcPublicURL+"/api/auth/oauth2/"+conn.String()+"/callback" {
		t.Errorf("authorization URL %s", authz)
	}
	if c := a.cookie; c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("login cookie %+v", c)
	}
	rec := e.finish(a)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/jit" {
		t.Fatalf("callback: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	v := e.session(cookieNamed(rec, auth.CookieName))
	active, _ := json.Marshal(at(v, "active_roles"))
	if at(v, "authn", "aal") != float64(1) || at(v, "authn", "phishing_resistant") != false ||
		at(v, "authn", "acr") != "urn:tessera:acr:aal1" || strings.Contains(string(active), "tenant_admin") {
		t.Errorf("session %v", v)
	}
	if u := e.userBySubject(conn, seed.DevGitHubID("00u-alice-admin")); u.DisplayName != "Alice (tenant admin)" {
		t.Errorf("user %+v", u)
	}
	ok := false
	for _, ev := range e.events("auth.login.success") {
		ok = ok || strings.Contains(string(ev.Detail), `"via":"oauth2"`)
	}
	if !ok {
		t.Error("no auth.login.success via oauth2")
	}
	e.refused(e.finish(a), seed.LarkspurID, "login_transaction_expired_or_used")
}

func TestOAuth2Login_FaultsRefused(t *testing.T) {
	e := newGitHubEnv(t)
	want := map[devidp.Fault]string{
		devidp.FaultGitHubTokenError: oauth2rp.ReasonTokenExchange, devidp.FaultGitHubTokenType: oauth2rp.ReasonTokenType,
		devidp.FaultGitHubUserError: oauth2rp.ReasonUserAPI, devidp.FaultGitHubNoID: oauth2rp.ReasonSubject,
		devidp.FaultGitHubStringID: oauth2rp.ReasonSubject,
	}
	for _, f := range devidp.GitHubFaults() {
		t.Run(string(f), func(t *testing.T) {
			e.t = t
			e.refused(e.githubSignIn("00u-alice-admin", f), seed.LarkspurID, want[f])
		})
	}
}

// TestOAuth2Login_TransactionChecks: the shared callback checks, plus the
// protocol: an OAuth 2.0 transaction cannot finish at the OIDC callback and
// the reverse.
func TestOAuth2Login_TransactionChecks(t *testing.T) {
	e := newGitHubEnv(t)
	conn := githubConnID(t, e.db, seed.LarkspurID)
	a := e.githubStart(e.githubLoginURL(conn), "00u-alice-admin", devidp.FaultNone)
	cb := *a.callback
	v := query(&cb)
	v.Set("state", "nope")
	cb.RawQuery = v.Encode()
	e.refused(e.get(cb.RequestURI(), a.cookie), seed.LarkspurID, "state_mismatch")

	a = e.githubStart(e.githubLoginURL(conn), "00u-alice-admin", devidp.FaultNone)
	a.callback.Path = "/api/auth/oidc/" + conn.String() + "/callback"
	e.refused(e.finish(a), seed.LarkspurID, "connection_mismatch")

	o := e.start("/api/auth/login?tenant=larkspur", "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)
	o.callback.Path = "/api/auth/oauth2/" + devConnID(t, e.db, seed.LarkspurID).String() + "/callback"
	e.refused(e.finish(o), seed.LarkspurID, "connection_mismatch")

	a = e.githubStart(e.githubLoginURL(conn), "00u-alice-admin", devidp.FaultNone)
	a.callback.Path = "/api/auth/oauth2/" + githubConnID(t, e.db, seed.GlobexID).String() + "/callback"
	e.refused(e.finish(a), seed.LarkspurID, "connection_mismatch")

	// Gina (globex) has no larkspur account
	e.refused(e.githubSignIn("00u-gina-globex", devidp.FaultNone), seed.LarkspurID, "unknown_subject")
}

// TestOAuth2Login_NoAssurance: step-up is unavailable to an OAuth 2.0
// session, a bootstrap invitation cannot use the connection, and an
// attestation on it is ignored.
func TestOAuth2Login_NoAssurance(t *testing.T) {
	e := newGitHubEnv(t)
	conn := githubConnID(t, e.db, seed.LarkspurID)
	sid := cookieNamed(e.githubSignIn("00u-pat-policy", devidp.FaultNone), auth.CookieName)
	if rec := e.get("/api/auth/step-up?acr=urn:tessera:acr:phr", sid); rec.Code != http.StatusConflict ||
		decode(t, rec)["error"] != "step_up_unavailable" {
		t.Errorf("step-up: %d %s", rec.Code, rec.Body.String())
	}
	code := e.invite(seed.LarkspurID, conn, "newbie@larkspur.example", time.Hour)
	e.refused(e.get("/t/larkspur/bootstrap?code="+code), seed.LarkspurID, "unknown_connection")

	attested := uuid.New()
	if err := e.db.InTenant(context.Background(), seed.LarkspurID, func(tx *store.TenantTx) error {
		c, err := tx.IdPConnection(conn)
		if err != nil {
			return err
		}
		secret, err := e.sealer.Open(c.ClientSecretEnc, auth.ClientSecretAAD(seed.LarkspurID, conn))
		if err != nil {
			return err
		}
		c.ID, c.Name, c.AssumePhishingResistant, c.JITProvisioning = attested, "Attested GitHub", true, true
		if c.ClientSecretEnc, err = e.sealer.Seal(secret, auth.ClientSecretAAD(seed.LarkspurID, attested)); err != nil {
			return err
		}
		return tx.InsertIdPConnection(c)
	}); err != nil {
		t.Fatal(err)
	}
	rec := e.finish(e.githubStart(e.githubLoginURL(attested), "00u-alice-admin", devidp.FaultNone))
	if v := e.session(cookieNamed(rec, auth.CookieName)); at(v, "authn", "phishing_resistant") != false {
		t.Errorf("an attested OAuth 2.0 connection gave phr: %v", at(v, "authn"))
	}
}
