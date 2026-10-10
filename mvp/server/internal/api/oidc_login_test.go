package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/oidcrp"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp/devidptest"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// The OIDC browser sign-in tests (design §19 PR6) drive Tessera's
// /api/auth/login and callback against the dev IdP running in-process, with
// the dev IdP's sign-in page filled in by devidptest.Browser.

const (
	oidcClientID  = "tessera-dev"
	oidcSecret    = "oidc-test-secret" // #nosec G101 -- fixed test-only value for an in-process mock IdP
	oidcPublicURL = "http://127.0.0.1:5173"
)

type mutableClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *mutableClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *mutableClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type oidcEnv struct {
	t      testing.TB
	idp    *devidptest.IdP
	srv    *Server
	h      http.Handler
	db     *store.DB
	sealer *seal.Sealer
	clk    *mutableClock
}

// newbie is a dev IdP user with no Tessera account (JIT provisioning).
var newbie = devidp.User{Sub: "00u-newbie", Email: "newbie@larkspur.example", Name: "Newbie", Tenant: "larkspur",
	Groups: []string{"Tessera Operators"}, Authenticators: []devidp.Method{devidp.MethodPasskey, devidp.MethodPassword}}

func newOIDCEnv(t *testing.T, users ...devidp.User) *oidcEnv {
	t.Helper()
	return newAuthEnv(t, false, users...)
}

// newAuthEnv is newOIDCEnv, with the dev_mock SAML connection seeded too
// when saml is set.
func newAuthEnv(t testing.TB, saml bool, users ...devidp.User) *oidcEnv {
	t.Helper()
	clk := &mutableClock{t: testkit.Now.UTC()}
	if len(users) == 0 {
		var err error
		if users, err = devidp.DefaultUsers(); err != nil {
			t.Fatal(err)
		}
		users = append(users, newbie)
	}
	idp := devidptest.Start(t, devidp.Config{Now: clk.now, Users: users, Clients: []devidp.Client{{ID: oidcClientID,
		Secret: oidcSecret, RedirectURIs: []string{"http://127.0.0.1:*/api/auth/oidc/*/callback"}}}})
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	db := testkit.Open(t)
	client := seed.DevIdPClient{Sealer: sealer, Secret: oidcSecret}
	if saml {
		client.SAMLCert = idp.SAMLCertificatePEM()
	}
	tenants := seed.WithDevIdPClient([]seed.Tenant{
		{ID: seed.LarkspurID, Slug: seed.LarkspurSlug, Name: "Larkspur Labs", Connectors: []connectors.Connector{connectors.Tiny{Now: testkit.Now}}},
		{ID: seed.GlobexID, Slug: seed.GlobexSlug, Name: "Globex", Connectors: []connectors.Connector{connectors.Tiny{Now: testkit.Now, Sentinel: "G"}}},
	}, idp.URL, client)
	if _, err := seed.Run(context.Background(), db, testkit.Now, testkit.Policies(t), tenants); err != nil {
		t.Fatal(err)
	}
	hc, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Config{Store: db, Clock: clk.now, Policies: policy.NewLoader(policies.FS), Env: "test",
		AllowedOrigins: []string{oidcPublicURL}, PublicURL: oidcPublicURL, Sealer: sealer, OutboundHTTP: hc,
		RateLimits: noRateLimits, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	return &oidcEnv{t: t, idp: idp, srv: srv, h: srv.Handler(), db: db, sealer: sealer, clk: clk}
}

// get serves a GET with cookies.
func (e *oidcEnv) get(target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", target, nil)
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	return serve(e.h, r)
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.Value != "" && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

// attempt is one sign-in: the login start, the IdP, and the callback URL.
type attempt struct {
	login    *httptest.ResponseRecorder
	cookie   *http.Cookie
	callback *url.URL
}

// start begins a sign-in at target (/api/auth/login?... or /t/.../bootstrap)
// and signs in at the IdP.
func (e *oidcEnv) start(target, sub string, m devidp.Method, p devidp.Profile) attempt {
	e.t.Helper()
	rec := e.get(target)
	if rec.Code != http.StatusFound {
		e.t.Fatalf("%s: %d %s", target, rec.Code, rec.Body.String())
	}
	a := attempt{login: rec, cookie: cookieNamed(rec, LoginCookieName)}
	if a.cookie == nil {
		e.t.Fatalf("%s set no login cookie", target)
	}
	a.callback = e.idp.NewBrowser(e.t).Authorize(e.t, rec.Header().Get("Location"), sub, m, p)
	return a
}

// finish sends the callback (path and query only) with the login cookie.
func (e *oidcEnv) finish(a attempt) *httptest.ResponseRecorder {
	return e.get(a.callback.RequestURI(), a.cookie)
}

func (e *oidcEnv) signIn(sub string, m devidp.Method, p devidp.Profile) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.finish(e.start("/api/auth/login?tenant=larkspur&return_to=/jit", sub, m, p))
}

func (e *oidcEnv) session(c *http.Cookie) map[string]any {
	e.t.Helper()
	rec := e.get("/api/auth/session", c)
	if rec.Code != 200 {
		e.t.Fatalf("session: %d %s", rec.Code, rec.Body.String())
	}
	return decode(e.t, rec)
}

// lastFailure is the newest auth.login.failure reason in tn's chain.
func (e *oidcEnv) lastFailure(tn tenancy.ID) string {
	for _, ev := range ledger(e.t, e.db, tn) {
		if ev.Action == "auth.login.failure" {
			var d map[string]any
			_ = json.Unmarshal(ev.Detail, &d)
			r, _ := d["reason"].(string)
			return r
		}
	}
	return ""
}

func (e *oidcEnv) refused(rec *httptest.ResponseRecorder, tn tenancy.ID, reason string) {
	e.t.Helper()
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.HasPrefix(loc, "/login?error=login_failed&request_id=") ||
		cookieNamed(rec, auth.CookieName) != nil || strings.Contains(loc, reason) {
		e.t.Fatalf("want a redirect to the generic sign-in error without a session: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	if got := e.lastFailure(tn); got != reason {
		e.t.Errorf("auth.login.failure reason %q, want %q", got, reason)
	}
}

// TestOIDCLogin_OktaPasskeyAdmin (§20.1 E1.1): Alice signs in with a passkey
// through the dev IdP's Okta emulation; Tessera asked for acr_values=phr, so
// acr=phr is phishing resistance (basis acr) and tenant_admin is active.
func TestOIDCLogin_OktaPasskeyAdmin(t *testing.T) {
	e := newOIDCEnv(t)
	a := e.start("/api/auth/login?tenant=larkspur&return_to=/jit", "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)
	loc, _ := url.Parse(a.login.Header().Get("Location"))
	if q := query(loc); q.Get("acr_values") != "phr" || q.Get("max_age") != "43200" || q.Get("code_challenge_method") != "S256" ||
		q.Get("redirect_uri") == "" || !strings.HasPrefix(q.Get("redirect_uri"), oidcPublicURL+"/api/auth/oidc/") {
		t.Errorf("authorize URL %s", loc)
	}
	if c := a.cookie; !c.HttpOnly || !c.Secure || c.Path != "/" || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 600 {
		t.Errorf("login cookie %+v", c)
	}
	rec := e.finish(a)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/jit" {
		t.Fatalf("callback: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	sid := cookieNamed(rec, auth.CookieName)
	if sid == nil {
		t.Fatal("no session cookie")
	}
	v := e.session(sid)
	active, _ := json.Marshal(at(v, "active_roles"))
	if !strings.Contains(string(active), "tenant_admin") || at(v, "authn", "phishing_resistant") != true ||
		at(v, "authn", "phr_basis") != "acr" || at(v, "authn", "aal") != float64(2) || at(v, "tenant", "slug") != "larkspur" {
		t.Errorf("session %v", v)
	}
	found := false
	for _, ev := range ledger(t, e.db, seed.LarkspurID) {
		if ev.Action == "auth.login.success" && ev.ActorType == store.ActorUser && strings.Contains(string(ev.Detail), `"via":"oidc"`) {
			found = true
		}
	}
	if !found {
		t.Error("no auth.login.success attributed to Alice")
	}
	// the transaction is single use: replaying the callback is refused
	e.refused(e.finish(a), seed.LarkspurID, "login_transaction_expired_or_used")
}

// TestOIDCLogin_AssuranceAndProfiles: the normalized context follows the
// method and the vendor emulation; admin roles stay inactive without phr.
func TestOIDCLogin_AssuranceAndProfiles(t *testing.T) {
	e := newOIDCEnv(t)
	for _, tc := range []struct {
		sub         string
		m           devidp.Method
		p           devidp.Profile
		phr         bool
		activeAdmin bool
	}{
		{"00u-alice-admin", devidp.MethodPasswordOTP, devidp.ProfileOkta, false, false},
		{"00u-alice-admin", devidp.MethodPassword, devidp.ProfileOkta, false, false},
		{"00u-ivan-admin2", devidp.MethodHardwareKey, devidp.ProfileOkta, true, true},
		{"00u-alice-admin", devidp.MethodPasskey, devidp.ProfileGeneric, true, true}, // the generic vocabulary acr=phr, requested
	} {
		rec := e.signIn(tc.sub, tc.m, tc.p)
		if rec.Code != http.StatusFound {
			t.Fatalf("%s %s: %d %s", tc.m, tc.p, rec.Code, rec.Body.String())
		}
		v := e.session(cookieNamed(rec, auth.CookieName))
		active, _ := json.Marshal(at(v, "active_roles"))
		if at(v, "authn", "phishing_resistant") != tc.phr || strings.Contains(string(active), "tenant_admin") != tc.activeAdmin {
			t.Errorf("%s %s: authn %v active %s", tc.m, tc.p, at(v, "authn"), active)
		}
	}
}

// TestOIDCLogin_Entra: the Entra emulation's subject is oid (never the
// pairwise sub), and amr fido is phishing resistance.
func TestOIDCLogin_Entra(t *testing.T) {
	e := newOIDCEnv(t)
	// the seeded links are Okta subjects: an Entra sign-in is another subject
	e.refused(e.signIn("00u-alice-admin", devidp.MethodPasskey, devidp.ProfileEntra), seed.LarkspurID, "unknown_subject")
	conn := e.addConn(func(c *store.IdPConnection) {
		c.JITProvisioning = true
		c.AuthnMapping = json.RawMessage(`{"dev_emulation":"entra","entra_tenant_id":"` + devidp.EntraTenantID("larkspur") + `"}`)
	})
	login := "/api/auth/login?tenant=larkspur&connection=" + conn.ID.String()
	for _, tc := range []struct {
		m   devidp.Method
		phr bool
	}{{devidp.MethodPasskey, true}, {devidp.MethodPasswordOTP, false}} {
		rec := e.finish(e.start(login, "00u-pat-policy", tc.m, devidp.ProfileEntra))
		if rec.Code != http.StatusFound {
			t.Fatalf("%s: %d %s", tc.m, rec.Code, rec.Body.String())
		}
		if v := e.session(cookieNamed(rec, auth.CookieName)); at(v, "authn", "phishing_resistant") != tc.phr {
			t.Errorf("%s: authn %v", tc.m, at(v, "authn"))
		}
	}
	if u := e.userBySubject(conn.ID, devidp.EntraObjectID("00u-pat-policy")); u == nil {
		t.Error("the Entra user is not keyed by oid")
	}
}

// TestOIDCLogin_FaultsRefused: each dev IdP fault ends in the generic error
// page and auth.login.failure with the oidcrp reason; no session is created.
func TestOIDCLogin_FaultsRefused(t *testing.T) {
	e := newOIDCEnv(t)
	for f, reason := range map[devidp.Fault]string{
		devidp.FaultWrongIss:        oidcrp.ReasonIssuer,
		devidp.FaultWrongAud:        oidcrp.ReasonAudience,
		devidp.FaultAlgNone:         oidcrp.ReasonAlg,
		devidp.FaultHS256WithPubkey: oidcrp.ReasonAlg,
		devidp.FaultBadSignature:    oidcrp.ReasonSignature,
		devidp.FaultExpired:         oidcrp.ReasonExpired,
		devidp.FaultFutureIat:       oidcrp.ReasonIat,
		devidp.FaultNonceMismatch:   oidcrp.ReasonNonce,
		devidp.FaultMissingAuthTime: oidcrp.ReasonAuthTimeMissing,
		devidp.FaultStaleAuthTime:   oidcrp.ReasonAuthTimeStale,
		devidp.FaultKidUnknown:      oidcrp.ReasonSignature,
		devidp.FaultJKUHeader:       oidcrp.ReasonHeader,
		devidp.FaultNoIssParam:      oidcrp.ReasonIssParam,
	} {
		t.Run(string(f), func(t *testing.T) {
			if err := e.idp.SetFault(f); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = e.idp.SetFault(devidp.FaultNone) }()
			e.t = t
			e.refused(e.signIn("00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta), seed.LarkspurID, reason)
		})
	}
	e.t = t
}

// TestOIDCLogin_TransactionChecks: the cookie, the state, the connection,
// the iss parameter, an IdP error and expiry are each refused.
func TestOIDCLogin_TransactionChecks(t *testing.T) {
	e := newOIDCEnv(t)
	sub, m, p := "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta
	start := func() attempt { return e.start("/api/auth/login?tenant=larkspur", sub, m, p) }

	a := start()
	e.refused(e.get(a.callback.RequestURI()), tenancy.Platform, "login_cookie_missing")

	a = start()
	e.refused(e.get(a.callback.RequestURI(), &http.Cookie{Name: LoginCookieName, Value: seal.RandomSecret(32)}),
		tenancy.Platform, "login_transaction_unknown")

	a = start()
	q := query(a.callback)
	q.Set("state", "forged")
	a.callback.RawQuery = q.Encode()
	e.refused(e.finish(a), seed.LarkspurID, "state_mismatch")

	a = start()
	q = query(a.callback)
	q.Set("iss", "https://evil.example")
	a.callback.RawQuery = q.Encode()
	e.refused(e.finish(a), seed.LarkspurID, oidcrp.ReasonIssParam)

	a = start()
	a.callback.Path = "/api/auth/oidc/" + uuid.NewString() + "/callback"
	e.refused(e.finish(a), seed.LarkspurID, "connection_mismatch")

	a = start()
	q = query(a.callback)
	q.Del("code")
	q.Set("error", "access_denied")
	a.callback.RawQuery = q.Encode()
	e.refused(e.finish(a), seed.LarkspurID, "idp_error")

	a = start()
	e.clk.add(11 * time.Minute)
	e.refused(e.finish(a), seed.LarkspurID, "login_transaction_expired_or_used")
	e.clk.add(-11 * time.Minute)

	// unknown tenant, unknown connection, unsafe return_to: refused at the start
	for target, want := range map[string]struct {
		tn     tenancy.ID
		reason string
	}{
		"/api/auth/login?tenant=nope":                          {tenancy.Platform, "unknown_tenant"},
		"/api/auth/login?tenant=_platform":                     {tenancy.Platform, "unknown_tenant"},
		"/api/auth/login?tenant=larkspur&connection=x":         {seed.LarkspurID, "unknown_connection"},
		"/api/auth/login?tenant=larkspur&return_to=//evil.com": {seed.LarkspurID, "invalid_return_to"},
		"/api/auth/login?tenant=larkspur&return_to=/%5Cevil":   {seed.LarkspurID, "invalid_return_to"},
	} {
		rec := e.get(target)
		if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/login?error=") ||
			cookieNamed(rec, LoginCookieName) != nil {
			t.Errorf("%s: %d %s", target, rec.Code, rec.Header().Get("Location"))
		}
		if got := e.lastFailure(want.tn); got != want.reason {
			t.Errorf("%s: reason %q, want %q", target, got, want.reason)
		}
	}
}

// addConn adds a copy of larkspur's dev connection, edited, with its own sealed secret.
func (e *oidcEnv) addConn(edit func(c *store.IdPConnection)) *store.IdPConnection {
	e.t.Helper()
	var conn *store.IdPConnection
	err := e.db.InTenant(context.Background(), seed.LarkspurID, func(tx *store.TenantTx) error {
		cs, err := tx.IdPConnections()
		if err != nil {
			return err
		}
		base := cs[0]
		now := testkit.Now
		c := *base
		c.ID, c.Name, c.IsDefault, c.CreatedAt, c.UpdatedAt = uuid.New(), "Test "+uuid.NewString()[:8], false, now, now
		if c.ClientSecretEnc, err = e.sealer.Seal([]byte(oidcSecret), auth.ClientSecretAAD(seed.LarkspurID, c.ID)); err != nil {
			return err
		}
		edit(&c)
		conn = &c
		return tx.InsertIdPConnection(conn)
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return conn
}

func (e *oidcEnv) userBySubject(conn uuid.UUID, sub string) *store.PlatformUser {
	e.t.Helper()
	var u *store.PlatformUser
	err := e.db.ReadTenant(context.Background(), seed.LarkspurID, func(tx *store.TenantTx) error {
		l, err := tx.ExternalLoginBySubject(conn, sub)
		if err != nil {
			return err
		}
		u, err = tx.PlatformUser(l.UserID)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

// TestOIDCLogin_Provisioning: an unknown subject is refused without JIT
// provisioning and created (with the connection's default role) with it;
// group mapping adds non-admin roles and never an admin role.
func TestOIDCLogin_Provisioning(t *testing.T) {
	e := newOIDCEnv(t)
	e.refused(e.signIn("00u-newbie", devidp.MethodPasskey, devidp.ProfileOkta), seed.LarkspurID, "unknown_subject")

	conn := e.addConn(func(c *store.IdPConnection) {
		c.JITProvisioning = true
		c.GroupRoleMapping = json.RawMessage(`{"Tessera Operators":"operator","Tessera Viewers":"tenant_admin"}`)
	})
	login := "/api/auth/login?tenant=larkspur&connection=" + conn.ID.String()
	rec := e.finish(e.start(login, "00u-newbie", devidp.MethodPasskey, devidp.ProfileOkta))
	if rec.Code != http.StatusFound {
		t.Fatalf("JIT sign-in: %d %s", rec.Code, rec.Body.String())
	}
	u := e.userBySubject(conn.ID, "00u-newbie")
	v := e.session(cookieNamed(rec, auth.CookieName))
	roles, _ := json.Marshal(at(v, "roles"))
	if u.Email == nil || *u.Email != newbie.Email || string(roles) != `["viewer","operator"]` {
		t.Errorf("JIT user %+v roles %s", u, roles)
	}
	jit := false
	for _, ev := range ledger(t, e.db, seed.LarkspurID) {
		if ev.Action == "auth.user.jit_created" {
			jit = true
		}
	}
	if !jit {
		t.Error("no auth.user.jit_created event")
	}
	// Vic is in "Tessera Viewers", which the mapping points at tenant_admin:
	// the admin role is never granted from a group
	rec = e.finish(e.start(login, "00u-vic-viewer", devidp.MethodPassword, devidp.ProfileOkta))
	if rec.Code != http.StatusFound {
		t.Fatalf("Vic: %d %s", rec.Code, rec.Body.String())
	}
	if roles, _ := json.Marshal(at(e.session(cookieNamed(rec, auth.CookieName)), "roles")); strings.Contains(string(roles), "admin") {
		t.Errorf("Vic got an admin role from a group: %s", roles)
	}
	// a second sign-in reuses the user (subject keyed)
	rec = e.finish(e.start(login, "00u-newbie", devidp.MethodPasskey, devidp.ProfileOkta))
	if again := e.userBySubject(conn.ID, "00u-newbie"); rec.Code != http.StatusFound || again.ID != u.ID {
		t.Errorf("second sign-in: %d, user %s then %s", rec.Code, u.ID, again.ID)
	}
}

// TestOIDCLogin_SubjectKeyed: an email change at the IdP does not create a
// new user or sign in as someone else (users are keyed by connection and
// subject, never email).
func TestOIDCLogin_SubjectKeyed(t *testing.T) {
	users, _ := devidp.DefaultUsers()
	for i := range users {
		if users[i].Sub == "00u-alice-admin" {
			users[i].Email = "alice.renamed@larkspur.example"
		}
		if users[i].Sub == "00u-vic-viewer" {
			users[i].Email = "alice.admin@larkspur.example" // someone else's address
		}
	}
	e := newOIDCEnv(t, users...)
	before := len(platformUsers(t, e.db))
	rec := e.signIn("00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)
	v := e.session(cookieNamed(rec, auth.CookieName))
	if at(v, "user", "email") != "alice.admin@larkspur.example" {
		t.Errorf("Alice after an email change: %v", at(v, "user"))
	}
	rec = e.signIn("00u-vic-viewer", devidp.MethodPassword, devidp.ProfileOkta)
	if v := e.session(cookieNamed(rec, auth.CookieName)); at(v, "user", "email") != "vic@larkspur.example" {
		t.Errorf("Vic with Alice's email signed in as %v", at(v, "user"))
	}
	if after := len(platformUsers(t, e.db)); after != before {
		t.Errorf("%d users before, %d after", before, after)
	}
}

func platformUsers(t *testing.T, db *store.DB) []*store.PlatformUser {
	t.Helper()
	var out []*store.PlatformUser
	if err := db.ReadTenant(context.Background(), seed.LarkspurID, func(tx *store.TenantTx) error {
		var err error
		out, err = tx.PlatformUsers()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestOIDCLogin_DisabledUser: a disabled user is refused.
func TestOIDCLogin_DisabledUser(t *testing.T) {
	e := newOIDCEnv(t)
	conns := devConnID(t, e.db, seed.LarkspurID)
	u := e.userBySubject(conns, "00u-pat-policy")
	if err := e.db.InTenant(context.Background(), seed.LarkspurID, func(tx *store.TenantTx) error {
		return tx.DisableUser(u.ID, "left", testkit.Now)
	}); err != nil {
		t.Fatal(err)
	}
	e.refused(e.signIn("00u-pat-policy", devidp.MethodPasskey, devidp.ProfileOkta), seed.LarkspurID, "user_disabled")
}

func devConnID(t *testing.T, db *store.DB, tn tenancy.ID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.ReadTenant(context.Background(), tn, func(tx *store.TenantTx) error {
		c, err := devConnection(tx)
		if err == nil {
			id = c.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *oidcEnv) invite(tn tenancy.ID, conn uuid.UUID, email string, ttl time.Duration) string {
	e.t.Helper()
	code := "tbi_" + seal.RandomSecret(32)
	now := e.clk.now()
	if err := e.db.InTenant(context.Background(), tn, func(tx *store.TenantTx) error {
		return tx.InsertBootstrapInvitation(&store.BootstrapInvitation{CodeHash: seal.SHA256Hex([]byte(code)),
			IdPConnectionID: conn, Email: email, CreatedBy: "operator", CreatedAt: now, ExpiresAt: now.Add(ttl)})
	}); err != nil {
		e.t.Fatal(err)
	}
	return code
}

// TestOIDCLogin_Bootstrap (§15.3): an invitation makes the user who redeems
// it with a phishing-resistant sign-in a tenant admin (source bootstrap),
// once; a weaker sign-in, another email, a used, expired or foreign code is
// refused.
func TestOIDCLogin_Bootstrap(t *testing.T) {
	e := newOIDCEnv(t)
	conn := e.addConn(func(c *store.IdPConnection) {})
	code := e.invite(seed.LarkspurID, conn.ID, newbie.Email, 24*time.Hour)
	target := "/t/larkspur/bootstrap?code=" + url.QueryEscape(code)

	// a password sign-in does not redeem it (and does not consume it)
	e.refused(e.finish(e.start(target, "00u-newbie", devidp.MethodPassword, devidp.ProfileOkta)), seed.LarkspurID,
		"bootstrap_requires_phr")
	// another person of the IdP cannot redeem it
	e.refused(e.finish(e.start(target, "00u-ivan-admin2", devidp.MethodPasskey, devidp.ProfileOkta)), seed.LarkspurID,
		"bootstrap_email_mismatch")

	rec := e.finish(e.start(target, "00u-newbie", devidp.MethodPasskey, devidp.ProfileOkta))
	if rec.Code != http.StatusFound {
		t.Fatalf("bootstrap: %d %s", rec.Code, rec.Body.String())
	}
	v := e.session(cookieNamed(rec, auth.CookieName))
	active, _ := json.Marshal(at(v, "active_roles"))
	if string(active) != `["tenant_admin"]` {
		t.Errorf("bootstrap user active roles %s", active)
	}
	consumed := false
	for _, ev := range ledger(t, e.db, seed.LarkspurID) {
		if ev.Action == "recovery.invitation.consumed" {
			consumed = true
		}
	}
	if !consumed {
		t.Error("no recovery.invitation.consumed event")
	}
	// single use
	rec = e.get(target)
	if rec.Code != http.StatusFound || e.lastFailure(seed.LarkspurID) != "bootstrap_code_used" {
		t.Errorf("second redemption: %d %s", rec.Code, e.lastFailure(seed.LarkspurID))
	}
	// expired, unknown, and another tenant's code at this tenant's URL
	old := e.invite(seed.LarkspurID, conn.ID, newbie.Email, time.Minute)
	e.clk.add(2 * time.Minute)
	for target, reason := range map[string]string{
		"/t/larkspur/bootstrap?code=" + url.QueryEscape(old): "bootstrap_code_expired",
		"/t/larkspur/bootstrap?code=tbi_nope":                "bootstrap_code_unknown",
		"/t/larkspur/bootstrap?code=" + url.QueryEscape(e.invite(seed.GlobexID, devConnID(t, e.db, seed.GlobexID), "gina@globex.example", time.Hour)): "bootstrap_code_unknown",
	} {
		if rec := e.get(target); rec.Code != http.StatusFound || e.lastFailure(seed.LarkspurID) != reason {
			t.Errorf("%s: %d %s, want %s", target, rec.Code, e.lastFailure(seed.LarkspurID), reason)
		}
	}
}

// TestIsolation_LoginCrossTenant: a login transaction of one tenant cannot be
// completed through another tenant's connection, and discovery lists only
// the named tenant's connections.
func TestIsolation_LoginCrossTenant(t *testing.T) {
	e := newOIDCEnv(t)
	a := e.start("/api/auth/login?tenant=larkspur", "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)
	a.callback.Path = "/api/auth/oidc/" + devConnID(t, e.db, seed.GlobexID).String() + "/callback"
	e.refused(e.finish(a), seed.LarkspurID, "connection_mismatch")

	for q, want := range map[string]int{"tenant=larkspur": 1, "tenant=globex": 1, "tenant=nope": 0, "": 0,
		"tenant=larkspur&email=alice@larkspur.example": 1, "tenant=larkspur&email=x@globex.example": 0} {
		rec := e.get("/api/auth/discover?" + q)
		if rec.Code != 200 {
			t.Fatalf("discover %s: %d", q, rec.Code)
		}
		cs := at(decode(t, rec), "connections").([]any)
		if len(cs) != want {
			t.Errorf("discover %s: %v", q, cs)
		}
		for _, c := range cs {
			id := c.(map[string]any)["id"]
			if strings.Contains(q, "larkspur") && id == devConnID(t, e.db, seed.GlobexID).String() {
				t.Errorf("discover %s lists globex's connection", q)
			}
		}
	}
	// Gina (globex) cannot sign in to larkspur
	e.refused(e.signIn("00u-gina-globex", devidp.MethodPasskey, devidp.ProfileOkta), seed.LarkspurID, "unknown_subject")
}

// TestOIDCLogin_ReplacesPreviousSession: signing in again revokes the
// session the browser still held.
func TestOIDCLogin_ReplacesPreviousSession(t *testing.T) {
	e := newOIDCEnv(t)
	first := cookieNamed(e.signIn("00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta), auth.CookieName)
	a := e.start("/api/auth/login?tenant=larkspur", "00u-ivan-admin2", devidp.MethodPasskey, devidp.ProfileOkta)
	rec := e.get(a.callback.RequestURI(), a.cookie, first)
	if rec.Code != http.StatusFound {
		t.Fatalf("second sign-in: %d", rec.Code)
	}
	if code := e.get("/api/auth/session", first).Code; code != 401 {
		t.Errorf("the previous session still works: %d", code)
	}
}

// query parses a URL's query (url.URL.Query without the method name that
// internal/archtest reserves for SQL).
func query(u *url.URL) url.Values {
	v, _ := url.ParseQuery(u.RawQuery)
	return v
}

// devConnection returns the tenant's active dev_mock connection.
func devConnection(tx *store.TenantTx) (*store.IdPConnection, error) {
	cs, err := tx.IdPConnections()
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		if c.Profile == store.ProfileDevMock && c.Status == "active" {
			return c, nil
		}
	}
	return nil, store.ErrNotFound
}
