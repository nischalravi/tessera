package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// Break-glass over HTTP (design §9.6, §15.4, §16.1): the public sign-in
// routes, what the resulting session may and may not reach, and the 60
// minute expiry, with a clock the test moves.

const (
	bgTestRPID   = "localhost"
	bgTestOrigin = authtest.Origin
)

type bgHTTP struct {
	f   *storetest.Fixture
	now time.Time
	srv *Server
	h   http.Handler

	key    *ecdsa.PrivateKey
	credID []byte
	glass  uuid.UUID // the break-glass user of tenant B
}

func newBGHTTP(t *testing.T) *bgHTTP {
	t.Helper()
	f := storetest.TwoTenants(t)
	e := &bgHTTP{f: f, now: storetest.Now}
	e.srv = New(Config{Store: f.DB, Clock: func() time.Time { return e.now }, Policies: policy.NewLoader(policies.FS),
		Connectors: func(now time.Time) ([]connectors.Connector, error) {
			return []connectors.Connector{connectors.Tiny{Now: now}}, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), AllowedOrigins: []string{bgTestOrigin}, PublicOrigin: bgTestOrigin,
		RPID: bgTestRPID, Env: "test", RateLimits: noRateLimits})
	e.h = e.srv.Handler()
	var err error
	if e.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	e.credID = make([]byte, 32)
	if _, err := rand.Read(e.credID); err != nil {
		t.Fatal(err)
	}
	e.seedKey(t)
	return e
}

// seedKey registers e.key for a break-glass user of tenant B, as an applied
// breakglass.register request and a completed registration would have.
func (e *bgHTTP) seedKey(t *testing.T) {
	t.Helper()
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	cose, err := enc.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: e.key.PublicKey.X.FillBytes(make([]byte, 32)),
		-3: e.key.PublicKey.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	now := e.now
	err = e.f.DB.InTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		req := &store.PlatformUser{DisplayName: "requester", CreatedAt: now}
		glass := &store.PlatformUser{DisplayName: "Break-glass: Safe A", IsBreakGlass: true, CreatedAt: now}
		for _, u := range []*store.PlatformUser{req, glass} {
			if err := tx.InsertPlatformUser(u); err != nil {
				return err
			}
		}
		e.glass = glass.ID
		ch := &store.AdminChange{Type: admin.TypeBGRegister, Payload: json.RawMessage(fmt.Sprintf(`{"user_id":%q,"label":"Safe A","custodian":"Ops"}`, glass.ID)),
			PayloadHash: strings.Repeat("a", 64), Status: store.ChangeCoolingOff, RequestedBy: req.ID, RequestedAt: now,
			ExpiresAt: now.Add(72 * time.Hour), EffectiveAt: &now}
		if err := tx.InsertAdminChange(ch); err != nil {
			return err
		}
		if err := tx.MarkAdminChangeApplied(ch.ID, now); err != nil {
			return err
		}
		cid := ch.ID.String()
		if err := tx.InsertRoleAssignment(&store.RoleAssignment{UserID: glass.ID, Role: store.RoleBreakGlass,
			Source: store.RoleSourceBreakGlass, ChangeRequestID: &cid, CreatedAt: now}); err != nil {
			return err
		}
		return tx.InsertBreakGlassCredential(&store.BreakGlassCredential{UserID: glass.ID, ChangeRequestID: ch.ID,
			CredentialID: e.credID, PublicKey: cose, AAGUID: "2fc0579f-8113-47ea-b116-bb5a8db9202a", AttestationFormat: "packed",
			AttestationTrust: "basic", Transports: []string{"usb"}, Label: "Safe A", Custodian: "Ops", CreatedAt: now})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func b64u(b []byte) string { return protocol.URLEncodedBase64(b).String() }

// assertion is what the hardware key answers to a request: the
// PublicKeyCredential JSON for challenge with the given sign count.
func (e *bgHTTP) assertion(t *testing.T, challenge string, count uint32) string {
	t.Helper()
	cd, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": bgTestOrigin, "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(bgTestRPID))
	ad := append(append([]byte{}, h[:]...), 0x05) // user present, user verified
	ad = binary.BigEndian.AppendUint32(ad, count)
	cdh := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, e.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(map[string]any{"id": b64u(e.credID), "rawId": b64u(e.credID), "type": "public-key",
		"response":               map[string]any{"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad), "signature": b64u(sig)},
		"clientExtensionResults": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func (e *bgHTTP) post(path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return serve(e.h, req)
}

// signIn runs the public ceremony of tenant B and returns the session
// cookie.
func (e *bgHTTP) signIn(t *testing.T, count uint32) *http.Cookie {
	t.Helper()
	opts := e.post("/api/auth/break-glass/options", `{"tenant":"tenant-b"}`)
	if opts.Code != http.StatusOK {
		t.Fatalf("options: %d %s", opts.Code, opts.Body.String())
	}
	var o struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			UserVerification string `json:"userVerification"`
			RPID             string `json:"rpId"`
			Allow            []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(opts.Body.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	if o.PublicKey.UserVerification != "required" || o.PublicKey.RPID != bgTestRPID || len(o.PublicKey.Allow) != 1 ||
		o.PublicKey.Allow[0].ID != b64u(e.credID) {
		t.Fatalf("options %s: want user verification required, rp %s and the tenant's one key", opts.Body.String(), bgTestRPID)
	}
	rec := e.post("/api/auth/break-glass/verify",
		fmt.Sprintf(`{"tenant":"tenant-b","credential":%s}`, e.assertion(t, o.PublicKey.Challenge, count)))
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			return c
		}
	}
	t.Fatalf("verify set no session cookie: %v", rec.Result().Header)
	return nil
}

// as runs a request of the session; the CSRF token comes from /api/auth/session.
func (e *bgHTTP) as(t *testing.T, c *http.Cookie, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.AddCookie(c)
	req.Header.Set("Origin", bgTestOrigin)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		sess := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
		sess.AddCookie(c)
		var v struct {
			CSRF string `json:"csrf_token"`
		}
		if err := json.Unmarshal(serve(e.h, sess).Body.Bytes(), &v); err != nil || v.CSRF == "" {
			t.Fatalf("no CSRF token for the session: %v", err)
		}
		req.Header.Set(auth.CSRFHeader, v.CSRF)
	}
	return serve(e.h, req)
}

func jsonOf(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("not JSON: %v: %s", err, rec.Body.String())
	}
	return v
}

// TestBreakGlassHTTP_SignInAndLimits: the whole path over HTTP. A signed-in
// break-glass session reads admin state and runs the §15.4 actions, and every
// data route is 403; the sign-in is audited and notified; the session ends
// after 60 minutes (and 15 idle ones).
func TestBreakGlassHTTP_SignInAndLimits(t *testing.T) {
	e := newBGHTTP(t)
	cookie := e.signIn(t, 1)
	if !cookie.HttpOnly || cookie.Name != auth.CookieName {
		t.Errorf("cookie %+v", cookie)
	}

	// who the session is
	sess := jsonOf(t, e.as(t, cookie, "GET", "/api/auth/session", ""))
	if roles, _ := sess["active_roles"].([]any); len(roles) != 1 || roles[0] != "break_glass" {
		t.Errorf("active roles %v", sess["active_roles"])
	}
	perms := fmt.Sprint(sess["permissions"])
	if perms != "[auth.self admin.read breakglass.recover]" {
		t.Errorf("a break-glass session holds %s, want exactly auth.self admin.read breakglass.recover", perms)
	}
	if a, _ := sess["authn"].(map[string]any); a["aal"] != float64(3) || a["phishing_resistant"] != true ||
		a["phr_basis"] != "webauthn_attested" || a["acr"] != string(auth.ACRPhrh) {
		t.Errorf("authn %v", sess["authn"])
	}
	// 15 minutes idle, 60 absolute
	s := sess["session"].(map[string]any)
	if s["idle_expires_at"] != rt3339(e.now.Add(15*time.Minute)) || s["absolute_expires_at"] != rt3339(e.now.Add(60*time.Minute)) {
		t.Errorf("session expiry %v", s)
	}

	// admin state is readable
	for _, path := range []string{"/api/admin/users", "/api/admin/idp-connections", "/api/admin/change-requests", "/api/admin/notifications",
		"/api/admin/recovery", "/api/admin/break-glass"} {
		if rec := e.as(t, cookie, "GET", path, ""); rec.Code != http.StatusOK {
			t.Errorf("GET %s: %d %s, want 200", path, rec.Code, rec.Body.String())
		}
	}
	// data routes and everything else an admin does are 403
	for _, tc := range [][3]string{
		{"GET", "/api/summary", ""}, {"GET", "/api/identities", ""}, {"GET", "/api/graph", ""}, {"GET", "/api/groups", ""},
		{"GET", "/api/resources", ""}, {"GET", "/api/connectors", ""}, {"GET", "/api/connections", ""}, {"GET", "/api/audit", ""},
		{"GET", "/api/audit/export", ""}, {"POST", "/api/audit/verify", `{}`}, {"POST", "/api/connectors/sync", `{}`},
		{"POST", "/api/jit/requests", `{}`}, {"POST", "/api/least-privilege/revoke", `{}`}, {"POST", "/api/simulate", `{}`},
		{"POST", "/api/admin/change-requests", `{"type":"role.grant","payload":{}}`},
		{"POST", "/api/admin/users/" + uuid.NewString() + "/disable", `{}`},
		{"POST", "/api/admin/break-glass/registration/options", `{}`},
		{"POST", "/api/admin/break-glass/uses/" + uuid.NewString() + "/attest", `{"reason":"it was me, trust me"}`},
	} {
		if rec := e.as(t, cookie, tc[0], tc[1], tc[2]); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: %d %.200s, want 403", tc[0], tc[1], rec.Code, rec.Body.String())
		}
	}

	// the §15.4 actions
	if rec := e.as(t, cookie, "POST", "/api/admin/break-glass/actions/idp_connection.disable",
		fmt.Sprintf(`{"connection_id":%q}`, uuid.NewString())); rec.Code != http.StatusNotFound {
		t.Errorf("disable an unknown connection: %d %s, want 404", rec.Code, rec.Body.String())
	}
	if rec := e.as(t, cookie, "POST", "/api/admin/break-glass/actions/idp_connection.create", `{}`); rec.Code != http.StatusNotFound {
		t.Errorf("an action that is not §15.4's: %d %s", rec.Code, rec.Body.String())
	}
	rec := e.as(t, cookie, "POST", "/api/admin/break-glass/actions/sessions.revoke_all", `{}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("revoke all: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := jsonOf(t, rec)["revoked_sessions"]; !ok {
		t.Errorf("revoke all: %s", rec.Body.String())
	}
	// its own session survives its revoke-all
	if rec := e.as(t, cookie, "GET", "/api/admin/users", ""); rec.Code != http.StatusOK {
		t.Errorf("after revoking all: %d", rec.Code)
	}

	// the sign-in is audited (tenant and platform chains) and notified as critical
	events := ledger(t, e.f.DB, e.f.B.ID)
	var used, action int
	for _, ev := range events {
		switch ev.Action {
		case "auth.break_glass.used":
			used++
			if ev.ActorType != store.ActorUser || ev.ActorID == nil || *ev.ActorID != e.glass.String() {
				t.Errorf("auth.break_glass.used actor %s %v", ev.ActorType, ev.ActorID)
			}
		case "breakglass.action":
			action++
		}
	}
	if used != 1 || action != 1 {
		t.Errorf("%d auth.break_glass.used and %d breakglass.action events", used, action)
	}
	if p := ledger(t, e.f.DB, tenancy.Platform); !slices.ContainsFunc(p, func(ev *store.AuditEvent) bool { return ev.Action == "auth.break_glass.used" }) {
		t.Error("auth.break_glass.used is not on the platform chain")
	}
	notes := jsonOf(t, e.as(t, cookie, "GET", "/api/admin/notifications", ""))["notifications"].([]any)
	critical := 0
	for _, n := range notes {
		if m := n.(map[string]any); m["kind"] == admin.KindBreakGlassUsed && m["severity"] == "critical" {
			critical++
		}
	}
	if critical == 0 {
		t.Errorf("no critical break-glass notification among %d", len(notes))
	}
	// the overview shows the use, waiting for its explanation
	ov := jsonOf(t, e.as(t, cookie, "GET", "/api/admin/break-glass", ""))
	if ov["unanswered_uses"] != float64(1) || ov["available"] != true || len(ov["keys"].([]any)) != 1 {
		t.Errorf("overview %v", ov)
	}

	// 15 idle minutes end it ...
	e.now = e.now.Add(15*time.Minute + time.Second)
	if rec := e.as(t, cookie, "GET", "/api/admin/users", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("after 15 idle minutes: %d", rec.Code)
	}
	// ... and 60 minutes end a session that kept being used
	e.now = storetest.Now
	cookie = e.signIn(t, 2)
	for _, min := range []int{10, 20, 30, 40, 50, 59} {
		e.now = storetest.Now.Add(time.Duration(min) * time.Minute)
		if rec := e.as(t, cookie, "GET", "/api/admin/users", ""); rec.Code != http.StatusOK {
			t.Fatalf("%d minutes in: %d %s", min, rec.Code, rec.Body.String())
		}
	}
	e.now = storetest.Now.Add(60 * time.Minute)
	if rec := e.as(t, cookie, "GET", "/api/admin/users", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("at 60 minutes: %d, want 401", rec.Code)
	}
}

// TestBreakGlassHTTP_Refusals: the public routes refuse what they should and
// say as little as they can.
func TestBreakGlassHTTP_Refusals(t *testing.T) {
	e := newBGHTTP(t)
	body := func(rec *httptest.ResponseRecorder) string { return rec.Body.String() }
	// an unknown tenant and a tenant with no key look the same
	unknown := e.post("/api/auth/break-glass/options", `{"tenant":"no-such-tenant"}`)
	noKey := e.post("/api/auth/break-glass/options", `{"tenant":"tenant-a"}`)
	if unknown.Code != http.StatusNotFound || noKey.Code != http.StatusNotFound || body(unknown) != body(noKey) ||
		!strings.Contains(body(unknown), "break_glass_unavailable") {
		t.Errorf("unknown tenant: %d %s; tenant with no key: %d %s", unknown.Code, body(unknown), noKey.Code, body(noKey))
	}
	if rec := e.post("/api/auth/break-glass/options", `{"tenant":"../etc"}`); rec.Code != http.StatusNotFound {
		t.Errorf("a malformed slug: %d", rec.Code)
	}
	// JSON only, strict bodies
	form := httptest.NewRequest(http.MethodPost, "/api/auth/break-glass/options", strings.NewReader("tenant=tenant-b"))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec := serve(e.h, form); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("form post: %d, want 415", rec.Code)
	}
	for _, b := range []string{``, `{}`, `{"tenant":"tenant-b","x":1}`, `[]`} {
		if rec := e.post("/api/auth/break-glass/options", b); rec.Code < 400 || rec.Code >= 500 {
			t.Errorf("options %q: %d", b, rec.Code)
		}
	}
	// a verify for an unknown tenant, without credential, or with a made-up one is 401/422, never a session
	for _, b := range []string{`{"tenant":"no-such-tenant","credential":{}}`, `{"tenant":"tenant-b"}`, `{"tenant":"tenant-b","credential":{"id":"x"}}`,
		`{"tenant":"tenant-b","credential":"x"}`} {
		rec := e.post("/api/auth/break-glass/verify", b)
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
			t.Errorf("verify %s: %d %s", b, rec.Code, rec.Body.String())
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("verify %s set a cookie", b)
		}
	}
	// a replayed response is refused
	opts := e.post("/api/auth/break-glass/options", `{"tenant":"tenant-b"}`)
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(opts.Body.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	payload := fmt.Sprintf(`{"tenant":"tenant-b","credential":%s}`, e.assertion(t, o.PublicKey.Challenge, 5))
	if rec := e.post("/api/auth/break-glass/verify", payload); rec.Code != http.StatusOK {
		t.Fatalf("first verify: %d %s", rec.Code, rec.Body.String())
	}
	rec := e.post("/api/auth/break-glass/verify", payload)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "break_glass_failed") || len(rec.Result().Cookies()) != 0 {
		t.Errorf("replay: %d %s", rec.Code, rec.Body.String())
	}
	// a sign count that does not rise is refused
	opts = e.post("/api/auth/break-glass/options", `{"tenant":"tenant-b"}`)
	if err := json.Unmarshal(opts.Body.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	rec = e.post("/api/auth/break-glass/verify", fmt.Sprintf(`{"tenant":"tenant-b","credential":%s}`, e.assertion(t, o.PublicKey.Challenge, 5)))
	if rec.Code != http.StatusUnauthorized || len(rec.Result().Cookies()) != 0 {
		t.Errorf("a repeated sign count: %d %s", rec.Code, rec.Body.String())
	}
	// the failures are audited in the tenant's chain
	var reasons []string
	for _, ev := range ledger(t, e.f.DB, e.f.B.ID) {
		if ev.Action == "auth.break_glass.rejected" {
			var d struct {
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal(ev.Detail, &d); err != nil || ev.Outcome != store.OutcomeFailure || ev.ActorType != store.ActorAnonymous {
				t.Errorf("rejection event %s %s: %v", ev.Outcome, ev.ActorType, err)
			}
			reasons = append(reasons, d.Reason)
		}
	}
	slices.Sort(reasons)
	if want := []string{"challenge_expired_or_used", "malformed_response", "malformed_response", "sign_count_regression"}; !slices.Equal(reasons, want) {
		t.Errorf("rejection reasons %v, want %v", reasons, want)
	}
}

// TestBreakGlassHTTP_Unavailable: without a relying party break-glass is 503
// and the admin overview says so.
func TestBreakGlassHTTP_Unavailable(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := New(Config{Store: f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), AllowedOrigins: []string{bgTestOrigin}, Env: "test", RateLimits: noRateLimits})
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/break-glass/options", strings.NewReader(`{"tenant":"tenant-b"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := serve(h, req)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "break_glass_unavailable") {
		t.Errorf("options without a relying party: %d %s", rec.Code, rec.Body.String())
	}
}

// TestBreakGlassSession_OnlyTheDesignedRoutes: for every route, a break-glass
// session is allowed exactly the routes whose permission is auth.self,
// admin.read or breakglass.recover; every other route is 403.
func TestBreakGlassSession_OnlyTheDesignedRoutes(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	allowed := []auth.Permission{auth.PermAuthenticated, auth.PermAdminRead, auth.PermBreakGlassRecover}
	glass := authtest.User{Email: "glass@b.example", Roles: []auth.Role{auth.RoleBreakGlass}, IsBreakGlass: true}
	n := 0
	for _, rt := range srv.Routes() {
		if rt.Public {
			continue
		}
		n++
		l := signIn(t, f.DB, f.B.ID, glass, authtest.BreakGlass, storetest.Now)
		req := routeRequest(rt, f.B)
		l.Apply(req)
		rec := serve(h, req)
		if slices.Contains(allowed, rt.Perm) {
			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Errorf("%s %s (%s): %d %.200s, want the handler to run", rt.Method, rt.Pattern, rt.Perm, rec.Code, rec.Body.String())
			}
		} else if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s (%s): %d %.200s, want 403", rt.Method, rt.Pattern, rt.Perm, rec.Code, rec.Body.String())
		}
	}
	if n < 100 {
		t.Errorf("only %d routes were checked", n)
	}
}

// TestBreakGlassRoutes_OtherRolesCannotAct: the actions route is the
// break_glass role's alone, and the registration and attestation routes are
// the tenant admin's alone (a viewer, an operator, an auditor and a policy
// admin get 403).
func TestBreakGlassRoutes_OtherRolesCannotAct(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor, auth.RolePolicyAdmin, auth.RoleTenantAdmin} {
		l := signIn(t, f.DB, f.B.ID, authtest.User{Email: string(role) + "@b.example", Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
		rec := serve(h, authed(l, "POST", "/api/admin/break-glass/actions/sessions.revoke_all", `{}`))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: actions: %d, want 403", role, rec.Code)
		}
		for _, path := range []string{"/api/admin/break-glass/registration/options", "/api/admin/break-glass/registration/verify"} {
			rec := serve(h, authed(l, "POST", path, `{}`))
			if (role == auth.RoleTenantAdmin) == (rec.Code == http.StatusForbidden) {
				t.Errorf("%s: %s: %d %.100s", role, path, rec.Code, rec.Body.String())
			}
		}
		if rec := serve(h, authed(l, "GET", "/api/admin/break-glass", "")); (role == auth.RoleAuditor || role == auth.RoleTenantAdmin) !=
			(rec.Code == http.StatusOK) {
			t.Errorf("%s: overview: %d", role, rec.Code)
		}
	}
}

// TestBreakGlassRoutes_Isolation: tenant A's admin sees none of tenant B's
// keys or uses, and cannot attest B's use.
func TestBreakGlassRoutes_Isolation(t *testing.T) {
	e := newBGHTTP(t)
	cookie := e.signIn(t, 1)
	_ = cookie
	var use store.BreakGlassUse
	if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		us, err := tx.RecentBreakGlassUses(e.now.Add(-time.Hour))
		if err == nil && len(us) == 1 {
			use = *us[0]
		}
		return err
	}); err != nil || use.ID == uuid.Nil {
		t.Fatalf("no use recorded: %v", err)
	}
	a := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "admin@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, e.now)
	rec := serve(e.h, authed(a, "GET", "/api/admin/break-glass", ""))
	ov := jsonOf(t, rec)
	if rec.Code != http.StatusOK || len(ov["keys"].([]any)) != 0 || len(ov["uses"].([]any)) != 0 || strings.Contains(rec.Body.String(), e.glass.String()) {
		t.Errorf("tenant A sees tenant B's break-glass rows: %d %s", rec.Code, rec.Body.String())
	}
	rec = serve(e.h, authed(a, "POST", "/api/admin/break-glass/uses/"+use.ID.String()+"/attest", `{"reason":"not my tenant at all"}`))
	if rec.Code != http.StatusNotFound {
		t.Errorf("attesting B's use as A: %d %s, want 404", rec.Code, rec.Body.String())
	}
	// B's admin can, once
	b := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "admin@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, e.now)
	body := `{"reason":"Okta outage, ticket INC-4821"}`
	if rec := serve(e.h, authed(b, "POST", "/api/admin/break-glass/uses/"+use.ID.String()+"/attest", body)); rec.Code != http.StatusOK {
		t.Errorf("attest: %d %s", rec.Code, rec.Body.String())
	}
	if rec := serve(e.h, authed(b, "POST", "/api/admin/break-glass/uses/"+use.ID.String()+"/attest", body)); rec.Code != http.StatusConflict {
		t.Errorf("attest again: %d %s, want 409", rec.Code, rec.Body.String())
	}
	if rec := serve(e.h, authed(b, "POST", "/api/admin/break-glass/uses/"+use.ID.String()+"/attest", `{"reason":"x"}`)); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("short reason: %d", rec.Code)
	}
	ov = jsonOf(t, serve(e.h, authed(b, "GET", "/api/admin/break-glass", "")))
	if ov["unanswered_uses"] != float64(0) || len(ov["uses"].([]any)) != 1 {
		t.Errorf("overview after the answer: %v", ov)
	}
}
