package auth_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TestSession_HashOnlyStorage: the database holds the SHA-256 of the cookie
// secret and never the secret; the CSRF secret is separate.
func TestSession_HashOnlyStorage(t *testing.T) {
	e := newEnv(t)
	l := authtest.LoginAs(t, e.db, tenantA, admin, authtest.Phr, t0)
	s := e.session(t, tenantA, l.SessionID)
	secret := l.Cookie.Value
	if len(secret) != 43 {
		t.Errorf("secret length %d, want 43 (32 bytes base64url)", len(secret))
	}
	if s.SecretHash == nil || *s.SecretHash != auth.HashSecret(secret) || len(*s.SecretHash) != 64 {
		t.Fatalf("stored hash %v, want sha256(secret)", s.SecretHash)
	}
	for _, v := range []*string{s.SecretHash, s.CSRFSecret, s.IPFirst, s.UserAgentFirst, s.ClientID} {
		if v != nil && strings.Contains(*v, secret) {
			t.Error("the cookie secret is stored")
		}
	}
	if s.CSRFSecret == nil || *s.CSRFSecret == secret || l.CSRFToken == "" || l.CSRFToken == secret {
		t.Error("the CSRF secret must be its own secret")
	}
	// the hash is what the lookup finds; the secret itself finds nothing
	err := e.db.ReadSystem(context.Background(), "test", func(st *store.SystemTx) error {
		if _, _, err := st.LookupSessionBySecretHash(secret); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("lookup by the raw secret: %v", err)
		}
		_, sid, err := st.LookupSessionBySecretHash(auth.HashSecret(secret))
		if err != nil || sid != l.SessionID {
			t.Errorf("lookup by hash: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestSession_CookieFlags checks the serialized Set-Cookie header (§11).
func TestSession_CookieFlags(t *testing.T) {
	got := auth.Cookies{}.Session("s3cret").String()
	for _, want := range []string{"__Host-tessera_sid=s3cret", "Path=/", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(got, want) {
			t.Errorf("cookie %q lacks %q", got, want)
		}
	}
	for _, bad := range []string{"Domain=", "Max-Age=", "Expires="} {
		if strings.Contains(got, bad) {
			t.Errorf("cookie %q has %q", got, bad)
		}
	}
	clear := auth.Cookies{}.Clear().String()
	if !strings.Contains(clear, "__Host-tessera_sid=;") || !strings.Contains(clear, "Max-Age=0") || !strings.Contains(clear, "Secure") {
		t.Errorf("clearing cookie %q", clear)
	}
	dev := auth.Cookies{Insecure: true}.Session("x").String()
	if !strings.HasPrefix(dev, "tessera_sid=x") || strings.Contains(dev, "Secure") || !strings.Contains(dev, "HttpOnly") {
		t.Errorf("dev cookie %q", dev)
	}
}

// TestSession_Lifetimes: admin sessions get 15 min idle / 12 h absolute,
// others 60 min / 24 h (§10.2); an admin whose role is inactive (no phr)
// gets the user lifetimes.
func TestSession_Lifetimes(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		name           string
		user           authtest.User
		ctx            authtest.Ctx
		idle, absolute time.Duration
	}{
		{"active admin", admin, authtest.Phr, auth.AdminIdle, auth.AdminAbsolute},
		{"inactive admin", authtest.User{Email: "ivan@a.example", Roles: admin.Roles}, authtest.AAL2, auth.UserIdle, auth.UserAbsolute},
		{"viewer", viewer, authtest.Phr, auth.UserIdle, auth.UserAbsolute},
	} {
		l := authtest.LoginAs(t, e.db, tenantA, tc.user, tc.ctx, t0)
		s := e.session(t, tenantA, l.SessionID)
		if got := s.IdleExpiresAt.Sub(s.CreatedAt); got != tc.idle {
			t.Errorf("%s: idle %s, want %s", tc.name, got, tc.idle)
		}
		if got := s.AbsoluteExpiresAt.Sub(s.CreatedAt); got != tc.absolute {
			t.Errorf("%s: absolute %s, want %s", tc.name, got, tc.absolute)
		}
	}
}

// TestSession_IdleExpiry: a session unused for its idle timeout is refused
// and marked expired; activity within it extends it (throttled to one write
// a minute).
func TestSession_IdleExpiry(t *testing.T) {
	e := newEnv(t)
	l := authtest.LoginAs(t, e.db, tenantA, viewer, authtest.Phr, t0)
	// 30 s later: valid, not touched (throttled)
	e.clock.now = t0.Add(30 * time.Second)
	if p, why := e.authenticate(t, l.Cookie); p == nil {
		t.Fatalf("refused: %s", why)
	}
	if s := e.session(t, tenantA, l.SessionID); !s.LastActivityAt.Equal(t0) {
		t.Errorf("touched within the throttle interval: %s", s.LastActivityAt)
	}
	// 50 min later: valid, touched; idle expiry moves to now + 60 min
	e.clock.now = t0.Add(50 * time.Minute)
	if p, why := e.authenticate(t, l.Cookie); p == nil {
		t.Fatalf("refused: %s", why)
	}
	s := e.session(t, tenantA, l.SessionID)
	if !s.LastActivityAt.Equal(e.clock.now) || !s.IdleExpiresAt.Equal(e.clock.now.Add(auth.UserIdle)) {
		t.Errorf("touch: last %s idle %s", s.LastActivityAt, s.IdleExpiresAt)
	}
	// exactly at the idle expiry: refused and expired
	e.clock.now = s.IdleExpiresAt
	if p, why := e.authenticate(t, l.Cookie); p != nil || why != auth.FailExpired {
		t.Fatalf("at idle expiry: %v %s", p, why)
	}
	if s := e.session(t, tenantA, l.SessionID); s.Status != store.SessionExpired {
		t.Errorf("status %s, want expired", s.Status)
	}
	// and it stays refused, even back in time
	e.clock.now = t0.Add(51 * time.Minute)
	if p, _ := e.authenticate(t, l.Cookie); p != nil {
		t.Error("an expired session came back")
	}
}

// TestSession_AbsoluteExpiry: activity cannot extend a session past its
// absolute lifetime, and idle expiry never passes it.
func TestSession_AbsoluteExpiry(t *testing.T) {
	e := newEnv(t)
	l := authtest.LoginAs(t, e.db, tenantA, admin, authtest.Phr, t0)
	for now := t0.Add(10 * time.Minute); now.Before(t0.Add(auth.AdminAbsolute)); now = now.Add(10 * time.Minute) {
		e.clock.now = now
		if p, why := e.authenticate(t, l.Cookie); p == nil {
			t.Fatalf("refused at %s: %s", now.Sub(t0), why)
		}
		if s := e.session(t, tenantA, l.SessionID); s.IdleExpiresAt.After(s.AbsoluteExpiresAt) {
			t.Fatalf("idle expiry %s passes the absolute %s", s.IdleExpiresAt, s.AbsoluteExpiresAt)
		}
	}
	e.clock.now = t0.Add(auth.AdminAbsolute)
	if p, why := e.authenticate(t, l.Cookie); p != nil || why != auth.FailExpired {
		t.Fatalf("at absolute expiry: %v %s", p, why)
	}
}

// TestSession_Rotation: rotation issues a new secret and CSRF token in the
// same row; the old cookie stops working at once.
func TestSession_Rotation(t *testing.T) {
	e := newEnv(t)
	l := authtest.LoginAs(t, e.db, tenantA, admin, authtest.Phr, t0)
	before := e.session(t, tenantA, l.SessionID)
	var iss auth.Issued
	err := e.db.InTenant(context.Background(), tenantA, func(tx *store.TenantTx) error {
		var err error
		iss, err = auth.RotateSession(tx, l.SessionID, before.CurrentAuthnContextID, auth.ActivationSettings{}, t0.Add(time.Minute))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if iss.Session.ID != l.SessionID || iss.Secret == l.Cookie.Value || iss.CSRFToken == l.CSRFToken {
		t.Errorf("rotation kept the secret or changed the sid: %+v", iss.Session)
	}
	e.clock.now = t0.Add(2 * time.Minute)
	if p, why := e.authenticate(t, l.Cookie); p != nil || why != auth.FailInvalidSession {
		t.Errorf("old cookie after rotation: %v %s", p, why)
	}
	p, why := e.authenticate(t, auth.Cookies{}.Session(iss.Secret))
	if p == nil || *p.SessionID != l.SessionID || p.CSRFToken() != iss.CSRFToken {
		t.Fatalf("new cookie: %v %s", p, why)
	}
	if after := e.session(t, tenantA, l.SessionID); after.CreatedAt != before.CreatedAt ||
		!after.AbsoluteExpiresAt.Equal(before.AbsoluteExpiresAt) {
		t.Error("rotation must not extend the absolute lifetime")
	}
}

// TestSession_Revocation: a revoked session is refused; revoking a user's
// sessions revokes all of them; a disabled user is refused.
func TestSession_Revocation(t *testing.T) {
	e := newEnv(t)
	l1 := authtest.LoginAs(t, e.db, tenantA, admin, authtest.Phr, t0)
	l2 := authtest.LoginAs(t, e.db, tenantA, admin, authtest.Phr, t0)
	l3 := authtest.LoginAs(t, e.db, tenantA, admin, authtest.Phr, t0)
	other := authtest.LoginAs(t, e.db, tenantA, viewer, authtest.Phr, t0)
	if err := e.db.InTenant(context.Background(), tenantA, func(tx *store.TenantTx) error {
		return auth.RevokeSession(tx, l1.SessionID, auth.RevokedLogout, t0)
	}); err != nil {
		t.Fatal(err)
	}
	if p, why := e.authenticate(t, l1.Cookie); p != nil || why != auth.FailRevoked {
		t.Errorf("revoked session: %v %s", p, why)
	}
	if s := e.session(t, tenantA, l1.SessionID); s.RevokedReason == nil || *s.RevokedReason != auth.RevokedLogout || s.RevokedAt == nil {
		t.Errorf("revocation not recorded: %+v", s)
	}
	var n int64
	if err := e.db.InTenant(context.Background(), tenantA, func(tx *store.TenantTx) error {
		var err error
		n, err = auth.RevokeUserSessions(tx, l2.UserID, auth.RevokedRoleChange, t0)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("revoked %d sessions, want the user's 2 active ones", n)
	}
	for _, l := range []authtest.Login{l2, l3} {
		if p, _ := e.authenticate(t, l.Cookie); p != nil {
			t.Error("a revoked user session still works")
		}
	}
	if p, _ := e.authenticate(t, other.Cookie); p == nil {
		t.Error("another user's session was revoked")
	}
	// a disabled user is refused even with an active session
	if err := e.db.InTenant(context.Background(), tenantA, func(tx *store.TenantTx) error {
		return tx.DisableUser(other.UserID, "left", t0)
	}); err != nil {
		t.Fatal(err)
	}
	if p, why := e.authenticate(t, other.Cookie); p != nil || why != auth.FailUserDisabled {
		t.Errorf("disabled user: %v %s", p, why)
	}
}

// TestSession_BadCookies: no cookie, an unknown secret, an oversized value
// and the wrong cookie name are all unauthenticated, without errors.
func TestSession_BadCookies(t *testing.T) {
	e := newEnv(t)
	l := authtest.LoginAs(t, e.db, tenantA, admin, authtest.Phr, t0)
	for name, c := range map[string]*http.Cookie{
		"none":      nil,
		"unknown":   auth.Cookies{}.Session(auth.NewSecret()),
		"empty":     {Name: auth.CookieName, Value: ""},
		"oversized": {Name: auth.CookieName, Value: strings.Repeat("a", 4096)},
		"hash":      {Name: auth.CookieName, Value: auth.HashSecret(l.Cookie.Value)},
		"dev name":  {Name: auth.InsecureCookieName, Value: l.Cookie.Value},
	} {
		if p, why := e.authenticate(t, c); p != nil || why == "" {
			t.Errorf("%s: %v %q", name, p, why)
		}
	}
	if p, _ := e.authenticate(t, l.Cookie); p == nil {
		t.Error("the valid cookie was refused")
	}
}

// TestSession_CreateRefuses: no session for a disabled user or for another
// user's authentication context.
func TestSession_CreateRefuses(t *testing.T) {
	e := newEnv(t)
	a := authtest.LoginAs(t, e.db, tenantA, admin, authtest.Phr, t0)
	b := authtest.LoginAs(t, e.db, tenantA, viewer, authtest.Phr, t0)
	err := e.db.InTenant(context.Background(), tenantA, func(tx *store.TenantTx) error {
		ua, err := tx.PlatformUser(a.UserID)
		if err != nil {
			return err
		}
		sb, err := tx.Session(b.SessionID)
		if err != nil {
			return err
		}
		ctxB, err := tx.AuthnContext(sb.CurrentAuthnContextID)
		if err != nil {
			return err
		}
		if _, err := auth.CreateSession(tx, auth.SessionInput{User: ua, Authn: ctxB, Now: t0}); err == nil {
			t.Error("a session was created with another user's authentication")
		}
		ua.Status = "disabled"
		rec := authtest.Record(ua.ID, authtest.Phr, t0)
		if _, err := auth.CreateSession(tx, auth.SessionInput{User: ua, Authn: rec, Now: t0}); err == nil {
			t.Error("a session was created for a disabled user")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestSession_CookieScopedToItsTenant (TestIsolation_SessionCookieScoped):
// a session only ever yields its own tenant; nothing in the request can
// switch it.
func TestIsolation_SessionCookieScoped(t *testing.T) {
	e := newEnv(t)
	la := authtest.LoginAs(t, e.db, tenantA, admin, authtest.Phr, t0)
	lb := authtest.LoginAs(t, e.db, tenantB, admin, authtest.Phr, t0)
	for _, tc := range []struct {
		l    authtest.Login
		want any
	}{{la, tenantA}, {lb, tenantB}} {
		r := request(tc.l.Cookie)
		r.Header.Set("X-Tessera-Tenant", "tenant-b")
		r.URL.RawQuery = "tenant=tenant-a&tenant_id=" + tenantB.String()
		p, why, err := e.a.Authenticate(r)
		if err != nil || p == nil || p.TenantID != tc.want {
			t.Errorf("principal %v %s %v, want tenant %v", p, why, err, tc.want)
		}
	}
	// B's session row is not reachable from A
	err := e.db.ReadTenant(context.Background(), tenantA, func(tx *store.TenantTx) error {
		if _, err := tx.Session(lb.SessionID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B's session from A: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestAuthtestRefusesOutsideTest: the test-only helper mints nothing unless
// TESSERA_ENV=test.
func TestAuthtestRefusesOutsideTest(t *testing.T) {
	e := newEnv(t)
	for _, env := range []string{"dev", "prod", ""} {
		t.Setenv("TESSERA_ENV", env)
		if _, err := authtest.New(e.db, tenantA, admin, authtest.Phr, t0); !errors.Is(err, authtest.ErrNotTest) {
			t.Errorf("TESSERA_ENV=%q: %v, want ErrNotTest", env, err)
		}
	}
}
