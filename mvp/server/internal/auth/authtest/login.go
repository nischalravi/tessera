// Package authtest is the test-only sign-in helper of design §19 PR5:
// LoginAs creates a platform user, its roles, an authentication context and
// a session row directly in the store, so tests reach authenticated routes
// without an IdP.
//
// It is imported only by _test.go files (internal/archtest enforces this)
// and refuses to run unless TESSERA_ENV=test, so it can never mint a session
// in a running server.
package authtest

import (
	"context"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Origin is the browser origin test requests claim (an allowed origin of
// test servers: put it in their AllowedOrigins).
const Origin = "http://localhost:5173"

// User describes the platform user to sign in. An existing user of the
// tenant with the same Email is reused (roles are added if missing).
type User struct {
	ID      uuid.UUID // zero: a fresh one (fixed ids keep recorded fixtures stable)
	Email   string
	Display string
	Roles   []auth.Role
	// IdentityID links the user to an identity of the tenant (optional).
	IdentityID *int64
	// IsBreakGlass makes the user a break-glass user (when it is created).
	IsBreakGlass bool
}

// Ctx describes the authentication context of the session.
type Ctx struct {
	ID       uuid.UUID // zero: a fresh one
	AAL      int
	Phr      bool
	Phrh     bool
	AuthTime time.Time // zero: the session's creation time
	// WebAuthn is a break-glass sign-in: a WebAuthn-attested context and a
	// session of kind break_glass.
	WebAuthn bool
	// Device is the JSON of the device claims the IdP asserted (for example
	// `{"managed":true,"compliant":false}`); empty: none.
	Device string
}

// Common contexts.
var (
	// Phr is a phishing-resistant sign-in (synced passkey): admin roles active.
	Phr = Ctx{AAL: 2, Phr: true}
	// AAL2 is MFA without phishing resistance: admin roles inactive.
	AAL2 = Ctx{AAL: 2}
	// AAL1 is a password-only sign-in: no role is active.
	AAL1 = Ctx{AAL: 1}
	// BreakGlass is a break-glass sign-in with a hardware key: the break_glass
	// role is active, and the session has kind break_glass.
	BreakGlass = Ctx{AAL: 3, Phr: true, Phrh: true, WebAuthn: true}
)

// Login is a signed-in test session.
type Login struct {
	Cookie    *http.Cookie
	CSRFToken string
	UserID    uuid.UUID
	SessionID uuid.UUID
	Tenant    tenancy.ID
}

// Apply makes req a browser request of this session: the session cookie, an
// allowed Origin and the CSRF token.
func (l Login) Apply(req *http.Request) {
	req.AddCookie(l.Cookie)
	if req.Header.Get("Origin") == "" {
		req.Header.Set("Origin", Origin)
	}
	req.Header.Set(auth.CSRFHeader, l.CSRFToken)
}

// Handler wraps h so every request without a Cookie header is sent as this
// session (Apply). Requests that set a Cookie header themselves, or the
// header X-Test-Anonymous, pass unchanged.
func (l Login) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") == "" && r.Header.Get("X-Test-Anonymous") == "" {
			r = r.Clone(r.Context())
			l.Apply(r)
		}
		r.Header.Del("X-Test-Anonymous")
		h.ServeHTTP(w, r)
	})
}

// Allowed reports whether the helper may run: only with TESSERA_ENV=test.
func Allowed() bool { return os.Getenv("TESSERA_ENV") == "test" }

// LoginAs signs u in to tenant with context c at now and returns the session.
// It fails the test unless TESSERA_ENV=test.
func LoginAs(tb testing.TB, db *store.DB, tenant tenancy.ID, u User, c Ctx, now time.Time) Login {
	tb.Helper()
	l, err := New(db, tenant, u, c, now)
	if err != nil {
		tb.Fatal(err)
	}
	return l
}

// ErrNotTest is returned outside TESSERA_ENV=test.
var ErrNotTest = errNotTest{}

type errNotTest struct{}

func (errNotTest) Error() string {
	return "authtest: refusing to create a session unless TESSERA_ENV=test"
}

// New is LoginAs returning the error: ErrNotTest unless TESSERA_ENV=test.
func New(db *store.DB, tenant tenancy.ID, u User, c Ctx, now time.Time) (Login, error) {
	if !Allowed() {
		return Login{}, ErrNotTest
	}
	now = now.UTC()
	var l Login
	err := db.InTenant(context.Background(), tenant, func(tx *store.TenantTx) error {
		users, err := tx.PlatformUsers()
		if err != nil {
			return err
		}
		var user *store.PlatformUser
		for _, x := range users {
			if x.Email != nil && *x.Email == u.Email {
				user = x
			}
		}
		if user == nil {
			email := u.Email
			display := u.Display
			if display == "" {
				display = u.Email
			}
			user = &store.PlatformUser{ID: u.ID, Email: &email, DisplayName: display, IdentityID: u.IdentityID, CreatedAt: now,
				IsBreakGlass: u.IsBreakGlass}
			if err := tx.InsertPlatformUser(user); err != nil {
				return err
			}
		}
		have, err := tx.RoleAssignments(user.ID)
		if err != nil {
			return err
		}
		for _, r := range u.Roles {
			if slices.ContainsFunc(have, func(a *store.RoleAssignment) bool { return a.Role == string(r) }) {
				continue
			}
			src := store.RoleSourceManual
			if r.IsAdmin() {
				src = store.RoleSourceBootstrap
			}
			if err := tx.InsertRoleAssignment(&store.RoleAssignment{UserID: user.ID, Role: string(r), Source: src,
				CreatedAt: now}); err != nil {
				return err
			}
		}
		rec := Record(user.ID, c, now)
		if err := tx.InsertAuthnContext(rec); err != nil {
			return err
		}
		kind := store.SessionBrowser
		if c.WebAuthn {
			kind = store.SessionBreakGlass
		}
		iss, err := auth.CreateSession(tx, auth.SessionInput{User: user, Authn: rec, Kind: kind, Now: now})
		if err != nil {
			return err
		}
		l = Login{Cookie: auth.Cookies{}.Session(iss.Secret), CSRFToken: iss.CSRFToken, UserID: user.ID,
			SessionID: iss.Session.ID, Tenant: tenant}
		return nil
	})
	return l, err
}

// Record builds the authentication context record of c for user at now.
func Record(user uuid.UUID, c Ctx, now time.Time) *store.AuthnContextRecord {
	at := c.AuthTime
	if at.IsZero() {
		at = now
	}
	acr, basis := auth.ACRAAL1, "none"
	switch {
	case c.Phrh:
		acr, basis = auth.ACRPhrh, "acr"
	case c.Phr:
		acr, basis = auth.ACRPhr, "acr"
	case c.AAL >= 2:
		acr = auth.ACRAAL2
	}
	aal := c.AAL
	if c.Phrh {
		aal = 3
	}
	var device *string
	if c.Device != "" {
		device = &c.Device
	}
	protocol, purpose := "oidc", "login"
	if c.WebAuthn {
		protocol, purpose, basis = "webauthn", "break_glass", "webauthn_attested"
	}
	return &store.AuthnContextRecord{ID: c.ID, UserID: user, Device: device, Protocol: protocol, Purpose: purpose, AAL: aal,
		PhishingResistant: c.Phr || c.Phrh, PhrBasis: basis, TesseraACR: string(acr), AuthTime: at.UTC(),
		MappingProfile: "authtest", MappingVersion: 1, ClaimsSHA256: "authtest", CreatedAt: now}
}
