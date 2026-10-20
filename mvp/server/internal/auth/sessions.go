package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Browser sessions (design §11). The cookie carries 32 random bytes; the
// database keeps only their SHA-256. A session has an idle and an absolute
// expiry (both enforced on every request), is rotated (new secret, same sid)
// at login, step-up and role change, and can be revoked server-side.

// Cookie names. The __Host- prefix makes the browser refuse the cookie
// unless it is Secure, has Path=/ and no Domain. InsecureCookieName is the
// dev-only Safari fallback (TESSERA_COOKIE_SECURE=false, §11).
const (
	CookieName         = "__Host-tessera_sid"
	InsecureCookieName = "tessera_sid"
)

// Session lifetimes (§10.2). Users with an active admin role get the
// AAL3-style privileged timeouts.
const (
	AdminIdle          = 15 * time.Minute
	AdminAbsolute      = 12 * time.Hour
	UserIdle           = 60 * time.Minute
	UserAbsolute       = 24 * time.Hour
	BreakGlassIdle     = 15 * time.Minute
	BreakGlassAbsolute = 60 * time.Minute
	// TouchInterval throttles last_activity_at writes to once a minute per session.
	TouchInterval = 60 * time.Second
)

// Revocation reasons (store.Session.RevokedReason).
const (
	RevokedLogout       = "logout"
	RevokedAdmin        = "admin"
	RevokedRoleChange   = "role_change"
	RevokedUserDisabled = "user_disabled"
	RevokedIdPDisabled  = "idp_disabled"
	RevokedRTReuse      = "rt_reuse"
	RevokedReplaced     = "replaced" // the browser signed in again
	// RevokedBreakGlass: a break-glass session revoked every other session (§15.4).
	RevokedBreakGlass = "break_glass"
	// RevokedBreakGlassKey: the break-glass key that signed the session in was revoked.
	RevokedBreakGlassKey = "break_glass_key_revoked"
	// RevokedIdentityDisabled: the governed identity the user is linked to
	// was disabled (containment.Disable, #316).
	RevokedIdentityDisabled = "identity_disabled"
	// RevokedIdentityTerminated: the linked identity was terminated (a
	// leaver, #331). store.TerminateIdentity writes it.
	RevokedIdentityTerminated = store.RevokedIdentityTerminated
)

// IdentityInactive reports whether u is linked to a governed identity that is
// not active: disabled (containment.Disable, #316), terminated (a leaver),
// merged into another identity, or any other status. Such a user may not
// sign in or use a session; every sign-in path and the session middleware
// check it. It fails closed (#331): only status "active" passes, and a link
// to an identity that cannot be found blocks too.
func IdentityInactive(tx *store.TenantTx, u *store.PlatformUser) (bool, error) {
	if u == nil || u.IdentityID == nil {
		return false, nil
	}
	ident, err := tx.Identity(*u.IdentityID)
	if errors.Is(err, store.ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return ident.Status != "active", nil
}

// secretBytes is the size of session secrets and CSRF secrets.
const secretBytes = 32

// NewSecret returns a new random secret (32 bytes, base64url, 43 chars).
func NewSecret() string {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("auth: random secret: %w", err)) // crypto/rand does not fail on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashSecret is the stored form of a bearer secret: SHA-256, lower-case hex.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// Timeouts returns the idle and absolute lifetimes of a session of kind
// whose user has the active roles.
func Timeouts(kind string, active RoleSet) (idle, absolute time.Duration) {
	switch {
	case kind == store.SessionBreakGlass:
		return BreakGlassIdle, BreakGlassAbsolute
	case active.HasAdmin():
		return AdminIdle, AdminAbsolute
	}
	return UserIdle, UserAbsolute
}

// Cookies builds the session cookie (one helper, so a test can check the
// serialized header).
type Cookies struct {
	// Insecure selects the dev-only Safari fallback: tessera_sid without
	// Secure. config refuses it outside dev on localhost.
	Insecure bool
}

// Name is the session cookie's name.
func (c Cookies) Name() string {
	if c.Insecure {
		return InsecureCookieName
	}
	return CookieName
}

// Session returns the session cookie carrying secret: HttpOnly,
// SameSite=Lax, Path=/, no Domain, no Max-Age (a browser-session cookie;
// the server-side expiry is authoritative), Secure unless Insecure.
func (c Cookies) Session(secret string) *http.Cookie {
	// #nosec G124 -- Secure is false only for the dev-only Safari fallback, which config allows only with
	// TESSERA_ENV=dev and a localhost public URL (§11); HttpOnly and SameSite=Lax are always set
	return &http.Cookie{Name: c.Name(), Value: secret, Path: "/", Secure: !c.Insecure, HttpOnly: true,
		SameSite: http.SameSiteLaxMode}
}

// Clear returns a cookie that deletes the session cookie.
func (c Cookies) Clear() *http.Cookie {
	k := c.Session("") // #nosec G124 -- the same attributes as the session cookie (see Session)
	k.MaxAge = -1
	return k
}

// Issued is a newly created or rotated session: the secret goes into the
// cookie once and is never stored or logged.
type Issued struct {
	Secret    string
	CSRFToken string
	Session   *store.Session
}

// SessionInput describes a session to create.
type SessionInput struct {
	User     *store.PlatformUser
	Authn    *store.AuthnContextRecord // the authentication that created it
	Kind     string                    // browser (default) | break_glass
	IP, UA   *string
	Settings ActivationSettings
	Now      time.Time
	ClientID *string
}

// CreateSession creates a session for an authenticated user in tx (the
// user's tenant) and returns the cookie secret. The lifetimes depend on the
// roles the authentication activates.
func CreateSession(tx *store.TenantTx, in SessionInput) (Issued, error) {
	if in.User == nil || in.Authn == nil {
		return Issued{}, fmt.Errorf("auth: CreateSession needs a user and an authentication context")
	}
	if in.User.Status != "active" {
		return Issued{}, fmt.Errorf("auth: user %s is %s", in.User.ID, in.User.Status)
	}
	// Re-read the user in tx: a sign-in may have linked it to an identity
	// since the caller loaded it.
	if cur, err := tx.PlatformUser(in.User.ID); err == nil {
		if off, err := IdentityInactive(tx, cur); err != nil {
			return Issued{}, err
		} else if off {
			return Issued{}, fmt.Errorf("auth: user %s is linked to an identity that is not active", in.User.ID)
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return Issued{}, err
	}
	if in.Authn.UserID != in.User.ID {
		return Issued{}, fmt.Errorf("auth: the authentication context belongs to another user")
	}
	kind := in.Kind
	if kind == "" {
		kind = store.SessionBrowser
	}
	as, err := tx.RoleAssignments(in.User.ID)
	if err != nil {
		return Issued{}, err
	}
	ctx := ContextFromRecord(in.Authn)
	active, _ := ActivateRoles(AssignedRoles(as, in.Now), &ctx, in.Settings, in.Now)
	idle, absolute := Timeouts(kind, active)
	secret, csrf := NewSecret(), NewSecret()
	hash := HashSecret(secret)
	now := in.Now.UTC()
	s := &store.Session{TenantID: tx.Tenant(), UserID: in.User.ID, Kind: kind, SecretHash: &hash,
		CSRFSecret: &csrf, InitialAuthnContextID: in.Authn.ID, CurrentAuthnContextID: in.Authn.ID, ClientID: in.ClientID,
		CreatedAt: now, LastActivityAt: now, IdleExpiresAt: now.Add(idle), AbsoluteExpiresAt: now.Add(absolute),
		IPFirst: in.IP, UserAgentFirst: in.UA}
	if err := tx.InsertSession(s); err != nil {
		return Issued{}, err
	}
	if err := tx.SetUserLastLogin(in.User.ID, now); err != nil {
		return Issued{}, err
	}
	return Issued{Secret: secret, CSRFToken: CSRFToken(csrf), Session: s}, nil
}

// CLIIdle is the idle lifetime of a CLI session: the refresh token's (§10.2).
// A CLI session has no cookie, so there is no secret to store.
const CLIIdle = 12 * time.Hour

// CLISessionInput describes the CLI session a device approval creates.
type CLISessionInput struct {
	User     *store.PlatformUser
	Authn    *store.AuthnContextRecord // the authentication that approved the device
	ClientID string
	IP, UA   *string
	Settings ActivationSettings
	Now      time.Time
}

// CreateCLISession creates the kind=cli session of an approved device grant in
// tx (the user's tenant). Its current authentication context is the approving
// one, so the CLI's roles are activated (or not) exactly as in that sign-in.
// The absolute lifetime follows the roles that context activates (24 h, or
// 12 h with an admin role, §10.2); the idle lifetime is CLIIdle, moved by
// every refresh.
func CreateCLISession(tx *store.TenantTx, in CLISessionInput) (*store.Session, error) {
	if in.User == nil || in.Authn == nil || in.ClientID == "" {
		return nil, fmt.Errorf("auth: CreateCLISession needs a user, an authentication context and a client")
	}
	if in.User.Status != "active" {
		return nil, fmt.Errorf("auth: user %s is %s", in.User.ID, in.User.Status)
	}
	if in.Authn.UserID != in.User.ID {
		return nil, fmt.Errorf("auth: the authentication context belongs to another user")
	}
	as, err := tx.RoleAssignments(in.User.ID)
	if err != nil {
		return nil, err
	}
	ctx := ContextFromRecord(in.Authn)
	active, _ := ActivateRoles(AssignedRoles(as, in.Now), &ctx, in.Settings, in.Now)
	_, absolute := Timeouts(store.SessionBrowser, active)
	now := in.Now.UTC()
	idle := now.Add(CLIIdle)
	if abs := now.Add(absolute); idle.After(abs) {
		idle = abs
	}
	client := in.ClientID
	s := &store.Session{TenantID: tx.Tenant(), UserID: in.User.ID, Kind: store.SessionCLI, ClientID: &client,
		InitialAuthnContextID: in.Authn.ID, CurrentAuthnContextID: in.Authn.ID, CreatedAt: now, LastActivityAt: now,
		IdleExpiresAt: idle, AbsoluteExpiresAt: now.Add(absolute), IPFirst: in.IP, UserAgentFirst: in.UA}
	if err := tx.InsertSession(s); err != nil {
		return nil, err
	}
	return s, nil
}

// RotateSession issues a new secret and CSRF secret for an active session
// (same sid), sets its current authentication context to ctxID (the same one
// on a role change, the new one after step-up) and recomputes its idle
// expiry for the roles that context activates. The old cookie stops working
// at once.
func RotateSession(tx *store.TenantTx, sid, ctxID uuid.UUID, settings ActivationSettings, now time.Time) (Issued, error) {
	s, err := tx.Session(sid)
	if err != nil {
		return Issued{}, err
	}
	if s.Status != store.SessionActive {
		return Issued{}, store.ErrSessionInactive
	}
	rec, err := tx.AuthnContext(ctxID)
	if err != nil {
		return Issued{}, err
	}
	if rec.UserID != s.UserID {
		return Issued{}, fmt.Errorf("auth: the authentication context belongs to another user")
	}
	as, err := tx.RoleAssignments(s.UserID)
	if err != nil {
		return Issued{}, err
	}
	ctx := ContextFromRecord(rec)
	active, _ := ActivateRoles(AssignedRoles(as, now), &ctx, settings, now)
	idle, _ := Timeouts(s.Kind, active)
	idleExpires := now.UTC().Add(idle)
	if idleExpires.After(s.AbsoluteExpiresAt) {
		idleExpires = s.AbsoluteExpiresAt
	}
	secret, csrf := NewSecret(), NewSecret()
	if err := tx.RotateSession(sid, HashSecret(secret), csrf, ctxID, now.UTC(), idleExpires); err != nil {
		return Issued{}, err
	}
	s, err = tx.Session(sid)
	if err != nil {
		return Issued{}, err
	}
	return Issued{Secret: secret, CSRFToken: CSRFToken(csrf), Session: s}, nil
}

// RevokeSession revokes one active session.
func RevokeSession(tx *store.TenantTx, sid uuid.UUID, reason string, now time.Time) error {
	return tx.RevokeSession(sid, reason, now.UTC())
}

// RevokeReplaced revokes the session a browser held when it signed in again
// (in tx, the session's tenant) and records auth.session.revoke. A session
// that is no longer active is left alone; ok reports whether one was revoked.
func RevokeReplaced(ctx context.Context, tx *store.TenantTx, sid uuid.UUID, now time.Time) (ok bool, err error) {
	if err := tx.RevokeSession(sid, RevokedReplaced, now.UTC()); errors.Is(err, store.ErrSessionInactive) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	_, err = audit.Record(ctx, tx, "auth.session.revoke", ojson.Object{{Key: "session_id", Value: sid.String()},
		{Key: "reason", Value: RevokedReplaced}}, audit.At(now), audit.Target("session", sid.String()))
	return err == nil, err
}

// RevokeUserSessions revokes every active session of a user (user disabled,
// role granted or removed: §15.6).
func RevokeUserSessions(tx *store.TenantTx, userID uuid.UUID, reason string, now time.Time) (int64, error) {
	return tx.RevokeUserSessions(userID, reason, now.UTC())
}

// ClientSecretAAD binds a sealed IdP client secret (idp_connections.
// client_secret_enc) to its tenant and connection.
func ClientSecretAAD(t tenancy.ID, conn uuid.UUID) []byte {
	return seal.AAD(t, "idp_connections", "client_secret_enc", conn.String())
}

// SPKeyAAD binds a sealed SAML SP signing key (idp_connections.sp_key_enc)
// to its tenant and connection.
func SPKeyAAD(t tenancy.ID, conn uuid.UUID) []byte {
	return seal.AAD(t, "idp_connections", "sp_key_enc", conn.String())
}
