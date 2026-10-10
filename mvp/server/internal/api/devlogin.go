package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	authnorm "github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Dev sign-in (design §19 PR5, guarded by §18.4): until browser sign-in
// through the tenant's IdP lands (PR6, PR7), TESSERA_ENV=dev or test exposes
//
//	GET  /api/auth/dev-login  the users a dev_mock IdP connection knows
//	POST /api/auth/dev-login  {tenant, subject, method}: sign one in
//
// The user is resolved exactly like an IdP login would: through the tenant's
// active dev_mock connection and the (connection, subject) ExternalLogin,
// never by email. The authentication context is what the dev IdP's Okta
// emulation returns for the chosen method when Tessera asks for phr, run
// through the same normalization as a real login, so roles activate the same
// way (admin roles need the passkey or hardware key). PR7 removes both routes.
//
// Guard rails: the routes are registered only with TESSERA_ENV=dev, or with
// TESSERA_ENV=test plus the explicit opt-in TESSERA_DEV_LOGIN=1, and a test
// server answers them only to a loopback peer (cmd/tessera refuses prod with
// a dev IdP URL, a dev_mock connection or TESSERA_DEV_LOGIN, §18.4). The
// picker lists one named tenant's users, never every tenant's. POST needs a
// JSON body and an allowed Origin (login CSRF); every attempt is audited
// (auth.login.success or auth.login.failure).

// devLoginEnabled reports whether the routes are registered: always in dev,
// in test only with the opt-in.
func (s *Server) devLoginEnabled() bool {
	return s.cfg.Env == "dev" || (s.cfg.Env == "test" && s.cfg.DevLogin)
}

// devLoginAllowed reports whether this request may use dev sign-in: a test
// server serves it to loopback peers only (the TCP peer; forwarding headers
// are not trusted).
func (s *Server) devLoginAllowed(r *http.Request) bool {
	if !s.devLoginEnabled() {
		return false
	}
	if s.cfg.Env == "dev" {
		return true
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	return err == nil && ap.Addr().Unmap().IsLoopback()
}

// devMethods are the dev IdP's sign-in methods (users.yaml authenticators)
// and what the Okta emulation returns for each when phr was requested.
var devMethods = map[string]struct {
	acr string
	amr []string
}{
	"passkey":      {authnorm.OktaPhr, []string{"swk", "user", "mfa"}},
	"hardware_key": {authnorm.OktaPhr, []string{"hwk", "user", "mfa"}},
	"password_otp": {authnorm.Okta2FA, []string{"pwd", "otp", "mfa"}},
	"password":     {authnorm.Okta1FA, []string{"pwd"}},
}

// devLoginACR is what dev sign-in asks the (emulated) IdP for: the design's
// default login_acr, phishing resistance (§9.1).
const devLoginACR = authnorm.OktaPhr

type devLoginIn struct {
	Tenant  string `json:"tenant"`
	Subject string `json:"subject"`
	Method  string `json:"method"`
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

// devLoginUsers is GET /api/auth/dev-login?tenant=<slug>: the users of that
// tenant's dev_mock connection, for the dev sign-in picker. An unknown or
// inactive tenant lists no users (the same answer as a tenant without a dev
// connection), and no other tenant's users are ever listed.
func (s *Server) devLoginUsers(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	if !s.devLoginAllowed(r) {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	methods := ojson.Object{{Key: "methods", Value: []string{"passkey", "hardware_key", "password_otp", "password"}}}
	out := []ojson.Object{}
	slug := r.URL.Query().Get("tenant")
	var t store.Tenant
	err := s.store.ReadSystem(r.Context(), "dev login tenant", func(st *store.SystemTx) error {
		var err error
		t, err = st.TenantBySlug(slug)
		return err
	})
	if errors.Is(err, store.ErrNotFound) || (err == nil && (t.Status != "active" || t.ID == tenancy.Platform)) {
		return append(ojson.Object{{Key: "users", Value: out}}, methods...), nil
	}
	if err != nil {
		return nil, err
	}
	err = s.store.ReadTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		conn, err := devConnection(tx)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		users, err := tx.PlatformUsers()
		if err != nil {
			return err
		}
		for _, u := range users {
			logins, err := tx.ExternalLoginsForUser(u.ID)
			if err != nil {
				return err
			}
			i := slices.IndexFunc(logins, func(l *store.ExternalLogin) bool { return l.IdPConnectionID == conn.ID })
			if i < 0 || u.Status != "active" {
				continue
			}
			as, err := tx.RoleAssignments(u.ID)
			if err != nil {
				return err
			}
			out = append(out, ojson.Object{{Key: "tenant", Value: t.Slug}, {Key: "tenant_name", Value: t.Name},
				{Key: "subject", Value: logins[i].Subject}, {Key: "email", Value: u.Email},
				{Key: "display_name", Value: u.DisplayName},
				{Key: "roles", Value: roleNames(auth.AssignedRoles(as, s.clock()).Sorted())}})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return append(ojson.Object{{Key: "users", Value: out}}, methods...), nil
}

// devLoginFailure audits a refused dev sign-in in the tenant's chain (or the
// platform's for an unknown tenant) and answers a generic 401.
func (s *Server) devLoginFailure(ctx context.Context, t tenancy.ID, in devLoginIn, reason string) (any, error) {
	if t.IsZero() {
		t = tenancy.Platform
	}
	detail := ojson.Object{{Key: "via", Value: "dev_login"}, {Key: "reason", Value: reason},
		{Key: "tenant", Value: truncate(in.Tenant, 64)}, {Key: "subject", Value: truncate(in.Subject, 128)}}
	if err := s.store.InTenant(ctx, t, func(tx *store.TenantTx) error {
		_, err := audit.Record(ctx, tx, "auth.login.failure", detail, audit.At(s.clock()), audit.Outcome(store.OutcomeFailure))
		return err
	}); err != nil {
		return nil, err
	}
	return statusBody{http.StatusUnauthorized, ojson.Object{{Key: "error", Value: "login_failed"}}}, nil
}

func truncate(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}

// devLogin is POST /api/auth/dev-login.
func (s *Server) devLogin(w http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	if !s.devLoginAllowed(r) {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	if !jsonContentType(r) {
		return statusBody{http.StatusUnsupportedMediaType, ojson.Object{{Key: "error", Value: "unsupported_media_type"}}}, nil
	}
	if err := auth.CheckOrigin(r, s.csrfOrigins()); err != nil {
		return statusBody{http.StatusForbidden, ojson.Object{{Key: "error", Value: "csrf_failed"}}}, nil
	}
	var in devLoginIn
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		if errors.Is(err, errBodyTooLarge) || strings.Contains(err.Error(), "request body too large") {
			return nil, errBodyTooLarge
		}
		return statusBody{http.StatusUnprocessableEntity, detail("invalid dev-login request")}, nil
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return statusBody{http.StatusUnprocessableEntity, detail("invalid dev-login request")}, nil
	}
	ctx := r.Context()
	if in.Method == "" {
		in.Method = "passkey"
	}
	m, ok := devMethods[in.Method]
	if !ok {
		return statusBody{http.StatusUnprocessableEntity, detail("unknown method")}, nil
	}
	var tenant store.Tenant
	err := s.store.ReadSystem(ctx, "dev login tenant", func(st *store.SystemTx) error {
		var err error
		tenant, err = st.TenantBySlug(in.Tenant)
		return err
	})
	if errors.Is(err, store.ErrNotFound) || (err == nil && (tenant.Status != "active" || tenant.ID == tenancy.Platform)) {
		return s.devLoginFailure(ctx, tenancy.ID{}, in, "unknown_tenant")
	}
	if err != nil {
		return nil, err
	}
	// Resolve (connection, subject) -> user, as an IdP callback would.
	var conn *store.IdPConnection
	var user *store.PlatformUser
	reason := ""
	err = s.store.ReadTenant(ctx, tenant.ID, func(tx *store.TenantTx) error {
		var err error
		if conn, err = devConnection(tx); errors.Is(err, store.ErrNotFound) {
			reason = "no_dev_connection"
			return nil
		} else if err != nil {
			return err
		}
		l, err := tx.ExternalLoginBySubject(conn.ID, in.Subject)
		if errors.Is(err, store.ErrNotFound) {
			reason = "unknown_subject"
			return nil
		} else if err != nil {
			return err
		}
		if user, err = tx.PlatformUser(l.UserID); err != nil {
			return err
		}
		if user.Status != "active" {
			reason = "user_disabled"
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if reason != "" {
		return s.devLoginFailure(ctx, tenant.ID, in, reason)
	}
	now := s.clock().UTC()
	mapping, err := authnorm.ParseMapping(conn.AuthnMapping)
	if err != nil {
		return nil, err
	}
	mapping.DevEmulation = "okta"
	res, err := authnorm.Normalize(authnorm.Connection{Profile: conn.Profile, Mapping: mapping,
		AssumePhishingResistant: conn.AssumePhishingResistant},
		authnorm.Requested{ACRValues: []string{devLoginACR}},
		authnorm.Claims{Subject: in.Subject, ACR: m.acr, AMR: m.amr, AuthTime: &now})
	if err != nil {
		return nil, err
	}
	issued, err := s.completeLogin(w, r, tenant, conn, res, loginOptions{via: "dev_login", protocol: "oidc",
		purpose: "login", user: user, detail: ojson.Object{{Key: "method", Value: in.Method}}})
	if err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "status", Value: "signed_in"}, {Key: "csrf_token", Value: issued.CSRFToken}}, nil
}

// clientAddr is the TCP peer address (forwarding headers are not trusted).
func clientAddr(r *http.Request) *string {
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return nil
	}
	host = truncate(host, 64)
	return &host
}

func userAgent(r *http.Request) *string {
	ua := r.UserAgent()
	if ua == "" {
		return nil
	}
	ua = truncate(ua, 256)
	return &ua
}
