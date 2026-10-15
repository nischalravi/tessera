package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	authnorm "github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/oidcrp"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Browser sign-in through the tenant's OIDC IdP (design §9.1, §19 PR6):
//
//	GET /api/auth/discover?tenant=&email=           home-realm discovery
//	GET /api/auth/login?tenant=&connection=&return_to=  302 to the IdP
//	GET /api/auth/oidc/{connection_id}/callback     the redirect URI
//	GET /t/{slug}/bootstrap?code=                   redeem a bootstrap invitation (§15.3)
//
// /login creates a LoginTransaction (state and cookie stored as SHA-256 hex,
// the PKCE verifier sealed, a fresh nonce, expiry 10 minutes) bound to the
// __Host-tessera_login cookie. The callback finds the transaction by that
// cookie (the second §14.2 hash lookup), checks the connection and state,
// consumes it once, redeems the code and validates the ID token (oidcrp),
// normalizes the authentication, resolves (connection, subject) to a
// platform user (never by email) and creates the session. Every refusal is
// audited as auth.login.failure with a reason, and the browser sees a
// generic page with the request id.

// Login transaction lifetimes and the max_age sent at login (§9.1, §10.2).
const (
	loginTxnTTL     = 10 * time.Minute
	loginMaxAge     = int64(43200)
	bootstrapTTLMax = 24 * time.Hour
)

// LoginCookieName is the login-transaction cookie; InsecureLoginCookieName
// is its dev-only form without Secure (and so without the __Host- prefix).
const (
	LoginCookieName         = "__Host-tessera_login"
	InsecureLoginCookieName = "tessera_login"
)

func (s *Server) loginCookieName() string {
	if s.cfg.InsecureCookie {
		return InsecureLoginCookieName
	}
	return LoginCookieName
}

// loginCookie is the transaction cookie. SameSite=Lax is enough for the OIDC
// redirect back (a top-level GET). The SAML POST binding arrives cross-site
// without it; the ACS then re-posts from a same-site page (samlBounce), so
// the cookie never needs SameSite=None.
func (s *Server) loginCookie(value string, maxAge int) *http.Cookie {
	// #nosec G124 -- Secure is false only for the dev-only insecure-cookie mode (config allows it only in dev on localhost)
	return &http.Cookie{Name: s.loginCookieName(), Value: value, Path: "/", Secure: !s.cfg.InsecureCookie, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: maxAge}
}

func (s *Server) registerLoginRoutes() {
	G := http.MethodGet
	s.handle(G, "/api/auth/discover", noTenant, publicRoute, s.authDiscover)
	s.handle(G, "/api/auth/login", noTenant, publicRoute, s.authLogin)
	s.handle(G, "/api/auth/oidc/{connection_id}/callback", noTenant, publicRoute, s.oidcCallback)
	s.handle(G, "/t/{slug}/bootstrap", noTenant, publicRoute, s.bootstrapRedeem)
}

// ---------------------------------------------------------------- discovery

// activeTenant returns the active (non-platform) tenant with slug.
func (s *Server) activeTenant(ctx context.Context, slug string) (store.Tenant, bool, error) {
	if !store.ValidSlug(slug) {
		return store.Tenant{}, false, nil
	}
	var t store.Tenant
	err := s.store.ReadSystem(ctx, "login tenant", func(st *store.SystemTx) error {
		var err error
		t, err = st.TenantBySlug(slug)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return store.Tenant{}, false, nil
	}
	if err != nil {
		return store.Tenant{}, false, err
	}
	return t, t.Status == "active" && t.ID != tenancy.Platform, nil
}

// loginConnections are a tenant's active OIDC, SAML and OAuth 2.0 connections that browser
// sign-in may use (dev_mock only outside prod: config refuses prod with one).
func loginConnections(tx *store.TenantTx) ([]*store.IdPConnection, error) {
	cs, err := tx.IdPConnections()
	if err != nil {
		return nil, err
	}
	out := cs[:0]
	for _, c := range cs {
		if c.Status == "active" && (c.Protocol == "oidc" || c.Protocol == "saml" || c.Protocol == "oauth2") {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b *store.IdPConnection) int {
		if a.IsDefault != b.IsDefault {
			if a.IsDefault {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

// authDiscover is GET /api/auth/discover?tenant=<slug> (or ?email=, matched
// against verified_domains within the named tenant only). An unknown tenant
// gets the same shape with no connections, so the answer does not reveal
// which tenants exist; no connection is listed before a slug is given (I4).
func (s *Server) authDiscover(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	slug := r.URL.Query().Get("tenant")
	email := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("email")))
	out := []ojson.Object{}
	t, ok, err := s.activeTenant(r.Context(), slug)
	if err != nil {
		return nil, err
	}
	if ok {
		err := s.store.ReadTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
			cs, err := loginConnections(tx)
			if err != nil {
				return err
			}
			_, domain, hasDomain := strings.Cut(email, "@")
			for _, c := range cs {
				if hasDomain {
					var domains []string
					_ = json.Unmarshal(c.VerifiedDomains, &domains)
					if !slices.Contains(domains, domain) {
						continue
					}
				}
				out = append(out, ojson.Object{{Key: "id", Value: c.ID.String()}, {Key: "name", Value: c.Name},
					{Key: "protocol", Value: c.Protocol}, {Key: "default", Value: c.IsDefault}})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return ojson.Object{{Key: "tenant", Value: truncate(slug, 64)}, {Key: "connections", Value: out}}, nil
}

// ---------------------------------------------------------------- starting a login

// loginFailure audits a refused sign-in step in the tenant's chain (the
// platform's when the tenant is unknown) and sends the browser back to the
// sign-in page with a generic error and the request id (§9.1: the reason is
// in the audit event, never in the URL).
func (s *Server) loginFailure(w http.ResponseWriter, r *http.Request, t tenancy.ID, reason string, extra ojson.Object) (any, error) {
	if t.IsZero() {
		t = tenancy.Platform
	}
	detail := append(ojson.Object{{Key: "via", Value: "oidc"}, {Key: "reason", Value: reason}}, extra...)
	if err := s.store.InTenant(r.Context(), t, func(tx *store.TenantTx) error {
		_, err := audit.Record(r.Context(), tx, "auth.login.failure", detail, audit.At(s.clock()),
			audit.Outcome(store.OutcomeFailure))
		return err
	}); err != nil {
		return nil, err
	}
	rid := audit.RequestID(r.Context())
	s.log.Info("sign-in refused", "reason", reason, "request_id", rid)
	http.SetCookie(w, s.loginCookie("", -1))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, LoginErrorURL(rid), http.StatusFound)
	return nil, nil
}

// LoginErrorURL is where a refused sign-in lands: the UI's sign-in page.
func LoginErrorURL(requestID string) string {
	v := url.Values{"error": {"login_failed"}}
	if requestID != "" {
		v.Set("request_id", requestID)
	}
	return "/login?" + v.Encode()
}

// rpConnection is the oidcrp view of a connection, with its client secret
// opened.
func (s *Server) rpConnection(t tenancy.ID, c *store.IdPConnection) (oidcrp.Connection, error) {
	rc := oidcrp.Connection{Key: c.ID.String()}
	if c.Issuer != nil {
		rc.Issuer = *c.Issuer
	}
	if c.ClientID != nil {
		rc.ClientID = *c.ClientID
	}
	_ = json.Unmarshal(c.Scopes, &rc.Scopes)
	_ = json.Unmarshal(c.IDTokenAlgs, &rc.IDTokenAlgs)
	if c.Profile == store.ProfileEntra {
		rc.JWKSHosts = []string{"login.microsoftonline.com"}
	}
	if len(c.ClientSecretEnc) > 0 {
		if s.cfg.Sealer == nil {
			return rc, errors.New("api: no sealer to open the client secret")
		}
		b, err := s.cfg.Sealer.Open(c.ClientSecretEnc, auth.ClientSecretAAD(t, c.ID))
		if err != nil {
			return rc, err
		}
		rc.ClientSecret = string(b)
	}
	return rc, nil
}

func verifierAAD(t tenancy.ID, txn uuid.UUID) []byte {
	return seal.AAD(t, "login_transactions", "pkce_verifier_enc", txn.String())
}

// requestedAuthn is what Tessera asks the IdP for when it needs acr
// (§8.3): the connection's step_up_request entry, else the profile default.
func requestedAuthn(c *store.IdPConnection, acr string) (authnorm.Requested, string) {
	var m map[string]struct {
		ACRValues string          `json:"acr_values"`
		Claims    json.RawMessage `json:"claims"`
		ClassRefs []string        `json:"authn_context_class_refs"`
	}
	if err := json.Unmarshal(c.StepUpRequest, &m); err == nil {
		if e, ok := m[acr]; ok {
			if c.Protocol == "saml" {
				return authnorm.Requested{ClassRefs: e.ClassRefs}, ""
			}
			req := authnorm.Requested{ACRValues: strings.Fields(e.ACRValues)}
			claims := ""
			if len(e.Claims) > 0 {
				claims = string(e.Claims)
				req.EntraContexts = entraContexts(e.Claims)
			}
			return req, claims
		}
	}
	if c.Protocol == "saml" {
		return authnorm.Requested{}, "" // nothing requested: phr only by attestation (rule 4) or amr attribute
	}
	switch c.Profile {
	case store.ProfileOkta, store.ProfileDevMock:
		v := map[string]string{authnorm.ACRPhr: authnorm.OktaPhr, authnorm.ACRPhrh: authnorm.OktaPhrh,
			authnorm.ACRAAL2: authnorm.Okta2FA}[acr]
		if v != "" {
			return authnorm.Requested{ACRValues: []string{v}}, ""
		}
	case store.ProfileEntra:
		mapping, _ := authnorm.ParseMapping(c.AuthnMapping)
		if acr == authnorm.ACRPhr && len(mapping.EntraPhrContexts) > 0 {
			b, _ := json.Marshal(map[string]any{"id_token": map[string]any{"acrs": map[string]any{
				"essential": true, "values": mapping.EntraPhrContexts}}})
			return authnorm.Requested{EntraContexts: mapping.EntraPhrContexts}, string(b)
		}
	}
	return authnorm.Requested{}, ""
}

func entraContexts(raw json.RawMessage) []string {
	var v struct {
		IDToken struct {
			ACRS struct {
				Values []string `json:"values"`
			} `json:"acrs"`
		} `json:"id_token"`
	}
	_ = json.Unmarshal(raw, &v)
	return v.IDToken.ACRS.Values
}

// LoginACR is the Tessera ACR a tenant asks for at sign-in (settings
// login_acr, §18.3): phr by default; aal2, phr or phrh when set.
func LoginACR(settings string) string {
	var v struct {
		LoginACR string `json:"login_acr"`
	}
	_ = json.Unmarshal([]byte(settings), &v)
	switch v.LoginACR {
	case authnorm.ACRAAL2, authnorm.ACRPhr, authnorm.ACRPhrh:
		return v.LoginACR
	}
	return authnorm.ACRPhr
}

func (s *Server) redirectURI(conn uuid.UUID) string {
	base := strings.TrimRight(s.cfg.PublicURL, "/")
	return base + "/api/auth/oidc/" + conn.String() + "/callback"
}

// startLogin creates the transaction and redirects to the IdP.
// loginStart describes a login transaction to create (startLogin).
type loginStart struct {
	purpose, returnTo, acr string
	invitation             *uuid.UUID // bootstrap
	// step-up: the session to upgrade and the external login that must
	// sign in again; max_age=0 and prompt=login force a real re-authentication
	session, expectedLogin *uuid.UUID
	maxAge                 int64
	prompt                 string
}

func (s *Server) startLogin(w http.ResponseWriter, r *http.Request, t store.Tenant, c *store.IdPConnection, ls loginStart) (any, error) {
	switch c.Protocol {
	case "saml":
		return s.startSAMLLogin(w, r, t, c, ls)
	case "oauth2":
		return s.startOAuth2Login(w, r, t, c, ls)
	}
	purpose, returnTo, acr, invitation := ls.purpose, ls.returnTo, ls.acr, ls.invitation
	if s.rp == nil {
		return nil, errors.New("api: OIDC sign-in is not configured (no outbound HTTP client)")
	}
	rc, err := s.rpConnection(t.ID, c)
	if err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	cookie, state, nonce, verifier := seal.RandomSecret(32), seal.RandomSecret(32), seal.RandomSecret(32), seal.RandomSecret(48)
	stateHash := seal.SHA256Hex([]byte(state))
	maxAge := loginMaxAge
	if ls.purpose == "step_up" {
		maxAge = ls.maxAge
	}
	req, claims := requestedAuthn(c, acr)
	txn := &store.LoginTransaction{ID: uuid.New(), CookieHash: seal.SHA256Hex([]byte(cookie)), IdPConnectionID: c.ID,
		Purpose: purpose, StateHash: &stateHash, Nonce: &nonce, RequiredTesseraACR: &acr, MaxAge: &maxAge,
		BootstrapInvitationID: invitation, SessionID: ls.session, ExpectedExternalLoginID: ls.expectedLogin,
		ReturnTo: returnTo, CreatedAt: now, ExpiresAt: now.Add(loginTxnTTL)}
	if s.cfg.Sealer == nil {
		return nil, errors.New("api: no sealer for the PKCE verifier")
	}
	if txn.PKCEVerifierEnc, err = s.cfg.Sealer.Seal([]byte(verifier), verifierAAD(t.ID, txn.ID)); err != nil {
		return nil, err
	}
	authURL, err := s.rp.AuthURL(r.Context(), rc, oidcrp.AuthRequest{RedirectURI: s.redirectURI(c.ID), State: state,
		Nonce: nonce, Verifier: verifier, ACRValues: req.ACRValues, MaxAge: &maxAge, Claims: claims, Prompt: ls.prompt})
	if err != nil {
		return s.loginFailure(w, r, t.ID, oidcrp.ReasonOf(err), ojson.Object{{Key: "connection_id", Value: c.ID.String()}})
	}
	if err := s.store.InTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		if err := tx.InsertLoginTransaction(txn); err != nil {
			return err
		}
		_, err := audit.Record(r.Context(), tx, "auth.login.start", ojson.Object{{Key: "via", Value: "oidc"},
			{Key: "purpose", Value: purpose}, {Key: "connection_id", Value: c.ID.String()},
			{Key: "login_transaction_id", Value: txn.ID.String()}, {Key: "required_acr", Value: acr}},
			audit.At(now), audit.Target("login_transaction", txn.ID.String()))
		return err
	}); err != nil {
		return nil, err
	}
	http.SetCookie(w, s.loginCookie(cookie, int(loginTxnTTL/time.Second)))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusFound)
	return nil, nil
}

// authLogin is GET /api/auth/login?tenant=&connection=&return_to=.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	q := r.URL.Query()
	returnTo := q.Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}
	t, ok, err := s.activeTenant(r.Context(), q.Get("tenant"))
	if err != nil {
		return nil, err
	}
	if !ok {
		return s.loginFailure(w, r, tenancy.ID{}, "unknown_tenant", ojson.Object{{Key: "tenant", Value: truncate(q.Get("tenant"), 64)}})
	}
	if !store.ValidReturnTo(returnTo) {
		return s.loginFailure(w, r, t.ID, "invalid_return_to", nil)
	}
	var conn *store.IdPConnection
	if err := s.store.ReadTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		cs, err := loginConnections(tx)
		if err != nil {
			return err
		}
		want := q.Get("connection")
		for _, c := range cs {
			if (want == "" && c.IsDefault) || c.ID.String() == want {
				conn = c
				break
			}
		}
		if conn == nil && want == "" && len(cs) == 1 {
			conn = cs[0]
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if conn == nil {
		return s.loginFailure(w, r, t.ID, "unknown_connection", ojson.Object{{Key: "connection", Value: truncate(q.Get("connection"), 64)}})
	}
	return s.startLogin(w, r, t, conn, loginStart{purpose: "login", returnTo: returnTo, acr: LoginACR(t.Settings)})
}

// bootstrapRedeem is GET /t/{slug}/bootstrap?code=: an unexpired, unused
// invitation starts a phishing-resistant sign-in (purpose bootstrap)
// through its connection. The invitation is consumed only by a successful
// callback.
func (s *Server) bootstrapRedeem(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	t, ok, err := s.activeTenant(r.Context(), p.path["slug"])
	if err != nil {
		return nil, err
	}
	if !ok {
		return s.loginFailure(w, r, tenancy.ID{}, "unknown_tenant", nil)
	}
	code := r.URL.Query().Get("code")
	var inv *store.BootstrapInvitation
	var conn *store.IdPConnection
	reason := ""
	if err := s.store.ReadTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		var err error
		inv, err = tx.BootstrapInvitationByCodeHash(seal.SHA256Hex([]byte(code)))
		switch {
		case errors.Is(err, store.ErrNotFound) || code == "":
			reason = "bootstrap_code_unknown"
			return nil
		case err != nil:
			return err
		case inv.ConsumedAt != nil:
			reason = "bootstrap_code_used"
			return nil
		case !s.clock().Before(inv.ExpiresAt):
			reason = "bootstrap_code_expired"
			return nil
		}
		if conn, err = tx.IdPConnection(inv.IdPConnectionID); err != nil {
			return err
		}
		if conn.Status != "active" || (conn.Protocol != "oidc" && conn.Protocol != "saml") {
			reason = "unknown_connection"
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if reason != "" {
		return s.loginFailure(w, r, t.ID, reason, nil)
	}
	return s.startLogin(w, r, t, conn, loginStart{purpose: "bootstrap", returnTo: "/", acr: authnorm.ACRPhr, invitation: &inv.ID})
}

// ---------------------------------------------------------------- the callback

// loginTxnFromCookie resolves the login cookie to its active tenant and
// transaction id; reason is set when the browser holds none that is usable.
func (s *Server) loginTxnFromCookie(r *http.Request) (store.Tenant, uuid.UUID, string, error) {
	c, err := r.Cookie(s.loginCookieName())
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return store.Tenant{}, uuid.Nil, "login_cookie_missing", nil
	}
	var tid tenancy.ID
	var txnID uuid.UUID
	err = s.store.ReadSystem(r.Context(), "login transaction lookup", func(st *store.SystemTx) error {
		var err error
		tid, txnID, err = st.LookupLoginTxnByCookieHash(seal.SHA256Hex([]byte(c.Value)))
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return store.Tenant{}, uuid.Nil, "login_transaction_unknown", nil
	}
	if err != nil {
		return store.Tenant{}, uuid.Nil, "", err
	}
	var tenant store.Tenant
	if err := s.store.ReadSystem(r.Context(), "login tenant", func(st *store.SystemTx) error {
		var err error
		tenant, err = st.TenantByID(tid)
		return err
	}); err != nil {
		return store.Tenant{}, uuid.Nil, "", err
	}
	if tenant.Status != "active" {
		return store.Tenant{}, uuid.Nil, "unknown_tenant", nil
	}
	return tenant, txnID, "", nil
}

// oidcCallback is GET /api/auth/oidc/{connection_id}/callback.
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ctx := r.Context()
	q := r.URL.Query()
	tenant, txnID, reason, err := s.loginTxnFromCookie(r)
	if err != nil {
		return nil, err
	}
	if reason != "" {
		return s.loginFailure(w, r, tenancy.ID{}, reason, nil)
	}
	tid := tenant.ID
	// Load, check and consume the transaction in one committed step, so a
	// replayed callback finds it used whatever happens afterwards.
	var txn *store.LoginTransaction
	var conn *store.IdPConnection
	now := s.clock().UTC()
	if err := s.store.InTenant(ctx, tid, func(tx *store.TenantTx) error {
		var err error
		if txn, err = tx.LoginTransaction(txnID); err != nil {
			return err
		}
		switch {
		case txn.IdPConnectionID.String() != p.path["connection_id"]:
			reason = "connection_mismatch"
		case txn.StateHash == nil || subtle.ConstantTimeCompare([]byte(*txn.StateHash), []byte(seal.SHA256Hex([]byte(q.Get("state"))))) != 1:
			reason = "state_mismatch"
		}
		if reason != "" {
			return nil
		}
		if err := tx.ConsumeLoginTransaction(txn.ID, now); errors.Is(err, store.ErrNotFound) {
			reason = "login_transaction_expired_or_used"
			return nil
		} else if err != nil {
			return err
		}
		if q.Get("error") != "" {
			reason = "idp_error"
			return nil
		}
		conn, err = tx.IdPConnection(txn.IdPConnectionID)
		switch {
		case err != nil:
		case conn.Status != "active":
			reason = "connection_disabled"
		case (conn.Protocol == "oauth2") != strings.HasPrefix(r.URL.Path, "/api/auth/oauth2/"):
			reason = "connection_mismatch" // an OIDC transaction at the OAuth 2.0 callback or the reverse
		}
		return err
	}); err != nil {
		return nil, err
	}
	if reason != "" {
		extra := ojson.Object{{Key: "login_transaction_id", Value: txnID.String()}}
		if reason == "idp_error" {
			extra = append(extra, ojson.KV{Key: "idp_error", Value: truncate(q.Get("error"), 64)})
		}
		if txn != nil && txn.Purpose == "step_up" && reason != "connection_mismatch" && reason != "state_mismatch" {
			return s.stepUpFailure(w, r, tid, txn, "auth.step_up.failure", reason, extra)
		}
		return s.loginFailure(w, r, tid, reason, extra)
	}
	if conn.Protocol == "oauth2" {
		return s.finishOAuth2Callback(w, r, tenant, conn, txn)
	}
	rc, err := s.rpConnection(tid, conn)
	if err != nil {
		return nil, err
	}
	verifier, err := s.cfg.Sealer.Open(txn.PKCEVerifierEnc, verifierAAD(tid, txn.ID))
	if err != nil {
		return nil, err
	}
	cb := oidcrp.Callback{Code: q.Get("code"), Iss: q.Get("iss"), RedirectURI: s.redirectURI(conn.ID),
		Verifier: string(verifier), Nonce: deref(txn.Nonce), MaxAge: txn.MaxAge}
	if txn.Purpose == "step_up" {
		started := txn.CreatedAt
		cb.NotBefore = &started // the IdP must really have re-authenticated
	}
	tok, err := s.rp.Exchange(ctx, rc, cb)
	if err != nil {
		s.log.Info("OIDC callback refused", "err", err, "request_id", audit.RequestID(ctx))
		if txn.Purpose == "step_up" {
			return s.stepUpFailure(w, r, tid, txn, "auth.step_up.failure", oidcrp.ReasonOf(err), nil)
		}
		return s.loginFailure(w, r, tid, oidcrp.ReasonOf(err), ojson.Object{{Key: "login_transaction_id", Value: txnID.String()}})
	}
	mapping, err := authnorm.ParseMapping(conn.AuthnMapping)
	if err != nil {
		return nil, err
	}
	req, _ := requestedAuthn(conn, deref(txn.RequiredTesseraACR))
	at := tok.AuthTime
	res, err := authnorm.Normalize(authnorm.Connection{Profile: conn.Profile, Mapping: mapping,
		AssumePhishingResistant: conn.AssumePhishingResistant}, req,
		authnorm.Claims{Subject: tok.Subject, ACR: tok.ACR, AMR: tok.AMR, ACRS: tok.ACRS, TID: tok.TID, OID: tok.OID,
			AuthTime: &at, Raw: tok.Raw})
	if err != nil {
		if txn.Purpose == "step_up" {
			return s.stepUpFailure(w, r, tid, txn, "auth.step_up.failure", "normalization_failed", nil)
		}
		return s.loginFailure(w, r, tid, "normalization_failed", ojson.Object{{Key: "error", Value: err.Error()}})
	}
	if txn.Purpose == "step_up" {
		return s.finishStepUp(w, r, tenant, conn, txn, res)
	}
	return s.finishLogin(w, r, tenant, conn, txn, idpProfile{email: tok.Email, name: tok.Name, groups: tok.Groups}, res)
}

// idpProfile is what a sign-in tells about the user besides the subject:
// display data (email is never an identifier) and IdP groups.
type idpProfile struct {
	email, name string
	groups      []string
}

// finishLogin resolves the user and creates the session (OIDC callback or
// SAML ACS; the transaction is consumed and the result normalized).
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, tenant store.Tenant, conn *store.IdPConnection,
	txn *store.LoginTransaction, tok idpProfile, res authnorm.Result) (any, error) {
	ctx := r.Context()
	now := s.clock().UTC()
	issuer := deref(conn.Issuer)
	switch conn.Protocol {
	case "saml":
		issuer = deref(conn.IdPEntityID)
	case "oauth2":
		issuer = oauth2Issuer(conn)
	}
	var user *store.PlatformUser
	reason := ""
	var inv *store.BootstrapInvitation
	// Resolve (connection, subject) -> user; create it when JIT provisioning
	// or a bootstrap invitation allows. Never by email.
	err := s.store.ReadTenant(ctx, tenant.ID, func(tx *store.TenantTx) error {
		if txn.Purpose == "bootstrap" {
			var err error
			if txn.BootstrapInvitationID == nil {
				reason = "bootstrap_code_unknown"
				return nil
			}
			if inv, err = tx.BootstrapInvitation(*txn.BootstrapInvitationID); err != nil {
				return err
			}
			switch {
			case inv.ConsumedAt != nil:
				reason = "bootstrap_code_used"
			case !now.Before(inv.ExpiresAt):
				reason = "bootstrap_code_expired"
			case inv.IdPConnectionID != conn.ID:
				reason = "connection_mismatch"
			case !res.PhishingResistant:
				reason = "bootstrap_requires_phr"
			case !strings.EqualFold(strings.TrimSpace(tok.email), inv.Email):
				reason = "bootstrap_email_mismatch"
			}
			if reason != "" {
				return nil
			}
		}
		l, err := tx.ExternalLoginBySubject(conn.ID, res.Subject)
		switch {
		case errors.Is(err, store.ErrNotFound):
			if txn.Purpose != "bootstrap" && !conn.JITProvisioning {
				reason = "unknown_subject"
			}
			return nil
		case err != nil:
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
		return s.loginFailure(w, r, tenant.ID, reason, ojson.Object{{Key: "connection_id", Value: conn.ID.String()},
			{Key: "subject", Value: truncate(res.Subject, 128)}})
	}
	// Conditional access (issue #163): the tenant's sign-in policies see the
	// client address and the IdP's device claims. The operator bootstrap is
	// exempt, so a policy can never block the recovery of a tenant.
	var accessDetail ojson.KV
	if txn.Purpose != "bootstrap" {
		var uid *uuid.UUID
		if user != nil {
			uid = &user.ID
		}
		dec, err := s.signinAccess(ctx, tenant.ID, r, uid, res)
		if err != nil {
			return nil, err
		}
		if dec.Evaluated > 0 {
			accessDetail = ojson.KV{Key: "conditional_access", Value: dec.Audit()}
		}
		if why := signinRefusal(dec, res, now); why != "" {
			return s.loginFailure(w, r, tenant.ID, why, ojson.Object{{Key: "connection_id", Value: conn.ID.String()},
				{Key: "subject", Value: truncate(res.Subject, 128)}, accessDetail})
		}
	}
	groups := s.mappedGroupRoles(conn, tok.groups)
	jitCreated := user == nil
	o := loginOptions{via: conn.Protocol, protocol: conn.Protocol, purpose: txn.Purpose,
		detail: ojson.Object{{Key: "jit_created", Value: jitCreated}}}
	if accessDetail.Key != "" {
		o.detail = append(o.detail, accessDetail)
	}
	if user == nil {
		// a new user: its id is chosen now so the sign-in's events are
		// attributed to it
		email, name := strings.TrimSpace(tok.email), strings.TrimSpace(tok.name)
		if name == "" {
			name = email
		}
		if name == "" {
			name = res.Subject
		}
		user = &store.PlatformUser{ID: uuid.New(), DisplayName: truncate(name, 200), Status: "active", CreatedAt: now}
		if email != "" {
			e := truncate(email, 320)
			user.Email = &e
		}
		o.insert = func(tx *store.TenantTx) error {
			if err := tx.InsertPlatformUser(user); err != nil {
				return err
			}
			if err := tx.InsertExternalLogin(&store.ExternalLogin{UserID: user.ID, IdPConnectionID: conn.ID, Issuer: issuer,
				Subject: res.Subject, EmailAtLastLogin: user.Email, CreatedAt: now}); err != nil {
				return err
			}
			var role any
			if txn.Purpose != "bootstrap" {
				role = conn.DefaultRole
				if err := tx.InsertRoleAssignment(&store.RoleAssignment{UserID: user.ID, Role: conn.DefaultRole,
					Source: store.RoleSourceManual, CreatedAt: now}); err != nil {
					return err
				}
			}
			_, err := audit.Record(ctx, tx, "auth.user.jit_created", ojson.Object{{Key: "user_id", Value: user.ID.String()},
				{Key: "connection_id", Value: conn.ID.String()}, {Key: "purpose", Value: txn.Purpose},
				{Key: "default_role", Value: role}}, audit.At(now), audit.Target("platform_user", user.ID.String()))
			return err
		}
	}
	o.user = user
	o.extra = func(tx *store.TenantTx) error {
		if err := s.syncGroupRoles(tx, user, groups, now); err != nil {
			return err
		}
		if inv == nil {
			return nil
		}
		if err := tx.ConsumeBootstrapInvitation(inv.ID, user.ID, now); errors.Is(err, store.ErrNotFound) {
			return errBootstrapRace
		} else if err != nil {
			return err
		}
		as, err := tx.RoleAssignments(user.ID)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(as, func(a *store.RoleAssignment) bool { return a.Role == store.RoleTenantAdmin }) {
			if err := tx.InsertRoleAssignment(&store.RoleAssignment{UserID: user.ID, Role: store.RoleTenantAdmin,
				Source: store.RoleSourceBootstrap, CreatedAt: now}); err != nil {
				return err
			}
		}
		_, err = audit.Record(ctx, tx, "recovery.invitation.consumed", ojson.Object{{Key: "invitation_id", Value: inv.ID.String()},
			{Key: "user_id", Value: user.ID.String()}, {Key: "role", Value: store.RoleTenantAdmin}},
			audit.At(now), audit.Target("bootstrap_invitation", inv.ID.String()))
		return err
	}
	_, err = s.completeLogin(w, r, tenant, conn, res, o)
	if errors.Is(err, errBootstrapRace) {
		return s.loginFailure(w, r, tenant.ID, "bootstrap_code_used", nil)
	}
	if err != nil {
		return nil, err
	}
	http.SetCookie(w, s.loginCookie("", -1))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, txn.ReturnTo, http.StatusFound)
	return nil, nil
}

var errBootstrapRace = errors.New("api: the bootstrap invitation was consumed concurrently")

// mappedGroupRoles are the non-admin roles the connection's
// group_role_mapping gives the token's groups. Admin roles are never granted
// from IdP groups (§7, E1): such mapping entries are ignored (and the schema
// refuses them too).
func (s *Server) mappedGroupRoles(conn *store.IdPConnection, idpGroups []string) []string {
	var m map[string]string
	if err := json.Unmarshal(conn.GroupRoleMapping, &m); err != nil || len(m) == 0 {
		return nil
	}
	var out []string
	for _, g := range idpGroups {
		role, ok := m[g]
		if !ok || slices.Contains(out, role) {
			continue
		}
		if auth.Role(role).IsAdmin() || role == store.RoleBreakGlass {
			s.log.Warn("group_role_mapping names an admin role; ignored", "connection_id", conn.ID, "group", g, "role", role)
			continue
		}
		out = append(out, role)
	}
	slices.Sort(out)
	return out
}

// syncGroupRoles adds the mapped roles the user lacks (source idp_group).
func (s *Server) syncGroupRoles(tx *store.TenantTx, u *store.PlatformUser, roles []string, now time.Time) error {
	if len(roles) == 0 {
		return nil
	}
	as, err := tx.RoleAssignments(u.ID)
	if err != nil {
		return err
	}
	for _, role := range roles {
		if slices.ContainsFunc(as, func(a *store.RoleAssignment) bool { return a.Role == role }) {
			continue
		}
		if err := tx.InsertRoleAssignment(&store.RoleAssignment{UserID: u.ID, Role: role, Source: store.RoleSourceIdPGroup,
			CreatedAt: now}); err != nil {
			return fmt.Errorf("api: group role %s: %w", role, err)
		}
	}
	return nil
}
