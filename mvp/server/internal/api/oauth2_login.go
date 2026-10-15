package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	authnorm "github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/oauth2rp"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Sign-in through OAuth 2.0-only providers such as GitHub (issue #151):
//
//	GET /api/auth/login?tenant=&connection=<oauth2>  302 to the provider (state, PKCE S256)
//	GET /api/auth/oauth2/{connection_id}/callback    the redirect URI
//
// The callback shares the OIDC callback's transaction checks (cookie, state,
// single use, connection) and then redeems the code and asks the user API
// who signed in (oauth2rp). Nothing proves the factor or when the user
// authenticated: auth_time is the callback time, the session is AAL1 and
// never phishing resistant (so admin roles stay inactive), and step-up is
// unavailable.

func (s *Server) registerOAuth2Routes() {
	s.handle(http.MethodGet, "/api/auth/oauth2/{connection_id}/callback", noTenant, publicRoute, s.oidcCallback)
}

func (s *Server) oauth2RedirectURI(conn uuid.UUID) string {
	return strings.TrimRight(s.cfg.PublicURL, "/") + "/api/auth/oauth2/" + conn.String() + "/callback"
}

// oauth2Issuer is the authority recorded on external logins: the user API's
// origin (https://api.github.com for GitHub).
func oauth2Issuer(c *store.IdPConnection) string {
	u := deref(c.UserinfoEndpoint)
	if u == "" && c.Profile == store.ProfileGitHub {
		u = oauth2rp.GitHubUserURL
	}
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		return p.Scheme + "://" + p.Host
	}
	return u
}

// oauth2Connection is the oauth2rp view of a connection, with its client
// secret opened.
func (s *Server) oauth2Connection(t tenancy.ID, c *store.IdPConnection) (oauth2rp.Connection, error) {
	oc := oauth2rp.Connection{Profile: c.Profile, AuthorizationURL: deref(c.AuthorizationEndpoint),
		TokenURL: deref(c.TokenEndpoint), UserinfoURL: deref(c.UserinfoEndpoint), ClientID: deref(c.ClientID)}
	if c.Profile == store.ProfileDevMock {
		oc.Profile = oauth2rp.GitHub // the dev IdP's GitHub emulation
	}
	_ = json.Unmarshal(c.Scopes, &oc.Scopes)
	if f, ok := strings.CutPrefix(c.SubjectSource, "field:"); ok {
		oc.SubjectField = f
	}
	if len(c.ClientSecretEnc) > 0 {
		if s.cfg.Sealer == nil {
			return oc, errors.New("api: no sealer to open the client secret")
		}
		b, err := s.cfg.Sealer.Open(c.ClientSecretEnc, auth.ClientSecretAAD(t, c.ID))
		if err != nil {
			return oc, err
		}
		oc.ClientSecret = string(b)
	}
	return oc.Defaults(), nil
}

// startOAuth2Login creates the transaction and redirects to the provider.
func (s *Server) startOAuth2Login(w http.ResponseWriter, r *http.Request, t store.Tenant, c *store.IdPConnection, ls loginStart) (any, error) {
	connKV := ojson.Object{{Key: "connection_id", Value: c.ID.String()}}
	if ls.purpose != "login" {
		return s.loginFailure(w, r, t.ID, "oauth2_purpose_unsupported", connKV) // no bootstrap, no step-up
	}
	if s.oauth2 == nil || s.cfg.Sealer == nil {
		return nil, errors.New("api: OAuth 2.0 sign-in is not configured (no outbound HTTP client or sealer)")
	}
	oc, err := s.oauth2Connection(t.ID, c)
	if err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	cookie, state, verifier := seal.RandomSecret(32), seal.RandomSecret(32), seal.RandomSecret(48)
	stateHash := seal.SHA256Hex([]byte(state))
	acr := ls.acr
	txn := &store.LoginTransaction{ID: uuid.New(), CookieHash: seal.SHA256Hex([]byte(cookie)), IdPConnectionID: c.ID,
		Purpose: ls.purpose, StateHash: &stateHash, RequiredTesseraACR: &acr, ReturnTo: ls.returnTo, CreatedAt: now,
		ExpiresAt: now.Add(loginTxnTTL)}
	if txn.PKCEVerifierEnc, err = s.cfg.Sealer.Seal([]byte(verifier), verifierAAD(t.ID, txn.ID)); err != nil {
		return nil, err
	}
	authURL, err := oauth2rp.AuthURL(oc, oauth2rp.AuthRequest{RedirectURI: s.oauth2RedirectURI(c.ID), State: state,
		Verifier: verifier})
	if err != nil {
		s.log.Warn("OAuth 2.0 connection unusable", "connection_id", c.ID, "err", err)
		return s.loginFailure(w, r, t.ID, oauth2rp.ReasonOf(err), connKV)
	}
	if err := s.store.InTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		if err := tx.InsertLoginTransaction(txn); err != nil {
			return err
		}
		_, err := audit.Record(r.Context(), tx, "auth.login.start", ojson.Object{{Key: "via", Value: "oauth2"},
			{Key: "purpose", Value: ls.purpose}, {Key: "connection_id", Value: c.ID.String()},
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

// finishOAuth2Callback runs after the shared transaction checks: redeem the
// code, ask the user API, normalize, sign in.
func (s *Server) finishOAuth2Callback(w http.ResponseWriter, r *http.Request, tenant store.Tenant, conn *store.IdPConnection,
	txn *store.LoginTransaction) (any, error) {
	ctx := r.Context()
	fail := func(reason string) (any, error) {
		return s.loginFailure(w, r, tenant.ID, reason, ojson.Object{{Key: "login_transaction_id", Value: txn.ID.String()}})
	}
	if txn.Purpose != "login" {
		return fail("oauth2_purpose_unsupported")
	}
	oc, err := s.oauth2Connection(tenant.ID, conn)
	if err != nil {
		return nil, err
	}
	verifier, err := s.cfg.Sealer.Open(txn.PKCEVerifierEnc, verifierAAD(tenant.ID, txn.ID))
	if err != nil {
		return nil, err
	}
	u, err := s.oauth2.Exchange(ctx, oc, r.URL.Query().Get("code"), s.oauth2RedirectURI(conn.ID), string(verifier))
	if err != nil {
		s.log.Info("OAuth 2.0 callback refused", "err", err, "request_id", audit.RequestID(ctx))
		return fail(oauth2rp.ReasonOf(err))
	}
	mapping, err := authnorm.ParseMapping(conn.AuthnMapping)
	if err != nil {
		return nil, err
	}
	at := s.clock().UTC() // the provider says nothing about when the user authenticated
	res, err := authnorm.Normalize(authnorm.Connection{Profile: conn.Profile, Mapping: mapping,
		AssumePhishingResistant: conn.AssumePhishingResistant}, authnorm.Requested{},
		authnorm.Claims{Subject: u.Subject, AuthTime: &at, Raw: u.Raw})
	if err != nil {
		return fail("normalization_failed")
	}
	name := u.Name
	if name == "" {
		name = u.Login
	}
	return s.finishLogin(w, r, tenant, conn, txn, idpProfile{email: u.Email, name: name}, res)
}
