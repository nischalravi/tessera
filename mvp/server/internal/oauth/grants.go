package oauth

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth/dpop"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The token endpoint (RFC 6749 §3.2, RFC 8628 §3.4, RFC 9449 §5): the device
// code and refresh-token grants. Every request carries a DPoP proof, which is
// validated before anything is looked up or issued, and every token issued is
// bound to the proof's key (cnf.jkt in the access token, dpop_jkt on the
// refresh token). The current server nonce rides on every response
// (DPoP-Nonce), and a proof without it gets use_dpop_nonce.

// refreshTokenPrefix marks a refresh token (§10.3).
const refreshTokenPrefix = "trt_"

// tokenResult is what a grant decided inside its transaction: either tokens
// or an OAuth error to send after the transaction (so that the events it
// recorded commit with the error response).
type tokenResult struct {
	status int
	errMsg string // OAuth error code; "" = success
	desc   string
	body   map[string]any
}

func fail(code, desc string) *tokenResult {
	return &tokenResult{status: http.StatusBadRequest, errMsg: code, desc: desc}
}

// Token is POST /t/{slug}/oauth/token.
func (s *Service) Token(w http.ResponseWriter, r *http.Request, slug string) {
	t, ok, err := s.tenantBySlug(r.Context(), slug)
	if err != nil {
		serverError(w, s.cfg.Log, r, err)
		return
	}
	if !ok {
		notFound(w)
		return
	}
	ctx := attribute(r.Context(), t.ID)
	r = r.WithContext(ctx)
	now := s.now()
	if n := s.dpop.NewNonce(now); n != "" {
		w.Header().Set("DPoP-Nonce", n)
	}
	if !formBody(w, r) {
		return
	}
	grant, ok1 := formValue(r, "grant_type")
	clientID, ok2 := formValue(r, "client_id")
	if clientID == "" && grant == GrantClientCredentials {
		// RFC 7523 §3: client_id may be omitted when the assertion names the
		// client; it is only a lookup key until the assertion is verified
		if raw, ok := formValue(r, "client_assertion"); ok {
			if a, err := ParseClientAssertion(raw); err == nil {
				clientID = a.UnverifiedIssuer()
			}
		}
	}
	if !ok1 || !ok2 || grant == "" || len(grant) > 128 || clientID == "" || len(clientID) > 64 {
		oauthError(w, http.StatusBadRequest, "invalid_request", "grant_type and client_id are required and must not repeat")
		return
	}
	var client *store.APIClient
	err = s.db.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) error {
		var err error
		client, err = tx.APIClientByClientID(clientID)
		return err
	})
	if errors.Is(err, store.ErrNotFound) || (err == nil && client.Status != store.ClientActive) {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}
	if err != nil {
		serverError(w, s.cfg.Log, r, err)
		return
	}
	// the first-party CLI is a public client: its events are its own from here
	// on. A machine client's are anonymous until its assertion is verified.
	asClient := audit.Principal{Tenant: t.ID, ClientID: &client.ClientID,
		Actor: store.AuditActor{Type: store.ActorAPIClient, ID: &client.ClientID, Display: &client.Name}}
	if client.Kind == store.ClientFirstPartyCLI {
		ctx = audit.SetPrincipal(ctx, asClient)
		r = r.WithContext(ctx)
	}
	switch grant {
	case GrantDeviceCode, GrantRefresh, GrantClientCredentials:
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type",
			"this server supports the device code, refresh token and client credentials grants")
		return
	}
	// device and refresh tokens are the CLI's; client credentials are a machine client's
	machine := grant == GrantClientCredentials
	if !slices.Contains(client.GrantTypes, grant) || machine != (client.Kind == store.ClientMachine) {
		oauthError(w, http.StatusBadRequest, "unauthorized_client", "this client may not use that grant")
		return
	}
	// DPoP first (RFC 9449 §5): nothing is looked up or issued for a request
	// whose proof is not valid for this endpoint. A machine client configured
	// without DPoP may omit the proof, and then gets an unbound token; a proof
	// it does send is validated and binds the token.
	var jkt string
	if !machine || client.DPoPRequired || len(r.Header.Values("DPoP")) > 0 {
		jkt, err = s.dpop.ValidateProof(ctx, r.Header, dpop.ProofParams{Method: http.MethodPost, URL: s.endpoint(slug, "token"),
			RequireNonce: true, Now: now})
		if err != nil {
			var pe *dpop.ProofError
			if !errors.As(err, &pe) {
				serverError(w, s.cfg.Log, r, err)
				return
			}
			s.dpopRefused(w, r, t.ID, pe)
			return
		}
	}
	var res *tokenResult
	switch grant {
	case GrantDeviceCode:
		res, err = s.deviceCodeGrant(r, t, client, jkt)
	case GrantClientCredentials:
		res, err = s.clientCredentialsGrant(r, t, client, jkt, asClient)
	default:
		res, err = s.refreshGrant(r, t, client, jkt)
	}
	switch {
	case err != nil:
		serverError(w, s.cfg.Log, r, err)
	case res.errMsg != "":
		oauthError(w, res.status, res.errMsg, res.desc)
	default:
		writeJSON(w, http.StatusOK, res.body)
	}
}

// dpopRefused answers an invalid proof and records oauth.dpop.invalid (not
// for the routine first request that only lacks the nonce).
func (s *Service) dpopRefused(w http.ResponseWriter, r *http.Request, tid tenancy.ID, pe *dpop.ProofError) {
	if pe.Code == dpop.CodeUseNonce {
		w.Header().Set("DPoP-Nonce", pe.NewNonce)
		oauthError(w, http.StatusBadRequest, dpop.CodeUseNonce, "retry with the DPoP-Nonce of this response")
		return
	}
	if err := s.db.InTenant(r.Context(), tid, func(tx *store.TenantTx) error {
		_, err := audit.Record(r.Context(), tx, "oauth.dpop.invalid", ojson.Object{{Key: "reason", Value: pe.Description},
			{Key: "endpoint", Value: "token"}}, audit.At(s.now()), audit.Outcome(store.OutcomeFailure))
		return err
	}); err != nil {
		serverError(w, s.cfg.Log, r, err)
		return
	}
	oauthError(w, http.StatusBadRequest, dpop.CodeInvalidProof, pe.Description)
}

// ---------------------------------------------------------------- device_code

func (s *Service) deviceCodeGrant(r *http.Request, t store.Tenant, client *store.APIClient, jkt string) (*tokenResult, error) {
	code, ok := formValue(r, "device_code")
	if !ok || code == "" {
		return fail("invalid_request", "device_code is required"), nil
	}
	if len(code) > 256 {
		return fail("invalid_grant", "the device code is not valid"), nil
	}
	hash := hashHex(code)
	now := s.now()
	var res *tokenResult
	err := s.db.InTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		g, err := tx.DeviceGrantByDeviceCodeHash(hash)
		if errors.Is(err, store.ErrNotFound) || (err == nil && g.ClientID != client.ClientID) {
			res = fail("invalid_grant", "the device code is not valid")
			return nil
		}
		if err != nil {
			return err
		}
		switch {
		case g.Status == store.DeviceDenied:
			res = fail("access_denied", "the user denied the request")
			return nil
		case g.Status == store.DeviceConsumed:
			res = fail("invalid_grant", "the device code was already used")
			return nil
		case g.Status == store.DeviceExpired:
			res = fail("expired_token", "the device code has expired")
			return nil
		case !now.Before(g.ExpiresAt):
			if g.Status == store.DevicePending {
				if err := tx.ExpireDeviceGrant(g.ID); err != nil {
					return err
				}
				if _, err := audit.Record(r.Context(), tx, "oauth.device.expired", ojson.Object{{Key: "grant_id", Value: g.ID.String()}},
					audit.At(now), audit.Target("device_grant", g.ID.String())); err != nil {
					return err
				}
			}
			res = fail("expired_token", "the device code has expired")
			return nil
		case !DeviceGrantEnabled(t.Settings):
			res = fail("access_denied", "device sign-in is turned off for this organization")
			return nil
		case g.Status == store.DevicePending:
			interval := g.Interval
			if g.LastPolledAt != nil && now.Sub(*g.LastPolledAt) < time.Duration(interval)*time.Second {
				interval += DeviceInterval // RFC 8628 §3.5
				res = fail("slow_down", "poll no faster than the interval")
			} else {
				res = fail("authorization_pending", "the user has not approved the request yet")
			}
			return tx.PollDeviceGrant(g.ID, now, interval)
		case g.Status != store.DeviceApproved || g.SessionID == nil:
			res = fail("invalid_grant", "the device code is not valid")
			return nil
		}
		sess, err := tx.Session(*g.SessionID)
		if err != nil {
			return err
		}
		if reason := cliSessionProblem(sess, now); reason != "" {
			res = fail("invalid_grant", reason)
			return nil
		}
		user, err := tx.PlatformUser(sess.UserID)
		if err != nil {
			return err
		}
		if user.Status != "active" {
			res = fail("invalid_grant", "the user is disabled")
			return nil
		}
		if off, err := auth.IdentityInactive(tx, user); err != nil {
			return err
		} else if off {
			res = fail("invalid_grant", "the identity is not active")
			return nil
		}
		if err := tx.ConsumeDeviceGrant(g.ID, now); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				res = fail("invalid_grant", "the device code was already used")
				return nil
			}
			return err
		}
		res, err = s.issue(tx, t, client, sess, g.Scope, jkt, uuid.New(), nil, "device_code", now)
		return err
	})
	return res, err
}

// cliSessionProblem is why a CLI session cannot get tokens ("" if it can).
func cliSessionProblem(sess *store.Session, now time.Time) string {
	switch {
	case sess.Kind != store.SessionCLI:
		return "the session is not a command-line session"
	case sess.Status != store.SessionActive:
		return "the session has ended"
	case !now.Before(sess.IdleExpiresAt) || !now.Before(sess.AbsoluteExpiresAt):
		return "the session has expired"
	}
	return ""
}

// issue mints an access token and a new refresh token of family for sess, in
// tx, and records oauth.token.issued (or oauth.refresh.rotated when parent is
// set) with the token's key thumbprint, never the tokens.
func (s *Service) issue(tx *store.TenantTx, t store.Tenant, client *store.APIClient, sess *store.Session, scope, jkt string,
	family uuid.UUID, parent *uuid.UUID, grant string, now time.Time) (*tokenResult, error) {
	rec, err := tx.AuthnContext(sess.CurrentAuthnContextID)
	if err != nil {
		return nil, err
	}
	plain := refreshTokenPrefix + seal.RandomSecret(32)
	idle := now.Add(RefreshIdle)
	if idle.After(sess.AbsoluteExpiresAt) {
		idle = sess.AbsoluteExpiresAt
	}
	rt := &store.RefreshToken{TokenHash: hashHex(plain), FamilyID: family, ParentID: parent, SessionID: sess.ID,
		UserID: sess.UserID, ClientID: client.ClientID, DPoPJKT: jkt, Scope: scope, IssuedAt: now, ExpiresAt: idle,
		AbsoluteExpiresAt: sess.AbsoluteExpiresAt}
	if err := tx.InsertRefreshToken(rt); err != nil {
		return nil, err
	}
	at, ttl, err := s.mintAccessToken(mintInput{Slug: t.Slug, User: sess.UserID, Session: sess.ID, ClientID: client.ClientID,
		Scope: scope, AuthTime: rec.AuthTime, ACR: rec.TesseraACR, AMR: rec.AMR, JKT: jkt, Now: now, SigningTx: tx})
	if err != nil {
		return nil, err
	}
	if err := tx.TouchAPIClient(client.ClientID, now); err != nil {
		return nil, err
	}
	action := "oauth.token.issued"
	if parent != nil {
		action = "oauth.refresh.rotated"
		// activity moves the session's idle expiry (the refresh token's idle lifetime)
		if err := tx.TouchSession(sess.ID, now, idle); err != nil {
			return nil, err
		}
	}
	if _, err := audit.Record(tx.Context(), tx, action, ojson.Object{{Key: "grant", Value: grant},
		{Key: "client_id", Value: client.ClientID}, {Key: "jkt", Value: jkt}, {Key: "scope", Value: scope},
		{Key: "session_id", Value: sess.ID.String()}, {Key: "user_id", Value: sess.UserID.String()},
		{Key: "family_id", Value: family.String()}}, audit.At(now), audit.Target("session", sess.ID.String())); err != nil {
		return nil, err
	}
	return &tokenResult{body: map[string]any{"access_token": at, "token_type": "DPoP", "expires_in": int(ttl / time.Second),
		"refresh_token": plain, "scope": scope}}, nil
}

// ---------------------------------------------------------------- refresh_token

func (s *Service) refreshGrant(r *http.Request, t store.Tenant, client *store.APIClient, jkt string) (*tokenResult, error) {
	token, ok := formValue(r, "refresh_token")
	if !ok || token == "" {
		return fail("invalid_request", "refresh_token is required"), nil
	}
	if len(token) > 256 { // not one of ours (a refresh token is 36 characters)
		return fail("invalid_grant", "the refresh token is not valid"), nil
	}
	scopeParam, ok := formValue(r, "scope")
	if !ok {
		return fail("invalid_request", "scope must not repeat"), nil
	}
	hash := hashHex(token)
	now := s.now()
	var res *tokenResult
	err := s.db.InTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		rt, err := tx.RefreshTokenByHash(hash)
		if errors.Is(err, store.ErrNotFound) || (err == nil && rt.ClientID != client.ClientID) {
			res = fail("invalid_grant", "the refresh token is not valid")
			return nil
		}
		if err != nil {
			return err
		}
		// bound to one key: another key gets invalid_grant, and the token is
		// neither used up nor revoked (a thief with the token alone cannot
		// burn the real client's session)
		if subtle.ConstantTimeCompare([]byte(rt.DPoPJKT), []byte(jkt)) != 1 {
			res = fail("invalid_grant", "the refresh token is bound to another key")
			_, err := audit.Record(r.Context(), tx, "oauth.dpop.invalid", ojson.Object{
				{Key: "reason", Value: "refresh token presented with another DPoP key"}, {Key: "endpoint", Value: "token"},
				{Key: "session_id", Value: rt.SessionID.String()}}, audit.At(now), audit.Outcome(store.OutcomeDenied),
				audit.Target("session", rt.SessionID.String()))
			return err
		}
		if rt.RevokedAt != nil {
			res = fail("invalid_grant", "the refresh token has been revoked")
			return nil
		}
		if rt.UsedAt != nil {
			return s.reuseDetected(tx, rt, now, &res)
		}
		if !now.Before(rt.ExpiresAt) {
			res = fail("invalid_grant", "the refresh token has expired (idle)")
			return nil
		}
		if !now.Before(rt.AbsoluteExpiresAt) {
			res = fail("invalid_grant", "the refresh token has expired")
			return nil
		}
		scope := rt.Scope
		if scopeParam != "" {
			for _, f := range strings.Fields(scopeParam) {
				if !slices.Contains(strings.Fields(rt.Scope), f) {
					res = fail("invalid_scope", "a refreshed token cannot gain scopes")
					return nil
				}
			}
			scope = strings.Join(strings.Fields(scopeParam), " ")
		}
		sess, err := tx.Session(rt.SessionID)
		if err != nil {
			return err
		}
		if reason := cliSessionProblem(sess, now); reason != "" {
			res = fail("invalid_grant", reason)
			return nil
		}
		user, err := tx.PlatformUser(sess.UserID)
		if err != nil {
			return err
		}
		if user.Status != "active" {
			res = fail("invalid_grant", "the user is disabled")
			return nil
		}
		if off, err := auth.IdentityInactive(tx, user); err != nil {
			return err
		} else if off {
			res = fail("invalid_grant", "the identity is not active")
			return nil
		}
		// rotation: a compare-and-set, so two requests with one token cannot
		// both succeed; the loser is a reuse
		if err := tx.UseRefreshToken(rt.ID, now); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return s.reuseDetected(tx, rt, now, &res)
			}
			return err
		}
		res, err = s.issue(tx, t, client, sess, scope, jkt, rt.FamilyID, &rt.ID, "refresh_token", now)
		return err
	})
	return res, err
}

// reuseDetected handles a used refresh token presented again (RFC 9700
// §4.14.2): it revokes the whole family and the CLI session and records a
// critical oauth.refresh.reuse_detected. The caller commits it and answers
// invalid_grant.
func (s *Service) reuseDetected(tx *store.TenantTx, rt *store.RefreshToken, now time.Time, res **tokenResult) error {
	n, err := tx.RevokeRefreshFamily(rt.FamilyID, auth.RevokedRTReuse, now)
	if err != nil {
		return err
	}
	sessionRevoked := true
	if err := auth.RevokeSession(tx, rt.SessionID, auth.RevokedRTReuse, now); err != nil {
		if !errors.Is(err, store.ErrSessionInactive) {
			return err
		}
		sessionRevoked = false // it had already ended
	}
	*res = fail("invalid_grant", "the refresh token has already been used; the session was revoked")
	_, err = audit.Record(tx.Context(), tx, "oauth.refresh.reuse_detected", ojson.Object{{Key: "severity", Value: "critical"},
		{Key: "family_id", Value: rt.FamilyID.String()}, {Key: "session_id", Value: rt.SessionID.String()},
		{Key: "user_id", Value: rt.UserID.String()}, {Key: "client_id", Value: rt.ClientID},
		{Key: "tokens_revoked", Value: int(n)}, {Key: "session_revoked", Value: sessionRevoked}},
		audit.At(now), audit.Outcome(store.OutcomeDenied), audit.Target("session", rt.SessionID.String()))
	return err
}

// ---------------------------------------------------------------- revocation

// Revoke is POST /t/{slug}/oauth/revoke (RFC 7009): a refresh token is
// revoked with its family and its CLI session, which ends every access token
// of the session at their next use (access tokens are revoked by revoking
// their session). Possessing the refresh token is the credential; an unknown
// token is answered like a known one.
func (s *Service) Revoke(w http.ResponseWriter, r *http.Request, slug string) {
	t, ok, err := s.tenantBySlug(r.Context(), slug)
	if err != nil {
		serverError(w, s.cfg.Log, r, err)
		return
	}
	if !ok {
		notFound(w)
		return
	}
	ctx := attribute(r.Context(), t.ID)
	r = r.WithContext(ctx)
	if !formBody(w, r) {
		return
	}
	token, ok1 := formValue(r, "token")
	clientID, ok2 := formValue(r, "client_id")
	if !ok1 || !ok2 || token == "" || len(token) > 256 || clientID == "" || len(clientID) > 64 {
		oauthError(w, http.StatusBadRequest, "invalid_request", "token and client_id are required")
		return
	}
	now := s.now()
	err = s.db.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
		rt, err := tx.RefreshTokenByHash(hashHex(token))
		if errors.Is(err, store.ErrNotFound) || (err == nil && rt.ClientID != clientID) {
			// RFC 7009 §2.2: an invalid token is not an error; nothing changed
			_, err := audit.Record(ctx, tx, "oauth.token.revoked", ojson.Object{{Key: "result", Value: "unknown_token"},
				{Key: "client_id", Value: clientID}}, audit.At(now), audit.Outcome(store.OutcomeFailure))
			return err
		}
		if err != nil {
			return err
		}
		n, err := tx.RevokeRefreshFamily(rt.FamilyID, "revoked", now)
		if err != nil {
			return err
		}
		if err := auth.RevokeSession(tx, rt.SessionID, auth.RevokedLogout, now); err != nil && !errors.Is(err, store.ErrSessionInactive) {
			return err
		}
		_, err = audit.Record(ctx, tx, "oauth.token.revoked", ojson.Object{{Key: "result", Value: "revoked"},
			{Key: "client_id", Value: rt.ClientID}, {Key: "session_id", Value: rt.SessionID.String()},
			{Key: "tokens_revoked", Value: int(n)}}, audit.At(now), audit.Target("session", rt.SessionID.String()))
		return err
	})
	if err != nil {
		serverError(w, s.cfg.Log, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------------- client_credentials

// maxScopeParam bounds the scope parameter.
const maxScopeParam = 512

// clientCredentialsGrant is RFC 6749 §4.4 with private_key_jwt client
// authentication (RFC 7523, design §9.5). The client proves itself with a
// signed assertion (clientauth.go) and gets an access token of at most
// AccessTokenTTL, no refresh token, with the scopes it asked for out of the
// ones registered for it (all of them when it asks for none). The token names
// the client, never a user or a session; what it can do is the client's
// configured roles intersected with these scopes, read on every request
// (auth.authenticateMachine). When the client requires DPoP the token is bound
// to the proof's key (jkt); otherwise it is a Bearer token, unless a proof was
// sent.
func (s *Service) clientCredentialsGrant(r *http.Request, t store.Tenant, client *store.APIClient, jkt string,
	asClient audit.Principal) (*tokenResult, error) {
	now := s.now()
	scopeParam, ok := formValue(r, "scope")
	if !ok || len(scopeParam) > maxScopeParam {
		return fail("invalid_request", "scope must appear once and be short"), nil
	}
	params, msg := readClientAuth(r)
	if msg != "" {
		return fail("invalid_request", msg), nil
	}
	if params.clientID != "" && params.clientID != client.ClientID {
		return clientAuthFailed(), nil
	}
	reason, err := s.authenticateClient(r, t.ID, client, params.assertion, s.endpoint(t.Slug, "token"), now)
	if err != nil {
		return nil, err
	}
	if reason != "" {
		return s.clientAuthRefused(r, t, client, "token", reason, now)
	}
	// authenticated: from here the events are the client's
	ctx := audit.SetPrincipal(r.Context(), asClient)
	scope, ok := grantedScope(scopeParam, client.AllowedScopes)
	var res *tokenResult
	err = s.db.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
		if !ok {
			res = fail("invalid_scope", "a scope is not registered for this client")
			_, err := audit.Record(ctx, tx, "oauth.token.refused", ojson.Object{{Key: "grant", Value: GrantClientCredentials},
				{Key: "client_id", Value: client.ClientID}, {Key: "reason", Value: "invalid_scope"}},
				audit.At(now), audit.Outcome(store.OutcomeDenied), audit.Target("api_client", client.ID.String()))
			return err
		}
		// a client that holds permissions its approver lacks gets no token until an admin re-approves it (re-keys it,
		// which checks the creator, or the approver gets the role back): issue #522
		if missing, err := auth.ClientExceedsApprover(tx, client, strings.Fields(scope), now); err != nil {
			return err
		} else if len(missing) > 0 {
			res = fail("unauthorized_client", "the client holds permissions the person who approved it lacks; an admin must re-approve it")
			_, err := audit.Record(ctx, tx, "oauth.token.refused", ojson.Object{{Key: "grant", Value: GrantClientCredentials},
				{Key: "client_id", Value: client.ClientID}, {Key: "reason", Value: "exceeds_approver"},
				{Key: "missing", Value: anyStrings(missing)}},
				audit.At(now), audit.Outcome(store.OutcomeDenied), audit.Target("api_client", client.ID.String()))
			return err
		}
		at, ttl, err := s.mintAccessToken(mintInput{Slug: t.Slug, Machine: true, ClientRowID: client.ID, ClientID: client.ClientID,
			Scope: scope, JKT: jkt, Now: now, SigningTx: tx})
		if err != nil {
			return err
		}
		if err := tx.TouchAPIClient(client.ClientID, now); err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, "oauth.token.issued", ojson.Object{{Key: "grant", Value: GrantClientCredentials},
			{Key: "client_id", Value: client.ClientID}, {Key: "jkt", Value: jkt}, {Key: "scope", Value: scope},
			{Key: "dpop_bound", Value: jkt != ""}}, audit.At(now), audit.Target("api_client", client.ID.String())); err != nil {
			return err
		}
		tokenType := "Bearer"
		if jkt != "" {
			tokenType = "DPoP"
		}
		res = &tokenResult{body: map[string]any{"access_token": at, "token_type": tokenType,
			"expires_in": int(ttl / time.Second), "scope": scope}}
		return nil
	})
	return res, err
}

// grantedScope resolves the scope parameter against the client's registered
// scopes: the requested ones (each must be registered), or all of them when
// none is requested. ok is false for an unregistered scope or an empty result.
func grantedScope(param string, allowed []string) (scope string, ok bool) {
	var out []string
	for _, f := range strings.Fields(param) {
		if !slices.Contains(allowed, f) {
			return "", false
		}
		if !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		out = slices.Clone(allowed)
	}
	if len(out) == 0 {
		return "", false
	}
	return strings.Join(out, " "), true
}

// clientAuthFailed is the invalid_client answer of a failed client
// authentication; it says nothing about why.
func clientAuthFailed() *tokenResult {
	return &tokenResult{status: http.StatusUnauthorized, errMsg: "invalid_client", desc: "client authentication failed"}
}

// clientAuthRefused records oauth.client_auth.failed (the reason is for the
// operator, in the audit log only) and answers invalid_client.
func (s *Service) clientAuthRefused(r *http.Request, t store.Tenant, client *store.APIClient, endpoint, reason string,
	now time.Time) (*tokenResult, error) {
	err := s.db.InTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		_, err := audit.Record(r.Context(), tx, "oauth.client_auth.failed", ojson.Object{{Key: "client_id", Value: client.ClientID},
			{Key: "endpoint", Value: endpoint}, {Key: "reason", Value: reason}},
			audit.At(now), audit.Outcome(store.OutcomeFailure), audit.Target("api_client", client.ID.String()))
		return err
	})
	return clientAuthFailed(), err
}

func anyStrings(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
