package oauth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Token introspection (RFC 7662, design §16.1): a machine client that
// authenticates with private_key_jwt and holds the tessera:introspect scope
// (registered for it, so that gateways can be given just this capability) asks
// whether an access token of its own tenant is active. The assertion's aud is
// the introspection endpoint's URL. Anything that is not an active token of
// this tenant, whatever the reason, is {"active": false} (RFC 7662 §2.2): the
// answer never says why, and never leaks another tenant's tokens. An active
// token is the same one the API would accept now: signature, claims, its
// client, and for a user's token its live session and user. The DPoP proof of
// the token's holder is not part of it: the caller is not the holder.

// Introspect is POST /t/{slug}/oauth/introspect.
func (s *Service) Introspect(w http.ResponseWriter, r *http.Request, slug string) {
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
	params, msg := readClientAuth(r)
	token, ok1 := formValue(r, "token")
	switch {
	case msg != "":
		oauthError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	case !ok1 || token == "" || len(token) > MaxTokenBytes:
		oauthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	clientID := params.clientID
	if clientID == "" { // the assertion names its client (RFC 7523 §3)
		if a, err := ParseClientAssertion(params.assertion); err == nil {
			clientID = a.UnverifiedIssuer()
		}
	}
	if clientID == "" || len(clientID) > 64 {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	var client *store.APIClient
	err = s.db.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) error {
		var err error
		client, err = tx.APIClientByClientID(clientID)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if err != nil {
		serverError(w, s.cfg.Log, r, err)
		return
	}
	now := s.now()
	reason, err := s.authenticateClient(r, t.ID, client, params.assertion, s.endpoint(slug, "introspect"), now)
	if err != nil {
		serverError(w, s.cfg.Log, r, err)
		return
	}
	if reason != "" {
		res, err := s.clientAuthRefused(r, t, client, "introspect", reason, now)
		if err != nil {
			serverError(w, s.cfg.Log, r, err)
			return
		}
		oauthError(w, res.status, res.errMsg, res.desc)
		return
	}
	// authenticated: from here the events are the client's
	ctx = audit.SetPrincipal(ctx, audit.Principal{Tenant: t.ID, ClientID: &client.ClientID,
		Actor: store.AuditActor{Type: store.ActorAPIClient, ID: &client.ClientID, Display: &client.Name}})
	r = r.WithContext(ctx)
	if !slices.Contains(client.AllowedScopes, ScopeIntrospect) {
		err = s.db.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			_, err := audit.Record(ctx, tx, "oauth.token.introspected", ojson.Object{{Key: "client_id", Value: client.ClientID},
				{Key: "result", Value: "insufficient_scope"}}, audit.At(now), audit.Outcome(store.OutcomeDenied),
				audit.Target("api_client", client.ID.String()))
			return err
		})
		if err != nil {
			serverError(w, s.cfg.Log, r, err)
			return
		}
		oauthError(w, http.StatusForbidden, "insufficient_scope", "this client may not introspect tokens")
		return
	}
	body, jti, err := s.introspection(ctx, t, token, now)
	if err != nil {
		serverError(w, s.cfg.Log, r, err)
		return
	}
	err = s.db.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
		_, err := audit.Record(ctx, tx, "oauth.token.introspected", ojson.Object{{Key: "client_id", Value: client.ClientID},
			{Key: "active", Value: body["active"] == true}, {Key: "jti", Value: jti}},
			audit.At(now), audit.Target("api_client", client.ID.String()))
		return err
	})
	if err != nil {
		serverError(w, s.cfg.Log, r, err)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// introspection is the RFC 7662 response for token in tenant t, and the jti of
// an active one (for the audit event).
func (s *Service) introspection(ctx context.Context, t store.Tenant, token string, now time.Time) (map[string]any, string, error) {
	inactive := map[string]any{"active": false}
	ct, reason, err := s.checkAccessToken(ctx, token, now)
	if err != nil {
		return nil, "", err
	}
	// checkClaims allows a token that expired up to 30 s ago; introspection does not
	if reason != "" || ct.tenant.ID != t.ID || !time.Unix(int64(*ct.c.Expiry), 0).After(now) {
		return inactive, "", nil
	}
	c := ct.c
	if c.SessionID != "" { // a user's token: its CLI session and the user must be live
		live := false
		err := s.db.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			sid, err := uuid.Parse(c.SessionID)
			if err != nil {
				return nil
			}
			sess, err := tx.Session(sid)
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			if sub, _ := strings.CutPrefix(c.Subject, SubjectPrefix); sess.Kind != store.SessionCLI ||
				sess.UserID.String() != sub || sess.Status != store.SessionActive ||
				!now.Before(sess.IdleExpiresAt) || !now.Before(sess.AbsoluteExpiresAt) {
				return nil
			}
			u, err := tx.PlatformUser(sess.UserID)
			if err != nil {
				return err
			}
			live = u.Status == "active"
			return nil
		})
		if err != nil {
			return nil, "", err
		}
		if !live {
			return inactive, "", nil
		}
	}
	tokenType := "Bearer"
	body := map[string]any{"active": true, "scope": c.Scope, "client_id": c.ClientID, "sub": c.Subject, "iss": c.Issuer,
		"aud": s.cfg.APIAudience, "jti": c.JTI, "exp": int64(*c.Expiry), "iat": int64(*c.IssuedAt)}
	if c.NotBefore != nil {
		body["nbf"] = int64(*c.NotBefore)
	}
	if c.Cnf != nil { // RFC 9449 §6.2
		tokenType = "DPoP"
		body["cnf"] = map[string]string{"jkt": c.Cnf.JKT}
	}
	body["token_type"] = tokenType
	return body, c.JTI, nil
}
