package api

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"encoding/pem"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	authnorm "github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/oidcrp"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/samlsp"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// SAML 2.0 sign-in, SP-initiated only (design §9.2, PR9):
//
//	GET  /api/auth/login?tenant=&connection=<saml>  302 to the IdP (signed AuthnRequest, Redirect binding)
//	GET  /api/auth/saml/{connection_id}/metadata    the SP's metadata
//	POST /api/auth/saml/{connection_id}/acs         the ACS (HTTP-POST binding)
//
// The login transaction holds the AuthnRequest ID (InResponseTo) and is
// found by the login cookie AND RelayState (its id). The IdP's POST arrives
// cross-site, so a SameSite=Lax login cookie is not sent with it: the ACS
// then answers with a page that posts the same form again from Tessera's
// origin, where the cookie is sent. The cookie never needs SameSite=None.
// Each assertion ID is used once (replay_cache, until NotOnOrAfter).

// maxACSBody caps the ACS POST (§4 D1), checked before parsing.
const maxACSBody = 256 << 10

func (s *Server) registerSAMLRoutes() {
	s.handle(http.MethodGet, "/api/auth/saml/{connection_id}/metadata", noTenant, publicRoute, s.samlMetadata)
	s.handle(http.MethodPost, "/api/auth/saml/{connection_id}/acs", noTenant, publicRoute, s.samlACS)
}

// SPEntityID is a SAML connection's SP entity ID (and audience): its
// metadata URL.
func SPEntityID(publicURL string, conn uuid.UUID) string {
	return strings.TrimRight(publicURL, "/") + "/api/auth/saml/" + conn.String() + "/metadata"
}

// ACSURL is a SAML connection's assertion consumer service URL.
func ACSURL(publicURL string, conn uuid.UUID) string {
	return strings.TrimRight(publicURL, "/") + "/api/auth/saml/" + conn.String() + "/acs"
}

// samlConnection is the samlsp view of a connection; withKey opens the
// sealed SP key (sign-in), else only the SP certificate is loaded (metadata).
func (s *Server) samlConnection(t tenancy.ID, c *store.IdPConnection, withKey bool) (samlsp.Connection, error) {
	sc := samlsp.Connection{IdPEntityID: deref(c.IdPEntityID), IdPSSOURL: deref(c.IdPSSOURL),
		SPEntityID: SPEntityID(s.cfg.PublicURL, c.ID), ACSURL: ACSURL(s.cfg.PublicURL, c.ID)}
	var pems []string
	if err := json.Unmarshal(c.IdPSigningCerts, &pems); err != nil {
		return sc, err
	}
	var err error
	if sc.IdPCerts, err = samlsp.ParseCerts(pems); err != nil {
		return sc, err
	}
	certPEM := deref(c.SPCertPEM)
	if !withKey {
		if b, _ := pem.Decode([]byte(certPEM)); b != nil && b.Type == "CERTIFICATE" {
			sc.SPCert = b.Bytes
		}
		return sc, nil
	}
	if len(c.SPKeyEnc) == 0 || certPEM == "" {
		return sc, errors.New("api: the SAML connection has no SP key")
	}
	if s.cfg.Sealer == nil {
		return sc, errors.New("api: no sealer to open the SP key")
	}
	keyPEM, err := s.cfg.Sealer.Open(c.SPKeyEnc, auth.SPKeyAAD(t, c.ID))
	if err != nil {
		return sc, err
	}
	sc.SPKey, sc.SPCert, err = samlsp.ParseSPKey(keyPEM, certPEM)
	return sc, err
}

// startSAMLLogin creates the transaction and redirects to the IdP with a
// signed AuthnRequest; a step-up sets ForceAuthn.
func (s *Server) startSAMLLogin(w http.ResponseWriter, r *http.Request, t store.Tenant, c *store.IdPConnection, ls loginStart) (any, error) {
	connKV := ojson.Object{{Key: "connection_id", Value: c.ID.String()}}
	sc, err := s.samlConnection(t.ID, c, true)
	if err != nil {
		s.log.Warn("SAML connection unusable", "connection_id", c.ID, "err", err)
		return s.loginFailure(w, r, t.ID, samlsp.ReasonConfig, connKV)
	}
	now := s.clock().UTC()
	cookie, txnID := seal.RandomSecret(32), uuid.New()
	req, _ := requestedAuthn(c, ls.acr)
	ar, err := samlsp.BuildAuthnRequest(sc, txnID.String(), ls.purpose == "step_up", req.ClassRefs, now)
	if err != nil {
		s.log.Warn("SAML AuthnRequest not built", "connection_id", c.ID, "err", err)
		return s.loginFailure(w, r, t.ID, samlsp.ReasonOf(err), connKV)
	}
	maxAge := loginMaxAge
	if ls.purpose == "step_up" {
		maxAge = ls.maxAge
	}
	acr := ls.acr
	txn := &store.LoginTransaction{ID: txnID, CookieHash: seal.SHA256Hex([]byte(cookie)), IdPConnectionID: c.ID,
		Purpose: ls.purpose, SAMLRequestID: &ar.ID, RequiredTesseraACR: &acr, MaxAge: &maxAge,
		BootstrapInvitationID: ls.invitation, SessionID: ls.session, ExpectedExternalLoginID: ls.expectedLogin,
		ReturnTo: ls.returnTo, CreatedAt: now, ExpiresAt: now.Add(loginTxnTTL)}
	if err := s.store.InTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		if err := tx.InsertLoginTransaction(txn); err != nil {
			return err
		}
		_, err := audit.Record(r.Context(), tx, "auth.login.start", ojson.Object{{Key: "via", Value: "saml"},
			{Key: "purpose", Value: ls.purpose}, {Key: "connection_id", Value: c.ID.String()},
			{Key: "login_transaction_id", Value: txn.ID.String()}, {Key: "required_acr", Value: acr}},
			audit.At(now), audit.Target("login_transaction", txn.ID.String()))
		return err
	}); err != nil {
		return nil, err
	}
	http.SetCookie(w, s.loginCookie(cookie, int(loginTxnTTL/time.Second)))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, ar.URL, http.StatusFound)
	return nil, nil
}

// samlMetadata is GET /api/auth/saml/{connection_id}/metadata. The
// connection's tenant is not in the URL (the entity ID must be stable), so
// the active tenants are searched; an unknown id is a plain 404.
func (s *Server) samlMetadata(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := uuid.Parse(p.path["connection_id"])
	if err != nil {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	var tenants []store.Tenant
	if err := s.store.ReadSystem(r.Context(), "saml metadata tenants", func(st *store.SystemTx) error {
		var err error
		tenants, err = st.ActiveTenants()
		return err
	}); err != nil {
		return nil, err
	}
	var conn *store.IdPConnection
	var tid tenancy.ID
	for _, t := range tenants {
		if t.ID == tenancy.Platform {
			continue
		}
		if err := s.store.ReadTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
			c, err := tx.IdPConnection(id)
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			if err == nil && c.Protocol == "saml" && c.Status != "disabled" {
				conn, tid = c, t.ID
			}
			return err
		}); err != nil {
			return nil, err
		}
		if conn != nil {
			break
		}
	}
	if conn == nil {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	sc, err := s.samlConnection(tid, conn, false)
	if err != nil {
		return nil, err
	}
	b, err := samlsp.Metadata(sc, s.clock())
	if err != nil {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b) // #nosec G705 -- XML built by encoding/xml from the connection's own values, served with nosniff
	return nil, nil
}

// samlACS is POST /api/auth/saml/{connection_id}/acs.
func (s *Server) samlACS(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, maxACSBody)
	if err := r.ParseForm(); err != nil {
		reason := samlsp.ReasonMalformed
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			reason = samlsp.ReasonTooLarge
		}
		return s.loginFailure(w, r, tenancy.ID{}, reason, nil)
	}
	resp, relay := r.PostForm.Get("SAMLResponse"), r.PostForm.Get("RelayState")
	tenant, txnID, reason, err := s.loginTxnFromCookie(r)
	if err != nil {
		return nil, err
	}
	if reason == "login_cookie_missing" && r.PostForm.Get("bounce") == "" && resp != "" {
		return s.samlBounce(w, p.path["connection_id"], resp, relay)
	}
	if reason != "" {
		return s.loginFailure(w, r, tenancy.ID{}, reason, nil)
	}
	tid := tenant.ID
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
		case txn.SAMLRequestID == nil || subtle.ConstantTimeCompare([]byte(relay), []byte(txn.ID.String())) != 1:
			reason = "relay_state_mismatch"
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
		conn, err = tx.IdPConnection(txn.IdPConnectionID)
		if err == nil && (conn.Status != "active" || conn.Protocol != "saml") {
			reason = "connection_disabled"
		}
		return err
	}); err != nil {
		return nil, err
	}
	stepUp := txn != nil && txn.Purpose == "step_up"
	fail := func(reason string, extra ojson.Object) (any, error) {
		extra = append(ojson.Object{{Key: "login_transaction_id", Value: txnID.String()}}, extra...)
		if stepUp && reason != "connection_mismatch" && reason != "relay_state_mismatch" {
			return s.stepUpFailure(w, r, tid, txn, "auth.step_up.failure", reason, extra[1:])
		}
		return s.loginFailure(w, r, tid, reason, extra)
	}
	if reason != "" {
		return fail(reason, nil)
	}
	sc, err := s.samlConnection(tid, conn, true)
	if err != nil {
		s.log.Warn("SAML connection unusable", "connection_id", conn.ID, "err", err)
		return fail(samlsp.ReasonConfig, nil)
	}
	a, err := samlsp.ValidateResponse(sc, resp, samlsp.Expect{RequestID: deref(txn.SAMLRequestID), Now: now})
	if err != nil {
		s.log.Info("SAML response refused", "err", err, "request_id", audit.RequestID(ctx))
		return fail(samlsp.ReasonOf(err), nil)
	}
	return s.finishAssertion(w, r, tenant, conn, txn, sc.IdPEntityID, a, fail)
}

// finishAssertion completes a sign-in from a verified SAML 2.0 assertion
// (SAML ACS, WS-Federation): freshness, one use per assertion ID, the
// subject, normalization, then the session or the step-up.
func (s *Server) finishAssertion(w http.ResponseWriter, r *http.Request, tenant store.Tenant, conn *store.IdPConnection,
	txn *store.LoginTransaction, idpEntityID string, a *samlsp.Assertion, fail func(string, ojson.Object) (any, error)) (any, error) {
	ctx := r.Context()
	now := s.clock().UTC()
	stepUp := txn.Purpose == "step_up"
	// freshness: max_age at sign-in, and a step-up must have re-authenticated
	// after it started (ForceAuthn alone is only a request)
	if txn.MaxAge != nil && now.Sub(a.AuthnInstant) > time.Duration(*txn.MaxAge)*time.Second+oidcrp.AuthTimeSkew && !stepUp {
		return fail(oidcrp.ReasonAuthTimeStale, nil)
	}
	if stepUp && a.AuthnInstant.Before(txn.CreatedAt.Add(-oidcrp.StepUpSkew)) {
		return fail(oidcrp.ReasonAuthTimeStale, nil)
	}
	// one use per assertion ID (per IdP), kept until it expires
	used := seal.SHA256Hex([]byte(idpEntityID + "\x00" + a.ID))
	if err := s.store.InSystem(ctx, "saml replay cache", func(st *store.SystemTx) error {
		return st.UseOnce(store.ReplaySAMLAssertion, used, now, a.NotOnOrAfter.Add(samlsp.Skew))
	}); errors.Is(err, store.ErrDuplicate) {
		return fail(samlsp.ReasonReplay, nil)
	} else if err != nil {
		return nil, err
	}
	subject, ok := samlSubject(conn, a)
	if !ok {
		return fail(samlsp.ReasonSubject, ojson.Object{{Key: "subject_source", Value: conn.SubjectSource}})
	}
	mapping, err := authnorm.ParseMapping(conn.AuthnMapping)
	if err != nil {
		return nil, err
	}
	req, _ := requestedAuthn(conn, deref(txn.RequiredTesseraACR))
	at := a.AuthnInstant
	res, err := authnorm.Normalize(authnorm.Connection{Profile: conn.Profile, Mapping: mapping,
		AssumePhishingResistant: conn.AssumePhishingResistant}, req,
		authnorm.Claims{Subject: subject, ClassRef: a.ClassRef, Attributes: a.Attributes, AuthTime: &at, Raw: a.Raw})
	if err != nil {
		return fail("normalization_failed", nil)
	}
	if stepUp {
		return s.finishStepUp(w, r, tenant, conn, txn, res)
	}
	return s.finishLogin(w, r, tenant, conn, txn, samlProfile(conn, a), res)
}

// samlSubject is the user's key at the connection (subject_source): the
// persistent NameID (default), or attribute:<name> with exactly one value.
func samlSubject(conn *store.IdPConnection, a *samlsp.Assertion) (string, bool) {
	if name, ok := strings.CutPrefix(conn.SubjectSource, "attribute:"); ok {
		if v := a.Attributes[name]; len(v) == 1 && strings.TrimSpace(v[0]) != "" && len(v[0]) <= 256 {
			return v[0], true
		}
		return "", false
	}
	if conn.SubjectSource != "" && conn.SubjectSource != "nameid_persistent" {
		return "", false
	}
	return a.Subject, a.NameIDFormat == samlsp.NameIDPersistent && a.Subject != ""
}

// samlProfile reads display data and groups through attribute_map
// ({"email": , "name": , "groups": } attribute names; defaults email,
// displayName and groups_claim or groups).
func samlProfile(conn *store.IdPConnection, a *samlsp.Assertion) idpProfile {
	return attributeProfile(conn, a.Attributes, "groups")
}

// attributeProfile reads email, name and groups from attributes (SAML,
// CAS) through attribute_map, with the defaults email, displayName and
// groups_claim or defaultGroups.
func attributeProfile(conn *store.IdPConnection, attrs map[string][]string, defaultGroups string) idpProfile {
	m := map[string]string{"email": "email", "name": "displayName", "groups": defaultGroups}
	if conn.GroupsClaim != nil && *conn.GroupsClaim != "" {
		m["groups"] = *conn.GroupsClaim
	}
	var custom map[string]string
	if json.Unmarshal(conn.AttributeMap, &custom) == nil {
		for k, v := range custom {
			if _, ok := m[k]; ok && v != "" {
				m[k] = v
			}
		}
	}
	first := func(k string) string {
		if v := attrs[m[k]]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	return idpProfile{email: first("email"), name: first("name"), groups: attrs[m["groups"]]}
}

var bounceTmpl = template.Must(template.New("bounce").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Signing in to Tessera</title></head><body>
<form method="post" action="{{.Action}}">
{{range .Fields}}<input type="hidden" name="{{index . 0}}" value="{{index . 1}}">
{{end}}<input type="hidden" name="bounce" value="1">
<noscript><p>Signing in to Tessera.</p><button type="submit">Continue</button></noscript>
</form>
<script nonce="{{.Nonce}}">document.forms[0].submit()</script>
</body></html>`))

// samlBounce re-posts the IdP's form from Tessera's own origin, so the
// SameSite=Lax login cookie comes with it. It checks nothing and creates
// nothing: the second POST is validated like any other.
func (s *Server) samlBounce(w http.ResponseWriter, connID, resp, relay string) (any, error) {
	id, err := uuid.Parse(connID)
	if err != nil {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	return s.formBounce(w, ACSURL(s.cfg.PublicURL, id), [][2]string{{"SAMLResponse", resp}, {"RelayState", relay}})
}

// formBounce answers a cross-site form POST with a page that posts fields
// (plus bounce=1) again to action, from Tessera's origin.
func (s *Server) formBounce(w http.ResponseWriter, action string, fields [][2]string) (any, error) {
	nonce := seal.RandomSecret(16)
	var buf bytes.Buffer
	if err := bounceTmpl.Execute(&buf, struct {
		Action, Nonce string
		Fields        [][2]string
	}{action, nonce, fields}); err != nil {
		return nil, err
	}
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; form-action 'self'; "+
		"frame-ancestors 'none'; base-uri 'none'")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes()) // #nosec G705 -- html/template escapes the posted values; CSP allows only this nonce
	return nil, nil
}
