package oauth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/ratelimit"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The device authorization grant (RFC 8628, design §9.3): the CLI asks for a
// device code and a short user code, the user approves the user code in the
// browser (after a fresh phishing-resistant sign-in), and the CLI polls the
// token endpoint (grants.go).
//
// Device-code phishing controls (§9.3): only the first-party CLI client may
// use the grant; codes live 300 s and work once; the approval page shows who
// asked and from where; approval needs authentication within 300 s at the
// required ACR; a tenant can switch the grant off; device_authorization is
// limited to 10 per minute per IP and user-code lookups to 5 failures per
// session per 10 minutes; polling faster than the interval gets slow_down.
// There is no verification_uri_complete: the user types the code.

// userCodeAlphabet has no vowels and no look-alikes: 20 characters, 8 of them
// give about 34.6 bits.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

const userCodeLen = 8

// newUserCode returns a user code as shown (XXXX-XXXX) and in normalized form.
func newUserCode() (display, normalized string) {
	n := seal.RandomString(userCodeLen, userCodeAlphabet)
	return n[:4] + "-" + n[4:], n
}

// normalizeUserCode uppercases the input and drops dashes and spaces; ok is
// false unless the result is exactly eight characters of the alphabet.
func normalizeUserCode(in string) (string, bool) {
	if len(in) > 32 {
		return "", false
	}
	n := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(in))
	if len(n) != userCodeLen {
		return "", false
	}
	for _, c := range n {
		if !strings.ContainsRune(userCodeAlphabet, c) {
			return "", false
		}
	}
	return n, true
}

// parseACR maps the acr_values of a device authorization to a Tessera ACR.
func parseACR(v string) (auth.ACR, bool) {
	switch a := auth.ACR(strings.TrimSpace(v)); a {
	case auth.ACRAAL2, auth.ACRPhr, auth.ACRPhrh:
		return a, true
	}
	return "", false
}

// DeviceAuthorization is POST /t/{slug}/oauth/device_authorization (RFC 8628
// §3.1).
func (s *Service) DeviceAuthorization(w http.ResponseWriter, r *http.Request, slug string) {
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
	if !s.devAuth.AllowAt(ratelimit.IPKey(ipOf(s.cfg.ClientIP(r))), s.now()) {
		w.Header().Set("Retry-After", "6")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}
	if !formBody(w, r) {
		return
	}
	clientID, ok1 := formValue(r, "client_id")
	scopeParam, ok2 := formValue(r, "scope")
	acrParam, ok3 := formValue(r, "acr_values")
	maxAgeParam, ok4 := formValue(r, "max_age")
	if !ok1 || !ok2 || !ok3 || !ok4 || clientID == "" || len(clientID) > 64 {
		oauthError(w, http.StatusBadRequest, "invalid_request", "client_id is required and parameters must not repeat")
		return
	}
	var reqACR *string
	if acrParam != "" {
		a, ok := parseACR(acrParam)
		if !ok {
			oauthError(w, http.StatusBadRequest, "invalid_request", "acr_values must be one Tessera ACR (aal2, phr or phrh)")
			return
		}
		v := string(a)
		reqACR = &v
	}
	var maxAge *int
	if maxAgeParam != "" {
		n, err := strconv.Atoi(maxAgeParam)
		if err != nil || n < 0 || n > 900 {
			oauthError(w, http.StatusBadRequest, "invalid_request", "max_age must be from 0 to 900")
			return
		}
		maxAge = &n
	}
	now := s.now()
	var resp map[string]any
	var refuse func()
	err = s.db.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
		client, err := tx.APIClientByClientID(clientID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && client.Status != store.ClientActive) {
			refuse = func() { oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown client") }
			return nil
		}
		if err != nil {
			return err
		}
		denied := func(reason, desc string) error {
			refuse = func() { oauthError(w, http.StatusBadRequest, "unauthorized_client", desc) }
			_, err := audit.Record(ctx, tx, "oauth.device.refused", ojson.Object{{Key: "client_id", Value: clientID},
				{Key: "reason", Value: reason}}, audit.At(now), audit.Outcome(store.OutcomeDenied))
			return err
		}
		switch {
		case client.Kind != store.ClientFirstPartyCLI || !slices.Contains(client.GrantTypes, GrantDeviceCode):
			return denied("client_not_allowed", "this client may not use the device authorization grant")
		case !DeviceGrantEnabled(t.Settings):
			return denied("tenant_disabled", "device sign-in is turned off for this organization")
		}
		scope, ok := grantScope(scopeParam, client.AllowedScopes)
		if !ok {
			refuse = func() { oauthError(w, http.StatusBadRequest, "invalid_scope", "unknown or disallowed scope") }
			return nil
		}
		if _, err := tx.ExpireStaleDeviceGrants(now); err != nil {
			return err
		}
		ip, ua := s.cfg.ClientIP(r), truncate(r.UserAgent(), 256)
		g := &store.DeviceGrant{ClientID: client.ClientID, Scope: scope, RequiredTesseraACR: reqACR, MaxAge: maxAge,
			Interval: DeviceInterval, CreatedAt: now, ExpiresAt: now.Add(s.cfg.DeviceCodeTTL), RequestIP: &ip}
		if ua != "" {
			g.RequestUserAgent = &ua
		}
		deviceCode := seal.RandomSecret(32)
		g.DeviceCodeHash = hashHex(deviceCode)
		var display string
		for range 8 { // a user-code collision among pending grants is retried
			var normalized string
			display, normalized = newUserCode()
			g.UserCodeHash = hashHex(normalized)
			if err = tx.InsertDeviceGrant(g); !errors.Is(err, store.ErrDuplicate) {
				break
			}
		}
		if err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, "oauth.device.created", ojson.Object{{Key: "grant_id", Value: g.ID.String()},
			{Key: "client_id", Value: client.ClientID}, {Key: "scope", Value: scope}, {Key: "request_ip", Value: ip}},
			audit.At(now), audit.Target("device_grant", g.ID.String())); err != nil {
			return err
		}
		resp = map[string]any{"device_code": deviceCode, "user_code": display, "verification_uri": s.cfg.PublicURL + "/device",
			"expires_in": int(s.cfg.DeviceCodeTTL / time.Second), "interval": DeviceInterval}
		return nil
	})
	switch {
	case err != nil:
		serverError(w, s.cfg.Log, r, err)
	case refuse != nil:
		refuse()
	default:
		writeJSON(w, http.StatusOK, resp)
	}
}

// grantScope validates a requested scope string against what a client may
// ask for and returns the normalized scope (the default when none is asked).
func grantScope(requested string, allowed []string) (string, bool) {
	fields := strings.Fields(requested)
	if len(fields) == 0 {
		fields = []string{DefaultScope}
	}
	var out []string
	for _, f := range fields {
		if !slices.Contains(allowed, f) {
			return "", false
		}
		if !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return strings.Join(out, " "), true
}

func truncate(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}

// ---------------------------------------------------------------- lookup and approval

// deviceRequest is the body of the lookup and approve routes.
type deviceRequest struct {
	UserCode string `json:"user_code"`
	Decision string `json:"decision"`
}

func readDeviceRequest(w http.ResponseWriter, r *http.Request) (*deviceRequest, bool) {
	var req deviceRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || dec.More() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return nil, false
	}
	return &req, true
}

// devicePrincipal is the signed-in browser user a lookup or approval is for.
// A token principal (the CLI itself, or a machine client) is refused: a
// device must be approved by a person in a browser.
func devicePrincipal(w http.ResponseWriter, r *http.Request) (*auth.Principal, bool) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		auth.WriteDenial(w, &auth.Denial{Status: http.StatusUnauthorized, Error: "login_required"})
		return nil, false
	}
	if p.Kind != auth.KindUser || p.Via != auth.ViaCookie || p.SessionID == nil || p.UserID == nil || p.Session() == nil {
		auth.WriteDenial(w, &auth.Denial{Status: http.StatusForbidden, Error: "interactive_authentication_required"})
		return nil, false
	}
	return p, true
}

// lookupGate returns false (and has answered 429) while the session is locked
// out of user-code lookups.
func (s *Service) lookupGate(w http.ResponseWriter, p *auth.Principal) bool {
	if until, locked := s.lockouts.locked(p.SessionID.String(), s.now()); locked {
		tooManyLookups(w, until.Sub(s.now()))
		return false
	}
	return true
}

func tooManyLookups(w http.ResponseWriter, wait time.Duration) {
	secs := max(int((wait+time.Second-1)/time.Second), 1)
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "lookup_locked", "retry_after": secs})
}

// lookupFailed records a failed user-code lookup or approval for the session,
// audits it (and, when it starts the lockout, oauth.device.lookup_bruteforce)
// and answers.
func (s *Service) lookupFailed(w http.ResponseWriter, r *http.Request, p *auth.Principal, action string) {
	now := s.now()
	until, locked := s.lockouts.fail(p.SessionID.String(), now)
	err := s.db.InTenant(r.Context(), p.TenantID, func(tx *store.TenantTx) error {
		if _, err := audit.Record(r.Context(), tx, "oauth.device.lookup", ojson.Object{{Key: "result", Value: "not_found"},
			{Key: "via", Value: action}}, audit.At(now), audit.Outcome(store.OutcomeFailure)); err != nil {
			return err
		}
		if !locked {
			return nil
		}
		_, err := audit.Record(r.Context(), tx, "oauth.device.lookup_bruteforce", ojson.Object{
			{Key: "severity", Value: "critical"}, {Key: "failures", Value: lookupMaxFailures},
			{Key: "session_id", Value: p.SessionID.String()},
			{Key: "locked_until", Value: store.RT(until)}}, audit.At(now), audit.Outcome(store.OutcomeDenied),
			audit.Target("session", p.SessionID.String()))
		return err
	})
	switch {
	case err != nil:
		serverError(w, s.cfg.Log, r, err)
	case locked:
		tooManyLookups(w, until.Sub(now))
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invalid_user_code",
			"detail": "That code is not valid, or it has expired. Run the command again to get a new one."})
	}
}

// DeviceLookup is POST /api/auth/device/lookup {user_code}: what the browser
// shows before the user decides (client, address, time, scope). The caller's
// principal is in the request context (the API's authorize step).
func (s *Service) DeviceLookup(w http.ResponseWriter, r *http.Request) {
	p, ok := devicePrincipal(w, r)
	if !ok || !s.lookupGate(w, p) {
		return
	}
	req, ok := readDeviceRequest(w, r)
	if !ok {
		return
	}
	now := s.now()
	code, valid := normalizeUserCode(req.UserCode)
	var g *store.DeviceGrant
	var client *store.APIClient
	if valid {
		err := s.db.ReadTenant(r.Context(), p.TenantID, func(tx *store.TenantTx) error {
			var err error
			if g, err = tx.PendingDeviceGrantByUserCodeHash(hashHex(code), now); errors.Is(err, store.ErrNotFound) {
				g = nil
				return nil
			} else if err != nil {
				return err
			}
			client, err = tx.APIClientByClientID(g.ClientID)
			return err
		})
		if err != nil {
			serverError(w, s.cfg.Log, r, err)
			return
		}
	}
	if g == nil {
		s.lookupFailed(w, r, p, "lookup")
		return
	}
	if err := s.db.InTenant(r.Context(), p.TenantID, func(tx *store.TenantTx) error {
		_, err := audit.Record(r.Context(), tx, "oauth.device.lookup", ojson.Object{{Key: "result", Value: "found"},
			{Key: "grant_id", Value: g.ID.String()}}, audit.At(now), audit.Target("device_grant", g.ID.String()))
		return err
	}); err != nil {
		serverError(w, s.cfg.Log, r, err)
		return
	}
	req2 := requirementFor(g)
	writeJSON(w, http.StatusOK, map[string]any{
		"client":       client.Name,
		"client_id":    client.ClientID,
		"scope":        strings.Fields(g.Scope),
		"requested_at": store.RT(g.CreatedAt),
		"request_ip":   deref(g.RequestIP),
		"expires_at":   store.RT(g.ExpiresAt),
		"requires":     map[string]any{"acr": string(req2.ACR), "max_age": int(req2.MaxAge / time.Second)},
	})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// requirementFor is what approving g needs of the browser's authentication:
// StepUpAdmin (phishing-resistant, within 300 s), raised by the stronger ACR
// or the shorter max_age the CLI asked for (RFC 9470 acr_values and max_age).
func requirementFor(g *store.DeviceGrant) auth.AuthnRequirement {
	req := auth.StepUpAdmin
	if g.RequiredTesseraACR != nil && auth.ACR(*g.RequiredTesseraACR).Rank() > req.ACR.Rank() {
		req.ACR = auth.ACR(*g.RequiredTesseraACR)
	}
	if g.MaxAge != nil {
		// max_age=0 asks for an authentication right now; AuthnRequirement
		// reads a zero MaxAge as "no limit", so it becomes one second
		m := max(time.Duration(*g.MaxAge)*time.Second, time.Second)
		if m < req.MaxAge {
			req.MaxAge = m
		}
	}
	return req
}

// DeviceApprove is POST /api/auth/device/approve {user_code, decision}. The
// session must have authenticated within 300 s at the required ACR (§9.3
// control 3): otherwise 401 step_up_required, and the browser re-authenticates
// and repeats the call. Approval creates the CLI session (kind=cli) whose
// authentication context is the approving one, and records
// oauth.device.approved in the same transaction.
func (s *Service) DeviceApprove(w http.ResponseWriter, r *http.Request) {
	p, ok := devicePrincipal(w, r)
	if !ok {
		return
	}
	now := s.now()
	if d := auth.Check(p, auth.PermAuthenticated, &auth.StepUpAdmin, now); d != nil {
		auth.WriteDenial(w, d)
		return
	}
	if !s.lookupGate(w, p) {
		return
	}
	req, ok := readDeviceRequest(w, r)
	if !ok {
		return
	}
	if req.Decision != "approve" && req.Decision != "deny" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "detail": "decision must be approve or deny"})
		return
	}
	code, valid := normalizeUserCode(req.UserCode)
	var g *store.DeviceGrant
	if valid {
		err := s.db.ReadTenant(r.Context(), p.TenantID, func(tx *store.TenantTx) error {
			var err error
			if g, err = tx.PendingDeviceGrantByUserCodeHash(hashHex(code), now); errors.Is(err, store.ErrNotFound) {
				g = nil
				return nil
			}
			return err
		})
		if err != nil {
			serverError(w, s.cfg.Log, r, err)
			return
		}
	}
	if g == nil {
		s.lookupFailed(w, r, p, "approve")
		return
	}
	// the stronger requirement this particular device asked for
	if need := requirementFor(g); !p.Authn.Satisfies(need, now) {
		auth.WriteDenial(w, &auth.Denial{Status: http.StatusUnauthorized, Error: "step_up_required",
			Permission: auth.PermAuthenticated, Requirement: &need})
		return
	}
	var tenant store.Tenant
	if err := s.db.ReadSystem(r.Context(), "device approval tenant", func(st *store.SystemTx) error {
		var err error
		tenant, err = st.TenantByID(p.TenantID)
		return err
	}); err != nil {
		serverError(w, s.cfg.Log, r, err)
		return
	}
	var status string
	err := s.db.InTenant(r.Context(), p.TenantID, func(tx *store.TenantTx) error {
		if req.Decision == "deny" {
			if err := tx.DenyDeviceGrant(g.ID, *p.UserID, now); err != nil {
				return err
			}
			status = "denied"
			_, err := audit.Record(r.Context(), tx, "oauth.device.denied", ojson.Object{{Key: "grant_id", Value: g.ID.String()},
				{Key: "client_id", Value: g.ClientID}}, audit.At(now), audit.Target("device_grant", g.ID.String()))
			return err
		}
		client, err := tx.APIClientByClientID(g.ClientID)
		if err != nil {
			return err
		}
		if client.Status != store.ClientActive || client.Kind != store.ClientFirstPartyCLI || !DeviceGrantEnabled(tenant.Settings) {
			return errDeviceGrantRefused
		}
		user, err := tx.PlatformUser(*p.UserID)
		if err != nil {
			return err
		}
		if off, err := auth.IdentityInactive(tx, user); err != nil {
			return err
		} else if off {
			return errIdentityInactive
		}
		rec, err := tx.AuthnContext(p.Session().CurrentAuthnContextID)
		if err != nil {
			return err
		}
		sess, err := auth.CreateCLISession(tx, auth.CLISessionInput{User: user, Authn: rec, ClientID: g.ClientID,
			IP: g.RequestIP, UA: g.RequestUserAgent, Settings: auth.TenantSettings(tenant.Settings), Now: now})
		if err != nil {
			return err
		}
		if err := tx.ApproveDeviceGrant(g.ID, user.ID, rec.ID, sess.ID, now); err != nil {
			return err
		}
		status = "approved"
		_, err = audit.Record(r.Context(), tx, "oauth.device.approved", ojson.Object{{Key: "grant_id", Value: g.ID.String()},
			{Key: "client_id", Value: g.ClientID}, {Key: "scope", Value: g.Scope}, {Key: "cli_session_id", Value: sess.ID.String()},
			{Key: "authn_context_id", Value: rec.ID.String()}, {Key: "request_ip", Value: deref(g.RequestIP)}},
			audit.At(now), audit.Target("device_grant", g.ID.String()))
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		// expired or decided between the read and the write
		s.lookupFailed(w, r, p, "approve")
	case errors.Is(err, errIdentityInactive):
		auth.WriteDenial(w, &auth.Denial{Status: http.StatusUnauthorized, Error: "login_required"})
	case errors.Is(err, errDeviceGrantRefused):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "device_grant_disabled",
			"detail": "Command-line sign-in is turned off for this organization."})
	case err != nil:
		serverError(w, s.cfg.Log, r, err)
	default:
		writeJSON(w, http.StatusOK, map[string]string{"status": status})
	}
}

var errIdentityInactive = errors.New("oauth: the approving user's identity is not active")

var errDeviceGrantRefused = errors.New("oauth: the device grant is not allowed for this client or tenant")

// ipOf parses the client address text of Config.ClientIP into a limiter key
// address; text that is not an address shares the "invalid" bucket.
func ipOf(s string) netip.Addr {
	a, _ := netip.ParseAddr(s)
	return a.Unmap()
}
