package oauth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

var userCodeRE = regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`)

// decodeJWT reads a token's header and claims without verifying it.
func decodeJWT(t testing.TB, token string) (hdr, claims map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %.40s", token)
	}
	for i, dst := range []*map[string]any{&hdr, &claims} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil || json.Unmarshal(b, dst) != nil {
			t.Fatalf("JWT part %d is not base64url JSON", i)
		}
	}
	return hdr, claims
}

// TestDeviceFlow is the whole RFC 8628 flow through the HTTP routes:
// authorization, the DPoP nonce, authorization_pending, slow_down, the
// browser's lookup and approval, and the token response with its DPoP binding.
func TestDeviceFlow(t *testing.T) {
	h := newHarness(t)
	k := newKey(t)
	d := h.startDevice(slugA, nil)

	t.Run("authorization response", func(t *testing.T) {
		if !userCodeRE.MatchString(d.UserCode) {
			t.Errorf("user code %q is not XXXX-XXXX over the 20-letter alphabet", d.UserCode)
		}
		if d.ExpiresIn != 300 || d.Interval != 5 || len(d.DeviceCode) < 43 {
			t.Errorf("expires_in %d, interval %d, device_code of %d characters", d.ExpiresIn, d.Interval, len(d.DeviceCode))
		}
		if d.VerificationURI != h.srv.URL+"/device" {
			t.Errorf("verification_uri = %q", d.VerificationURI)
		}
		// the user types the code: no pre-filled URL, no QR payload
		for _, k := range []string{"verification_uri_complete", "verification_url_complete", "qr"} {
			if _, ok := d.Raw.Body[k]; ok || strings.Contains(d.Raw.Raw, k) {
				t.Errorf("the response has %q", k)
			}
		}
		if cc := d.Raw.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q", cc)
		}
	})

	t.Run("polling needs a DPoP proof with the server nonce", func(t *testing.T) {
		form := url.Values{"grant_type": {GrantDeviceCode}, "client_id": {CLIClientID}, "device_code": {d.DeviceCode}}
		if r := h.postForm("/t/"+slugA+"/oauth/token", form, nil); r.Status != 400 || r.str("error") != "invalid_dpop_proof" {
			t.Errorf("no proof: %d %s", r.Status, r.Raw)
		}
		target := h.srv.URL + "/t/" + slugA + "/oauth/token"
		r := h.postForm("/t/"+slugA+"/oauth/token", form, map[string]string{"DPoP": h.proof(k, "POST", target, "", "")})
		nonce := r.Header.Get("DPoP-Nonce")
		if r.Status != 400 || r.str("error") != "use_dpop_nonce" || nonce == "" {
			t.Fatalf("no nonce: %d %s nonce=%q", r.Status, r.Raw, nonce)
		}
		// that attempt was not a poll: the first real poll is pending, not slow_down
		r = h.postForm("/t/"+slugA+"/oauth/token", form, map[string]string{"DPoP": h.proof(k, "POST", target, "", nonce)})
		if r.Status != 400 || r.str("error") != "authorization_pending" {
			t.Errorf("poll with the nonce: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("slow_down raises the interval by 5 s each time", func(t *testing.T) {
		if r := h.devicePoll(slugA, d, k); r.str("error") != "slow_down" {
			t.Errorf("immediate repeat: %d %s", r.Status, r.Raw)
		}
		h.clock.Advance(6 * time.Second) // more than 5 s, less than the new 10 s
		if r := h.devicePoll(slugA, d, k); r.str("error") != "slow_down" {
			t.Errorf("after 6 s at interval 10: %d %s", r.Status, r.Raw)
		}
		h.clock.Advance(16 * time.Second) // at least the new 15 s
		if r := h.devicePoll(slugA, d, k); r.str("error") != "authorization_pending" {
			t.Errorf("after 16 s at interval 15: %d %s", r.Status, r.Raw)
		}
	})

	l := h.login(slugA, "alice@a.example", []auth.Role{auth.RoleViewer}, authtest.Phr)
	t.Run("lookup shows who is asking", func(t *testing.T) {
		r := h.browser(l, "POST", "/api/auth/device/lookup", map[string]string{"user_code": strings.ToLower(d.UserCode)})
		if r.Status != 200 || r.str("client") != "Tessera CLI" || r.str("client_id") != CLIClientID || r.str("request_ip") == "" ||
			r.str("requested_at") == "" {
			t.Fatalf("lookup: %d %s", r.Status, r.Raw)
		}
		if sc, _ := r.Body["scope"].([]any); len(sc) != 2 {
			t.Errorf("scope = %v", r.Body["scope"])
		}
		if strings.Contains(r.Raw, d.DeviceCode) {
			t.Error("the lookup response carries the device code")
		}
	})
	t.Run("approval", func(t *testing.T) {
		if r := h.approve(l, d.UserCode, "approve"); r.Status != 200 || r.str("status") != "approved" {
			t.Fatalf("approve: %d %s", r.Status, r.Raw)
		}
		// the code works once
		if r := h.approve(l, d.UserCode, "approve"); r.Status != 404 || r.str("error") != "invalid_user_code" {
			t.Errorf("second approval: %d %s", r.Status, r.Raw)
		}
	})

	var tok tokens
	t.Run("the token response", func(t *testing.T) {
		h.clock.Advance(6 * time.Second)
		tok = tokensOf(t, h.devicePoll(slugA, d, k))
		if tok.Raw.str("token_type") != "DPoP" || tok.ExpiresIn != 600 || tok.Scope != "tessera:read tessera:write" ||
			!strings.HasPrefix(tok.Refresh, "trt_") {
			t.Errorf("token response %s", tok.Raw.Raw)
		}
		if cc := tok.Raw.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q", cc)
		}
		hdr, c := decodeJWT(t, tok.Access)
		if hdr["typ"] != "at+jwt" || hdr["alg"] != "ES256" || hdr["kid"] == "" {
			t.Errorf("header %v", hdr)
		}
		cnf, _ := c["cnf"].(map[string]any)
		if c["iss"] != h.srv.URL+"/t/"+slugA || c["aud"] != h.srv.URL+"/api" || c["client_id"] != CLIClientID ||
			c["tid"] != tenantAID.String() || cnf["jkt"] != jktOf(t, k) || c["sid"] == "" || c["scope"] != tok.Scope ||
			!strings.HasPrefix(c["sub"].(string), "usr_") || c["acr"] != "urn:tessera:acr:phr" {
			t.Errorf("claims %v", c)
		}
		if _, ok := c["roles"]; ok {
			t.Error("the token carries roles; they must be read from the database on each request")
		}
		if int64(c["exp"].(float64))-int64(c["iat"].(float64)) != 600 {
			t.Errorf("lifetime %v", c)
		}
		// the refresh token is stored only as a hash
		if _, err := h.refreshRow(slugA, tok.Refresh); err == nil {
			t.Error("the refresh token is stored in plain text")
		}
		if rt, err := h.refreshRow(slugA, hashHex(tok.Refresh)); err != nil || rt.DPoPJKT != jktOf(t, k) {
			t.Errorf("the refresh token row: %+v %v", rt, err)
		}
		w := h.whoamiReq(k, tok.Access)
		if w.Status != 200 || w.str("via") != "dpop" || w.str("client_id") != CLIClientID {
			t.Errorf("whoami: %d %s", w.Status, w.Raw)
		}
	})
	t.Run("a device code is used once", func(t *testing.T) {
		if r := h.devicePoll(slugA, d, k); r.Status != 400 || r.str("error") != "invalid_grant" {
			t.Errorf("second exchange: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("events", func(t *testing.T) {
		if got := len(h.auditEvents(slugA, "oauth.device.lookup")); got != 2 { // found, then the second approval's miss
			t.Errorf("%d oauth.device.lookup events, want 2", got)
		}
		for _, a := range []string{"oauth.device.created", "oauth.device.approved", "oauth.token.issued"} {
			evs := h.auditEvents(slugA, a)
			if len(evs) != 1 {
				t.Errorf("%s: %d events, want 1", a, len(evs))
				continue
			}
			if s := string(evs[0].Detail); strings.Contains(s, d.DeviceCode) || strings.Contains(s, d.UserCode) ||
				strings.Contains(s, tok.Refresh) || strings.Contains(s, tok.Access) {
				t.Errorf("%s records a secret: %s", a, s)
			}
		}
		if evs := h.auditEvents(slugB, "oauth.device.created"); len(evs) != 0 {
			t.Errorf("tenant B has %d device events", len(evs))
		}
	})
}

func TestDeviceExpiredAndDenied(t *testing.T) {
	h := newHarness(t)
	k := newKey(t)
	l := h.login(slugA, "alice@a.example", []auth.Role{auth.RoleViewer}, authtest.Phr)

	t.Run("expired_token", func(t *testing.T) {
		d := h.startDevice(slugA, nil)
		h.clock.Advance(301 * time.Second)
		if r := h.devicePoll(slugA, d, k); r.Status != 400 || r.str("error") != "expired_token" {
			t.Errorf("poll after 301 s: %d %s", r.Status, r.Raw)
		}
		if r := h.devicePoll(slugA, d, k); r.str("error") != "expired_token" {
			t.Errorf("poll again: %d %s", r.Status, r.Raw)
		}
		if evs := h.auditEvents(slugA, "oauth.device.expired"); len(evs) != 1 {
			t.Errorf("%d oauth.device.expired events, want 1", len(evs))
		}
	})
	t.Run("an expired code cannot be looked up or approved", func(t *testing.T) {
		l := h.login(slugA, "alice@a.example", []auth.Role{auth.RoleViewer}, authtest.Phr)
		d := h.startDevice(slugA, nil)
		h.clock.Advance(301 * time.Second)
		l = h.login(slugA, "alice@a.example", []auth.Role{auth.RoleViewer}, authtest.Phr) // fresh step-up
		if r := h.browser(l, "POST", "/api/auth/device/lookup", map[string]string{"user_code": d.UserCode}); r.Status != 404 {
			t.Errorf("lookup: %d %s", r.Status, r.Raw)
		}
		if r := h.approve(l, d.UserCode, "approve"); r.Status != 404 {
			t.Errorf("approve: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("approved but never collected", func(t *testing.T) {
		d := h.startDevice(slugA, nil)
		l := h.login(slugA, "alice@a.example", []auth.Role{auth.RoleViewer}, authtest.Phr)
		if r := h.approve(l, d.UserCode, "approve"); r.Status != 200 {
			t.Fatalf("approve: %d %s", r.Status, r.Raw)
		}
		h.clock.Advance(301 * time.Second)
		if r := h.devicePoll(slugA, d, k); r.str("error") != "expired_token" {
			t.Errorf("collected after the code expired: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("access_denied", func(t *testing.T) {
		d := h.startDevice(slugA, nil)
		l = h.login(slugA, "alice@a.example", []auth.Role{auth.RoleViewer}, authtest.Phr)
		if r := h.approve(l, d.UserCode, "deny"); r.Status != 200 || r.str("status") != "denied" {
			t.Fatalf("deny: %d %s", r.Status, r.Raw)
		}
		for range 2 {
			h.clock.Advance(6 * time.Second)
			if r := h.devicePoll(slugA, d, k); r.Status != 400 || r.str("error") != "access_denied" {
				t.Errorf("poll after a denial: %d %s", r.Status, r.Raw)
			}
		}
		if evs := h.auditEvents(slugA, "oauth.device.denied"); len(evs) != 1 {
			t.Errorf("%d oauth.device.denied events, want 1", len(evs))
		}
	})
	t.Run("a bad decision", func(t *testing.T) {
		d := h.startDevice(slugA, nil)
		l = h.login(slugA, "alice@a.example", []auth.Role{auth.RoleViewer}, authtest.Phr)
		if r := h.approve(l, d.UserCode, "maybe"); r.Status != 400 {
			t.Errorf("decision maybe: %d %s", r.Status, r.Raw)
		}
		if r := h.browser(l, "POST", "/api/auth/device/approve", map[string]any{"user_code": d.UserCode, "decision": "approve", "extra": 1}); r.Status != 400 {
			t.Errorf("unknown field: %d %s", r.Status, r.Raw)
		}
	})
}

// TestDeviceMachineClientRefused: only the first-party CLI client may use the
// device grant (§9.3 control 1).
func TestDeviceMachineClientRefused(t *testing.T) {
	h := newHarness(t)
	k := newKey(t)
	h.login(slugA, "owner@a.example", []auth.Role{auth.RoleViewer}, authtest.Phr)
	h.mutateTenant(slugA, func(tx *store.TenantTx) error {
		users, err := tx.PlatformUsers()
		if err != nil {
			return err
		}
		return tx.InsertAPIClient(&store.APIClient{ClientID: "tsc_machine01", Name: "ETL", Kind: store.ClientMachine,
			GrantTypes: []string{"client_credentials"}, TokenEndpointAuthMethod: "private_key_jwt", DPoPRequired: true,
			AllowedScopes: []string{"tessera:read"}, Roles: []string{"viewer"}, OwnerUserID: &users[0].ID, CreatedAt: h.clock.Now()})
	})
	r := h.postForm("/t/"+slugA+"/oauth/device_authorization", url.Values{"client_id": {"tsc_machine01"}, "scope": {"tessera:read"}}, nil)
	if r.Status != 400 || r.str("error") != "unauthorized_client" || r.str("device_code") != "" {
		t.Errorf("device_authorization for a machine client: %d %s", r.Status, r.Raw)
	}
	if evs := h.auditEvents(slugA, "oauth.device.refused"); len(evs) != 1 || evs[0].Outcome != store.OutcomeDenied ||
		!strings.Contains(string(evs[0].Detail), "client_not_allowed") {
		t.Errorf("refusal events: %+v", evs)
	}
	// nor can it redeem a device code at the token endpoint, even one it never got
	r = h.tokenReq(slugA, url.Values{"grant_type": {GrantDeviceCode}, "client_id": {"tsc_machine01"}, "device_code": {"x"}}, k)
	if r.Status != 400 || r.str("error") != "unauthorized_client" {
		t.Errorf("token endpoint, machine client: %d %s", r.Status, r.Raw)
	}
	// an unknown client is invalid_client
	r = h.postForm("/t/"+slugA+"/oauth/device_authorization", url.Values{"client_id": {"nobody"}}, nil)
	if r.Status != 401 || r.str("error") != "invalid_client" {
		t.Errorf("unknown client: %d %s", r.Status, r.Raw)
	}
}

// TestDeviceTenantDisabled: tenant.settings.device_grant_enabled=false turns
// the grant off, for new requests, for polling and for approval (§9.3 control 4).
func TestDeviceTenantDisabled(t *testing.T) {
	h := newHarness(t)
	k := newKey(t)
	l := h.login(slugA, "alice@a.example", []auth.Role{auth.RoleViewer}, authtest.Phr)
	pending := h.startDevice(slugA, nil)
	approved := h.startDevice(slugA, nil)
	if r := h.approve(l, approved.UserCode, "approve"); r.Status != 200 {
		t.Fatalf("approve: %d %s", r.Status, r.Raw)
	}

	h.setSettings(slugA, `{"device_grant_enabled": false}`)
	r := h.deviceAuthorize(slugA, nil)
	if r.Status != 400 || r.str("error") != "unauthorized_client" || !strings.Contains(r.str("error_description"), "turned off") {
		t.Errorf("device_authorization with the grant off: %d %s", r.Status, r.Raw)
	}
	if evs := h.auditEvents(slugA, "oauth.device.refused"); len(evs) != 1 || !strings.Contains(string(evs[0].Detail), "tenant_disabled") {
		t.Errorf("refusal events: %+v", evs)
	}
	if r := h.approve(l, pending.UserCode, "approve"); r.Status != 403 || r.str("error") != "device_grant_disabled" {
		t.Errorf("approval with the grant off: %d %s", r.Status, r.Raw)
	}
	h.clock.Advance(6 * time.Second)
	if r := h.devicePoll(slugA, approved, k); r.Status != 400 || r.str("error") != "access_denied" {
		t.Errorf("polling an approved grant with the grant off: %d %s", r.Status, r.Raw)
	}
	// the other tenant is unaffected
	if r := h.deviceAuthorize(slugB, nil); r.Status != 200 {
		t.Errorf("tenant B: %d %s", r.Status, r.Raw)
	}
	// and turning it back on works
	h.setSettings(slugA, `{"device_grant_enabled": true}`)
	if r := h.deviceAuthorize(slugA, nil); r.Status != 200 {
		t.Errorf("grant back on: %d %s", r.Status, r.Raw)
	}
}

func TestDeviceGrantEnabled(t *testing.T) {
	for in, want := range map[string]bool{
		"": true, "{}": true, `{"device_grant_enabled":true}`: true, `{"device_grant_enabled":false}`: false,
		`{"other":1}`: true,
		// unreadable settings fail closed
		"not json": false, "[]": false, "null": false, `{"device_grant_enabled":"no"}`: false,
	} {
		if got := DeviceGrantEnabled(in); got != want {
			t.Errorf("DeviceGrantEnabled(%q) = %t, want %t", in, got, want)
		}
	}
}

// TestDeviceLookupLockout: five failed lookups within ten minutes lock the
// session out for ten minutes and write oauth.device.lookup_bruteforce
// (§9.3 control 5).
func TestDeviceLookupLockout(t *testing.T) {
	h := newHarness(t)
	l1 := h.login(slugA, "alice@a.example", []auth.Role{auth.RoleViewer}, authtest.Phr)
	l2 := h.login(slugA, "bob@a.example", []auth.Role{auth.RoleViewer}, authtest.Phr)
	d := h.startDevice(slugA, nil)
	lookup := func(l authtest.Login, code string) resp {
		return h.browser(l, "POST", "/api/auth/device/lookup", map[string]string{"user_code": code})
	}
	for i := 1; i <= 4; i++ {
		code := "BBBB-BBB" + string("CDFG"[i-1])
		if i == 4 {
			code = "not a code" // a malformed code counts as a failure too
		}
		if r := lookup(l1, code); r.Status != 404 || r.str("error") != "invalid_user_code" {
			t.Fatalf("failure %d: %d %s", i, r.Status, r.Raw)
		}
	}
	// the fifth failure starts the lockout
	r := lookup(l1, "BBBB-BBBH")
	if r.Status != 429 || r.str("error") != "lookup_locked" || r.Header.Get("Retry-After") != "600" {
		t.Fatalf("fifth failure: %d %s retry-after=%q", r.Status, r.Raw, r.Header.Get("Retry-After"))
	}
	evs := h.auditEvents(slugA, "oauth.device.lookup_bruteforce")
	if len(evs) != 1 || evs[0].Outcome != store.OutcomeDenied || !strings.Contains(string(evs[0].Detail), `"severity":"critical"`) ||
		evs[0].SessionID == nil || *evs[0].SessionID != l1.SessionID.String() {
		t.Fatalf("bruteforce events: %+v", evs)
	}
	// locked out: even the right code is refused, for lookup and approval, and no second event
	if r := lookup(l1, d.UserCode); r.Status != 429 {
		t.Errorf("the right code while locked out: %d %s", r.Status, r.Raw)
	}
	if r := h.approve(l1, d.UserCode, "approve"); r.Status != 429 {
		t.Errorf("approval while locked out: %d %s", r.Status, r.Raw)
	}
	if got := len(h.auditEvents(slugA, "oauth.device.lookup_bruteforce")); got != 1 {
		t.Errorf("%d bruteforce events after more attempts, want 1", got)
	}
	// the lockout is per session
	if r := lookup(l2, d.UserCode); r.Status != 200 {
		t.Errorf("another session: %d %s", r.Status, r.Raw)
	}
	// it ends after ten minutes
	h.clock.Advance(601 * time.Second)
	d = h.startDevice(slugA, nil) // the first code has expired by now
	if r := lookup(l1, d.UserCode); r.Status != 200 {
		t.Errorf("after the lockout: %d %s", r.Status, r.Raw)
	}
	// 5 failures and 2 hits wrote a lookup event each; the refused attempts wrote none
	if got := len(h.auditEvents(slugA, "oauth.device.lookup")); got != 7 {
		t.Errorf("%d oauth.device.lookup events, want 7", got)
	}
	// failures expire from the window: four, ten minutes, four more is no lockout
	l3 := h.login(slugA, "carol@a.example", []auth.Role{auth.RoleViewer}, authtest.Phr)
	for range 4 {
		lookup(l3, "BBBB-BBBB")
	}
	h.clock.Advance(11 * time.Minute)
	for range 4 {
		if r := lookup(l3, "BBBB-BBBB"); r.Status != 404 {
			t.Fatalf("failures outside the window locked the session: %d %s", r.Status, r.Raw)
		}
	}
}

// TestDeviceApproveStepUp: approval needs authentication within 300 s at the
// required ACR (§9.3 control 3); a refusal is 401 step_up_required and
// changes nothing.
func TestDeviceApproveStepUp(t *testing.T) {
	h := newHarness(t)
	roles := []auth.Role{auth.RoleViewer}
	assertStepUp := func(t *testing.T, r resp, acr string, maxAge int) {
		t.Helper()
		got, _ := r.Body["max_age"].(float64)
		if r.Status != 401 || r.str("error") != "step_up_required" || r.str("acr") != acr || int(got) != maxAge ||
			!strings.Contains(r.str("step_up_url"), "/api/auth/step-up") ||
			!strings.Contains(r.Header.Get("WWW-Authenticate"), "insufficient_user_authentication") {
			t.Errorf("want step_up_required acr=%s max_age=%d, got %d %s (%s)", acr, maxAge, r.Status, r.Raw, r.Header.Get("WWW-Authenticate"))
		}
	}
	t.Run("a sign-in older than 300 s", func(t *testing.T) {
		l := h.login(slugA, "alice@a.example", roles, authtest.Phr)
		d := h.startDevice(slugA, nil)
		h.clock.Advance(299 * time.Second)
		// still inside the window: but the device code (300 s) is nearly out; approve works
		if r := h.approve(l, d.UserCode, "approve"); r.Status != 200 {
			t.Fatalf("approve at 299 s: %d %s", r.Status, r.Raw)
		}
		d2 := h.startDevice(slugA, nil)
		h.clock.Advance(2 * time.Second) // 301 s after the sign-in
		assertStepUp(t, h.approve(l, d2.UserCode, "approve"), "urn:tessera:acr:phr", 300)
		// nothing changed: the grant is still pending and a fresh sign-in approves it
		l = h.login(slugA, "alice@a.example", roles, authtest.Phr)
		if r := h.approve(l, d2.UserCode, "approve"); r.Status != 200 {
			t.Errorf("approve after the step-up: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("a sign-in that was not phishing-resistant", func(t *testing.T) {
		l := h.login(slugA, "bob@a.example", roles, authtest.AAL2)
		d := h.startDevice(slugA, nil)
		assertStepUp(t, h.approve(l, d.UserCode, "approve"), "urn:tessera:acr:phr", 300)
		assertStepUp(t, h.approve(l, d.UserCode, "deny"), "urn:tessera:acr:phr", 300) // a denial too
	})
	t.Run("the CLI asked for a stronger ACR", func(t *testing.T) {
		l := h.login(slugA, "carol@a.example", roles, authtest.Phr)
		d := h.startDevice(slugA, url.Values{"acr_values": {"urn:tessera:acr:phrh"}})
		assertStepUp(t, h.approve(l, d.UserCode, "approve"), "urn:tessera:acr:phrh", 300)
		lk := h.browser(l, "POST", "/api/auth/device/lookup", map[string]string{"user_code": d.UserCode})
		if req, _ := lk.Body["requires"].(map[string]any); req["acr"] != "urn:tessera:acr:phrh" {
			t.Errorf("lookup requires %v", lk.Body["requires"])
		}
		lh := h.login(slugA, "dave@a.example", roles, authtest.Ctx{Phrh: true, AAL: 3})
		if r := h.approve(lh, d.UserCode, "approve"); r.Status != 200 {
			t.Errorf("approve with a hardware-bound sign-in: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("the CLI asked for a fresher sign-in", func(t *testing.T) {
		l := h.login(slugA, "erin@a.example", roles, authtest.Phr)
		d := h.startDevice(slugA, url.Values{"max_age": {"60"}})
		h.clock.Advance(90 * time.Second)
		assertStepUp(t, h.approve(l, d.UserCode, "approve"), "urn:tessera:acr:phr", 60)
		// max_age=0 means "just now", never "no limit"
		d0 := h.startDevice(slugA, url.Values{"max_age": {"0"}})
		h.clock.Advance(5 * time.Second)
		assertStepUp(t, h.approve(l, d0.UserCode, "approve"), "urn:tessera:acr:phr", 1)
		l = h.login(slugA, "erin@a.example", roles, authtest.Phr)
		if r := h.approve(l, d0.UserCode, "approve"); r.Status != 200 {
			t.Errorf("approve right after sign-in: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("a command-line session cannot approve a device", func(t *testing.T) {
		k := newKey(t)
		tok, _ := h.signInCLI(slugA, "frank@a.example", roles, authtest.Phr, k)
		d := h.startDevice(slugA, nil)
		target := h.srv.URL + "/api/auth/device/approve"
		req, _ := http.NewRequest(http.MethodPost, target, strings.NewReader(`{"user_code":"`+d.UserCode+`","decision":"approve"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "DPoP "+tok.Access)
		req.Header.Set("DPoP", h.proof(k, "POST", target, tok.Access, ""))
		if r := do(t, req); r.Status != 403 || r.str("error") != "interactive_authentication_required" {
			t.Errorf("approval by a token principal: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("an unauthenticated caller", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, h.url("/api/auth/device/approve"), strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		if r := do(t, req); r.Status != 401 {
			t.Errorf("no session: %d %s", r.Status, r.Raw)
		}
	})
}

func TestDeviceAuthorizeValidation(t *testing.T) {
	h := newHarness(t)
	base := func() url.Values { return url.Values{"client_id": {CLIClientID}} }
	with := func(k, v string) url.Values { f := base(); f.Set(k, v); return f }
	tests := []struct {
		name string
		form url.Values
		slug string
		want int
		code string
	}{
		{"default scope", base(), slugA, 200, ""},
		{"all CLI scopes", with("scope", "tessera:read tessera:write tessera:audit tessera:admin"), slugA, 200, ""},
		{"unknown scope", with("scope", "tessera:root"), slugA, 400, "invalid_scope"},
		{"one bad scope among good ones", with("scope", "tessera:read other"), slugA, 400, "invalid_scope"},
		{"no client_id", url.Values{}, slugA, 400, "invalid_request"},
		{"repeated client_id", url.Values{"client_id": {CLIClientID, CLIClientID}}, slugA, 400, "invalid_request"},
		{"bad acr_values", with("acr_values", "urn:tessera:acr:aal1"), slugA, 400, "invalid_request"},
		{"two acr values", with("acr_values", "urn:tessera:acr:phr urn:tessera:acr:phrh"), slugA, 400, "invalid_request"},
		{"bad max_age", with("max_age", "-1"), slugA, 400, "invalid_request"},
		{"max_age too large", with("max_age", "901"), slugA, 400, "invalid_request"},
		{"max_age not a number", with("max_age", "soon"), slugA, 400, "invalid_request"},
		{"unknown tenant", base(), "nope-tenant", 404, "not_found"},
		{"malformed slug", base(), "UPPER", 404, "not_found"},
		{"the platform tenant", base(), "_platform", 404, "not_found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h.clock.Advance(7 * time.Second) // stay under 10 requests a minute
			r := h.postForm("/t/"+tt.slug+"/oauth/device_authorization", tt.form, nil)
			if r.Status != tt.want || r.str("error") != tt.code {
				t.Errorf("%d %s, want %d %q", r.Status, r.Raw, tt.want, tt.code)
			}
			if tt.want != 200 && r.str("device_code") != "" {
				t.Error("an error response carries a device code")
			}
		})
	}
	t.Run("content type", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, h.url("/t/"+slugA+"/oauth/device_authorization"), strings.NewReader(`{"client_id":"tessera-cli"}`))
		req.Header.Set("Content-Type", "application/json")
		h.clock.Advance(7 * time.Second)
		if r := do(t, req); r.Status != 400 || r.str("error") != "invalid_request" {
			t.Errorf("JSON body: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("user codes are unique among pending grants", func(t *testing.T) {
		seen := map[string]bool{}
		for range 20 {
			h.clock.Advance(7 * time.Second)
			d := h.startDevice(slugA, nil)
			if seen[d.UserCode] {
				t.Fatalf("user code %s issued twice", d.UserCode)
			}
			seen[d.UserCode] = true
		}
	})
}

// TestDeviceAuthorizeRateLimit: 10 requests a minute per address.
func TestDeviceAuthorizeRateLimit(t *testing.T) {
	h := newHarness(t)
	for i := 1; i <= 10; i++ {
		if r := h.deviceAuthorize(slugA, nil); r.Status != 200 {
			t.Fatalf("request %d: %d %s", i, r.Status, r.Raw)
		}
	}
	r := h.deviceAuthorize(slugA, nil)
	if r.Status != 429 || r.str("error") != "rate_limited" || r.Header.Get("Retry-After") == "" {
		t.Errorf("11th request: %d %s", r.Status, r.Raw)
	}
	h.clock.Advance(7 * time.Second) // one token refills
	if r := h.deviceAuthorize(slugA, nil); r.Status != 200 {
		t.Errorf("after the refill: %d %s", r.Status, r.Raw)
	}
}

func TestUserCodes(t *testing.T) {
	for in, want := range map[string]string{"KDQV-TMWB": "KDQVTMWB", "bcdf-ghjk": "BCDFGHJK", "bcdf ghjk": "BCDFGHJK", "BCDFGHJK": "BCDFGHJK",
		" B-C-D-F-G-H-J-K ": "BCDFGHJK", "BCDFGHJ": "", "BCDFGHJKL": "", "BCDF-GHJA": "", "BCDF-GHJ1": "", "": "",
		strings.Repeat("B", 40): "", "BCDF-GHJ\x00": ""} {
		got, ok := normalizeUserCode(in)
		if (want == "") == ok || got != want && ok {
			t.Errorf("normalizeUserCode(%q) = %q, %t; want %q", in, got, ok, want)
		}
	}
	seen := map[string]bool{}
	for range 200 {
		display, norm := newUserCode()
		if !userCodeRE.MatchString(display) || display[:4]+display[5:] != norm {
			t.Fatalf("code %q / %q", display, norm)
		}
		seen[norm] = true
	}
	if len(seen) < 199 {
		t.Errorf("%d distinct codes in 200", len(seen))
	}
}
