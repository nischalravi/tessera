package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Conditional access at the Tessera sign-in (issue #163), through the dev IdP
// in-process: the IdP's device claims and the trusted-proxy client address
// decide whether the session is created.

// finishFrom sends the callback as a client at remote (a trusted proxy when
// the proxies are configured), with X-Forwarded-For entries.
func (e *oidcEnv) finishFrom(a attempt, remote string, xff ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", a.callback.RequestURI(), nil)
	r.RemoteAddr = remote + ":40000"
	for _, x := range xff {
		r.Header.Add("X-Forwarded-For", x)
	}
	r.AddCookie(a.cookie)
	return serve(e.h, r)
}

func (e *oidcEnv) signInFrom(sub string, m devidp.Method, remote string, xff ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.finishFrom(e.start("/api/auth/login?tenant=larkspur&return_to=/jit", sub, m, devidp.ProfileOkta), remote, xff...)
}

// loginEvent is the newest event of action in Larkspur's chain.
func (e *oidcEnv) loginEvent(action string) map[string]any {
	for _, ev := range ledger(e.t, e.db, seed.LarkspurID) {
		if ev.Action == action {
			var d map[string]any
			if err := json.Unmarshal(ev.Detail, &d); err != nil {
				e.t.Fatal(err)
			}
			return d
		}
	}
	return nil
}

func TestAccessLogin_NetworkOutcomes(t *testing.T) {
	e := newOIDCEnv(t)
	e.srv.cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.255.0.0/16")}
	S, E, R := store.AccessScopeSignin, store.AccessModeEnforce, store.AccessModeReportOnly
	for _, tc := range []struct {
		name   string
		specs  []pspec
		remote string
		xff    []string
		method devidp.Method
		reason string // "" signs in
		// outcome recorded in the sign-in's conditional_access detail
		outcome string
	}{
		{"deny outside the corporate network", []pspec{{name: "corp only", scope: S, mode: E, outcome: "deny", netOp: "not_in"}},
			outsideIP, nil, devidp.MethodPasskey, "conditional_access_denied", "deny"},
		{"inside the corporate network signs in", []pspec{{name: "corp only", scope: S, mode: E, outcome: "deny", netOp: "not_in"}},
			insideIP, nil, devidp.MethodPasskey, "", "allow"},
		{"a spoofed X-Forwarded-For from an untrusted peer does not help", []pspec{{name: "corp only", scope: S, mode: E, outcome: "deny", netOp: "not_in"}},
			outsideIP, []string{insideIP}, devidp.MethodPasskey, "conditional_access_denied", "deny"},
		{"through a trusted proxy the forwarded client counts", []pspec{{name: "corp only", scope: S, mode: E, outcome: "deny", netOp: "not_in"}},
			proxyIP, []string{insideIP}, devidp.MethodPasskey, "", "allow"},
		{"step up outside the network: a phishing-resistant sign-in meets it", []pspec{{name: "off-net phr", scope: S, mode: E, outcome: "step_up", netOp: "not_in"}},
			outsideIP, nil, devidp.MethodPasskey, "", "step_up"},
		{"step up outside the network: a weaker sign-in is refused", []pspec{{name: "off-net phr", scope: S, mode: E, outcome: "step_up", netOp: "not_in"}},
			outsideIP, nil, devidp.MethodPasswordOTP, "conditional_access_step_up_required", "step_up"},
		{"the same weaker sign-in passes on the network", []pspec{{name: "off-net phr", scope: S, mode: E, outcome: "step_up", netOp: "not_in"}},
			insideIP, nil, devidp.MethodPasswordOTP, "", "allow"},
		{"report-only deny signs in and is recorded", []pspec{{name: "trial", scope: S, mode: R, outcome: "deny", netOp: "not_in"}},
			outsideIP, nil, devidp.MethodPasskey, "", "allow"},
		{"a privileged-scope policy does not stop the sign-in", []pspec{{name: "priv", scope: store.AccessScopePrivileged, mode: E, outcome: "deny"}},
			outsideIP, nil, devidp.MethodPasskey, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearAccess(t, e.db, seed.LarkspurID)
			seedAccessIn(t, e.db, seed.LarkspurID, tc.specs...)
			rec := e.signInFrom("00u-alice-admin", tc.method, tc.remote, tc.xff...)
			var ca map[string]any
			if tc.reason != "" {
				e.refused(rec, seed.LarkspurID, tc.reason)
				ca = asMap(e.loginEvent("auth.login.failure")["conditional_access"])
			} else {
				if rec.Code != http.StatusFound || cookieNamed(rec, auth.CookieName) == nil {
					t.Fatalf("want a session: %d %s", rec.Code, rec.Body.String())
				}
				ca = asMap(e.loginEvent("auth.login.success")["conditional_access"])
			}
			if tc.outcome == "" {
				if ca != nil {
					t.Errorf("no policy of the sign-in scope, yet %v", ca)
				}
				return
			}
			in := asMap(ca["inputs"])
			if ca["outcome"] != tc.outcome && !(tc.specs[0].mode == R) {
				t.Errorf("conditional_access %v", ca)
			}
			if tc.specs[0].mode == R {
				if ro, _ := ca["report_only"].([]any); len(ro) != 1 || asMap(ro[0])["outcome"] != "deny" {
					t.Errorf("report-only hit not recorded: %v", ca)
				}
			}
			// the inputs that drove it: the address as the server resolved it, and the device posture
			wantIP := tc.remote
			if len(tc.xff) > 0 && tc.remote == proxyIP {
				wantIP = tc.xff[0]
			}
			if in["client_ip"] != wantIP || in["device_managed"] != "managed" || in["device_compliance"] != "compliant" ||
				in["device_compliance_source"] != "idp_claim" {
				t.Errorf("inputs %v, want client_ip %s and Alice's managed, compliant device", in, wantIP)
			}
		})
	}
}

// TestAccessLogin_DeviceClaims: the IdP's device claims (OIDC claims and SAML
// attributes alike) decide, are kept on the session's authentication
// context, and a signal set by an admin can still override them.
func TestAccessLogin_DeviceClaims(t *testing.T) {
	S, E := store.AccessScopeSignin, store.AccessModeEnforce
	t.Run("oidc", func(t *testing.T) {
		e := newOIDCEnv(t)
		seedAccessIn(t, e.db, seed.LarkspurID, pspec{name: "managed only", scope: S, mode: E, outcome: "deny", device: store.DeviceUnmanaged})
		// Olu's device is unmanaged in the dev IdP's users.yaml; Vic's IdP says nothing about devices
		e.refused(e.signInFrom("00u-olu-operator", devidp.MethodPasswordOTP, insideIP), seed.LarkspurID, "conditional_access_denied")
		ca := asMap(e.loginEvent("auth.login.failure")["conditional_access"])
		if in := asMap(ca["inputs"]); in["device_managed"] != "unmanaged" || in["device_compliance"] != "not_compliant" {
			t.Errorf("Olu's inputs %v", in)
		}
		e.refused(e.signInFrom("00u-vic-viewer", devidp.MethodPassword, insideIP), seed.LarkspurID, "conditional_access_denied")
		if in := asMap(asMap(e.loginEvent("auth.login.failure")["conditional_access"])["inputs"]); in["device_managed"] != "unknown" ||
			in["device_compliance"] != "unknown" || in["device_compliance_source"] != "none" {
			t.Errorf("no device claims counts as unmanaged, and says so: %v", in)
		}
		rec := e.signInFrom("00u-alice-admin", devidp.MethodPasskey, insideIP)
		if rec.Code != http.StatusFound || cookieNamed(rec, auth.CookieName) == nil {
			t.Fatalf("Alice's managed device signs in: %d %s", rec.Code, rec.Body.String())
		}
		// the claims are on the stored authentication context
		var device *string
		if err := e.db.ReadTenant(t.Context(), seed.LarkspurID, func(tx *store.TenantTx) error {
			us, err := tx.PlatformUsers()
			if err != nil {
				return err
			}
			for _, u := range us {
				ss, err := tx.SessionsForUser(u.ID)
				if err != nil {
					return err
				}
				for _, s := range ss {
					rec, err := tx.AuthnContext(s.CurrentAuthnContextID)
					if err != nil {
						return err
					}
					device = rec.Device
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if device == nil || *device != `{"managed":true,"compliant":true}` {
			t.Errorf("stored device claims %v", device)
		}
	})
	t.Run("saml", func(t *testing.T) {
		e := newAuthEnv(t, true)
		seedAccessIn(t, e.db, seed.LarkspurID, pspec{name: "compliant only", scope: S, mode: E, outcome: "deny", device: store.DeviceNotCompliant})
		e.refused(e.samlSignIn("00u-olu-operator", devidp.MethodPasswordOTP, ""), seed.LarkspurID, "conditional_access_denied")
		rec := e.samlSignIn("00u-alice-admin", devidp.MethodPasskey, "")
		if rec.Code != http.StatusFound || cookieNamed(rec, auth.CookieName) == nil {
			t.Fatalf("Alice's compliant device signs in over SAML: %d %s", rec.Code, rec.Body.String())
		}
		if in := asMap(asMap(e.loginEvent("auth.login.success")["conditional_access"])["inputs"]); in["device_compliance"] != "compliant" {
			t.Errorf("SAML inputs %v", in)
		}
	})
}

// TestAccessLogin_AdminSignalOverridesClaim: Alice's IdP says compliant, an
// admin marks the device not compliant, and the sign-in policy refuses.
func TestAccessLogin_AdminSignalOverridesClaim(t *testing.T) {
	e := newOIDCEnv(t)
	seedAccessIn(t, e.db, seed.LarkspurID, pspec{name: "compliant only", scope: store.AccessScopeSignin, mode: store.AccessModeEnforce,
		outcome: "deny", device: store.DeviceNotCompliant})
	if rec := e.signInFrom("00u-alice-admin", devidp.MethodPasskey, insideIP); cookieNamed(rec, auth.CookieName) == nil {
		t.Fatalf("first sign-in: %d", rec.Code)
	}
	if err := e.db.InTenant(t.Context(), seed.LarkspurID, func(tx *store.TenantTx) error {
		us, err := tx.PlatformUsers()
		if err != nil {
			return err
		}
		for _, u := range us {
			if u.Email != nil && *u.Email == "alice.admin@larkspur.example" {
				return tx.SetDeviceSignal(&store.DeviceSignal{UserID: u.ID, Status: store.DeviceNonCompliant,
					Source: store.DeviceSourceManual, SetAt: e.clk.now()})
			}
		}
		t.Fatal("Alice is not a platform user")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e.refused(e.signInFrom("00u-alice-admin", devidp.MethodPasskey, insideIP), seed.LarkspurID, "conditional_access_denied")
	in := asMap(asMap(e.loginEvent("auth.login.failure")["conditional_access"])["inputs"])
	if in["device_compliance"] != "not_compliant" || in["device_compliance_source"] != "signal:manual" {
		t.Errorf("inputs %v", in)
	}
}

// TestAccessLogin_BootstrapExempt: the operator bootstrap is never subject
// to sign-in policies, so a policy cannot block a tenant's recovery, while an
// ordinary sign-in under the same policy is refused.
func TestAccessLogin_BootstrapExempt(t *testing.T) {
	e := newOIDCEnv(t)
	seedAccessIn(t, e.db, seed.LarkspurID, pspec{name: "deny all", scope: store.AccessScopeSignin, mode: store.AccessModeEnforce, outcome: "deny"})
	e.refused(e.signInFrom("00u-alice-admin", devidp.MethodPasskey, insideIP), seed.LarkspurID, "conditional_access_denied")
	conn := e.addConn(func(c *store.IdPConnection) {})
	code := e.invite(seed.LarkspurID, conn.ID, newbie.Email, 24*time.Hour)
	rec := e.finish(e.start("/t/larkspur/bootstrap?code="+url.QueryEscape(code), "00u-newbie", devidp.MethodPasskey, devidp.ProfileOkta))
	if rec.Code != http.StatusFound || cookieNamed(rec, auth.CookieName) == nil {
		t.Fatalf("the bootstrap sign-in is not subject to policies: %d %s", rec.Code, rec.Body.String())
	}
}
