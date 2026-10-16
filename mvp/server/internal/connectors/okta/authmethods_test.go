package okta

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
)

func methodsOf(res *connectors.DiscoveryResult) map[string]connectors.AuthMethodRecord {
	out := map[string]connectors.AuthMethodRecord{}
	for _, m := range res.AuthMethods {
		out[m.Account.ExternalID+"/"+m.ExternalID] = m
	}
	return out
}

// Each Okta factor type lands in one class; pending factors and security
// questions are not methods.
func TestAuthMethodsAreClassified(t *testing.T) {
	f := newFake(t)
	res, err := f.connector(ssws()).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.AuthSource == nil || res.AuthSource.Unavailable || res.AuthSource.System != System {
		t.Fatalf("AuthSource = %+v, want available okta", res.AuthSource)
	}
	want := map[string][2]string{ // account/factor -> strength, kind
		avery + "/fwf1averyyubikey001":    {"phishing_resistant", "passkey"}, // webauthn
		avery + "/opf1averyverify0001":    {"push_number_match", "app_push"}, // Okta Verify, number challenge ALWAYS
		avery + "/smsf1averyphone0001":    {"sms_voice", "sms"},
		morgan + "/ost1morgantotp0001":    {"otp", "totp"},
		morgan + "/clf1morganvoice0001":   {"sms_voice", "voice"},
		morgan + "/hwt1morganrsa000001":   {"otp", "hardware_otp"},
		morgan + "/emf1morganemail0001":   {"sms_voice", "email"},
		morgan + "/sgn1morganfastpass1":   {"phishing_resistant", "fastpass"}, // signed_nonce
		morgan + "/u2f1morgansecuritykey": {"phishing_resistant", "security_key"},
	}
	got := methodsOf(res)
	for k, w := range want {
		m, ok := got[k]
		if !ok {
			t.Errorf("method %s missing", k)
			continue
		}
		if m.Strength != w[0] || m.Kind != w[1] || m.Account.Kind != "account" || m.Account.System != System {
			t.Errorf("%s = %s/%s (%+v), want %s/%s", k, m.Strength, m.Kind, m.Account, w[0], w[1])
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected method %s (pending factors and security questions are not methods)", k)
		}
	}
	if m := got[avery+"/fwf1averyyubikey001"]; m.Label != "YubiKey 5C" || m.EnrolledAt == nil {
		t.Errorf("security key label/enrolled = %q/%v", m.Label, m.EnrolledAt)
	}
	for _, m := range res.AuthMethods {
		if strings.Contains(m.Label, "+1") || strings.Contains(m.Label, "@") {
			t.Errorf("label %q carries a phone number or address", m.Label)
		}
	}
	// factors of a deprovisioned (drew) or suspended (casey) user are never read
	for _, id := range []string{drew, casey} {
		if n := f.srv.Count("/api/v1/users/" + id + "/factors"); n != 0 {
			t.Errorf("%d factor requests for the inactive user %s", n, id)
		}
	}
}

// Without an always-on number challenge a push is only Push; the declaration
// in Config.PushNumberMatch applies when the authenticator list is refused.
func TestPushNumberMatchDependsOnTheOrgSetting(t *testing.T) {
	const highRisk = `[{"key":"okta_verify","status":"ACTIVE","settings":{"channelBinding":{"style":"NUMBER_CHALLENGE","required":"HIGH_RISK_ONLY"}}}]`
	for _, tc := range []struct {
		name     string
		setup    func(*fake, *Config)
		wantPush string
	}{
		{"always", func(*fake, *Config) {}, "push_number_match"},
		{"high risk only", func(f *fake, _ *Config) { f.body["/api/v1/authenticators"] = highRisk }, "push"},
		{"listing forbidden", func(f *fake, _ *Config) { f.status["/api/v1/authenticators"] = 403 }, "push"},
		{"declared by the operator", func(f *fake, c *Config) { f.status["/api/v1/authenticators"] = 403; c.PushNumberMatch = true }, "push_number_match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			cfg := ssws()
			tc.setup(f, &cfg)
			res, err := f.connector(cfg).Discover(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if m := methodsOf(res)[avery+"/opf1averyverify0001"]; m.Strength != tc.wantPush {
				t.Errorf("push = %q, want %q", m.Strength, tc.wantPush)
			}
		})
	}
}

// A refused factor listing does not fail the sync and is not "no MFA": the
// source is unavailable and no methods are returned.
func TestAuthMethodsForbiddenDegrades(t *testing.T) {
	for _, status := range []int{401, 403, 500} {
		f := newFake(t)
		f.status["/api/v1/users/"+morgan+"/factors"] = status
		res, err := f.connector(ssws()).Discover(context.Background())
		if err != nil {
			t.Fatalf("status %d: %v", status, err)
		}
		if res.AuthSource == nil || !res.AuthSource.Unavailable || res.AuthSource.Detail == "" {
			t.Errorf("status %d: AuthSource = %+v, want unavailable with a detail", status, res.AuthSource)
		}
		if len(res.AuthMethods) != 0 {
			t.Errorf("status %d: %d methods returned from a failed read", status, len(res.AuthMethods))
		}
		if strings.Contains(res.AuthSource.Detail, "leaky-body") {
			t.Errorf("detail leaks the response body: %q", res.AuthSource.Detail)
		}
		if len(res.Accounts) != 4 {
			t.Errorf("status %d: accounts = %d, the rest of the sync must go on", status, len(res.Accounts))
		}
	}
}

func TestAuthMethodsCanBeSwitchedOff(t *testing.T) {
	f := newFake(t)
	cfg := ssws()
	cfg.SkipAuthMethods = true
	res, err := f.connector(cfg).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.AuthSource != nil || len(res.AuthMethods) != 0 || f.srv.Count("/api/v1/authenticators") != 0 {
		t.Error("authentication methods were read although switched off")
	}
}
