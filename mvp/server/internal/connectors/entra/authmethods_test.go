package entra

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

// Each Graph method type lands in one class; password, temporary access pass
// and the SSPR-only e-mail method are not MFA methods.
func TestAuthMethodsAreClassified(t *testing.T) {
	f := newFake(t)
	res, err := f.connector(baseCfg()).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.AuthSource == nil || res.AuthSource.Unavailable || res.AuthSource.System != System {
		t.Fatalf("AuthSource = %+v, want available entra", res.AuthSource)
	}
	want := map[string][2]string{ // account/method -> strength, kind
		ada + "/f0000001-0000-4000-8000-000000000001": {"phishing_resistant", "passkey"},       // fido2
		ada + "/f0000001-0000-4000-8000-000000000002": {"phishing_resistant", "windows_hello"}, // Windows Hello for Business
		ada + "/f0000001-0000-4000-8000-000000000003": {"push_number_match", "app_push"},       // Microsoft Authenticator
		ada + "/3179e48a-750b-4051-897c-87b9720928f7": {"sms_voice", "sms"},                    // mobile phone
		ben + "/f0000002-0000-4000-8000-000000000001": {"phishing_resistant", "certificate"},   // x509
		ben + "/f0000002-0000-4000-8000-000000000002": {"otp", "totp"},                         // software OATH
		ben + "/f0000002-0000-4000-8000-000000000003": {"otp", "hardware_otp"},                 // hardware OATH
		ben + "/f0000002-0000-4000-8000-000000000004": {"sms_voice", "voice"},                  // office phone
		ben + "/f0000002-0000-4000-8000-000000000005": {"push_number_match", "app_push"},       // passwordless Authenticator
	}
	got := methodsOf(res)
	for k, w := range want {
		m, ok := got[k]
		if !ok {
			t.Errorf("method %s missing", k)
			continue
		}
		if m.Strength != w[0] || m.Kind != w[1] || m.Account.Kind != "account" || m.Account.System != System {
			t.Errorf("%s = %s/%s, want %s/%s", k, m.Strength, m.Kind, w[0], w[1])
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected method %s (password, TAP and SSPR e-mail are not MFA methods)", k)
		}
	}
	if m := got[ada+"/f0000001-0000-4000-8000-000000000001"]; m.Label != "YubiKey 5 NFC" || m.EnrolledAt == nil {
		t.Errorf("passkey label/enrolled = %q/%v", m.Label, m.EnrolledAt)
	}
	for _, m := range res.AuthMethods {
		if strings.Contains(m.Label, "+1") || strings.Contains(m.Label, "@") {
			t.Errorf("label %q carries a phone number or address", m.Label)
		}
	}
	// cy is a disabled guest: never read
	if n := f.srv.Count("/v1.0/users/" + cy + "/authentication/methods"); n != 0 {
		t.Errorf("%d method requests for the disabled guest, want 0", n)
	}
}

// Missing UserAuthenticationMethod.Read.All (403) or any other failure does
// not fail the sync and is not "no MFA": the source is unavailable.
func TestAuthMethodsForbiddenDegrades(t *testing.T) {
	for _, status := range []int{401, 403, 500} {
		f := newFake(t)
		f.status["/v1.0/users/"+ben+"/authentication/methods"] = status
		res, err := f.connector(baseCfg()).Discover(context.Background())
		if err != nil {
			t.Fatalf("status %d: %v", status, err)
		}
		if res.AuthSource == nil || !res.AuthSource.Unavailable || res.AuthSource.Detail == "" {
			t.Fatalf("status %d: AuthSource = %+v, want unavailable with a detail", status, res.AuthSource)
		}
		if status == 403 && !strings.Contains(res.AuthSource.Detail, "UserAuthenticationMethod.Read.All") {
			t.Errorf("detail %q does not name the missing scope", res.AuthSource.Detail)
		}
		if strings.Contains(res.AuthSource.Detail, "leaky-body") {
			t.Errorf("detail leaks the response body: %q", res.AuthSource.Detail)
		}
		if len(res.AuthMethods) != 0 {
			t.Errorf("status %d: %d methods returned from a failed read", status, len(res.AuthMethods))
		}
		if len(res.Accounts) == 0 {
			t.Errorf("status %d: the rest of the sync must go on", status)
		}
	}
}

func TestAuthMethodsCanBeSwitchedOff(t *testing.T) {
	f := newFake(t)
	cfg := baseCfg()
	cfg.SkipAuthMethods = true
	res, err := f.connector(cfg).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.AuthSource != nil || len(res.AuthMethods) != 0 || f.srv.Count("/v1.0/users/"+ada+"/authentication") != 0 {
		t.Error("authentication methods were read although switched off")
	}
}
