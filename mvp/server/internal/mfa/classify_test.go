package mfa

import "testing"

func TestClassifyOkta(t *testing.T) {
	for _, tc := range []struct {
		factor, provider string
		numberMatch      bool
		want             Class
		ok               bool
	}{
		{"webauthn", "FIDO", false, Class{PhishingResistant, KindPasskey}, true},
		{"u2f", "FIDO", false, Class{PhishingResistant, KindSecurityKey}, true},
		{"signed_nonce", "OKTA", false, Class{PhishingResistant, KindFastPass}, true},
		{"push", "OKTA", true, Class{PushNumberMatch, KindAppPush}, true},
		{"push", "OKTA", false, Class{Push, KindAppPush}, true},
		{"token:software:totp", "GOOGLE", false, Class{OTP, KindTOTP}, true},
		{"token:software:totp", "OKTA", true, Class{OTP, KindTOTP}, true}, // number match never upgrades a code
		{"token:hotp", "CUSTOM", false, Class{OTP, KindTOTP}, true},
		{"token:hardware", "YUBICO", false, Class{OTP, KindHardwareOTP}, true},
		{"token", "RSA", false, Class{OTP, KindHardwareOTP}, true},
		{"sms", "OKTA", false, Class{SMSVoice, KindSMS}, true},
		{"call", "OKTA", false, Class{SMSVoice, KindVoice}, true},
		{"email", "OKTA", false, Class{SMSVoice, KindEmail}, true},
		{"question", "OKTA", false, Class{}, false}, // a knowledge factor is not MFA
		{"", "", false, Class{}, false},
		{"future:factor", "OKTA", false, Class{}, false}, // unknown is ignored, not guessed
	} {
		got, ok := ClassifyOkta(tc.factor, tc.provider, tc.numberMatch)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ClassifyOkta(%q, %q, %v) = %v, %v; want %v, %v", tc.factor, tc.provider, tc.numberMatch, got, ok, tc.want, tc.ok)
		}
	}
}

func TestOktaNumberMatch(t *testing.T) {
	for _, tc := range []struct {
		key, style, required string
		want                 bool
	}{
		{"okta_verify", "NUMBER_CHALLENGE", "ALWAYS", true},
		{"okta_verify", "NUMBER_CHALLENGE", "HIGH_RISK_ONLY", false},
		{"okta_verify", "NUMBER_CHALLENGE", "NEVER", false},
		{"okta_verify", "", "", false},
		{"phone_number", "NUMBER_CHALLENGE", "ALWAYS", false},
	} {
		if got := OktaNumberMatch(tc.key, tc.style, tc.required); got != tc.want {
			t.Errorf("OktaNumberMatch(%q, %q, %q) = %v, want %v", tc.key, tc.style, tc.required, got, tc.want)
		}
	}
}

func TestClassifyEntra(t *testing.T) {
	for _, tc := range []struct {
		odata string
		want  Class
		ok    bool
	}{
		{"#microsoft.graph.fido2AuthenticationMethod", Class{PhishingResistant, KindPasskey}, true},
		{"#microsoft.graph.windowsHelloForBusinessAuthenticationMethod", Class{PhishingResistant, KindWindowsHello}, true},
		{"#microsoft.graph.x509CertificateAuthenticationMethod", Class{PhishingResistant, KindCertificate}, true},
		{"#microsoft.graph.microsoftAuthenticatorAuthenticationMethod", Class{PushNumberMatch, KindAppPush}, true},
		{"#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod", Class{PushNumberMatch, KindAppPush}, true},
		{"#microsoft.graph.softwareOathAuthenticationMethod", Class{OTP, KindTOTP}, true},
		{"#microsoft.graph.hardwareOathAuthenticationMethod", Class{OTP, KindHardwareOTP}, true},
		{"#microsoft.graph.passwordAuthenticationMethod", Class{}, false},
		{"#microsoft.graph.temporaryAccessPassAuthenticationMethod", Class{}, false},
		{"#microsoft.graph.emailAuthenticationMethod", Class{}, false}, // SSPR only
		{"#microsoft.graph.somethingNew", Class{}, false},
	} {
		got, ok := ClassifyEntra(tc.odata)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ClassifyEntra(%q) = %v, %v; want %v, %v", tc.odata, got, ok, tc.want, tc.ok)
		}
	}
	for phoneType, want := range map[string]Class{
		"mobile": {SMSVoice, KindSMS}, "alternateMobile": {SMSVoice, KindSMS}, "office": {SMSVoice, KindVoice}, "": {SMSVoice, KindSMS}} {
		if got := ClassifyEntraPhone(phoneType); got != want {
			t.Errorf("ClassifyEntraPhone(%q) = %v, want %v", phoneType, got, want)
		}
	}
}

func TestStrengthOrderAndPasskeys(t *testing.T) {
	prev := 100
	for _, s := range Strengths {
		if !s.Valid() || s.Rank() >= prev || s.Label() == "" {
			t.Errorf("%s: rank %d is not below %d, or invalid", s, s.Rank(), prev)
		}
		prev = s.Rank()
	}
	if None.Valid() || Strength("bogus").Valid() || None.Rank() != 0 {
		t.Error("none and unknown strengths must not be valid method classes")
	}
	for kind, want := range map[string]bool{KindPasskey: true, KindSecurityKey: true, KindWindowsHello: false,
		KindCertificate: false, KindFastPass: false, KindTOTP: false} {
		if IsPasskey(kind) != want {
			t.Errorf("IsPasskey(%q) = %v, want %v", kind, !want, want)
		}
	}
}
