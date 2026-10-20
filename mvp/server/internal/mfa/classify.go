// Package mfa classifies registered authentication methods by strength and
// builds the MFA posture report (coverage per department and privileged group,
// passkey enrolment over time, apps that bypass SSO or MFA).
//
// Classification follows the knowledge base (docs/knowledge/01): a method is
// phishing-resistant only if it is bound to the origin (FIDO2/WebAuthn
// passkeys and security keys, Windows Hello for Business, certificate-based
// authentication, Okta FastPass). Push is a separate class, with and without
// number matching. OTP codes are replayable by a phishing proxy. SMS, voice
// and e-mail codes are the weakest and can be intercepted or SIM-swapped.
package mfa

// Strength is the class of an authentication method.
type Strength string

const (
	// PhishingResistant methods are origin-bound (FIDO2/passkey, Windows
	// Hello for Business, certificate-based, Okta FastPass).
	PhishingResistant Strength = "phishing_resistant"
	// PushNumberMatch is an app push the user must answer by typing or
	// choosing the number shown at sign-in.
	PushNumberMatch Strength = "push_number_match"
	// Push is an approve/deny push without number matching (fatigue prone).
	Push Strength = "push"
	// OTP is a time-based or hardware one-time code.
	OTP Strength = "otp"
	// SMSVoice is a code by SMS, voice call or e-mail.
	SMSVoice Strength = "sms_voice"
	// None is the absence of any method (a rank, never stored on a method).
	None Strength = "none"
)

// Strengths lists the classes a method can have, strongest first.
var Strengths = []Strength{PhishingResistant, PushNumberMatch, Push, OTP, SMSVoice}

// Rank orders strengths; an unknown strength and None rank 0.
func (s Strength) Rank() int {
	switch s {
	case PhishingResistant:
		return 5
	case PushNumberMatch:
		return 4
	case Push:
		return 3
	case OTP:
		return 2
	case SMSVoice:
		return 1
	}
	return 0
}

// Valid reports whether s is a class a stored method may have.
func (s Strength) Valid() bool { return s.Rank() > 0 }

// Label is the display name of a class.
func (s Strength) Label() string {
	switch s {
	case PhishingResistant:
		return "Phishing-resistant"
	case PushNumberMatch:
		return "Push with number match"
	case Push:
		return "Push (no number match)"
	case OTP:
		return "OTP"
	case SMSVoice:
		return "SMS, voice or e-mail"
	}
	return "No MFA"
}

// Method kinds (the detail under a class).
const (
	KindPasskey      = "passkey"       // FIDO2 / WebAuthn credential
	KindSecurityKey  = "security_key"  // FIDO U2F / FIDO2 hardware key
	KindWindowsHello = "windows_hello" // Windows Hello for Business
	KindCertificate  = "certificate"   // certificate-based authentication
	KindFastPass     = "fastpass"      // Okta FastPass
	KindAppPush      = "app_push"      // Okta Verify / Microsoft Authenticator push
	KindTOTP         = "totp"          // software OATH token
	KindHardwareOTP  = "hardware_otp"  // hardware OATH token
	KindSMS          = "sms"
	KindVoice        = "voice"
	KindEmail        = "email"
)

// Class is the classification of one method.
type Class struct {
	Strength Strength
	Kind     string
}

// IsPasskey reports whether a method kind is a FIDO2 credential. Passkey
// enrolment over time counts identities with at least one of these.
func IsPasskey(kind string) bool { return kind == KindPasskey || kind == KindSecurityKey }

// ClassifyOkta classifies an Okta factor (GET /api/v1/users/{id}/factors).
// numberMatch says the org's Okta Verify authenticator always requires number
// matching (see OktaNumberMatch); it only matters for push. ok is false for a
// factor that is not an MFA method (security questions, unknown types), which
// the report ignores rather than guesses at.
func ClassifyOkta(factorType, provider string, numberMatch bool) (Class, bool) {
	switch factorType {
	case "webauthn":
		return Class{PhishingResistant, KindPasskey}, true
	case "u2f":
		return Class{PhishingResistant, KindSecurityKey}, true
	case "signed_nonce":
		return Class{PhishingResistant, KindFastPass}, true
	case "push":
		if numberMatch {
			return Class{PushNumberMatch, KindAppPush}, true
		}
		return Class{Push, KindAppPush}, true
	case "token:software:totp", "token:hotp":
		return Class{OTP, KindTOTP}, true
	case "token:hardware", "token":
		return Class{OTP, KindHardwareOTP}, true
	case "sms":
		return Class{SMSVoice, KindSMS}, true
	case "call":
		return Class{SMSVoice, KindVoice}, true
	case "email":
		return Class{SMSVoice, KindEmail}, true
	}
	return Class{}, false
}

// OktaNumberMatch reads an Okta authenticator listing entry for Okta Verify:
// number matching applies to every push when its channel binding is a number
// challenge and is required ALWAYS (HIGH_RISK_ONLY is not enough: a push can
// then be approved without a number).
func OktaNumberMatch(key, style, required string) bool {
	return key == "okta_verify" && style == "NUMBER_CHALLENGE" && required == "ALWAYS"
}

// ClassifyEntra classifies a Graph authentication method by its @odata.type
// (GET /users/{id}/authentication/methods). Methods that are not an MFA factor
// (password, temporary access pass, the SSPR-only e-mail method) return
// ok = false. Microsoft Authenticator push always uses number matching (it is
// enforced by Microsoft for every tenant), so it is PushNumberMatch.
func ClassifyEntra(odataType string) (Class, bool) {
	switch odataType {
	case "#microsoft.graph.fido2AuthenticationMethod":
		return Class{PhishingResistant, KindPasskey}, true
	case "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod":
		return Class{PhishingResistant, KindWindowsHello}, true
	case "#microsoft.graph.x509CertificateAuthenticationMethod":
		return Class{PhishingResistant, KindCertificate}, true
	case "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
		"#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod":
		return Class{PushNumberMatch, KindAppPush}, true
	case "#microsoft.graph.softwareOathAuthenticationMethod":
		return Class{OTP, KindTOTP}, true
	case "#microsoft.graph.hardwareOathAuthenticationMethod":
		return Class{OTP, KindHardwareOTP}, true
	}
	return Class{}, false
}

// ClassifyEntraPhone classifies an Entra phone method by its phoneType:
// mobile and alternateMobile receive SMS or voice, office phones voice only.
func ClassifyEntraPhone(phoneType string) Class {
	if phoneType == "office" {
		return Class{SMSVoice, KindVoice}
	}
	return Class{SMSVoice, KindSMS}
}
