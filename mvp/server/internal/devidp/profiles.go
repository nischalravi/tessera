package devidp

import (
	"crypto/sha256"
	"encoding/base64"
	"slices"

	"github.com/google/uuid"
)

// Method is how the user authenticates on the dev IdP's sign-in page.
type Method string

// Sign-in methods (users.yaml "authenticators").
const (
	MethodPasskey     Method = "passkey"      // synced passkey (FIDO2 WebAuthn)
	MethodHardwareKey Method = "hardware_key" // device-bound, non-exportable key
	MethodPasswordOTP Method = "password_otp" // password + one-time code
	MethodPassword    Method = "password"     // password only
)

// Methods lists every method, strongest first.
func Methods() []Method {
	return []Method{MethodHardwareKey, MethodPasskey, MethodPasswordOTP, MethodPassword}
}

// Label is the text shown on the sign-in page.
func (m Method) Label() string {
	switch m {
	case MethodHardwareKey:
		return "Hardware security key (phishing-resistant, device-bound)"
	case MethodPasskey:
		return "Passkey (phishing-resistant)"
	case MethodPasswordOTP:
		return "Password + OTP"
	case MethodPassword:
		return "Password only"
	}
	return string(m)
}

func (m Method) phishingResistant() bool { return m == MethodPasskey || m == MethodHardwareKey }
func (m Method) multiFactor() bool       { return m != MethodPassword }

// rfc8176AMR is the RFC 8176 amr for a method, used by the Okta and generic
// emulations. A synced passkey is a software-protected key (swk), a
// device-bound one a hardware-protected key (hwk).
func (m Method) rfc8176AMR() []string {
	switch m {
	case MethodHardwareKey:
		return []string{"hwk", "user", "mfa"}
	case MethodPasskey:
		return []string{"swk", "user", "mfa"}
	case MethodPasswordOTP:
		return []string{"pwd", "otp", "mfa"}
	}
	return []string{"pwd"}
}

// Profile is the vendor whose ID-token behaviour the dev IdP emulates
// (docs/design/phase-0-platform-security.md §8.2, dev_mock row).
type Profile string

// Vendor emulation profiles.
const (
	ProfileOkta    Profile = "okta"
	ProfileEntra   Profile = "entra"
	ProfileGeneric Profile = "generic"
)

// Profiles lists every emulation profile.
func Profiles() []Profile { return []Profile{ProfileOkta, ProfileEntra, ProfileGeneric} }

// Label is the text shown on the sign-in page.
func (p Profile) Label() string {
	switch p {
	case ProfileOkta:
		return "Okta (Identity Engine)"
	case ProfileEntra:
		return "Microsoft Entra ID"
	case ProfileGeneric:
		return "Generic OIDC"
	}
	return string(p)
}

// Okta acr values (Okta Identity Engine). "phr" is satisfied only by the
// Passkey (FIDO2 WebAuthn) authenticator and "phrh" only by a device-bound
// key; the dev IdP models the latter as hardware_key.
const (
	OktaACRPhr  = "phr"
	OktaACRPhrh = "phrh"
	OktaACR2FA  = "urn:okta:loa:2fa:any"
	OktaACR1FA  = "urn:okta:loa:1fa:pwd"
)

// Generic-profile acr vocabulary, strongest first.
const (
	GenericACRPhrh = "phrh"
	GenericACRPhr  = "phr"
	GenericACRMFA  = "mfa"
	GenericACRPwd  = "pwd"
)

// acrValuesSupported is the union of what the profiles can return; it is
// what discovery advertises.
var acrValuesSupported = []string{OktaACRPhr, OktaACRPhrh, OktaACR2FA, OktaACR1FA, GenericACRMFA, GenericACRPwd}

// requested is what the relying party asked for in one authorization request.
type requested struct {
	acrValues []string // acr_values, space-separated in the request
	entraACRS []string // claims={"id_token":{"acrs":{"values":[…]}}}
}

// assurance is what a profile puts into the ID token for one sign-in.
type assurance struct {
	acr  string   // "" omits the claim
	amr  []string // never empty
	acrs []string // Entra auth contexts; nil omits the claim
}

// assuranceFor applies the profile's rules. They are deliberately literal so
// that relying-party tests see what each vendor does:
//
//   - okta: returns "phr"/"phrh" only when that value was requested and the
//     method satisfies it. Every other acr_values entry, including ones Okta
//     does not support (urn:tessera:acr:*), is ignored silently, never an
//     error. Otherwise the acr is the method's level (2fa or 1fa). Deliberate
//     deviation: real Okta enforces a supported value it cannot meet (it
//     prompts for a stronger factor or fails); the dev IdP returns the weaker
//     acr so relying-party tests can exercise the "IdP returned a weaker
//     context" path (§9.4, auth.step_up.insufficient).
//   - entra: ignores acr_values and emits no acr. A Conditional Access auth
//     context requested in the claims parameter is returned in "acrs" when the
//     method is phishing-resistant (the dev IdP assumes every context is bound
//     to the "Phishing-resistant MFA" strength); amr says "fido" for passkeys.
//   - generic: returns the first requested value the method satisfies, else
//     the method's level ("mfa" or "pwd").
func (p Profile) assuranceFor(m Method, req requested) assurance {
	switch p {
	case ProfileEntra:
		a := assurance{amr: entraAMR(m)}
		if m.phishingResistant() && len(req.entraACRS) > 0 {
			a.acrs = slices.Clone(req.entraACRS)
		}
		return a
	case ProfileGeneric:
		a := assurance{amr: m.rfc8176AMR(), acr: GenericACRPwd}
		if m.multiFactor() {
			a.acr = GenericACRMFA
		}
		for _, v := range req.acrValues {
			if genericSatisfies(m, v) {
				a.acr = v
				break
			}
		}
		return a
	default: // okta
		a := assurance{amr: m.rfc8176AMR(), acr: OktaACR1FA}
		if m.multiFactor() {
			a.acr = OktaACR2FA
		}
		for _, v := range req.acrValues {
			if (v == OktaACRPhrh && m == MethodHardwareKey) || (v == OktaACRPhr && m.phishingResistant()) {
				a.acr = v
				break
			}
		}
		return a
	}
}

func genericSatisfies(m Method, v string) bool {
	switch v {
	case GenericACRPhrh:
		return m == MethodHardwareKey
	case GenericACRPhr:
		return m.phishingResistant()
	case GenericACRMFA:
		return m.multiFactor()
	case GenericACRPwd:
		return true
	}
	return false
}

// entraAMR follows Entra's amr vocabulary: "fido" for FIDO2 keys and passkeys.
func entraAMR(m Method) []string {
	switch m {
	case MethodHardwareKey, MethodPasskey:
		return []string{"fido", "mfa"}
	case MethodPasswordOTP:
		return []string{"pwd", "mfa"} // Entra's "otp" means email one-time passcode
	}
	return []string{"pwd"}
}

// entraNamespace derives the Entra emulation's stable identifiers.
var entraNamespace = uuid.MustParse("6f1d3c52-4d0e-4b8e-9a51-2a7c1e0d9b11")

// EntraObjectID is the emulated Entra "oid" of a dev IdP subject.
func EntraObjectID(sub string) string {
	return uuid.NewSHA1(entraNamespace, []byte("oid:"+sub)).String()
}

// EntraTenantID is the emulated Entra "tid" of a Tessera tenant slug.
func EntraTenantID(tenant string) string {
	return uuid.NewSHA1(entraNamespace, []byte("tid:"+tenant)).String()
}

// EntraPairwiseSub is the emulated Entra "sub": pairwise per application, so
// it differs between clients and must not be used as the subject (§8.2 rule 7).
func EntraPairwiseSub(sub, clientID string) string {
	sum := sha256.Sum256([]byte("sub:" + sub + "\x00" + clientID))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
