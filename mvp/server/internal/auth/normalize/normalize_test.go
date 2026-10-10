package normalize_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
)

var at = time.Date(2026, 10, 8, 9, 29, 0, 0, time.UTC)

// want is the expected verdict of one row.
type want struct {
	aal     int
	phr     bool
	basis   string
	acr     string // Tessera ACR
	subject string
	err     error
}

type row struct {
	name   string
	conn   normalize.Connection
	req    normalize.Requested
	claims normalize.Claims
	want   want
}

func claims(sub, acr string, amr ...string) normalize.Claims {
	t := at
	return normalize.Claims{Subject: sub, ACR: acr, AMR: amr, AuthTime: &t}
}

func with(c normalize.Claims, fn func(*normalize.Claims)) normalize.Claims {
	fn(&c)
	return c
}

func acrValues(v ...string) normalize.Requested { return normalize.Requested{ACRValues: v} }

const (
	tenantGUID = "8d1f0c2a-0000-4000-8000-000000000001"
	oid        = "6a0e7d2c-0000-4000-8000-000000000002"
)

var (
	okta    = normalize.Connection{Profile: normalize.Okta}
	entra   = normalize.Connection{Profile: normalize.Entra, Mapping: normalize.Mapping{EntraTenantID: tenantGUID}}
	generic = normalize.Connection{Profile: normalize.GenericOIDC, Mapping: normalize.Mapping{
		PhrACRValues: []string{"urn:corp:phr"}, PhrhACRValues: []string{"urn:corp:phrh"}, AAL2ACRValues: []string{"urn:corp:mfa"}}}
	samlConn = normalize.Connection{Profile: normalize.GenericSAML, Mapping: normalize.Mapping{
		PhrClassRefs: []string{"urn:corp:ac:phishing-resistant"}, PhrhClassRefs: []string{"urn:corp:ac:hardware"},
		AAL2ClassRefs: []string{"urn:corp:ac:mfa"}, AMRAttribute: "http://schemas.microsoft.com/claims/authnmethodsreferences"}}
	devMock = normalize.Connection{Profile: normalize.DevMock}
)

func entraClaims(amr []string, acrs ...string) normalize.Claims {
	t := at
	return normalize.Claims{Subject: "pairwise-sub-not-the-user", TID: tenantGUID, OID: oid, AMR: amr, ACRS: acrs, AuthTime: &t}
}

func samlClaims(classRef string, amr ...string) normalize.Claims {
	t := at
	c := normalize.Claims{Subject: "persistent-nameid", ClassRef: classRef, AuthTime: &t}
	if amr != nil {
		c.Attributes = map[string][]string{"http://schemas.microsoft.com/claims/authnmethodsreferences": amr}
	}
	return c
}

// rows covers every row of design §8.2 for each profile, rules 1-7.
var rows = []row{
	// ---- okta: phr / phrh only from an acr Tessera requested (rule 2)
	{"okta phr requested and returned", okta, acrValues("phr"), claims("00u1", "phr", "swk", "user", "mfa"),
		want{2, true, "acr", normalize.ACRPhr, "00u1", nil}},
	{"okta phr not requested -> not phr", okta, acrValues(), claims("00u1", "phr", "swk", "user", "mfa"),
		want{2, false, "none", normalize.ACRAAL2, "00u1", nil}},
	{"okta phr returned when only aal2 requested -> not phr", okta, acrValues("urn:okta:loa:2fa:any"),
		claims("00u1", "phr", "swk", "user", "mfa"), want{2, false, "none", normalize.ACRAAL2, "00u1", nil}},
	{"okta phrh requested and returned", okta, acrValues("phrh"), claims("00u1", "phrh", "hwk", "user", "mfa"),
		want{3, true, "acr", normalize.ACRPhrh, "00u1", nil}},
	{"okta phrh returned but only phr requested -> not phr", okta, acrValues("phr"), claims("00u1", "phrh", "hwk", "user", "mfa"),
		want{2, false, "none", normalize.ACRAAL2, "00u1", nil}},
	{"okta phr requested, 2fa returned (weaker context)", okta, acrValues("phr"), claims("00u1", normalize.Okta2FA, "pwd", "otp", "mfa"),
		want{2, false, "none", normalize.ACRAAL2, "00u1", nil}},
	{"okta 2fa acr alone means MFA", okta, acrValues("phr"), claims("00u1", normalize.Okta2FA),
		want{2, false, "none", normalize.ACRAAL2, "00u1", nil}},
	{"okta 1fa password", okta, acrValues("phr"), claims("00u1", normalize.Okta1FA, "pwd"),
		want{1, false, "none", normalize.ACRAAL1, "00u1", nil}},
	{"okta nothing known -> aal 0", okta, acrValues("phr"), claims("00u1", ""),
		want{0, false, "none", normalize.ACRAAL1, "00u1", nil}},
	// "user" is a presence test, not a factor class: hwk+user is one factor
	{"okta amr hwk+user is not phr unless configured (rule 3)", okta, acrValues(), claims("00u1", "", "hwk", "user"),
		want{1, false, "none", normalize.ACRAAL1, "00u1", nil}},
	{"okta configured phr_amr", normalize.Connection{Profile: normalize.Okta,
		Mapping: normalize.Mapping{PhrAMR: [][]string{{"hwk", "user"}, {"hwk", "pin"}}}}, acrValues(), claims("00u1", "", "hwk", "pin"),
		want{2, true, "amr", normalize.ACRPhr, "00u1", nil}},
	{"okta connection attestation (rule 4)", normalize.Connection{Profile: normalize.Okta, AssumePhishingResistant: true},
		acrValues("phr"), claims("00u1", normalize.Okta1FA, "pwd"), want{2, true, "connection_attestation", normalize.ACRPhr, "00u1", nil}},
	{"okta auth_time missing (rule 5)", okta, acrValues("phr"),
		with(claims("00u1", "phr", "swk", "mfa"), func(c *normalize.Claims) { c.AuthTime = nil }), want{err: normalize.ErrMissingAuthTime}},
	{"okta subject missing", okta, acrValues("phr"), claims("", "phr", "swk", "mfa"), want{err: normalize.ErrMissingSubject}},

	// ---- entra: subject is oid with tid checked (rule 7); phr from a
	// requested auth context in acrs, or amr "fido"
	{"entra requested context in acrs", entra, normalize.Requested{EntraContexts: []string{"c1"}},
		entraClaims([]string{"pwd", "mfa"}, "c1"), want{2, true, "acr", normalize.ACRPhr, oid, nil}},
	{"entra context not requested -> not phr", entra, normalize.Requested{},
		entraClaims([]string{"pwd", "mfa"}, "c1"), want{2, false, "none", normalize.ACRAAL2, oid, nil}},
	{"entra context not bound to phr -> not phr", entra, normalize.Requested{EntraContexts: []string{"c7"}},
		entraClaims([]string{"pwd", "mfa"}, "c7"), want{2, false, "none", normalize.ACRAAL2, oid, nil}},
	{"entra amr fido", entra, normalize.Requested{}, entraClaims([]string{"fido", "mfa"}),
		want{2, true, "amr", normalize.ACRPhr, oid, nil}},
	{"entra phrh only by attestation", normalize.Connection{Profile: normalize.Entra,
		Mapping: normalize.Mapping{EntraTenantID: tenantGUID, PhrhAttested: true}}, normalize.Requested{},
		entraClaims([]string{"fido", "mfa"}), want{3, true, "amr", normalize.ACRPhrh, oid, nil}},
	{"entra fido without attestation is not phrh", entra, normalize.Requested{}, entraClaims([]string{"fido"}),
		want{2, true, "amr", normalize.ACRPhr, oid, nil}},
	{"entra password + mfa", entra, normalize.Requested{}, entraClaims([]string{"pwd", "mfa"}),
		want{2, false, "none", normalize.ACRAAL2, oid, nil}},
	{"entra password only", entra, normalize.Requested{}, entraClaims([]string{"pwd"}),
		want{1, false, "none", normalize.ACRAAL1, oid, nil}},
	{"entra wrong tid", entra, normalize.Requested{},
		with(entraClaims([]string{"fido"}), func(c *normalize.Claims) { c.TID = "another-directory" }), want{err: normalize.ErrEntraTenant}},
	{"entra without a configured tenant", normalize.Connection{Profile: normalize.Entra}, normalize.Requested{},
		entraClaims([]string{"fido"}), want{err: normalize.ErrEntraConfig}},
	{"entra without oid", entra, normalize.Requested{},
		with(entraClaims([]string{"fido"}), func(c *normalize.Claims) { c.OID = "" }), want{err: normalize.ErrMissingSubject}},

	// ---- generic_oidc: configured acr values, requested (rule 2); amr (rule 3)
	{"generic configured phr acr requested", generic, acrValues("urn:corp:phr"), claims("s1", "urn:corp:phr", "swk"),
		want{2, true, "acr", normalize.ACRPhr, "s1", nil}},
	{"generic configured phr acr not requested", generic, acrValues(), claims("s1", "urn:corp:phr", "swk"),
		want{1, false, "none", normalize.ACRAAL1, "s1", nil}},
	{"generic unconfigured acr named phr", generic, acrValues("phr"), claims("s1", "phr", "swk"),
		want{1, false, "none", normalize.ACRAAL1, "s1", nil}},
	{"generic configured phrh", generic, acrValues("urn:corp:phrh"), claims("s1", "urn:corp:phrh", "hwk", "user"),
		want{3, true, "acr", normalize.ACRPhrh, "s1", nil}},
	{"generic configured MFA acr", generic, acrValues(), claims("s1", "urn:corp:mfa"),
		want{2, false, "none", normalize.ACRAAL2, "s1", nil}},
	{"generic two factor classes", generic, acrValues(), claims("s1", "", "pwd", "otp"),
		want{2, false, "none", normalize.ACRAAL2, "s1", nil}},
	{"generic configured phr_amr", normalize.Connection{Profile: normalize.GenericOIDC,
		Mapping: normalize.Mapping{PhrAMR: [][]string{{"hwk", "user"}}}}, acrValues(), claims("s1", "", "hwk", "user"),
		want{2, true, "amr", normalize.ACRPhr, "s1", nil}},
	{"generic attestation", normalize.Connection{Profile: normalize.GenericOIDC, AssumePhishingResistant: true}, acrValues(),
		claims("s1", "", "pwd"), want{2, true, "connection_attestation", normalize.ACRPhr, "s1", nil}},
	{"google reads like generic", normalize.Connection{Profile: normalize.Google}, acrValues(), claims("s1", "", "pwd"),
		want{1, false, "none", normalize.ACRAAL1, "s1", nil}},

	// ---- generic_saml: configured AuthnContextClassRef requested; amr
	// attribute; PasswordProtectedTransport is a single factor; rule 4
	{"saml configured phr class requested", samlConn, normalize.Requested{ClassRefs: []string{"urn:corp:ac:phishing-resistant"}},
		samlClaims("urn:corp:ac:phishing-resistant"), want{2, true, "acr", normalize.ACRPhr, "persistent-nameid", nil}},
	{"saml configured phr class not requested", samlConn, normalize.Requested{},
		samlClaims("urn:corp:ac:phishing-resistant"), want{1, false, "none", normalize.ACRAAL1, "persistent-nameid", nil}},
	{"saml phrh class requested", samlConn, normalize.Requested{ClassRefs: []string{"urn:corp:ac:hardware"}},
		samlClaims("urn:corp:ac:hardware"), want{3, true, "acr", normalize.ACRPhrh, "persistent-nameid", nil}},
	{"saml password protected transport", samlConn, normalize.Requested{},
		samlClaims("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"),
		want{1, false, "none", normalize.ACRAAL1, "persistent-nameid", nil}},
	{"saml configured MFA class", samlConn, normalize.Requested{}, samlClaims("urn:corp:ac:mfa"),
		want{2, false, "none", normalize.ACRAAL2, "persistent-nameid", nil}},
	{"saml amr attribute mfa", samlConn, normalize.Requested{},
		samlClaims("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", "pwd", "mfa"),
		want{2, false, "none", normalize.ACRAAL2, "persistent-nameid", nil}},
	{"saml attestation (rule 4)", normalize.Connection{Profile: normalize.GenericSAML, AssumePhishingResistant: true},
		normalize.Requested{}, samlClaims("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"),
		want{2, true, "connection_attestation", normalize.ACRPhr, "persistent-nameid", nil}},
	{"saml no AuthnInstant", samlConn, normalize.Requested{},
		with(samlClaims("x"), func(c *normalize.Claims) { c.AuthTime = nil }), want{err: normalize.ErrMissingAuthTime}},
	{"saml empty subject", samlConn, normalize.Requested{},
		with(samlClaims("x"), func(c *normalize.Claims) { c.Subject = "" }), want{err: normalize.ErrMissingSubject}},

	// ---- dev_mock: the emulated profile's rules
	{"dev_mock okta phr requested", devMock, acrValues("phr"), claims("00u-alice-admin", "phr", "swk", "user", "mfa"),
		want{2, true, "acr", normalize.ACRPhr, "00u-alice-admin", nil}},
	{"dev_mock okta phr not requested -> not phr", devMock, acrValues(), claims("00u-alice-admin", "phr", "swk", "user", "mfa"),
		want{2, false, "none", normalize.ACRAAL2, "00u-alice-admin", nil}},
	{"dev_mock okta password + otp", devMock, acrValues("phr"), claims("00u-olu", normalize.Okta2FA, "pwd", "otp", "mfa"),
		want{2, false, "none", normalize.ACRAAL2, "00u-olu", nil}},
	{"dev_mock entra (inferred from tid)", devMock, normalize.Requested{EntraContexts: []string{"c1"}},
		entraClaims([]string{"fido", "mfa"}, "c1"), want{2, true, "acr", normalize.ACRPhr, oid, nil}},
	{"dev_mock generic phr requested", devMock, acrValues("phr", "mfa"),
		with(claims("00u-pat", "mfa", "pwd", "otp", "mfa"), func(c *normalize.Claims) {}),
		want{2, false, "none", normalize.ACRAAL2, "00u-pat", nil}},
	{"dev_mock generic phr emulation", normalize.Connection{Profile: normalize.DevMock,
		Mapping: normalize.Mapping{DevEmulation: "generic"}}, acrValues("phr"), claims("00u-pat", "phr", "swk", "user", "mfa"),
		want{2, true, "acr", normalize.ACRPhr, "00u-pat", nil}},
	{"dev_mock generic phr not requested", normalize.Connection{Profile: normalize.DevMock,
		Mapping: normalize.Mapping{DevEmulation: "generic"}}, acrValues("mfa"), claims("00u-pat", "phr", "swk", "user", "mfa"),
		want{2, false, "none", normalize.ACRAAL2, "00u-pat", nil}},

	{"dev_mock saml (inferred from the class ref) phr requested", normalize.Connection{Profile: normalize.DevMock,
		Mapping: normalize.Mapping{PhrClassRefs: []string{"urn:devidp:ac:phr"}}},
		normalize.Requested{ClassRefs: []string{"urn:devidp:ac:phr"}}, samlClaims("urn:devidp:ac:phr"),
		want{2, true, "acr", normalize.ACRPhr, "persistent-nameid", nil}},
	{"dev_mock saml phr not requested", normalize.Connection{Profile: normalize.DevMock,
		Mapping: normalize.Mapping{PhrClassRefs: []string{"urn:devidp:ac:phr"}}},
		normalize.Requested{}, samlClaims("urn:devidp:ac:phr"),
		want{1, false, "none", normalize.ACRAAL1, "persistent-nameid", nil}},

	{"unknown profile", normalize.Connection{Profile: "ping"}, acrValues(), claims("s", "phr"),
		want{err: normalize.ErrUnknownProfile}},
}

func TestNormalize(t *testing.T) {
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got, err := normalize.Normalize(r.conn, r.req, r.claims)
			if r.want.err != nil {
				if !errors.Is(err, r.want.err) {
					t.Fatalf("err = %v, want %v", err, r.want.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.AAL != r.want.aal || got.PhishingResistant != r.want.phr || got.PhrBasis != r.want.basis ||
				got.TesseraACR != r.want.acr || got.Subject != r.want.subject {
				t.Errorf("got aal=%d phr=%t basis=%s acr=%s sub=%s, want %+v", got.AAL, got.PhishingResistant, got.PhrBasis,
					got.TesseraACR, got.Subject, r.want)
			}
			// invariants of every result
			if !got.AuthTime.Equal(at) || got.MappingVersion != normalize.Version || len(got.ClaimsSHA256) != 64 {
				t.Errorf("auth_time %s, version %d, claims hash %q", got.AuthTime, got.MappingVersion, got.ClaimsSHA256)
			}
			if got.PhishingResistant != (got.PhrBasis != normalize.BasisNone) {
				t.Errorf("phr %t with basis %s", got.PhishingResistant, got.PhrBasis)
			}
			if got.AAL >= 2 && !slices.Contains(got.Methods, "mfa") {
				t.Errorf("aal %d without mfa in methods %v", got.AAL, got.Methods)
			}
			if r.conn.Profile == normalize.DevMock && got.MappingProfile[:9] != "dev_mock/" {
				t.Errorf("mapping profile %q", got.MappingProfile)
			}
		})
	}
}

// TestNormalize_NeverFromEmail: the subject is never the email or
// preferred_username, even when the email is all there is (rule 7).
func TestNormalize_NeverFromEmail(t *testing.T) {
	c := claims("", "phr", "swk", "mfa")
	if _, err := normalize.Normalize(okta, acrValues("phr"), c); !errors.Is(err, normalize.ErrMissingSubject) {
		t.Errorf("okta without sub: %v", err)
	}
	e := entraClaims([]string{"fido"})
	got, err := normalize.Normalize(entra, normalize.Requested{}, e)
	if err != nil || got.Subject != oid || got.Subject == e.Subject {
		t.Errorf("entra subject %q (%v), want oid", got.Subject, err)
	}
}

// TestNormalize_ClaimsHash: the evidence hash covers the raw claims.
func TestNormalize_ClaimsHash(t *testing.T) {
	a := claims("s", "phr", "swk", "mfa")
	b := a
	a.Raw, b.Raw = []byte(`{"sub":"s","acr":"phr"}`), []byte(`{"sub":"s","acr":"phrh"}`)
	ra, _ := normalize.Normalize(okta, acrValues("phr"), a)
	rb, _ := normalize.Normalize(okta, acrValues("phr"), b)
	if ra.ClaimsSHA256 == rb.ClaimsSHA256 {
		t.Error("different claims, same hash")
	}
}

func TestParseMapping(t *testing.T) {
	m, err := normalize.ParseMapping([]byte(`{"phr_acr_values":["x"],"phr_amr":[["hwk","user"]]}`))
	if err != nil || len(m.PhrACRValues) != 1 || len(m.PhrAMR) != 1 {
		t.Errorf("%+v %v", m, err)
	}
	if _, err := normalize.ParseMapping([]byte(`{"phr_acr_value":["typo"]}`)); err == nil {
		t.Error("an unknown authn_mapping key was accepted")
	}
	if m, err := normalize.ParseMapping(nil); err != nil || m.EntraTenantID != "" {
		t.Errorf("empty mapping: %v", err)
	}
}
