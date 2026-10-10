// Package normalize maps validated IdP claims (OIDC) or a validated SAML
// assertion to Tessera's normalized authentication context (design
// docs/design/phase-0-platform-security.md §8.2).
//
// The default is the weakest result. Phishing resistance is never inferred
// from vague signals:
//
//  1. The IdP profile decides how to read claims. Each profile is a versioned
//     table (Version is stored on every record).
//  2. Phishing resistance from acr (or Entra acrs, or a SAML
//     AuthnContextClassRef) is trusted only if Tessera requested that value
//     in this transaction and the IdP returned it: Okta silently ignores
//     unsupported acr_values, so an acr nobody asked for proves nothing.
//  3. Phishing resistance from amr only for values the profile (Entra
//     "fido") or the connection (authn_mapping.phr_amr) lists.
//  4. Connection attestation: assume_phishing_resistant makes every login
//     through the connection phr with basis connection_attestation.
//  5. auth_time is required (OIDC auth_time, SAML AuthnInstant).
//  6. AAL: phrh -> 3, phr -> 2, MFA (amr "mfa" or two distinct factor
//     classes) -> 2, a known single factor -> 1, nothing known -> 0.
//  7. Subject: sub (Okta, Google, generic), Entra oid with tid checked
//     against the configured tenant; never email or preferred_username.
//
// The package is pure: no I/O, no clock. Callers validate signatures,
// issuers, audiences and nonces first (PR6 oidcrp, PR9 samlsp).
package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// Version is the mapping version recorded on every AuthnContextRecord.
const Version = 1

// Tessera ACR values (design §8.1).
const (
	ACRAAL1 = "urn:tessera:acr:aal1"
	ACRAAL2 = "urn:tessera:acr:aal2"
	ACRPhr  = "urn:tessera:acr:phr"
	ACRPhrh = "urn:tessera:acr:phrh"
)

// Phishing-resistance bases.
const (
	BasisACR         = "acr"
	BasisAMR         = "amr"
	BasisAttestation = "connection_attestation"
	BasisWebAuthn    = "webauthn_attested"
	BasisNone        = "none"
)

// Profiles (store.Profile*).
const (
	Okta        = "okta"
	Entra       = "entra"
	Google      = "google"
	GenericOIDC = "generic_oidc"
	GenericSAML = "generic_saml"
	DevMock     = "dev_mock"
)

// Okta acr values (Identity Engine).
const (
	OktaPhr  = "phr"
	OktaPhrh = "phrh"
	Okta2FA  = "urn:okta:loa:2fa:any"
	Okta2FAP = "urn:okta:loa:2fa:any:ifpossible"
	Okta1FA  = "urn:okta:loa:1fa:pwd"
	Okta1FAA = "urn:okta:loa:1fa:any"
)

// Errors. A login with any of them is refused (auth.login.failure).
var (
	ErrMissingAuthTime = errors.New("normalize: auth_time is missing")
	ErrMissingSubject  = errors.New("normalize: subject is missing")
	ErrEntraTenant     = errors.New("normalize: Entra tid does not match the connection's tenant")
	ErrEntraConfig     = errors.New("normalize: the entra profile needs authn_mapping.entra_tenant_id")
	ErrUnknownProfile  = errors.New("normalize: unknown profile")
)

// Mapping is a connection's authn_mapping (and the profile-specific
// settings normalization needs). Every list is exact-match.
type Mapping struct {
	// generic_oidc / dev_mock generic: acr values that mean phr / phrh, when
	// Tessera requested them (rule 2), and acr values that mean MFA.
	PhrACRValues  []string `json:"phr_acr_values,omitempty"`
	PhrhACRValues []string `json:"phrh_acr_values,omitempty"`
	AAL2ACRValues []string `json:"aal2_acr_values,omitempty"`
	// PhrAMR lists amr combinations that prove phishing resistance (rule 3),
	// each satisfied when every value in it is present, e.g. [["hwk","user"]].
	PhrAMR [][]string `json:"phr_amr,omitempty"`
	// Entra: the configured directory (tid) and the Conditional Access auth
	// contexts bound to the phishing-resistant strength. PhrhAttested is an
	// admin attestation that the strength allows only device-bound keys.
	EntraTenantID    string   `json:"entra_tenant_id,omitempty"`
	EntraPhrContexts []string `json:"entra_phr_contexts,omitempty"`
	PhrhAttested     bool     `json:"phrh_attested,omitempty"`
	// SAML: AuthnContextClassRef values that mean phr / phrh / MFA, and the
	// attribute that carries amr-style values (for example Entra's
	// http://schemas.microsoft.com/claims/authnmethodsreferences).
	PhrClassRefs  []string `json:"phr_authn_context_class_refs,omitempty"`
	PhrhClassRefs []string `json:"phrh_authn_context_class_refs,omitempty"`
	AAL2ClassRefs []string `json:"aal2_authn_context_class_refs,omitempty"`
	AMRAttribute  string   `json:"amr_attribute,omitempty"`
	// DevEmulation pins the dev_mock emulation (okta | entra | generic | saml);
	// empty infers it from the claims.
	DevEmulation string `json:"dev_emulation,omitempty"`
}

// ParseMapping decodes an authn_mapping column strictly (unknown keys are
// an error, so a typo cannot silently weaken a rule).
func ParseMapping(raw []byte) (Mapping, error) {
	var m Mapping
	if len(raw) == 0 {
		return m, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Mapping{}, fmt.Errorf("normalize: authn_mapping: %w", err)
	}
	return m, nil
}

// Connection is what normalization needs from an IdP connection.
type Connection struct {
	Profile                 string
	AssumePhishingResistant bool // rule 4; set only through a two-person admin change
	Mapping                 Mapping
}

// Requested is what Tessera asked the IdP for in this transaction (from the
// LoginTransaction), so rule 2 can be applied.
type Requested struct {
	ACRValues     []string // OIDC acr_values sent
	EntraContexts []string // Entra claims={"id_token":{"acrs":{"values":[…]}}}
	ClassRefs     []string // SAML RequestedAuthnContext
}

// Claims are the validated inputs: ID-token claims or the values taken from
// a verified SAML assertion.
type Claims struct {
	Subject  string   // OIDC sub, or the SAML subject chosen by subject_source
	ACR      string   // OIDC acr
	AMR      []string // OIDC amr
	ACRS     []string // Entra acrs
	TID, OID string   // Entra
	AuthTime *time.Time
	// SAML
	ClassRef   string              // AuthnContextClassRef
	Attributes map[string][]string // attribute name -> values
	// Raw is the validated claims or assertion, hashed into ClaimsSHA256 as
	// evidence; when empty the Claims themselves are hashed.
	Raw []byte
}

// Result is the normalized context (the AuthnContextRecord fields that
// depend on claims).
type Result struct {
	Subject           string
	ACR               *string  // raw acr (OIDC) or class ref (SAML), as asserted
	AMR               []string // raw amr, as asserted
	Methods           []string // RFC 8176 vocabulary, sorted
	AAL               int
	PhishingResistant bool
	PhrBasis          string
	TesseraACR        string
	AuthTime          time.Time
	MappingProfile    string
	MappingVersion    int
	ClaimsSHA256      string
}

// Normalize applies the connection's profile to validated claims.
func Normalize(conn Connection, req Requested, c Claims) (Result, error) {
	profile := conn.Profile
	if profile == DevMock {
		profile = devEmulation(conn.Mapping, c)
	}
	var r Result
	var err error
	switch profile {
	case Okta:
		r, err = okta(conn, req, c)
	case Entra:
		r, err = entra(conn, req, c, conn.Profile == DevMock)
	case GenericOIDC, Google:
		r, err = generic(conn, req, c)
	case GenericSAML:
		r, err = saml(conn, req, c)
	default:
		return Result{}, fmt.Errorf("%w %q", ErrUnknownProfile, conn.Profile)
	}
	if err != nil {
		return Result{}, err
	}
	if c.AuthTime == nil || c.AuthTime.IsZero() {
		return Result{}, ErrMissingAuthTime // rule 5
	}
	if r.Subject == "" {
		return Result{}, ErrMissingSubject
	}
	if conn.AssumePhishingResistant && !r.PhishingResistant { // rule 4
		r.PhishingResistant, r.PhrBasis = true, BasisAttestation
	}
	r.AuthTime = c.AuthTime.UTC()
	r.MappingProfile, r.MappingVersion = conn.Profile, Version
	if conn.Profile == DevMock {
		r.MappingProfile = DevMock + "/" + profile
	}
	if r.PhrBasis == "" {
		r.PhrBasis = BasisNone
	}
	finish(&r)
	r.ClaimsSHA256 = claimsHash(c)
	return r, nil
}

// finish derives AAL floors, the Tessera ACR and the method list from the
// profile's verdict (rule 6).
func finish(r *Result) {
	phrh := r.TesseraACR == ACRPhrh
	switch {
	case phrh:
		r.AAL = 3
	case r.PhishingResistant:
		r.AAL = max(r.AAL, 2)
		r.AAL = min(r.AAL, 2) // a synced passkey is capped at AAL2 (SP 800-63B-4)
	}
	switch {
	case phrh && r.PhishingResistant:
		r.TesseraACR = ACRPhrh
	case r.PhishingResistant:
		r.TesseraACR = ACRPhr
	case r.AAL >= 2:
		r.TesseraACR = ACRAAL2
	default:
		r.TesseraACR = ACRAAL1 // any successful authentication; AAL 0 means unknown
	}
	if !r.PhishingResistant {
		r.PhrBasis = BasisNone
	}
	if r.AAL >= 2 && !slices.Contains(r.Methods, "mfa") {
		r.Methods = append(r.Methods, "mfa")
	}
	sort.Strings(r.Methods)
	r.Methods = slices.Compact(r.Methods)
	if r.Methods == nil {
		r.Methods = []string{}
	}
	if r.AMR == nil {
		r.AMR = []string{}
	}
}

func devEmulation(m Mapping, c Claims) string {
	switch m.DevEmulation {
	case "okta":
		return Okta
	case "entra":
		return Entra
	case "generic":
		return GenericOIDC
	case "saml":
		return GenericSAML
	}
	switch {
	case c.ClassRef != "" || c.Attributes != nil: // a SAML assertion (the dev IdP's SAML endpoints)
		return GenericSAML
	case c.TID != "" || c.OID != "":
		return Entra
	case c.ACR == "mfa" || c.ACR == "pwd":
		return GenericOIDC
	}
	return Okta
}

// ---------------------------------------------------------------- factors

// factorClass is the RFC 8176 value's factor class: know, have or are.
var factorClass = map[string]string{
	"pwd": "know", "pin": "know", "kba": "know",
	"otp": "have", "sms": "have", "tel": "have", "hwk": "have", "swk": "have", "pop": "have", "sc": "have",
	"fpt": "are", "face": "are", "iris": "are", "retina": "are", "vbm": "are", "user": "",
	"mfa": "", "mca": "", "rba": "", "geo": "", "wia": "",
}

// vendorAMR maps vendor amr values to RFC 8176 (Entra "fido" is a FIDO2 key).
var vendorAMR = map[string]string{"fido": "hwk", "rsa": "hwk", "ngcmfa": "mfa"}

// methods normalizes amr values to the RFC 8176 vocabulary, dropping unknown ones.
func methods(amr []string) []string {
	var out []string
	for _, v := range amr {
		v = strings.ToLower(strings.TrimSpace(v))
		if m, ok := vendorAMR[v]; ok {
			v = m
		}
		if _, ok := factorClass[v]; ok {
			out = append(out, v)
		}
	}
	return out
}

// amrAAL is the AAL the amr alone supports: 2 for "mfa" or two distinct
// factor classes, 1 for a single known factor, 0 when nothing is known.
func amrAAL(ms []string) int {
	classes := map[string]bool{}
	mfa := false
	for _, m := range ms {
		if m == "mfa" {
			mfa = true
		}
		if c := factorClass[m]; c != "" {
			classes[c] = true
		}
	}
	switch {
	case mfa || len(classes) >= 2:
		return 2
	case len(classes) == 1:
		return 1
	}
	return 0
}

// amrPhr reports whether one configured combination is fully present (rule 3).
func amrPhr(amr []string, combos [][]string) bool {
	have := map[string]bool{}
	for _, v := range amr {
		have[strings.ToLower(v)] = true
	}
	for _, combo := range combos {
		if len(combo) == 0 {
			continue
		}
		all := true
		for _, v := range combo {
			if !have[strings.ToLower(v)] {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// requestedAndReturned is rule 2: v was asked for and is in the allowed set.
func requestedAndReturned(v string, requested, allowed []string) bool {
	return v != "" && slices.Contains(requested, v) && slices.Contains(allowed, v)
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func claimsHash(c Claims) string {
	raw := c.Raw
	if len(raw) == 0 {
		c.Raw = nil
		raw, _ = json.Marshal(c) // plain structs, cannot fail
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------- profiles

// okta: phr/phrh only from an acr Tessera requested; AAL from the acr level
// or amr. Okta's amr value for passkeys is undocumented, so amr never proves
// phr unless the connection lists a combination (rule 3).
func okta(conn Connection, req Requested, c Claims) (Result, error) {
	r := Result{Subject: c.Subject, ACR: strPtr(c.ACR), AMR: slices.Clone(c.AMR), Methods: methods(c.AMR)}
	r.AAL = amrAAL(r.Methods)
	switch c.ACR {
	case Okta2FA, Okta2FAP:
		r.AAL = max(r.AAL, 2)
	case Okta1FA, Okta1FAA:
		r.AAL = max(r.AAL, 1)
	}
	switch {
	case requestedAndReturned(c.ACR, req.ACRValues, []string{OktaPhrh}):
		r.PhishingResistant, r.PhrBasis, r.TesseraACR = true, BasisACR, ACRPhrh
	case requestedAndReturned(c.ACR, req.ACRValues, []string{OktaPhr}):
		r.PhishingResistant, r.PhrBasis = true, BasisACR
	case amrPhr(c.AMR, conn.Mapping.PhrAMR):
		r.PhishingResistant, r.PhrBasis = true, BasisAMR
	}
	return r, nil
}

// entra: subject is oid with tid checked; phr from a requested auth context
// in acrs, or amr "fido"; phrh only by admin attestation.
func entra(conn Connection, req Requested, c Claims, dev bool) (Result, error) {
	m := conn.Mapping
	switch {
	case m.EntraTenantID != "":
		if !strings.EqualFold(c.TID, m.EntraTenantID) {
			return Result{}, ErrEntraTenant
		}
	case !dev:
		return Result{}, ErrEntraConfig
	}
	r := Result{Subject: c.OID, ACR: strPtr(c.ACR), AMR: slices.Clone(c.AMR), Methods: methods(c.AMR)}
	r.AAL = amrAAL(r.Methods)
	contexts := m.EntraPhrContexts
	if len(contexts) == 0 {
		contexts = []string{"c1"}
	}
	for _, v := range c.ACRS {
		if requestedAndReturned(v, req.EntraContexts, contexts) {
			r.PhishingResistant, r.PhrBasis = true, BasisACR
			break
		}
	}
	if !r.PhishingResistant {
		if slices.ContainsFunc(c.AMR, func(v string) bool { return strings.EqualFold(v, "fido") }) {
			r.PhishingResistant, r.PhrBasis = true, BasisAMR
		} else if amrPhr(c.AMR, m.PhrAMR) {
			r.PhishingResistant, r.PhrBasis = true, BasisAMR
		}
	}
	if r.PhishingResistant && m.PhrhAttested {
		r.TesseraACR = ACRPhrh
	}
	return r, nil
}

// generic_oidc (and google): phr/phrh from configured acr values Tessera
// requested, or configured amr combinations; AAL from amr or configured
// MFA acr values. dev_mock's generic emulation defaults phr/phrh to the
// literal "phr"/"phrh".
func generic(conn Connection, req Requested, c Claims) (Result, error) {
	m := conn.Mapping
	phr, phrh := m.PhrACRValues, m.PhrhACRValues
	aal2 := m.AAL2ACRValues
	if conn.Profile == DevMock {
		phr, phrh = slices.Concat(phr, []string{"phr"}), slices.Concat(phrh, []string{"phrh"})
		aal2 = slices.Concat(aal2, []string{"mfa"})
	}
	r := Result{Subject: c.Subject, ACR: strPtr(c.ACR), AMR: slices.Clone(c.AMR), Methods: methods(c.AMR)}
	r.AAL = amrAAL(r.Methods)
	if c.ACR != "" && slices.Contains(aal2, c.ACR) {
		r.AAL = max(r.AAL, 2)
	}
	switch {
	case requestedAndReturned(c.ACR, req.ACRValues, phrh):
		r.PhishingResistant, r.PhrBasis, r.TesseraACR = true, BasisACR, ACRPhrh
	case requestedAndReturned(c.ACR, req.ACRValues, phr):
		r.PhishingResistant, r.PhrBasis = true, BasisACR
	case amrPhr(c.AMR, m.PhrAMR):
		r.PhishingResistant, r.PhrBasis = true, BasisAMR
	}
	return r, nil
}

// generic_saml: phr/phrh from a configured AuthnContextClassRef Tessera
// requested, or configured amr-style attribute values; most SAML IdPs return
// PasswordProtectedTransport whatever the factor, so plan on rule 4.
func saml(conn Connection, req Requested, c Claims) (Result, error) {
	m := conn.Mapping
	var amr []string
	if m.AMRAttribute != "" {
		amr = slices.Clone(c.Attributes[m.AMRAttribute])
	}
	r := Result{Subject: c.Subject, ACR: strPtr(c.ClassRef), AMR: amr, Methods: methods(amr)}
	r.AAL = amrAAL(r.Methods)
	switch {
	case c.ClassRef != "" && slices.Contains(m.AAL2ClassRefs, c.ClassRef):
		r.AAL = max(r.AAL, 2)
	case c.ClassRef != "":
		r.AAL = max(r.AAL, 1)
	}
	switch {
	case requestedAndReturned(c.ClassRef, req.ClassRefs, m.PhrhClassRefs):
		r.PhishingResistant, r.PhrBasis, r.TesseraACR = true, BasisACR, ACRPhrh
	case requestedAndReturned(c.ClassRef, req.ClassRefs, m.PhrClassRefs):
		r.PhishingResistant, r.PhrBasis = true, BasisACR
	case amrPhr(amr, m.PhrAMR):
		r.PhishingResistant, r.PhrBasis = true, BasisAMR
	}
	return r, nil
}
