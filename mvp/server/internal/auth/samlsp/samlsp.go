// Package samlsp is Tessera's SAML 2.0 service provider for browser sign-in
// (design docs/design/phase-0-platform-security.md §9.2, §19 PR9): signed
// AuthnRequests over the HTTP-Redirect binding, and the ACS validation of the
// HTTP-POST response.
//
// gosaml2 (with goxmldsig ≥ v1.6.1) verifies the XML signature against the
// connection's pinned certificates only, the Issuer, the Destination, the
// Recipient and the bearer confirmation. Before handing it the document,
// samlsp refuses anything but a Response with exactly one Assertion, a direct
// child of the Response, carrying an enveloped Signature whose Reference
// names that assertion's ID (so a signed Response around an unsigned
// assertion, and every signature-wrapping shape, is refused), after
// xml-roundtrip-validator has checked the raw bytes. After gosaml2 returns,
// samlsp checks its own invariants on the verified assertion: Issuer,
// InResponseTo, Recipient, Audience, NotBefore/NotOnOrAfter ±60 s,
// AuthnInstant not in the future, a non-empty subject without comment
// artefacts. Values used (subject, AuthnInstant, class ref, attributes) come
// only from the assertion gosaml2 verified. Replay (the assertion ID) is
// checked by the caller against the replay cache until NotOnOrAfter.
//
// Every refusal is an *Error with a machine-readable Reason for
// auth.login.failure.
package samlsp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"
	xmlrt "github.com/mattermost/xml-roundtrip-validator"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	dsigtypes "github.com/russellhaering/goxmldsig/types"
)

// Limits (§9.2).
const (
	// MaxResponseBytes caps the decoded SAMLResponse (the POST body is capped
	// by the caller with http.MaxBytesReader).
	MaxResponseBytes = 256 << 10
	// Skew is the clock skew allowed on NotBefore, NotOnOrAfter and
	// AuthnInstant.
	Skew = 60 * time.Second
	// SPKeyBits is the size of a connection's SP signing key.
	SPKeyBits = 2048
)

// NameIDPersistent is the persistent NameID format, the default subject.
const NameIDPersistent = saml2.NameIdFormatPersistent

// XML namespaces.
const (
	NSProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	NSAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	NSDSig      = "http://www.w3.org/2000/09/xmldsig#"
)

// Failure reasons (auth.login.failure detail.reason).
const (
	ReasonMalformed        = "saml_malformed"
	ReasonTooLarge         = "saml_too_large"
	ReasonRoundTrip        = "saml_xml_roundtrip"
	ReasonAssertionCount   = "saml_assertion_count"
	ReasonEncrypted        = "saml_encrypted_assertion"
	ReasonUnsignedAssert   = "saml_assertion_unsigned"
	ReasonSignature        = "saml_signature_invalid"
	ReasonIssuer           = "saml_issuer_mismatch"
	ReasonInResponseTo     = "saml_in_response_to_mismatch"
	ReasonUnsolicited      = "saml_unsolicited"
	ReasonDestination      = "saml_destination_mismatch"
	ReasonRecipient        = "saml_recipient_mismatch"
	ReasonAudience         = "saml_audience_mismatch"
	ReasonExpired          = "saml_expired"
	ReasonNotYetValid      = "saml_not_yet_valid"
	ReasonAuthnInstant     = "saml_authn_instant_invalid"
	ReasonSubject          = "saml_subject_invalid"
	ReasonNameIDComment    = "saml_nameid_comment"
	ReasonStatus           = "saml_status_not_success"
	ReasonReplay           = "saml_replay"
	ReasonConfig           = "saml_connection_misconfigured"
	reasonValidationPrefix = "saml_validation_failed"
)

// Error is a refused sign-in step. Reason is safe to audit; Err is for logs.
type Error struct {
	Reason string
	Err    error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return "samlsp: " + e.Reason + ": " + e.Err.Error()
	}
	return "samlsp: " + e.Reason
}

func (e *Error) Unwrap() error { return e.Err }

func fail(reason string, err error) error { return &Error{Reason: reason, Err: err} }

// ReasonOf returns the audit reason of err ("internal_error" for others).
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return "internal_error"
}

// Connection is what the SP needs of one SAML IdP connection.
type Connection struct {
	IdPEntityID string
	IdPSSOURL   string
	// IdPCerts are the pinned signing certificates (never taken from the
	// response's KeyInfo or from metadata at sign-in).
	IdPCerts   []*x509.Certificate
	SPEntityID string // also the audience: <public>/api/auth/saml/<id>/metadata
	ACSURL     string // <public>/api/auth/saml/<id>/acs
	SPKey      *rsa.PrivateKey
	SPCert     []byte // DER
	// NextSPCerts are certificates being rotated in (DER): published in the SP
	// metadata beside SPCert so identity providers trust them before the
	// promotion, never used to sign.
	NextSPCerts [][]byte
}

func (c Connection) sp(now time.Time) (*saml2.SAMLServiceProvider, error) {
	if c.IdPEntityID == "" || c.IdPSSOURL == "" || len(c.IdPCerts) == 0 || c.SPEntityID == "" || c.ACSURL == "" ||
		c.SPKey == nil || len(c.SPCert) == 0 {
		return nil, fail(ReasonConfig, errors.New("the connection lacks an IdP entity ID, SSO URL, pinned certificate or SP key"))
	}
	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      c.IdPSSOURL,
		IdentityProviderSSOBinding:  saml2.BindingHttpRedirect,
		IdentityProviderIssuer:      c.IdPEntityID,
		ServiceProviderIssuer:       c.SPEntityID,
		AssertionConsumerServiceURL: c.ACSURL,
		AudienceURI:                 c.SPEntityID,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: c.IdPCerts},
		SignAuthnRequests:           true,
		NameIdFormat:                saml2.NameIdFormatPersistent,
		SkipSignatureValidation:     false,
		AllowMissingAttributes:      true,
		Clock:                       dsig.NewFakeClockAt(now),
		MaximumDecompressedBodySize: MaxResponseBytes,
	}
	if err := sp.SetSPKeyStore(&saml2.KeyStore{Signer: c.SPKey, Cert: c.SPCert}); err != nil {
		return nil, fail(ReasonConfig, err)
	}
	return sp, nil
}

// AuthnRequest is a built request: its ID (kept in the login transaction as
// saml_request_id) and the Redirect-binding URL to send the browser to.
type AuthnRequest struct {
	ID  string
	URL string
}

// BuildAuthnRequest builds and signs an AuthnRequest. forceAuthn makes the
// IdP re-authenticate (step-up); classRefs, when set, are requested with
// Comparison=exact.
func BuildAuthnRequest(c Connection, relayState string, forceAuthn bool, classRefs []string, now time.Time) (AuthnRequest, error) {
	sp, err := c.sp(now)
	if err != nil {
		return AuthnRequest{}, err
	}
	sp.ForceAuthn = forceAuthn
	if len(classRefs) > 0 {
		sp.RequestedAuthnContext = &saml2.RequestedAuthnContext{Comparison: saml2.AuthnPolicyMatchExact, Contexts: classRefs}
	}
	doc, err := sp.BuildAuthRequestDocument()
	if err != nil {
		return AuthnRequest{}, err
	}
	id := doc.Root().SelectAttrValue("ID", "")
	if id == "" {
		return AuthnRequest{}, errors.New("samlsp: the AuthnRequest has no ID")
	}
	u, err := sp.BuildAuthURLRedirect(relayState, doc)
	if err != nil {
		return AuthnRequest{}, err
	}
	return AuthnRequest{ID: id, URL: u}, nil
}

// Expect is what the response must answer.
type Expect struct {
	RequestID string // the login transaction's saml_request_id
	Now       time.Time
}

// Assertion is the verified assertion's content.
type Assertion struct {
	ID           string
	Subject      string
	NameIDFormat string
	ClassRef     string
	AuthnInstant time.Time
	NotOnOrAfter time.Time
	Attributes   map[string][]string
	// Raw is the canonical verified assertion (hashed into the AuthnContext
	// as evidence).
	Raw []byte
}

// precheck applies the structural rules before gosaml2 sees the document.
func precheck(raw []byte) error {
	root, err := parseChecked(raw)
	if err != nil {
		return err
	}
	if root.Tag != "Response" || root.NamespaceURI() != NSProtocol {
		return fail(ReasonMalformed, errors.New("the document is not a samlp:Response"))
	}
	_, err = soleSignedAssertion(root, root)
	return err
}

// parseChecked parses raw after the XML round-trip check.
func parseChecked(raw []byte) (*etree.Element, error) {
	if errs := xmlrt.ValidateAll(bytes.NewReader(raw)); len(errs) > 0 {
		return nil, fail(ReasonRoundTrip, errs[0])
	}
	doc := etree.NewDocument()
	doc.ReadSettings.Permissive = false
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, fail(ReasonMalformed, err)
	}
	if doc.Root() == nil {
		return nil, fail(ReasonMalformed, errors.New("no root element"))
	}
	return doc.Root(), nil
}

// soleSignedAssertion finds the document's only Assertion (in any
// namespace, anywhere under root), which must be a SAML 2.0 assertion
// directly under parent, carry one enveloped signature referencing its ID,
// and have no comment in a NameID. No EncryptedAssertion is accepted.
func soleSignedAssertion(root, parent *etree.Element) (*etree.Element, error) {
	var assertions, encrypted []*etree.Element
	var walk func(el *etree.Element)
	walk = func(el *etree.Element) {
		for _, ch := range el.ChildElements() {
			switch {
			case ch.Tag == "Assertion":
				assertions = append(assertions, ch)
			case ch.Tag == "EncryptedAssertion":
				encrypted = append(encrypted, ch)
			}
			walk(ch)
		}
	}
	walk(root)
	if len(encrypted) > 0 {
		return nil, fail(ReasonEncrypted, errors.New("encrypted assertions are not accepted"))
	}
	if len(assertions) != 1 {
		return nil, fail(ReasonAssertionCount, fmt.Errorf("%d assertions", len(assertions)))
	}
	a := assertions[0]
	if a.Parent() != parent || a.NamespaceURI() != NSAssertion {
		return nil, fail(ReasonAssertionCount, errors.New("the assertion is not a SAML 2.0 assertion in its expected place"))
	}
	id := a.SelectAttrValue("ID", "")
	var sig *etree.Element
	for _, ch := range a.ChildElements() {
		if ch.Tag == "Signature" && ch.NamespaceURI() == NSDSig {
			if sig != nil {
				return nil, fail(ReasonUnsignedAssert, errors.New("more than one assertion signature"))
			}
			sig = ch
		}
	}
	if id == "" || sig == nil {
		return nil, fail(ReasonUnsignedAssert, errors.New("the assertion carries no enveloped signature"))
	}
	refs := sig.FindElements("./SignedInfo/Reference")
	if len(refs) != 1 || refs[0].SelectAttrValue("URI", "") != "#"+id {
		return nil, fail(ReasonUnsignedAssert, errors.New("the signature does not reference the assertion"))
	}
	// a comment inside NameID: c14n drops it from the signed bytes, so a
	// parser that reads only the first text node would see another subject
	for _, nid := range a.FindElements(".//NameID") {
		for _, tok := range nid.Child {
			if _, ok := tok.(*etree.Comment); ok {
				return nil, fail(ReasonNameIDComment, nil)
			}
		}
	}
	return a, nil
}

// ValidateResponse validates a base64 SAMLResponse from the ACS.
func ValidateResponse(c Connection, encoded string, e Expect) (*Assertion, error) {
	if len(encoded) > base64.StdEncoding.EncodedLen(MaxResponseBytes) {
		return nil, fail(ReasonTooLarge, nil)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fail(ReasonMalformed, err)
	}
	if err := precheck(raw); err != nil {
		return nil, err
	}
	sp, err := c.sp(e.Now)
	if err != nil {
		return nil, err
	}
	info, err := sp.RetrieveAssertionInfo(encoded)
	if err != nil {
		return nil, classify(err)
	}
	if info.WarningInfo != nil && info.WarningInfo.NotInAudience {
		return nil, fail(ReasonAudience, nil)
	}
	if len(info.Assertions) != 1 {
		return nil, fail(ReasonAssertionCount, fmt.Errorf("%d verified assertions", len(info.Assertions)))
	}
	a := info.Assertions[0]
	if a.Issuer == nil || a.Issuer.Value != c.IdPEntityID {
		return nil, fail(ReasonIssuer, nil)
	}
	if a.Subject == nil || a.Subject.SubjectConfirmation == nil || a.Subject.SubjectConfirmation.SubjectConfirmationData == nil {
		return nil, fail(ReasonSubject, errors.New("no bearer subject confirmation"))
	}
	scd := a.Subject.SubjectConfirmation.SubjectConfirmationData
	switch {
	case scd.InResponseTo == "":
		return nil, fail(ReasonUnsolicited, nil) // IdP-initiated sign-in is not accepted
	case e.RequestID == "" || scd.InResponseTo != e.RequestID:
		return nil, fail(ReasonInResponseTo, nil)
	case scd.Recipient != c.ACSURL:
		return nil, fail(ReasonRecipient, nil)
	}
	if !audienceIs(a, c.SPEntityID) {
		return nil, fail(ReasonAudience, nil)
	}
	notOnOrAfter, err := parseTime(scd.NotOnOrAfter)
	if err != nil {
		return nil, fail(ReasonExpired, err)
	}
	if a.Conditions == nil {
		return nil, fail(ReasonMalformed, errors.New("no Conditions"))
	}
	nb, err1 := parseTime(a.Conditions.NotBefore)
	na, err2 := parseTime(a.Conditions.NotOnOrAfter)
	switch {
	case err1 != nil || err2 != nil:
		return nil, fail(ReasonMalformed, errors.New("Conditions times"))
	case !e.Now.Add(Skew).After(nb) && !e.Now.Add(Skew).Equal(nb):
		return nil, fail(ReasonNotYetValid, nil)
	case !e.Now.Add(-Skew).Before(na) || !e.Now.Add(-Skew).Before(notOnOrAfter):
		return nil, fail(ReasonExpired, nil)
	}
	if na.Before(notOnOrAfter) {
		notOnOrAfter = na
	}
	if info.AuthnInstant == nil || info.AuthnInstant.After(e.Now.Add(Skew)) {
		return nil, fail(ReasonAuthnInstant, nil)
	}
	sub := info.NameID
	if a.Subject.NameID == nil || sub == "" || strings.TrimSpace(sub) != sub || len(sub) > 255 ||
		strings.ContainsAny(sub, "<>") || a.Subject.NameID.Value != sub {
		return nil, fail(ReasonSubject, nil)
	}
	out := &Assertion{ID: a.ID, Subject: sub, NameIDFormat: info.NameIDFormat, AuthnInstant: info.AuthnInstant.UTC(),
		NotOnOrAfter: notOnOrAfter.UTC(), Attributes: map[string][]string{}}
	if a.AuthnStatement != nil && a.AuthnStatement.AuthnContext != nil && a.AuthnStatement.AuthnContext.AuthnContextClassRef != nil {
		out.ClassRef = strings.TrimSpace(a.AuthnStatement.AuthnContext.AuthnContextClassRef.Value)
	}
	for name, at := range info.Values {
		for _, v := range at.Values {
			out.Attributes[name] = append(out.Attributes[name], v.Value)
		}
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%s", a.ID, sub, out.ClassRef, out.AuthnInstant.Format(time.RFC3339), c.IdPEntityID)))
	out.Raw = []byte(hex.EncodeToString(sum[:]))
	return out, nil
}

// audienceIs reports whether the assertion is restricted to want: every
// AudienceRestriction must name it, and there must be at least one.
func audienceIs(a types.Assertion, want string) bool {
	if a.Conditions == nil || len(a.Conditions.AudienceRestrictions) == 0 {
		return false
	}
	for _, ar := range a.Conditions.AudienceRestrictions {
		if !slices.ContainsFunc(ar.Audiences, func(x types.Audience) bool { return x.Value == want }) {
			return false
		}
	}
	return true
}

func parseTime(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, errors.New("missing time")
	}
	return time.Parse(time.RFC3339, v)
}

// classify maps gosaml2 errors to reasons.
func classify(err error) error {
	var ve saml2.ErrVerification
	var iv saml2.ErrInvalidValue
	var me saml2.ErrMissingElement
	switch {
	case errors.As(err, &iv):
		switch iv.Key {
		case saml2.IssuerTag:
			return fail(ReasonIssuer, err)
		case saml2.DestinationAttr:
			return fail(ReasonDestination, err)
		case saml2.RecipientAttr:
			return fail(ReasonRecipient, err)
		case saml2.NotOnOrAfterAttr:
			return fail(ReasonExpired, err)
		case saml2.StatusCodeTag:
			return fail(ReasonStatus, err)
		}
	case errors.As(err, &me):
		return fail(ReasonMalformed, err)
	case errors.As(err, &ve):
		if errors.As(ve.Cause, &iv) || errors.As(ve.Cause, &me) {
			return classify(ve.Cause)
		}
		return fail(ReasonSignature, err)
	}
	return fail(reasonValidationPrefix, err)
}

// GenerateSPKey creates a connection's SP signing key and self-signed
// certificate (published in the SP metadata).
func GenerateSPKey(name string, now time.Time) (keyPEM []byte, certPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, SPKeyBits)
	if err != nil {
		return nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, "", err
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Tessera SP: " + name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, "", err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// ParseSPKey decodes an SP key (PKCS#8 PEM) and certificate (PEM).
func ParseSPKey(keyPEM []byte, certPEM string) (*rsa.PrivateKey, []byte, error) {
	kb, _ := pem.Decode(keyPEM)
	cb, _ := pem.Decode([]byte(certPEM))
	if kb == nil || cb == nil {
		return nil, nil, errors.New("samlsp: SP key or certificate is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("samlsp: SP key is not RSA")
	}
	if _, err := x509.ParseCertificate(cb.Bytes); err != nil {
		return nil, nil, err
	}
	return rk, cb.Bytes, nil
}

// ParseCerts decodes pinned IdP certificates given as PEM or bare base64 DER.
func ParseCerts(pems []string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, p := range pems {
		der := []byte(nil)
		if b, _ := pem.Decode([]byte(p)); b != nil {
			der = b.Bytes
		} else if d, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(p), "")); err == nil {
			der = d
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("samlsp: pinned certificate: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("samlsp: no pinned IdP certificate")
	}
	return out, nil
}

// Metadata is the SP's EntityDescriptor (signed AuthnRequests, signed
// assertions wanted, one HTTP-POST ACS). It needs only the SP side of c, so
// an admin can register Tessera at the IdP before the IdP side is set.
func Metadata(c Connection, now time.Time) ([]byte, error) {
	if c.SPEntityID == "" || c.ACSURL == "" || len(c.SPCert) == 0 {
		return nil, fail(ReasonConfig, errors.New("the connection has no SP certificate"))
	}
	ed := types.EntityDescriptor{ValidUntil: now.UTC().Add(7 * 24 * time.Hour), EntityID: c.SPEntityID,
		SPSSODescriptor: &types.SPSSODescriptor{AuthnRequestsSigned: true, WantAssertionsSigned: true,
			ProtocolSupportEnumeration: NSProtocol,
			KeyDescriptors:             spKeyDescriptors(c),
			AssertionConsumerServices:  []types.IndexedEndpoint{{Binding: saml2.BindingHttpPost, Location: c.ACSURL, Index: 1}}}}
	b, err := xml.MarshalIndent(ed, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), b...), nil
}

// spKeyDescriptors lists the active SP certificate first, then the ones being
// rotated in.
func spKeyDescriptors(c Connection) []types.KeyDescriptor {
	var out []types.KeyDescriptor
	for _, der := range append([][]byte{c.SPCert}, c.NextSPCerts...) {
		out = append(out, types.KeyDescriptor{Use: "signing", KeyInfo: dsigtypes.KeyInfo{X509Data: dsigtypes.X509Data{
			X509Certificates: []dsigtypes.X509Certificate{{Data: base64.StdEncoding.EncodeToString(der)}}}}})
	}
	return out
}
