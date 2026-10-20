package devidp

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// The dev IdP's SAML 2.0 side (docs/design/phase-0-platform-security.md
// §18.5, §19 PR9): SP-initiated SSO over the HTTP-Redirect binding, the same
// sign-in page as OIDC, and an auto-POST of a Response whose Assertion is
// signed (enveloped XML-DSig, exclusive c14n, RSA-SHA256) with the IdP key.
// SAML faults make exactly one property of the response wrong so the SP's
// refusals can be tested.
//
// AuthnRequests are accepted from any SP whose ACS URL matches SAMLACS (by
// default an http(s) loopback or localhost /api/auth/saml/*/acs); their
// signatures are not checked, which is a dev-only simplification.

// SAML protocol constants.
const (
	nsSAMLP   = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsSAML    = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsMD      = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDS      = "http://www.w3.org/2000/09/xmldsig#"
	nameIDPer = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	bearer    = "urn:oasis:names:tc:SAML:2.0:cm:bearer" // #nosec G101 -- a SAML URN, not a credential
	bindPOST  = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	bindRedir = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	statusOK  = "urn:oasis:names:tc:SAML:2.0:status:Success"
)

// AuthnContextClassRef values the dev IdP asserts per method. The
// phishing-resistant ones are dev vocabulary (no standard class means "phr");
// a connection lists them in authn_mapping.phr_authn_context_class_refs.
const (
	SAMLClassPhrh        = "urn:devidp:ac:phrh"
	SAMLClassPhr         = "urn:devidp:ac:phr"
	SAMLClassMFA         = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
	SAMLClassPassword    = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" // #nosec G101 -- a SAML class ref URN
	samlPendingTTL       = 10 * time.Minute
	samlAssertionTTL     = 5 * time.Minute
	maxSAMLRequestBytes  = 64 << 10
	samlCertValidityFrom = "2020-01-01T00:00:00Z"
	samlCertValidityTo   = "2099-12-31T23:59:59Z"
)

// SAML faults (SAMLFaults lists them). xsw1..xsw8 are XML signature
// wrapping attacks applied to a correctly signed response (WrapXSW).
const (
	FaultUnsignedAssertion     Fault = "unsigned_assertion"                 // no signature at all
	FaultSignedResponseOnly    Fault = "signed_response_unsigned_assertion" // the Response is signed, the Assertion is not
	FaultCommentInNameID       Fault = "comment_in_nameid"                  // NameID "<sub><!---->.evil": c14n drops the comment
	FaultWrongAudience         Fault = "wrong_audience"                     // Audience is another SP
	FaultWrongRecipient        Fault = "wrong_recipient"                    // SubjectConfirmationData Recipient is another ACS
	FaultSAMLExpired           Fault = "saml_expired"                       // NotOnOrAfter in the past
	FaultReplay                Fault = "replay"                             // the previous response's Assertion ID again
	FaultUnsolicited           Fault = "unsolicited"                        // no InResponseTo (IdP-initiated)
	FaultWrongInResponseTo     Fault = "wrong_in_response_to"               // InResponseTo names another request
	FaultXSW1, FaultXSW2       Fault = "xsw1", "xsw2"
	FaultXSW3, FaultXSW4       Fault = "xsw3", "xsw4"
	FaultXSW5, FaultXSW6       Fault = "xsw5", "xsw6"
	FaultXSW7, FaultXSW8       Fault = "xsw7", "xsw8"
	defaultSAMLACSPattern1           = "http://127.0.0.1:*/api/auth/saml/*/acs"
	defaultSAMLACSPattern2           = "http://localhost:*/api/auth/saml/*/acs"
	xswEvilSubject                   = "00u-attacker-chosen"
	samlEntityPath                   = "/saml/metadata"
	samlSSOPath                      = "/saml/sso"
	samlSessionIndexPrefix           = "_si"
	samlResponseIDPrefix             = "_r"
	samlAssertionIDPrefix            = "_a"
	samlPOSTFormNonceBytes           = 16
	samlEvilAudience                 = "https://evil.example/saml/metadata"
	samlEvilRecipient                = "https://evil.example/api/auth/saml/x/acs"
	samlEvilInResponseTo             = "_not-your-request"
	samlCommentSuffix                = ".evil"
	samlDefaultAttributeEmail        = "email"
	samlDefaultAttributeName         = "displayName"
	samlDefaultAttributeGroups       = "groups"
)

// pendingSAML is an AuthnRequest waiting for the sign-in page.
type pendingSAML struct {
	requestID   string
	acs         string
	spEntityID  string
	relayState  string
	forceAuthn  bool
	classRefs   []string
	fault       Fault
	requestedAt time.Time
	wsfed       bool // WS-Federation (wsfed.go): acs is wreply, spEntityID the realm, relayState wctx
}

// SAMLEntityID is the dev IdP's SAML entity ID (its metadata URL).
func (s *Server) SAMLEntityID() string { return s.issuer + samlEntityPath }

// SAMLSSOURL is the SingleSignOnService (HTTP-Redirect) URL.
func (s *Server) SAMLSSOURL() string { return s.issuer + samlSSOPath }

// SAMLCertificate returns the SAML signing certificate (DER). It is derived
// deterministically from the signing key, so it stays the same across
// restarts as long as the key does (an SP pins it).
func (s *Server) SAMLCertificate() []byte { return slices.Clone(s.samlCert) }

// SAMLCertificatePEM returns the signing certificate as PEM.
func (s *Server) SAMLCertificatePEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.samlCert}))
}

// deterministicReader is a stream of SHA-256 blocks of a seed; it makes
// x509.CreateCertificate's randomness reproducible (RSA PKCS#1 v1.5
// signatures are deterministic anyway).
type deterministicReader struct {
	seed []byte
	ctr  uint32
	buf  []byte
}

func (d *deterministicReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(d.buf) == 0 {
			h := sha256.Sum256(binary.LittleEndian.AppendUint32(slices.Clip(d.seed), d.ctr))
			d.ctr++
			d.buf = h[:]
		}
		c := copy(p[n:], d.buf)
		d.buf, n = d.buf[c:], n+c
	}
	return n, nil
}

// makeSAMLCert builds the self-signed signing certificate from the key.
func (s *Server) makeSAMLCert() error {
	from, _ := time.Parse(time.RFC3339, samlCertValidityFrom)
	to, _ := time.Parse(time.RFC3339, samlCertValidityTo)
	pub, err := x509.MarshalPKIXPublicKey(s.key.Public())
	if err != nil {
		return err
	}
	sum := sha256.Sum256(pub)
	tmpl := &x509.Certificate{SerialNumber: new(big.Int).SetBytes(sum[:16]),
		Subject:   pkix.Name{CommonName: "Tessera dev IdP (SAML signing)", Organization: []string{"Tessera development"}},
		NotBefore: from, NotAfter: to, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(&deterministicReader{seed: sum[:]}, tmpl, tmpl, s.key.Public(), s.key)
	if err != nil {
		return err
	}
	s.samlCert = der
	return nil
}

// handleSAMLMetadata serves the IdP's EntityDescriptor.
func (s *Server) handleSAMLMetadata(w http.ResponseWriter, _ *http.Request) {
	doc := etree.NewDocument()
	ed := doc.CreateElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", nsMD)
	ed.CreateAttr("xmlns:ds", nsDS)
	ed.CreateAttr("entityID", s.SAMLEntityID())
	idp := ed.CreateElement("md:IDPSSODescriptor")
	idp.CreateAttr("protocolSupportEnumeration", nsSAMLP)
	idp.CreateAttr("WantAuthnRequestsSigned", "false")
	kd := idp.CreateElement("md:KeyDescriptor")
	kd.CreateAttr("use", "signing")
	kd.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
		SetText(base64.StdEncoding.EncodeToString(s.samlCert))
	idp.CreateElement("md:NameIDFormat").SetText(nameIDPer)
	sso := idp.CreateElement("md:SingleSignOnService")
	sso.CreateAttr("Binding", bindRedir)
	sso.CreateAttr("Location", s.SAMLSSOURL())
	doc.Indent(2)
	b, err := doc.WriteToBytes()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(append([]byte(xmlHeader), b...))
}

const xmlHeader = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"

// SAMLACSAllowed reports whether acs is an ACS URL the dev IdP posts to.
func (s *Server) samlACSAllowed(acs string) bool {
	if !absoluteHTTP(acs) {
		return false
	}
	return slices.ContainsFunc(s.samlACS, func(p string) bool { return matchRedirect(p, acs) })
}

// parseAuthnRequest decodes a Redirect-binding SAMLRequest (base64 of raw
// DEFLATE).
func parseAuthnRequest(v string) (*etree.Element, error) {
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("SAMLRequest is not base64")
	}
	xmlb, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), maxSAMLRequestBytes+1))
	if err != nil || len(xmlb) > maxSAMLRequestBytes {
		return nil, fmt.Errorf("SAMLRequest does not inflate to at most 64 KiB")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlb); err != nil {
		return nil, fmt.Errorf("SAMLRequest is not XML")
	}
	root := doc.Root()
	if root == nil || root.Tag != "AuthnRequest" || root.NamespaceURI() != nsSAMLP {
		return nil, fmt.Errorf("not an AuthnRequest")
	}
	return root, nil
}

// handleSAMLSSO is GET /saml/sso (HTTP-Redirect binding).
func (s *Server) handleSAMLSSO(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := s.now()
	req, err := parseAuthnRequest(q.Get("SAMLRequest"))
	if err != nil {
		s.errorPage(w, http.StatusBadRequest, err.Error())
		return
	}
	p := pendingSAML{requestID: req.SelectAttrValue("ID", ""), acs: req.SelectAttrValue("AssertionConsumerServiceURL", ""),
		relayState: q.Get("RelayState"), forceAuthn: req.SelectAttrValue("ForceAuthn", "") == "true", requestedAt: now}
	if iss := req.FindElement("./Issuer"); iss != nil {
		p.spEntityID = strings.TrimSpace(iss.Text())
	}
	for _, c := range req.FindElements("./RequestedAuthnContext/AuthnContextClassRef") {
		p.classRefs = append(p.classRefs, strings.TrimSpace(c.Text()))
	}
	switch {
	case p.requestID == "" || len(p.requestID) > 256:
		s.errorPage(w, http.StatusBadRequest, "The AuthnRequest has no usable ID.")
		return
	case p.spEntityID == "":
		s.errorPage(w, http.StatusBadRequest, "The AuthnRequest has no Issuer.")
		return
	case !s.samlACSAllowed(p.acs):
		s.errorPage(w, http.StatusBadRequest, "AssertionConsumerServiceURL is missing or not allowed.")
		return
	}
	p.fault = s.currentFault()
	if f := q.Get("fault"); f != "" {
		ff, err := ParseFault(f)
		if err != nil || !s.faults {
			s.errorPage(w, http.StatusBadRequest, "Faults are disabled or unknown.")
			return
		}
		p.fault = ff
	}
	if sess, ok := s.session(r, now); ok && !p.forceAuthn {
		s.postSAMLResponse(w, p, sess.user, sess.method, sess.authTime, sess.sid)
		return
	}
	id := rand.Text()
	if err := s.samlPending.put(id, p, now.Add(samlPendingTTL), now); err != nil {
		s.errorPage(w, http.StatusServiceUnavailable, "Too many sign-ins in progress.")
		return
	}
	d := pageData{Title: "Sign in", Req: id, Action: s.SAMLSSOURL(), ClientID: p.spEntityID, SAML: true,
		ACRValues: strings.Join(p.classRefs, " "), Fault: string(p.fault)}
	if p.forceAuthn {
		d.MaxAge = "0 (ForceAuthn)"
	}
	s.renderUsers(w, &d, "")
}

// handleSAMLSubmit completes the sign-in page for a SAML request.
func (s *Server) handleSAMLSubmit(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, http.StatusBadRequest, "Malformed form.")
		return
	}
	f := r.PostForm
	p, ok := s.samlPending.take(f.Get("req"), now)
	if !ok {
		s.errorPage(w, http.StatusBadRequest, "This sign-in request is unknown or expired. Start again from the application.")
		return
	}
	if f.Get("action") == "cancel" {
		s.renderMessage(w, http.StatusOK, "Sign-in cancelled", "Go back to the application to start again.")
		return
	}
	sub, m, _ := strings.Cut(f.Get("choice"), " ")
	method := Method(m)
	var user *User
	for i := range s.users {
		if s.users[i].Sub == sub {
			user = &s.users[i]
		}
	}
	if user == nil || !user.has(method) {
		s.errorPage(w, http.StatusBadRequest, "Unknown user or authenticator.")
		return
	}
	sess := idpSession{sid: rand.Text(), user: *user, method: method, profile: ProfileGeneric, authTime: now}
	cookie := rand.Text()
	if err := s.sessions.put(cookie, sess, now.Add(sessionTTL), now); err != nil {
		s.errorPage(w, http.StatusServiceUnavailable, "Too many sessions.")
		return
	}
	s.setSessionCookie(w, cookie, int(sessionTTL/time.Second))
	s.log.Info("devidp SAML sign-in", "sub", user.Sub, "method", method, "sp", p.spEntityID)
	if p.wsfed {
		s.postWSFed(w, p, *user, method, now, sess.sid)
		return
	}
	s.postSAMLResponse(w, p, *user, method, now, sess.sid)
}

func samlClassRef(m Method) string {
	switch m {
	case MethodHardwareKey:
		return SAMLClassPhrh
	case MethodPasskey:
		return SAMLClassPhr
	case MethodPasswordOTP:
		return SAMLClassMFA
	}
	return SAMLClassPassword
}

func samlTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func newSAMLID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// SAMLAssertionInput is what one response asserts.
type SAMLAssertionInput struct {
	RequestID, ACS, SPEntityID string
	User                       User
	Method                     Method
	AuthTime, Now              time.Time
	SessionIndex               string
	AssertionID                string // empty: a fresh one
}

// BuildSAMLResponse builds and signs a response with fault applied. It is
// exported for relying-party tests (devidptest, the XSW corpus).
func (s *Server) BuildSAMLResponse(in SAMLAssertionInput, fault Fault) (*etree.Document, error) {
	now := in.Now.UTC()
	aid := in.AssertionID
	if aid == "" {
		aid = newSAMLID(samlAssertionIDPrefix)
	}
	inResponseTo, recipient, audience := in.RequestID, in.ACS, in.SPEntityID
	notOnOrAfter := now.Add(samlAssertionTTL)
	switch fault {
	case FaultUnsolicited:
		inResponseTo = ""
	case FaultWrongInResponseTo:
		inResponseTo = samlEvilInResponseTo
	case FaultWrongRecipient:
		recipient = samlEvilRecipient
	case FaultWrongAudience:
		audience = samlEvilAudience
	case FaultSAMLExpired:
		now = now.Add(-time.Hour)
		notOnOrAfter = now.Add(samlAssertionTTL)
	}
	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsSAMLP)
	resp.CreateAttr("xmlns:saml", nsSAML)
	resp.CreateAttr("ID", newSAMLID(samlResponseIDPrefix))
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", samlTime(now))
	resp.CreateAttr("Destination", in.ACS)
	if inResponseTo != "" {
		resp.CreateAttr("InResponseTo", inResponseTo)
	}
	resp.CreateElement("saml:Issuer").SetText(s.SAMLEntityID())
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", statusOK)

	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", nsSAML)
	a.CreateAttr("ID", aid)
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", samlTime(now))
	a.CreateElement("saml:Issuer").SetText(s.SAMLEntityID())
	subj := a.CreateElement("saml:Subject")
	nid := subj.CreateElement("saml:NameID")
	nid.CreateAttr("Format", nameIDPer)
	nid.SetText(in.User.Sub)
	if fault == FaultCommentInNameID {
		// signed as "<sub>.evil"; the comment goes in after signing (below)
		nid.SetText(in.User.Sub + samlCommentSuffix)
	}
	sc := subj.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", bearer)
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("NotOnOrAfter", samlTime(notOnOrAfter))
	scd.CreateAttr("Recipient", recipient)
	if inResponseTo != "" {
		scd.CreateAttr("InResponseTo", inResponseTo)
	}
	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", samlTime(now.Add(-time.Minute)))
	cond.CreateAttr("NotOnOrAfter", samlTime(notOnOrAfter))
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(audience)
	as := a.CreateElement("saml:AuthnStatement")
	as.CreateAttr("AuthnInstant", samlTime(in.AuthTime))
	si := in.SessionIndex
	if si == "" {
		si = newSAMLID(samlSessionIndexPrefix)
	}
	as.CreateAttr("SessionIndex", si)
	as.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText(samlClassRef(in.Method))
	attrs := a.CreateElement("saml:AttributeStatement")
	addAttr := func(name string, values ...string) {
		at := attrs.CreateElement("saml:Attribute")
		at.CreateAttr("Name", name)
		for _, v := range values {
			at.CreateElement("saml:AttributeValue").SetText(v)
		}
	}
	addAttr(samlDefaultAttributeEmail, in.User.Email)
	addAttr(samlDefaultAttributeName, in.User.Name)
	if len(in.User.Groups) > 0 {
		addAttr(samlDefaultAttributeGroups, in.User.Groups...)
	}
	if d := in.User.Device; d != nil {
		if d.Managed != nil {
			addAttr("device_managed", strconv.FormatBool(*d.Managed))
		}
		if d.Compliant != nil {
			addAttr("device_compliant", strconv.FormatBool(*d.Compliant))
		}
	}

	ctx, err := s.samlSigner()
	if err != nil {
		return nil, err
	}
	switch fault {
	case FaultUnsignedAssertion:
		resp.AddChild(a)
	case FaultSignedResponseOnly:
		resp.AddChild(a)
		signed, err := ctx.SignEnveloped(resp)
		if err != nil {
			return nil, err
		}
		doc.SetRoot(signed)
	default:
		signed, err := ctx.SignEnveloped(a)
		if err != nil {
			return nil, err
		}
		resp.AddChild(signed)
	}
	if fault == FaultCommentInNameID {
		// c14n drops comments, so the signature still verifies over
		// "<sub>.evil" while a first-text-node reader sees "<sub>"
		if nid := doc.FindElement("//Assertion/Subject/NameID"); nid != nil {
			nid.Child = nil
			nid.CreateText(in.User.Sub)
			nid.CreateComment("")
			nid.CreateText(samlCommentSuffix)
		}
	}
	if n, ok := xswNumber(fault); ok {
		if err := WrapXSW(doc, n); err != nil {
			return nil, err
		}
	}
	return doc, nil
}

func (s *Server) samlSigner() (*dsig.SigningContext, error) {
	ctx, err := dsig.NewSigningContext(s.key, [][]byte{s.samlCert})
	if err != nil {
		return nil, err
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, err
	}
	return ctx, nil
}

func xswNumber(f Fault) (int, bool) {
	var n int
	if _, err := fmt.Sscanf(string(f), "xsw%d", &n); err != nil || n < 1 || n > 8 || string(f) != fmt.Sprintf("xsw%d", n) {
		return 0, false
	}
	return n, true
}

// WrapXSW applies XML signature wrapping attack n (1..8) to a response whose
// Assertion is correctly signed, after Somorovsky et al., "On Breaking SAML"
// (2012), adapted to assertion signatures: each variant adds an unsigned
// "evil" assertion for xswEvilSubject that a careless SP might consume, and
// moves or copies the signed original so its signature still verifies.
func WrapXSW(doc *etree.Document, n int) error {
	resp := doc.Root()
	orig := resp.FindElement("./Assertion")
	if orig == nil {
		return fmt.Errorf("devidp: no assertion to wrap")
	}
	evil := orig.Copy()
	evil.CreateAttr("ID", newSAMLID("_evil"))
	if nid := evil.FindElement("./Subject/NameID"); nid != nil {
		nid.SetText(xswEvilSubject)
	}
	removeSig := func(el *etree.Element) {
		if sig := el.FindElement("./Signature"); sig != nil {
			el.RemoveChild(sig)
		}
	}
	switch n {
	case 1: // an unsigned evil assertion before the signed one
		removeSig(evil)
		resp.InsertChildAt(orig.Index(), evil)
	case 2: // ... after it
		removeSig(evil)
		resp.AddChild(evil)
	case 3: // the signed assertion wrapped inside the evil one
		removeSig(evil)
		resp.RemoveChild(orig)
		evil.AddChild(orig)
		resp.AddChild(evil)
	case 4: // the evil assertion wrapped inside the signed one's Signature/Object
		removeSig(evil)
		sig := orig.FindElement("./Signature")
		sig.CreateElement("ds:Object").AddChild(evil)
	case 5: // the evil assertion carries the original's signature; the original moves to Extensions
		resp.RemoveChild(orig)
		resp.CreateElement("samlp:Extensions").AddChild(orig)
		resp.AddChild(evil)
	case 6: // the evil assertion carries a copied signature whose Object holds the original
		resp.RemoveChild(orig)
		sig := evil.FindElement("./Signature")
		if sig == nil {
			return fmt.Errorf("devidp: no signature to copy")
		}
		sig.CreateElement("ds:Object").AddChild(orig)
		resp.AddChild(evil)
	case 7: // the signed original inside an unknown extension element, the evil assertion at top level
		removeSig(evil)
		resp.RemoveChild(orig)
		ext := resp.CreateElement("samlp:Extensions")
		ext.CreateElement("Wrapper").AddChild(orig)
		resp.AddChild(evil)
	case 8: // the evil assertion's (copied) signature holds an Object with the original, minus its signature
		resp.RemoveChild(orig)
		inner := orig.Copy()
		removeSig(inner)
		sig := evil.FindElement("./Signature")
		if sig == nil {
			return fmt.Errorf("devidp: no signature to copy")
		}
		sig.CreateElement("ds:Object").AddChild(inner)
		resp.AddChild(evil)
	default:
		return fmt.Errorf("devidp: no XSW variant %d", n)
	}
	return nil
}

var postTmpl = template.Must(template.New("post").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Signing in · Tessera dev IdP</title></head>
<body><form method="post" action="{{.ACS}}" id="f">
<input type="hidden" name="SAMLResponse" value="{{.Response}}">
{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}">{{end}}
<noscript><button type="submit">Continue</button></noscript>
</form>
<script nonce="{{.Nonce}}">document.getElementById("f").submit()</script>
</body></html>`))

// postSAMLResponse answers with the auto-POST form to the ACS.
func (s *Server) postSAMLResponse(w http.ResponseWriter, p pendingSAML, u User, m Method, authTime time.Time, sid string) {
	in := SAMLAssertionInput{RequestID: p.requestID, ACS: p.acs, SPEntityID: p.spEntityID, User: u, Method: m,
		AuthTime: authTime, Now: s.now(), SessionIndex: samlSessionIndexPrefix + sid}
	s.mu.Lock()
	if p.fault == FaultReplay && s.lastAssertionID != "" {
		in.AssertionID = s.lastAssertionID
	}
	s.mu.Unlock()
	doc, err := s.BuildSAMLResponse(in, p.fault)
	if err != nil {
		s.errorPage(w, http.StatusInternalServerError, "Could not build the SAML response.")
		return
	}
	if a := doc.FindElement("//Assertion"); a != nil {
		s.mu.Lock()
		s.lastAssertionID = a.SelectAttrValue("ID", "")
		s.mu.Unlock()
	}
	b, err := doc.WriteToBytes()
	if err != nil {
		s.errorPage(w, http.StatusInternalServerError, "Could not serialize the SAML response.")
		return
	}
	nonceB := make([]byte, samlPOSTFormNonceBytes)
	_, _ = rand.Read(nonceB)
	nonce := base64.RawStdEncoding.EncodeToString(nonceB)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; form-action "+p.acs+"; base-uri 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = postTmpl.Execute(w, map[string]string{"ACS": p.acs, "Response": base64.StdEncoding.EncodeToString(b),
		"RelayState": p.relayState, "Nonce": nonce})
}
