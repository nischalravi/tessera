package samlsp

import (
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"crypto/sha256"

	"github.com/beevik/etree"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// WS-Federation passive sign-in (issue #153, legacy ADFS). The IdP posts
// wa=wsignin1.0 and wresult: a WS-Trust RequestSecurityTokenResponse whose
// RequestedSecurityToken is a signed SAML 2.0 assertion. The checks are the
// SAML ACS's on that assertion (one assertion in the whole document, its own
// enveloped signature by a pinned certificate, no comment in NameID, only
// the verified element consumed, issuer, audience = the realm, time window,
// AuthnInstant), plus: AppliesTo, when present, names the realm, and a
// SubjectConfirmationData Recipient, when present, is the reply URL. There
// is no request ID in WS-Federation: the login transaction binds the
// sign-in (wctx), and the assertion ID is used once (replay_cache). SAML 1.1
// tokens are not accepted.

// NSWSTrust is WS-Trust 2005/02, which ADFS passive sign-in uses.
const NSWSTrust = "http://schemas.xmlsoap.org/ws/2005/02/trust"

// ReasonAppliesTo: the RSTR is for another realm.
const ReasonAppliesTo = "wsfed_applies_to_mismatch"

// WSFedLoginURL is the passive sign-in URL: wsignin1.0 for realm, replying
// to reply with wctx; fresh forces a new authentication (wfresh=0) and
// wauth names a requested authentication method.
func WSFedLoginURL(endpoint, realm, reply, wctx string, fresh bool, wauth string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.Fragment != "" {
		return "", fail(ReasonConfig, fmt.Errorf("passive endpoint %q", endpoint))
	}
	if realm == "" {
		return "", fail(ReasonConfig, errors.New("no realm"))
	}
	q := u.Query()
	q.Set("wa", "wsignin1.0")
	q.Set("wtrealm", realm)
	q.Set("wreply", reply)
	q.Set("wctx", wctx)
	if fresh {
		q.Set("wfresh", "0")
	}
	if wauth != "" {
		q.Set("wauth", wauth)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// WSFedExpect is what the token must match.
type WSFedExpect struct {
	Realm, Reply string
	Now          time.Time
}

// ValidateWSFed validates a wresult (the RSTR XML, as posted).
func ValidateWSFed(c Connection, wresult string, e WSFedExpect) (*Assertion, error) {
	if len(wresult) > MaxResponseBytes {
		return nil, fail(ReasonTooLarge, nil)
	}
	if c.IdPEntityID == "" || len(c.IdPCerts) == 0 || e.Realm == "" {
		return nil, fail(ReasonConfig, errors.New("the connection lacks an IdP issuer, pinned certificate or realm"))
	}
	root, err := parseChecked([]byte(wresult))
	if err != nil {
		return nil, err
	}
	if root.Tag != "RequestSecurityTokenResponse" || root.NamespaceURI() != NSWSTrust {
		return nil, fail(ReasonMalformed, errors.New("wresult is not a WS-Trust 2005/02 RequestSecurityTokenResponse"))
	}
	if at := root.FindElement("./AppliesTo/EndpointReference/Address"); at != nil && strings.TrimSpace(at.Text()) != e.Realm {
		return nil, fail(ReasonAppliesTo, nil)
	}
	var rst []*etree.Element
	for _, ch := range root.ChildElements() {
		if ch.Tag == "RequestedSecurityToken" && ch.NamespaceURI() == NSWSTrust {
			rst = append(rst, ch)
		}
	}
	if len(rst) != 1 {
		return nil, fail(ReasonAssertionCount, fmt.Errorf("%d RequestedSecurityToken elements", len(rst)))
	}
	el, err := soleSignedAssertion(root, rst[0])
	if err != nil {
		return nil, err
	}
	// verify the assertion on its own (with the namespaces it inherits) and
	// read only what was verified
	nsCtx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, fail(ReasonMalformed, err)
	}
	detached, err := etreeutils.NSDetatch(nsCtx, el)
	if err != nil {
		return nil, fail(ReasonMalformed, err)
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: c.IdPCerts})
	vc.Clock = dsig.NewFakeClockAt(e.Now)
	verified, err := vc.Validate(detached)
	if err != nil {
		return nil, fail(ReasonSignature, err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(verified)
	b, err := doc.WriteToBytes()
	if err != nil {
		return nil, fail(ReasonMalformed, err)
	}
	var a types.Assertion
	if err := xml.Unmarshal(b, &a); err != nil {
		return nil, fail(ReasonMalformed, err)
	}
	return checkWSFedAssertion(c, a, e)
}

func checkWSFedAssertion(c Connection, a types.Assertion, e WSFedExpect) (*Assertion, error) {
	if a.Issuer == nil || a.Issuer.Value != c.IdPEntityID {
		return nil, fail(ReasonIssuer, nil)
	}
	if a.Subject == nil || a.Subject.NameID == nil || a.Subject.SubjectConfirmation == nil ||
		a.Subject.SubjectConfirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return nil, fail(ReasonSubject, errors.New("no bearer subject"))
	}
	notOnOrAfter := time.Time{}
	if scd := a.Subject.SubjectConfirmation.SubjectConfirmationData; scd != nil {
		if scd.Recipient != "" && scd.Recipient != e.Reply {
			return nil, fail(ReasonRecipient, nil)
		}
		if scd.NotOnOrAfter != "" {
			t, err := parseTime(scd.NotOnOrAfter)
			if err != nil {
				return nil, fail(ReasonMalformed, err)
			}
			notOnOrAfter = t
		}
	}
	if !audienceIs(a, e.Realm) {
		return nil, fail(ReasonAudience, nil)
	}
	if a.Conditions == nil {
		return nil, fail(ReasonMalformed, errors.New("no Conditions"))
	}
	nb, err1 := parseTime(a.Conditions.NotBefore)
	na, err2 := parseTime(a.Conditions.NotOnOrAfter)
	if err1 != nil || err2 != nil {
		return nil, fail(ReasonMalformed, errors.New("Conditions times"))
	}
	if notOnOrAfter.IsZero() || na.Before(notOnOrAfter) {
		notOnOrAfter = na
	}
	switch {
	case e.Now.Add(Skew).Before(nb):
		return nil, fail(ReasonNotYetValid, nil)
	case !e.Now.Add(-Skew).Before(notOnOrAfter):
		return nil, fail(ReasonExpired, nil)
	}
	as := a.AuthnStatement
	if as == nil || as.AuthnInstant == nil || as.AuthnInstant.After(e.Now.Add(Skew)) {
		return nil, fail(ReasonAuthnInstant, nil)
	}
	sub := a.Subject.NameID.Value
	if sub == "" || strings.TrimSpace(sub) != sub || len(sub) > 255 || strings.ContainsAny(sub, "<>") {
		return nil, fail(ReasonSubject, nil)
	}
	out := &Assertion{ID: a.ID, Subject: sub, NameIDFormat: a.Subject.NameID.Format, AuthnInstant: as.AuthnInstant.UTC(),
		NotOnOrAfter: notOnOrAfter.UTC(), Attributes: map[string][]string{}}
	if as.AuthnContext != nil && as.AuthnContext.AuthnContextClassRef != nil {
		out.ClassRef = strings.TrimSpace(as.AuthnContext.AuthnContextClassRef.Value)
	}
	if a.AttributeStatement != nil {
		for _, at := range a.AttributeStatement.Attributes {
			for _, v := range at.Values {
				out.Attributes[at.Name] = append(out.Attributes[at.Name], v.Value)
			}
		}
	}
	if out.ID == "" {
		return nil, fail(ReasonMalformed, errors.New("no assertion ID"))
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%s", a.ID, sub, out.ClassRef, out.AuthnInstant.Format(time.RFC3339), c.IdPEntityID)))
	out.Raw = []byte(hex.EncodeToString(sum[:]))
	return out, nil
}
