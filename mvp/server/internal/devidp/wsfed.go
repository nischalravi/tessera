package devidp

import (
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// WS-Federation passive sign-in (issue #153), shaped like ADFS:
//
//	GET /wsfed?wa=wsignin1.0&wtrealm=&wreply=&wctx=[&wfresh=0][&wauth=]
//
// It answers with an auto-POST form to wreply carrying wa=wsignin1.0,
// wctx and wresult: a WS-Trust 2005/02 RequestSecurityTokenResponse whose
// RequestedSecurityToken is the SAML 2.0 assertion the SAML endpoint would
// sign (audience = the realm, Recipient = wreply, no InResponseTo). The SAML
// assertion faults apply; WS-Federation adds its own below. wreply must
// match a registered pattern (default: the API's /api/auth/wsfed/*/callback
// on loopback). wfresh=0 forces a new sign-in.

const (
	pathWSFed    = "/wsfed"
	nsWSTrust    = "http://schemas.xmlsoap.org/ws/2005/02/trust"
	nsWSPolicy   = "http://schemas.xmlsoap.org/ws/2004/09/policy"
	nsWSAddr     = "http://www.w3.org/2005/08/addressing"
	nsWSUtil     = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	samlV2Token  = "urn:oasis:names:tc:SAML:2.0:assertion" // #nosec G101 -- a token type URN, not a credential
	samlV11Token = "urn:oasis:names:tc:SAML:1.0:assertion" // #nosec G101 -- a token type URN, not a credential

	defaultWSFedReplyPattern1 = "http://127.0.0.1:*/api/auth/wsfed/*/callback"
	defaultWSFedReplyPattern2 = "http://localhost:*/api/auth/wsfed/*/callback"
)

// WS-Federation faults (besides the SAML assertion faults).
const (
	FaultWSFedSAML11         Fault = "wsfed_saml11"           // a SAML 1.1 token instead of SAML 2.0
	FaultWSFedWrongAppliesTo Fault = "wsfed_wrong_applies_to" // AppliesTo names another realm
	FaultWSFedTampered       Fault = "wsfed_tampered"         // an attribute changed after signing
)

// WSFedFaults lists the faults a WS-Federation sign-in accepts: its own and
// the SAML assertion faults that mean something without an AuthnRequest.
func WSFedFaults() []Fault {
	out := []Fault{FaultWSFedSAML11, FaultWSFedWrongAppliesTo, FaultWSFedTampered}
	for _, f := range SAMLFaults() {
		if f != FaultUnsolicited && f != FaultWrongInResponseTo {
			out = append(out, f)
		}
	}
	return out
}

// WSFedURL is the passive endpoint.
func (s *Server) WSFedURL() string { return s.issuer + pathWSFed }

func (s *Server) handleWSFed(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := s.now()
	for k, v := range q {
		if len(v) > 1 {
			s.errorPage(w, http.StatusBadRequest, "Parameter "+k+" is repeated.")
			return
		}
	}
	p := pendingSAML{wsfed: true, acs: q.Get("wreply"), spEntityID: q.Get("wtrealm"), relayState: q.Get("wctx"),
		forceAuthn: q.Get("wfresh") == "0", requestedAt: now}
	if a := q.Get("wauth"); a != "" {
		p.classRefs = []string{a}
	}
	switch {
	case q.Get("wa") != "wsignin1.0":
		s.errorPage(w, http.StatusBadRequest, "Only wa=wsignin1.0 is supported.")
		return
	case p.spEntityID == "" || len(p.spEntityID) > 1024:
		s.errorPage(w, http.StatusBadRequest, "wtrealm is required.")
		return
	case len(p.relayState) > 1024:
		s.errorPage(w, http.StatusBadRequest, "wctx is too long.")
		return
	case !absoluteHTTP(p.acs) || !slices.ContainsFunc([]string{defaultWSFedReplyPattern1, defaultWSFedReplyPattern2},
		func(pat string) bool { return matchRedirect(pat, p.acs) }):
		s.errorPage(w, http.StatusBadRequest, "wreply is missing or not allowed.")
		return
	}
	p.fault = s.currentFault()
	if f := q.Get("fault"); f != "" {
		if !s.faults || !slices.Contains(WSFedFaults(), Fault(f)) {
			s.errorPage(w, http.StatusBadRequest, "Unknown or disabled WS-Federation fault.")
			return
		}
		p.fault = Fault(f)
	}
	if !slices.Contains(WSFedFaults(), p.fault) {
		p.fault = FaultNone
	}
	if sess, ok := s.session(r, now); ok && !p.forceAuthn {
		s.postWSFed(w, p, sess.user, sess.method, sess.authTime, sess.sid)
		return
	}
	id := rand.Text()
	if err := s.samlPending.put(id, p, now.Add(samlPendingTTL), now); err != nil {
		s.errorPage(w, http.StatusServiceUnavailable, "Too many sign-ins in progress.")
		return
	}
	d := pageData{Title: "Sign in (WS-Federation)", Req: id, Action: s.SAMLSSOURL(), ClientID: p.spEntityID, SAML: true,
		ACRValues: strings.Join(p.classRefs, " "), Fault: string(p.fault)}
	if p.forceAuthn {
		d.MaxAge = "0 (wfresh=0)"
	}
	s.renderUsers(w, &d, "")
}

// BuildWSFedResult builds the wresult RSTR for in with fault applied.
func (s *Server) BuildWSFedResult(in SAMLAssertionInput, fault Fault) (*etree.Document, error) {
	samlFault := FaultNone
	if slices.Contains(SAMLFaults(), fault) {
		samlFault = fault
	}
	in.RequestID = ""
	resp, err := s.BuildSAMLResponse(in, samlFault)
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	rstr := doc.CreateElement("t:RequestSecurityTokenResponse")
	rstr.CreateAttr("xmlns:t", nsWSTrust)
	life := rstr.CreateElement("t:Lifetime")
	life.CreateAttr("xmlns:wsu", nsWSUtil)
	now := in.Now.UTC()
	life.CreateElement("wsu:Created").SetText(samlTime(now))
	life.CreateElement("wsu:Expires").SetText(samlTime(now.Add(samlAssertionTTL)))
	realm := in.SPEntityID
	if fault == FaultWSFedWrongAppliesTo {
		realm = samlEvilAudience
	}
	at := rstr.CreateElement("wsp:AppliesTo")
	at.CreateAttr("xmlns:wsp", nsWSPolicy)
	ep := at.CreateElement("wsa:EndpointReference")
	ep.CreateAttr("xmlns:wsa", nsWSAddr)
	ep.CreateElement("wsa:Address").SetText(realm)
	token := rstr.CreateElement("t:RequestedSecurityToken")
	tokenType := samlV2Token
	if fault == FaultWSFedSAML11 {
		tokenType = samlV11Token
		a1 := token.CreateElement("saml1:Assertion")
		a1.CreateAttr("xmlns:saml1", samlV11Token)
		a1.CreateAttr("MajorVersion", "1")
		a1.CreateAttr("MinorVersion", "1")
		a1.CreateAttr("AssertionID", newSAMLID(samlAssertionIDPrefix))
		a1.CreateAttr("Issuer", s.SAMLEntityID())
	} else {
		// everything the Response carried besides its Issuer and Status: the
		// assertion, or with an XSW fault the wrapped and evil copies
		for _, ch := range resp.Root().ChildElements() {
			if ch.Tag == "Issuer" || ch.Tag == "Status" {
				continue
			}
			token.AddChild(ch.Copy())
		}
	}
	rstr.CreateElement("t:TokenType").SetText(tokenType)
	rstr.CreateElement("t:RequestType").SetText(nsWSTrust + "/Issue")
	rstr.CreateElement("t:KeyType").SetText("http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey")
	if fault == FaultWSFedTampered {
		if v := doc.FindElement("//AttributeStatement/Attribute/AttributeValue"); v != nil {
			v.SetText("tampered-" + v.Text())
		}
	}
	return doc, nil
}

var wsfedPostTmpl = template.Must(template.New("wsfed").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Signing in · Tessera dev IdP</title></head>
<body><form method="post" action="{{.Reply}}" id="f">
<input type="hidden" name="wa" value="wsignin1.0">
<input type="hidden" name="wresult" value="{{.Result}}">
<input type="hidden" name="wctx" value="{{.Ctx}}">
<noscript><button type="submit">Continue</button></noscript>
</form>
<script nonce="{{.Nonce}}">document.getElementById("f").submit()</script>
</body></html>`))

// postWSFed answers with the auto-POST form to wreply.
func (s *Server) postWSFed(w http.ResponseWriter, p pendingSAML, u User, m Method, authTime time.Time, sid string) {
	in := SAMLAssertionInput{ACS: p.acs, SPEntityID: p.spEntityID, User: u, Method: m, AuthTime: authTime, Now: s.now(),
		SessionIndex: samlSessionIndexPrefix + sid}
	s.mu.Lock()
	if p.fault == FaultReplay && s.lastAssertionID != "" {
		in.AssertionID = s.lastAssertionID
	}
	s.mu.Unlock()
	doc, err := s.BuildWSFedResult(in, p.fault)
	if err != nil {
		s.errorPage(w, http.StatusInternalServerError, "Could not build the WS-Federation token.")
		return
	}
	if a := doc.FindElement("//Assertion"); a != nil && a.SelectAttrValue("ID", "") != "" {
		s.mu.Lock()
		s.lastAssertionID = a.SelectAttrValue("ID", "")
		s.mu.Unlock()
	}
	b, err := doc.WriteToBytes()
	if err != nil {
		s.errorPage(w, http.StatusInternalServerError, "Could not serialize the token.")
		return
	}
	nonceB := make([]byte, samlPOSTFormNonceBytes)
	_, _ = rand.Read(nonceB)
	nonce := base64.RawStdEncoding.EncodeToString(nonceB)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; form-action "+p.acs+"; base-uri 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = wsfedPostTmpl.Execute(w, map[string]string{"Reply": p.acs, "Result": string(b), "Ctx": p.relayState, "Nonce": nonce})
}
