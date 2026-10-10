package samlsp_test

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/nischalravi/tessera/mvp/server/internal/auth/samlsp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp/devidptest"
)

const acs = "http://127.0.0.1:5999/api/auth/saml/c1/acs"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

type env struct {
	idp  *devidptest.IdP
	conn samlsp.Connection
	clk  *clock
}

func setup(t testing.TB) *env {
	t.Helper()
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	idp := devidptest.Start(t, devidp.Config{Now: clk.now})
	cert, err := x509.ParseCertificate(idp.SAMLCertificate())
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, certPEM, err := samlsp.GenerateSPKey("test", clk.now())
	if err != nil {
		t.Fatal(err)
	}
	key, spCert, err := samlsp.ParseSPKey(keyPEM, certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &env{idp: idp, clk: clk, conn: samlsp.Connection{IdPEntityID: idp.SAMLEntityID(), IdPSSOURL: idp.SAMLSSOURL(),
		IdPCerts: []*x509.Certificate{cert}, SPEntityID: "http://127.0.0.1:5999/api/auth/saml/c1/metadata", ACSURL: acs,
		SPKey: key, SPCert: spCert}}
}

// signIn builds an AuthnRequest, signs in at the dev IdP (with fault) and
// returns the request ID and the posted response.
func (e *env) signIn(t testing.TB, sub string, m devidp.Method, fault devidp.Fault) (string, devidptest.SAMLPost) {
	t.Helper()
	req, err := samlsp.BuildAuthnRequest(e.conn, "relay-1", false, nil, e.clk.now())
	if err != nil {
		t.Fatal(err)
	}
	u := req.URL
	if fault != devidp.FaultNone {
		u += "&fault=" + url.QueryEscape(string(fault))
	}
	post := e.idp.NewBrowser(t).AuthorizeSAML(t, u, sub, m)
	if post.ACS != acs || post.RelayState != "relay-1" {
		t.Fatalf("posted to %s with RelayState %q", post.ACS, post.RelayState)
	}
	return req.ID, post
}

func (e *env) validate(id, resp string) (*samlsp.Assertion, error) {
	return samlsp.ValidateResponse(e.conn, resp, samlsp.Expect{RequestID: id, Now: e.clk.now()})
}

func TestAuthnRequest(t *testing.T) {
	e := setup(t)
	req, err := samlsp.BuildAuthnRequest(e.conn, "rs", true, []string{devidp.SAMLClassPhr}, e.clk.now())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(req.URL)
	q, _ := url.ParseQuery(u.RawQuery)
	if !strings.HasPrefix(req.URL, e.idp.SAMLSSOURL()+"?") || q.Get("RelayState") != "rs" || q.Get("Signature") == "" ||
		q.Get("SigAlg") == "" || req.ID == "" {
		t.Fatalf("AuthnRequest URL %s", req.URL)
	}
	if _, err := samlsp.BuildAuthnRequest(samlsp.Connection{}, "", false, nil, e.clk.now()); samlsp.ReasonOf(err) != samlsp.ReasonConfig {
		t.Errorf("unconfigured connection: %v", err)
	}
}

func TestValidResponse(t *testing.T) {
	e := setup(t)
	for m, ref := range map[devidp.Method]string{devidp.MethodPasskey: devidp.SAMLClassPhr,
		devidp.MethodPasswordOTP: devidp.SAMLClassMFA, devidp.MethodPassword: devidp.SAMLClassPassword} {
		sub := map[devidp.Method]string{devidp.MethodPasskey: "00u-alice-admin", devidp.MethodPasswordOTP: "00u-olu-operator",
			devidp.MethodPassword: "00u-vic-viewer"}[m]
		id, post := e.signIn(t, sub, m, devidp.FaultNone)
		a, err := e.validate(id, post.SAMLResponse)
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		if a.Subject != sub || a.ClassRef != ref || a.ID == "" || a.AuthnInstant.IsZero() || !a.NotOnOrAfter.After(e.clk.now()) ||
			len(a.Attributes["email"]) != 1 || len(a.Raw) == 0 {
			t.Errorf("%s: %+v", m, a)
		}
		// the same response answers no other request
		if _, err := e.validate("_another", post.SAMLResponse); samlsp.ReasonOf(err) != samlsp.ReasonInResponseTo {
			t.Errorf("%s for another request: %v", m, err)
		}
	}
}

// TestFaultsRefused: every SAML fault of the dev IdP (§18.5) is refused.
func TestFaultsRefused(t *testing.T) {
	wrap := []string{samlsp.ReasonAssertionCount, samlsp.ReasonUnsignedAssert, samlsp.ReasonSignature}
	want := map[devidp.Fault][]string{
		devidp.FaultUnsignedAssertion:  {samlsp.ReasonUnsignedAssert},
		devidp.FaultSignedResponseOnly: {samlsp.ReasonUnsignedAssert},
		devidp.FaultCommentInNameID:    {samlsp.ReasonNameIDComment},
		devidp.FaultWrongAudience:      {samlsp.ReasonAudience},
		devidp.FaultWrongRecipient:     {samlsp.ReasonRecipient},
		devidp.FaultSAMLExpired:        {samlsp.ReasonExpired},
		devidp.FaultUnsolicited:        {samlsp.ReasonUnsolicited},
		devidp.FaultWrongInResponseTo:  {samlsp.ReasonInResponseTo},
		devidp.FaultXSW1:               wrap, devidp.FaultXSW2: wrap, devidp.FaultXSW3: wrap, devidp.FaultXSW4: wrap,
		devidp.FaultXSW5: wrap, devidp.FaultXSW6: wrap, devidp.FaultXSW7: wrap, devidp.FaultXSW8: wrap,
	}
	for _, f := range devidp.SAMLFaults() {
		if _, ok := want[f]; !ok && f != devidp.FaultReplay { // replay: the ACS's replay cache (api tests)
			t.Errorf("SAML fault %s has no expected reason", f)
		}
	}
	e := setup(t)
	for f, reasons := range want {
		t.Run(string(f), func(t *testing.T) {
			id, post := e.signIn(t, "00u-alice-admin", devidp.MethodPasskey, f)
			a, err := e.validate(id, post.SAMLResponse)
			if err == nil {
				t.Fatalf("accepted: %+v", a)
			}
			if got := samlsp.ReasonOf(err); !slices.Contains(reasons, got) {
				t.Errorf("reason %s (%v), want one of %v", got, err, reasons)
			}
		})
	}
}

// TestReplayFaultReusesAssertionID: the replay fault sends the previous
// assertion ID again (the ACS refuses it through the replay cache).
func TestReplayFaultReusesAssertionID(t *testing.T) {
	e := setup(t)
	id1, p1 := e.signIn(t, "00u-alice-admin", devidp.MethodPasskey, devidp.FaultNone)
	a1, err := e.validate(id1, p1.SAMLResponse)
	if err != nil {
		t.Fatal(err)
	}
	id2, p2 := e.signIn(t, "00u-alice-admin", devidp.MethodPasskey, devidp.FaultReplay)
	a2, err := e.validate(id2, p2.SAMLResponse)
	if err != nil || a2.ID != a1.ID {
		t.Fatalf("replay fault: %v, ids %s %s", err, a1.ID, a2.ID)
	}
}

func decodeDoc(t testing.TB, resp string) *etree.Document {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(resp)
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	return doc
}

func encodeDoc(t testing.TB, doc *etree.Document) string {
	t.Helper()
	b, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestTamperingRefused(t *testing.T) {
	e := setup(t)
	id, post := e.signIn(t, "00u-vic-viewer", devidp.MethodPassword, devidp.FaultNone)
	for name, edit := range map[string]func(*etree.Document){
		"subject changed after signing": func(d *etree.Document) {
			d.FindElement("//Assertion/Subject/NameID").SetText("00u-alice-admin")
		},
		"class ref upgraded after signing": func(d *etree.Document) {
			d.FindElement("//AuthnContextClassRef").SetText(devidp.SAMLClassPhr)
		},
		"signature removed": func(d *etree.Document) {
			a := d.FindElement("//Assertion")
			a.RemoveChild(a.FindElement("./Signature"))
		},
		"encrypted assertion added": func(d *etree.Document) {
			d.Root().CreateElement("saml:EncryptedAssertion")
		},
		"not a Response": func(d *etree.Document) { d.Root().Tag = "LogoutResponse" },
	} {
		d := decodeDoc(t, post.SAMLResponse)
		edit(d)
		if a, err := e.validate(id, encodeDoc(t, d)); err == nil {
			t.Errorf("%s: accepted %+v", name, a)
		}
	}
	for name, resp := range map[string]string{"not base64": "!!!", "not XML": base64.StdEncoding.EncodeToString([]byte("<<")),
		"too large": strings.Repeat("A", base64.StdEncoding.EncodedLen(samlsp.MaxResponseBytes)+4)} {
		if _, err := e.validate(id, resp); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// another IdP certificate pinned: the signature does not verify
	other := setup(t)
	c := e.conn
	c.IdPCerts = other.conn.IdPCerts
	if _, err := samlsp.ValidateResponse(c, post.SAMLResponse, samlsp.Expect{RequestID: id, Now: e.clk.now()}); samlsp.ReasonOf(err) != samlsp.ReasonSignature {
		t.Errorf("wrong pinned certificate: %v", err)
	}
	// clock: before NotBefore - 60 s and after NotOnOrAfter + 60 s
	for _, d := range []time.Duration{-3 * time.Minute, 7 * time.Minute} {
		if _, err := samlsp.ValidateResponse(e.conn, post.SAMLResponse, samlsp.Expect{RequestID: id, Now: e.clk.now().Add(d)}); err == nil {
			t.Errorf("accepted at now%+v", d)
		}
	}
}

// FuzzACS: mutated responses never panic and never validate unless they are
// the original bytes.
func FuzzACS(f *testing.F) {
	e := setup(f)
	id, post := e.signIn(f, "00u-alice-admin", devidp.MethodPasskey, devidp.FaultNone)
	raw, _ := base64.StdEncoding.DecodeString(post.SAMLResponse)
	if _, err := e.validate(id, post.SAMLResponse); err != nil {
		f.Fatalf("the seed response is refused: %v", err)
	}
	f.Add(raw)
	f.Add(bytes.Replace(raw, []byte("00u-alice-admin"), []byte("00u-ivan-admin2"), 1))
	f.Add([]byte("<samlp:Response/>"))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := e.validate(id, base64.StdEncoding.EncodeToString(b))
		if err == nil && (!bytes.Equal(b, raw) || a.Subject != "00u-alice-admin") {
			t.Fatalf("accepted a mutated response: %+v", a)
		}
	})
}
