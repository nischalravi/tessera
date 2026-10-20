package samlsp_test

import (
	"crypto/x509"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth/samlsp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp/devidptest"
)

const (
	wsRealm = "http://127.0.0.1:5999/api/auth/wsfed/c1"
	wsReply = "http://127.0.0.1:5999/api/auth/wsfed/c1/callback"
)

type wsEnv struct {
	idp  *devidptest.IdP
	conn samlsp.Connection
	clk  *clock
}

func wsSetup(t testing.TB) *wsEnv {
	t.Helper()
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	idp := devidptest.Start(t, devidp.Config{Now: clk.now})
	cert, err := x509.ParseCertificate(idp.SAMLCertificate())
	if err != nil {
		t.Fatal(err)
	}
	return &wsEnv{idp: idp, clk: clk, conn: samlsp.Connection{IdPEntityID: idp.SAMLEntityID(), IdPCerts: []*x509.Certificate{cert}}}
}

func (e *wsEnv) signIn(t testing.TB, sub string, m devidp.Method, fault devidp.Fault, fresh bool) devidptest.WSFedPost {
	t.Helper()
	u, err := samlsp.WSFedLoginURL(e.idp.WSFedURL(), wsRealm, wsReply, "ctx-1", fresh, "")
	if err != nil {
		t.Fatal(err)
	}
	if fault != devidp.FaultNone {
		u += "&fault=" + url.QueryEscape(string(fault))
	}
	p := e.idp.NewBrowser(t).AuthorizeWSFed(t, u, sub, m)
	if p.Reply != wsReply || p.WCtx != "ctx-1" {
		t.Fatalf("posted to %s with wctx %q", p.Reply, p.WCtx)
	}
	return p
}

func (e *wsEnv) validate(wresult string) (*samlsp.Assertion, error) {
	return samlsp.ValidateWSFed(e.conn, wresult, samlsp.WSFedExpect{Realm: wsRealm, Reply: wsReply, Now: e.clk.now()})
}

func TestWSFedValid(t *testing.T) {
	e := wsSetup(t)
	p := e.signIn(t, "00u-ivan-admin2", devidp.MethodHardwareKey, devidp.FaultNone, false)
	a, err := e.validate(p.WResult)
	if err != nil {
		t.Fatal(err)
	}
	if a.Subject != "00u-ivan-admin2" || a.ClassRef != devidp.SAMLClassPhrh || a.ID == "" || len(a.Attributes["email"]) != 1 {
		t.Errorf("assertion %+v", a)
	}
	if _, err := samlsp.ValidateWSFed(e.conn, p.WResult, samlsp.WSFedExpect{Realm: wsRealm + "x", Reply: wsReply, Now: e.clk.now()}); err == nil {
		t.Error("accepted for another realm")
	}
	u, _ := samlsp.WSFedLoginURL("https://adfs.corp.example/adfs/ls/", wsRealm, wsReply, "c", true, "urn:x")
	q, _ := url.ParseQuery(u[strings.IndexByte(u, '?')+1:])
	if q.Get("wa") != "wsignin1.0" || q.Get("wfresh") != "0" || q.Get("wauth") != "urn:x" || q.Get("wctx") != "c" {
		t.Errorf("login URL %s", u)
	}
}

// TestWSFedFaultsRefused: every fault the dev IdP's WS-Federation endpoint
// accepts is refused (replay: the ACS's replay cache, api tests).
func TestWSFedFaultsRefused(t *testing.T) {
	wrap := []string{samlsp.ReasonAssertionCount, samlsp.ReasonUnsignedAssert, samlsp.ReasonSignature}
	want := map[devidp.Fault][]string{
		devidp.FaultWSFedSAML11: {samlsp.ReasonAssertionCount}, devidp.FaultWSFedWrongAppliesTo: {samlsp.ReasonAppliesTo},
		devidp.FaultWSFedTampered: {samlsp.ReasonSignature}, devidp.FaultUnsignedAssertion: {samlsp.ReasonUnsignedAssert},
		devidp.FaultSignedResponseOnly: {samlsp.ReasonUnsignedAssert}, devidp.FaultCommentInNameID: {samlsp.ReasonNameIDComment},
		devidp.FaultWrongAudience: {samlsp.ReasonAudience}, devidp.FaultWrongRecipient: {samlsp.ReasonRecipient},
		devidp.FaultSAMLExpired: {samlsp.ReasonExpired},
	}
	e := wsSetup(t)
	for _, f := range devidp.WSFedFaults() {
		if f == devidp.FaultReplay {
			continue
		}
		reasons := want[f]
		if strings.HasPrefix(string(f), "xsw") {
			reasons = wrap
		}
		if reasons == nil {
			t.Errorf("fault %s has no expected reason", f)
			continue
		}
		t.Run(string(f), func(t *testing.T) {
			a, err := e.validate(e.signIn(t, "00u-alice-admin", devidp.MethodPasskey, f, false).WResult)
			if err == nil {
				t.Fatalf("accepted: %+v", a)
			}
			if got := samlsp.ReasonOf(err); !slices.Contains(reasons, got) {
				t.Errorf("reason %s (%v), want one of %v", got, err, reasons)
			}
		})
	}
}

func TestWSFedRefusals(t *testing.T) {
	e := wsSetup(t)
	p := e.signIn(t, "00u-vic-viewer", devidp.MethodPassword, devidp.FaultNone, false)
	for name, body := range map[string]string{
		"not XML":         "<<",
		"a SAML Response": `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`,
		"WS-Trust 1.3":    strings.Replace(p.WResult, "http://schemas.xmlsoap.org/ws/2005/02/trust", "http://docs.oasis-open.org/ws-sx/ws-trust/200512", -1),
		"two tokens":      strings.Replace(p.WResult, "<t:TokenType>", "<t:RequestedSecurityToken/><t:TokenType>", 1),
		"too large":       strings.Repeat("A", samlsp.MaxResponseBytes+1),
	} {
		if a, err := e.validate(body); err == nil {
			t.Errorf("%s: accepted %+v", name, a)
		}
	}
	other := wsSetup(t)
	c := e.conn
	c.IdPCerts = other.conn.IdPCerts
	if _, err := samlsp.ValidateWSFed(c, p.WResult, samlsp.WSFedExpect{Realm: wsRealm, Reply: wsReply, Now: e.clk.now()}); samlsp.ReasonOf(err) != samlsp.ReasonSignature {
		t.Errorf("wrong pinned certificate: %v", err)
	}
	c = e.conn
	c.IdPEntityID = "https://other.example/adfs"
	if _, err := samlsp.ValidateWSFed(c, p.WResult, samlsp.WSFedExpect{Realm: wsRealm, Reply: wsReply, Now: e.clk.now()}); samlsp.ReasonOf(err) != samlsp.ReasonIssuer {
		t.Errorf("wrong issuer: %v", err)
	}
	if _, err := samlsp.ValidateWSFed(e.conn, p.WResult, samlsp.WSFedExpect{Realm: wsRealm, Reply: wsReply, Now: e.clk.now().Add(10 * time.Minute)}); samlsp.ReasonOf(err) != samlsp.ReasonExpired {
		t.Errorf("late: %v", err)
	}
}

// FuzzWSFed: mutated wresults never panic and never validate unless they
// are the original bytes.
func FuzzWSFed(f *testing.F) {
	e := wsSetup(f)
	p := e.signIn(f, "00u-alice-admin", devidp.MethodPasskey, devidp.FaultNone, false)
	if _, err := e.validate(p.WResult); err != nil {
		f.Fatalf("the seed is refused: %v", err)
	}
	f.Add(p.WResult)
	f.Add(strings.Replace(p.WResult, "00u-alice-admin", "00u-ivan-admin2", 1))
	f.Fuzz(func(t *testing.T, s string) {
		if a, err := e.validate(s); err == nil && (s != p.WResult || a.Subject != "00u-alice-admin") {
			t.Fatalf("accepted a mutated wresult: %+v", a)
		}
	})
}
