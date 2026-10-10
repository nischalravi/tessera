// Package devidptest runs the dev IdP in-process on a loopback httptest
// server, for relying-party tests (docs/design/phase-0-platform-security.md
// §18.5). Import it from _test.go files only.
package devidptest

import (
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
)

// Test client registered by Start when the config has no clients. The secret
// is a fixed test value, not a credential.
const (
	ClientID     = "tessera-test"
	ClientSecret = "devidp-test-secret" // #nosec G101 -- fixed test-only value for an in-process mock IdP
)

// IdP is a running in-process dev IdP.
type IdP struct {
	*devidp.Server
	HTTP *httptest.Server
	URL  string // the issuer
}

// Start starts a dev IdP on 127.0.0.1 with fault injection enabled. When
// cfg.Clients is empty it registers ClientID/ClientSecret with redirect URIs
// on any loopback port. The server stops when the test ends.
func Start(tb testing.TB, cfg devidp.Config) *IdP {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	cfg.Issuer = "http://" + ln.Addr().String()
	cfg.Faults = true
	if len(cfg.Clients) == 0 {
		cfg.Clients = []devidp.Client{{
			ID:           ClientID,
			Secret:       ClientSecret,
			RedirectURIs: []string{"http://127.0.0.1:*/callback", "http://127.0.0.1:*/api/auth/oidc/*/callback"},
		}}
	}
	srv, err := devidp.New(cfg)
	if err != nil {
		_ = ln.Close()
		tb.Fatal(err)
	}
	hs := httptest.NewUnstartedServer(srv.Handler())
	_ = hs.Listener.Close()
	hs.Listener = ln
	hs.Start()
	tb.Cleanup(hs.Close)
	return &IdP{Server: srv, HTTP: hs, URL: cfg.Issuer}
}

var reqRE = regexp.MustCompile(`name="req" value="([^"]+)"`)

// Browser is a user agent for the dev IdP's pages: it keeps the IdP's
// session cookie and never follows redirects, so the caller sees the
// redirect back to the relying party.
type Browser struct {
	IdP *IdP
	C   *http.Client
}

// NewBrowser returns a Browser with an empty cookie jar.
func (i *IdP) NewBrowser(tb testing.TB) *Browser {
	tb.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		tb.Fatal(err)
	}
	return &Browser{IdP: i, C: &http.Client{Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Authorize opens authURL (the IdP's /authorize with the RP's parameters)
// and, when the sign-in page is shown, signs in as sub with method and the
// profile emulation. It returns the URL the IdP redirects back to (the RP's
// redirect_uri with code, state and iss, or an error). With single sign-on
// the page is skipped and sub, method and profile are ignored.
func (b *Browser) Authorize(tb testing.TB, authURL, sub string, m devidp.Method, p devidp.Profile) *url.URL {
	tb.Helper()
	resp, err := b.C.Get(authURL)
	if err != nil {
		tb.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusFound, http.StatusSeeOther:
		return location(tb, resp)
	case http.StatusOK:
	default:
		tb.Fatalf("dev IdP authorize: %d %s", resp.StatusCode, body)
	}
	match := reqRE.FindSubmatch(body)
	if match == nil {
		tb.Fatalf("dev IdP sign-in page without a request id:\n%s", body)
	}
	resp, err = b.C.PostForm(b.IdP.URL+"/authorize", url.Values{"req": {html.UnescapeString(string(match[1]))},
		"choice": {sub + " " + string(m)}, "profile": {string(p)}})
	if err != nil {
		tb.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		tb.Fatalf("dev IdP sign-in: %d %s", resp.StatusCode, body)
	}
	return location(tb, resp)
}

func location(tb testing.TB, resp *http.Response) *url.URL {
	tb.Helper()
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || u.String() == "" {
		tb.Fatalf("dev IdP redirect without a Location: %v", err)
	}
	return u
}

var (
	formActionRE = regexp.MustCompile(`<form method="post" action="([^"]+)" id="f">`)
	hiddenRE     = regexp.MustCompile(`<input type="hidden" name="(SAMLResponse|RelayState)" value="([^"]*)">`)
)

// SAMLPost is the dev IdP's auto-POST to an ACS.
type SAMLPost struct {
	ACS          string
	SAMLResponse string
	RelayState   string
}

// AuthorizeSAML opens a SAML Redirect-binding SSO URL and, when the sign-in
// page is shown, signs in as sub with method. It returns the form the IdP
// would auto-POST to the SP's ACS.
func (b *Browser) AuthorizeSAML(tb testing.TB, ssoURL, sub string, m devidp.Method) SAMLPost {
	tb.Helper()
	resp, err := b.C.Get(ssoURL)
	if err != nil {
		tb.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		tb.Fatalf("dev IdP SAML SSO: %d %s", resp.StatusCode, body)
	}
	if match := reqRE.FindSubmatch(body); match != nil {
		resp, err = b.C.PostForm(b.IdP.URL+"/saml/sso", url.Values{"req": {html.UnescapeString(string(match[1]))},
			"choice": {sub + " " + string(m)}})
		if err != nil {
			tb.Fatal(err)
		}
		body, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			tb.Fatalf("dev IdP SAML sign-in: %d %s", resp.StatusCode, body)
		}
	}
	return parseSAMLPost(tb, body)
}

func parseSAMLPost(tb testing.TB, body []byte) SAMLPost {
	tb.Helper()
	a := formActionRE.FindSubmatch(body)
	if a == nil {
		tb.Fatalf("no SAML POST form in:\n%s", body)
	}
	p := SAMLPost{ACS: html.UnescapeString(string(a[1]))}
	for _, m := range hiddenRE.FindAllSubmatch(body, -1) {
		v := html.UnescapeString(string(m[2]))
		if string(m[1]) == "SAMLResponse" {
			p.SAMLResponse = v
		} else {
			p.RelayState = v
		}
	}
	if p.SAMLResponse == "" {
		tb.Fatalf("no SAMLResponse in:\n%s", body)
	}
	return p
}
