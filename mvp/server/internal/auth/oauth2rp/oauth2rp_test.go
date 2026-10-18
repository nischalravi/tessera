package oauth2rp_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strconv"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth/oauth2rp"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp/devidptest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

const redirect = "http://127.0.0.1:5999/api/auth/oauth2/c1/callback"

type env struct {
	idp  *devidptest.IdP
	rp   *oauth2rp.RP
	conn oauth2rp.Connection
}

func setup(t *testing.T) *env {
	t.Helper()
	idp := devidptest.Start(t, devidp.Config{})
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	rp, err := oauth2rp.New(hc)
	if err != nil {
		t.Fatal(err)
	}
	return &env{idp: idp, rp: rp, conn: oauth2rp.Connection{Profile: oauth2rp.GitHub, ClientID: devidptest.ClientID,
		ClientSecret: devidptest.ClientSecret, AuthorizationURL: idp.GitHubAuthorizeURL(), TokenURL: idp.GitHubTokenURL(),
		UserinfoURL: idp.GitHubUserURL(), Scopes: []string{"read:user", "user:email"}}}
}

// signIn runs the authorization request at the dev IdP (with fault) and
// redeems the code.
func (e *env) signIn(t *testing.T, c oauth2rp.Connection, sub string, fault devidp.Fault) (*oauth2rp.User, error) {
	t.Helper()
	verifier := rand.Text() + rand.Text()
	u, err := oauth2rp.AuthURL(c, oauth2rp.AuthRequest{RedirectURI: redirect, State: "st-1", Verifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(u)
	q, _ := url.ParseQuery(pu.RawQuery)
	sum := sha256.Sum256([]byte(verifier))
	if q.Get("state") != "st-1" || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) || q.Get("client_id") != c.ClientID {
		t.Fatalf("authorization URL %s", u)
	}
	if fault != devidp.FaultNone {
		u += "&fault=" + string(fault)
	}
	cb := e.idp.NewBrowser(t).Authorize(t, u, sub, devidp.MethodPasskey, "")
	cq, _ := url.ParseQuery(cb.RawQuery)
	if cq.Get("state") != "st-1" || cq.Get("code") == "" {
		t.Fatalf("callback %s", cb)
	}
	return e.rp.Exchange(context.Background(), c, cq.Get("code"), redirect, verifier)
}

func TestGitHubSignIn(t *testing.T) {
	e := setup(t)
	u, err := e.signIn(t, e.conn, "00u-alice-admin", devidp.FaultNone)
	if err != nil {
		t.Fatal(err)
	}
	if u.Subject != strconv.FormatInt(devidp.GitHubID("00u-alice-admin"), 10) || u.Login != "alice-admin" ||
		u.Email != "alice.admin@larkspur.example" || len(u.Raw) == 0 {
		t.Errorf("user %+v", u)
	}
	// without user:email the /user email is kept as is (display only)
	c := e.conn
	c.Scopes = []string{"read:user"}
	if u, err := e.signIn(t, c, "00u-ivan-admin2", devidp.FaultNone); err != nil || u.Email != "ivan.admin@larkspur.example" {
		t.Errorf("without user:email: %+v %v", u, err)
	}
}

func TestGitHubFaultsRefused(t *testing.T) {
	want := map[devidp.Fault]string{
		devidp.FaultGitHubTokenError: oauth2rp.ReasonTokenExchange,
		devidp.FaultGitHubTokenType:  oauth2rp.ReasonTokenType,
		devidp.FaultGitHubUserError:  oauth2rp.ReasonUserAPI,
		devidp.FaultGitHubNoID:       oauth2rp.ReasonSubject,
		devidp.FaultGitHubStringID:   oauth2rp.ReasonSubject,
	}
	for _, f := range devidp.GitHubFaults() {
		if _, ok := want[f]; !ok {
			t.Errorf("GitHub fault %s has no expected reason", f)
		}
	}
	e := setup(t)
	for f, reason := range want {
		t.Run(string(f), func(t *testing.T) {
			u, err := e.signIn(t, e.conn, "00u-alice-admin", f)
			if got := oauth2rp.ReasonOf(err); got != reason {
				t.Errorf("reason %q (%v, %+v), want %q", got, err, u, reason)
			}
		})
	}
}

// TestExchangeChecks: the PKCE verifier and redirect URI must match, a code
// is single use, and the client secret must be right.
func TestExchangeChecks(t *testing.T) {
	e := setup(t)
	verifier := rand.Text() + rand.Text()
	start := func() string {
		u, _ := oauth2rp.AuthURL(e.conn, oauth2rp.AuthRequest{RedirectURI: redirect, State: "s", Verifier: verifier})
		cb := e.idp.NewBrowser(t).Authorize(t, u, "00u-alice-admin", devidp.MethodPasskey, "")
		q, _ := url.ParseQuery(cb.RawQuery)
		return q.Get("code")
	}
	ctx := context.Background()
	if _, err := e.rp.Exchange(ctx, e.conn, start(), redirect, rand.Text()+rand.Text()); oauth2rp.ReasonOf(err) != oauth2rp.ReasonTokenExchange {
		t.Errorf("wrong verifier: %v", err)
	}
	if _, err := e.rp.Exchange(ctx, e.conn, start(), redirect+"x", verifier); oauth2rp.ReasonOf(err) != oauth2rp.ReasonTokenExchange {
		t.Errorf("wrong redirect URI: %v", err)
	}
	code := start()
	if _, err := e.rp.Exchange(ctx, e.conn, code, redirect, verifier); err != nil {
		t.Fatal(err)
	}
	if _, err := e.rp.Exchange(ctx, e.conn, code, redirect, verifier); oauth2rp.ReasonOf(err) != oauth2rp.ReasonTokenExchange {
		t.Errorf("code reused: %v", err)
	}
	c := e.conn
	c.ClientSecret = "nope"
	if _, err := e.rp.Exchange(ctx, c, start(), redirect, verifier); oauth2rp.ReasonOf(err) != oauth2rp.ReasonTokenExchange {
		t.Errorf("wrong secret: %v", err)
	}
}

// TestGenericProfile: generic_oauth2 uses the configured subject field
// (client_secret_basic), and refuses a missing or non-scalar one.
func TestGenericProfile(t *testing.T) {
	e := setup(t)
	c := e.conn
	c.Profile, c.SubjectField, c.Scopes = oauth2rp.Generic, "id", nil
	u, err := e.signIn(t, c, "00u-pat-policy", devidp.FaultNone)
	if err != nil || u.Subject != strconv.FormatInt(devidp.GitHubID("00u-pat-policy"), 10) {
		t.Fatalf("generic: %+v %v", u, err)
	}
	c.SubjectField = "login" // a string field is accepted when configured (the admin's choice)
	if u, err := e.signIn(t, c, "00u-pat-policy", devidp.FaultNone); err != nil || u.Subject != "pat-policy" {
		t.Errorf("string subject: %+v %v", u, err)
	}
	c.SubjectField = "nope"
	if _, err := e.signIn(t, c, "00u-pat-policy", devidp.FaultNone); oauth2rp.ReasonOf(err) != oauth2rp.ReasonSubject {
		t.Errorf("missing field: %v", err)
	}
}

func TestConfigRefused(t *testing.T) {
	for name, c := range map[string]oauth2rp.Connection{
		"unknown profile":           {Profile: "slack", ClientID: "x"},
		"generic without endpoints": {Profile: oauth2rp.Generic, ClientID: "x", SubjectField: "id"},
		"generic without subject": {Profile: oauth2rp.Generic, ClientID: "x", AuthorizationURL: "https://a.example/a",
			TokenURL: "https://a.example/t", UserinfoURL: "https://a.example/u"},
		"no client id": {Profile: oauth2rp.GitHub},
		"bad endpoint": {Profile: oauth2rp.GitHub, ClientID: "x", TokenURL: "javascript:alert(1)"},
	} {
		if _, err := oauth2rp.AuthURL(c, oauth2rp.AuthRequest{}); oauth2rp.ReasonOf(err) != oauth2rp.ReasonConfig {
			t.Errorf("%s: %v", name, err)
		}
	}
	if u, err := oauth2rp.AuthURL(oauth2rp.Connection{Profile: oauth2rp.GitHub, ClientID: "x"}, oauth2rp.AuthRequest{}); err != nil ||
		u[:len(oauth2rp.GitHubAuthorizationURL)] != oauth2rp.GitHubAuthorizationURL {
		t.Errorf("github defaults: %s %v", u, err)
	}
	if _, err := oauth2rp.New(nil); err == nil {
		t.Error("New without a client")
	}
}
