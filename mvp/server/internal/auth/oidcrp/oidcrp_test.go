package oidcrp_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth/oidcrp"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp/devidptest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

const redirectURI = "http://127.0.0.1:5999/callback"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

type env struct {
	idp  *devidptest.IdP
	rp   *oidcrp.RP
	conn oidcrp.Connection
	clk  *clock
}

func setup(t *testing.T) *env {
	t.Helper()
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	idp := devidptest.Start(t, devidp.Config{Now: clk.now})
	hc, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	rp, err := oidcrp.New(oidcrp.Config{HTTP: hc, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	return &env{idp: idp, rp: rp, clk: clk, conn: oidcrp.Connection{Key: "c1", Issuer: idp.URL,
		ClientID: devidptest.ClientID, ClientSecret: devidptest.ClientSecret}}
}

type flow struct {
	req oidcrp.AuthRequest
}

func newFlow(acr ...string) flow {
	maxAge := int64(43200)
	return flow{oidcrp.AuthRequest{RedirectURI: redirectURI, State: "st-" + rand.Text(), Nonce: "n-" + rand.Text(),
		Verifier: rand.Text() + rand.Text(), ACRValues: acr, MaxAge: &maxAge}}
}

// login runs the whole flow as sub and returns the validated token or the error.
func (e *env) login(t *testing.T, f flow, sub string, m devidp.Method, p devidp.Profile, edit func(*oidcrp.Callback)) (*oidcrp.IDToken, error) {
	t.Helper()
	u, err := e.rp.AuthURL(context.Background(), e.conn, f.req)
	if err != nil {
		t.Fatal(err)
	}
	cb := e.idp.NewBrowser(t).Authorize(t, u, sub, m, p)
	q := query(cb)
	if q.Get("state") != f.req.State {
		t.Fatalf("state %q, want %q (%s)", q.Get("state"), f.req.State, cb)
	}
	c := oidcrp.Callback{Code: q.Get("code"), Iss: q.Get("iss"), RedirectURI: redirectURI, Verifier: f.req.Verifier,
		Nonce: f.req.Nonce, MaxAge: f.req.MaxAge}
	if edit != nil {
		edit(&c)
	}
	return e.rp.Exchange(context.Background(), e.conn, c)
}

func TestAuthURL(t *testing.T) {
	e := setup(t)
	f := newFlow("phr")
	raw, err := e.rp.AuthURL(context.Background(), e.conn, f.req)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := query(u)
	for k, want := range map[string]string{"response_type": "code", "client_id": devidptest.ClientID, "redirect_uri": redirectURI,
		"state": f.req.State, "nonce": f.req.Nonce, "code_challenge_method": "S256", "acr_values": "phr", "max_age": "43200"} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if len(q.Get("code_challenge")) != 43 || strings.Contains(raw, f.req.Verifier) {
		t.Errorf("code_challenge %q (the verifier must not be sent)", q.Get("code_challenge"))
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("scope %q", q.Get("scope"))
	}
}

func TestLoginHappyPath(t *testing.T) {
	e := setup(t)
	for _, tc := range []struct {
		p    devidp.Profile
		m    devidp.Method
		want func(*oidcrp.IDToken) bool
	}{
		{devidp.ProfileOkta, devidp.MethodPasskey, func(x *oidcrp.IDToken) bool { return x.ACR == "phr" }},
		{devidp.ProfileOkta, devidp.MethodPasswordOTP, func(x *oidcrp.IDToken) bool { return x.ACR != "phr" }},
		{devidp.ProfileEntra, devidp.MethodPasskey, func(x *oidcrp.IDToken) bool { return x.OID != "" && x.TID != "" }},
	} {
		tok, err := e.login(t, newFlow("phr"), "00u-alice-admin", tc.m, tc.p, nil)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.p, tc.m, err)
		}
		if tok.Subject == "" || tok.AuthTime.IsZero() || len(tok.Raw) == 0 || !tc.want(tok) {
			t.Errorf("%s %s: %+v", tc.p, tc.m, tok)
		}
	}
}

// TestFaultsRefused: every OIDC fault of the dev IdP that is a defect at
// login is refused with its own reason (§18.5, §10.4).
func TestFaultsRefused(t *testing.T) {
	want := map[devidp.Fault]string{
		devidp.FaultWrongIss:        oidcrp.ReasonIssuer,
		devidp.FaultWrongAud:        oidcrp.ReasonAudience,
		devidp.FaultAlgNone:         oidcrp.ReasonAlg,
		devidp.FaultHS256WithPubkey: oidcrp.ReasonAlg,
		devidp.FaultBadSignature:    oidcrp.ReasonSignature,
		devidp.FaultExpired:         oidcrp.ReasonExpired,
		devidp.FaultFutureIat:       oidcrp.ReasonIat,
		devidp.FaultNonceMismatch:   oidcrp.ReasonNonce,
		devidp.FaultMissingAuthTime: oidcrp.ReasonAuthTimeMissing,
		devidp.FaultStaleAuthTime:   oidcrp.ReasonAuthTimeStale,
		devidp.FaultKidUnknown:      oidcrp.ReasonSignature,
		devidp.FaultJKUHeader:       oidcrp.ReasonHeader,
		devidp.FaultNoIssParam:      oidcrp.ReasonIssParam,
	}
	// sub_change_on_stepup is a step-up defect (PR8); acr_unrequested is a
	// normalization case (an unrequested acr proves nothing), not a refusal.
	notAtLogin := map[devidp.Fault]bool{devidp.FaultSubChangeStepUp: true, devidp.FaultACRUnrequested: true}
	for _, f := range devidp.OIDCFaults() {
		if notAtLogin[f] {
			continue
		}
		if _, ok := want[f]; !ok {
			t.Errorf("fault %s has no expected reason", f)
		}
	}
	e := setup(t)
	for f, reason := range want {
		t.Run(string(f), func(t *testing.T) {
			if err := e.idp.SetFault(f); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = e.idp.SetFault(devidp.FaultNone) }()
			_, err := e.login(t, newFlow("phr"), "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta, nil)
			if got := oidcrp.ReasonOf(err); got != reason {
				t.Errorf("reason %s (%v), want %s", got, err, reason)
			}
		})
	}
}

func TestCallbackChecks(t *testing.T) {
	e := setup(t)
	for name, tc := range map[string]struct {
		edit   func(*oidcrp.Callback)
		reason string
	}{
		"iss parameter of another issuer": {func(c *oidcrp.Callback) { c.Iss = "https://evil.example" }, oidcrp.ReasonIssParam},
		"missing iss parameter":           {func(c *oidcrp.Callback) { c.Iss = "" }, oidcrp.ReasonIssParam},
		"wrong PKCE verifier":             {func(c *oidcrp.Callback) { c.Verifier = rand.Text() + rand.Text() }, oidcrp.ReasonTokenExchange},
		"other nonce":                     {func(c *oidcrp.Callback) { c.Nonce = "n-other" }, oidcrp.ReasonNonce},
		"step-up older than the transaction": {func(c *oidcrp.Callback) {
			at := e.clk.now().Add(time.Hour)
			c.NotBefore = &at
		}, oidcrp.ReasonAuthTimeStale},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := e.login(t, newFlow("phr"), "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta, tc.edit)
			if got := oidcrp.ReasonOf(err); got != tc.reason {
				t.Errorf("reason %s (%v), want %s", got, err, tc.reason)
			}
		})
	}
}

// TestCodeSingleUse: an authorization code is redeemed once.
func TestCodeSingleUse(t *testing.T) {
	e := setup(t)
	var saved oidcrp.Callback
	if _, err := e.login(t, newFlow("phr"), "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta,
		func(c *oidcrp.Callback) { saved = *c }); err != nil {
		t.Fatal(err)
	}
	if _, err := e.rp.Exchange(context.Background(), e.conn, saved); oidcrp.ReasonOf(err) != oidcrp.ReasonTokenExchange {
		t.Errorf("second redemption: %v", err)
	}
}

func TestDiscoveryRefusals(t *testing.T) {
	e := setup(t)
	for name, c := range map[string]oidcrp.Connection{
		"issuer with a trailing slash": {Key: "x1", Issuer: e.idp.URL + "/", ClientID: "c"},
		"unreachable issuer":           {Key: "x2", Issuer: "http://127.0.0.1:1", ClientID: "c"},
		"private address":              {Key: "x3", Issuer: "https://10.0.0.1", ClientID: "c"},
		"no algorithm in common":       {Key: "x4", Issuer: e.idp.URL, ClientID: "c", IDTokenAlgs: []string{"HS256"}},
	} {
		_, err := e.rp.AuthURL(context.Background(), c, newFlow().req)
		if got := oidcrp.ReasonOf(err); got != oidcrp.ReasonDiscovery {
			t.Errorf("%s: %s (%v)", name, got, err)
		}
	}
	var oe *oidcrp.Error
	_, err := e.rp.AuthURL(context.Background(), oidcrp.Connection{Key: "x5"}, newFlow().req)
	if !errors.As(err, &oe) {
		t.Errorf("no issuer: %v", err)
	}
}

// query parses a URL's query (url.URL.Query without the method name that
// internal/archtest reserves for SQL).
func query(u *url.URL) url.Values {
	v, _ := url.ParseQuery(u.RawQuery)
	return v
}
