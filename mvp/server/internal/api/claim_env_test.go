package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp/devidptest"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/claim"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/credential"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// The guest claim tests (issue #69) drive the public claim API the way the
// claim page does: a key pair for the proof header, the session cookie, the
// emails the dispatcher "sends" captured in memory, and the dev IdP running
// in-process for the credential step.

// capturedMail is the Sender of the claim tests: it keeps every email.
type capturedMail struct {
	mu   sync.Mutex
	sent []notify.Email
}

func (m *capturedMail) Send(_ context.Context, e notify.Email) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, e)
	return nil
}

func (m *capturedMail) all() []notify.Email {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]notify.Email(nil), m.sent...)
}

// safeBuffer is a log sink that can be read while the server writes to it.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *safeBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// fakeAuthority is a credential.Authority for tests: it registers nothing and
// answers a chosen subject (a user of the in-process dev IdP).
type fakeAuthority struct {
	subject string
	err     error
	mu      sync.Mutex
	calls   []credential.Guest
}

func (f *fakeAuthority) Kind() string    { return "fake" }
func (f *fakeAuthority) Profile() string { return credential.DevProfile }
func (f *fakeAuthority) Register(_ context.Context, _ credential.Connection, g credential.Guest) (credential.Registration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, g)
	if f.err != nil {
		return credential.Registration{}, f.err
	}
	return credential.Registration{Subject: f.subject, LoginHint: f.subject}, nil
}

type claimOpts struct {
	authority credential.Authority // default: the dev IdP authority; set noAuthority for none
	none      bool
	minDur    time.Duration
	users     []devidp.User
}

type claimEnv struct {
	t       *testing.T
	clk     *mutableClock
	idp     *devidptest.IdP
	srv     *Server
	h       http.Handler
	db      *store.DB
	secrets *notify.Secrets
	mail    *capturedMail
	disp    *notify.Dispatcher
	logs    *safeBuffer
	tenant  tenancy.ID
	slug    string
	sponsor authtest.Login
	sponsID int64
}

const claimOrigin = oidcPublicURL

func newClaimEnv(t *testing.T, o claimOpts) *claimEnv {
	t.Helper()
	clk := &mutableClock{t: testkit.Now.UTC()}
	users, err := devidp.DefaultUsers()
	if err != nil {
		t.Fatal(err)
	}
	users = append(users, o.users...)
	idp := devidptest.Start(t, devidp.Config{Now: clk.now, Users: users, Clients: []devidp.Client{{ID: oidcClientID,
		Secret: oidcSecret, RedirectURIs: []string{"http://127.0.0.1:*/api/auth/oidc/*/callback"}}}})
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keyer := identifiers.NewKeyer(sealer)
	db := testkit.Open(t)
	tenants := seed.WithDevIdPClient([]seed.Tenant{
		{ID: seed.LarkspurID, Slug: seed.LarkspurSlug, Name: "Larkspur Labs", Connectors: []connectors.Connector{connectors.Tiny{Now: testkit.Now}}, Identifiers: keyer},
		{ID: seed.GlobexID, Slug: seed.GlobexSlug, Name: "Globex", Connectors: []connectors.Connector{connectors.Tiny{Now: testkit.Now, Sentinel: "G"}}, Identifiers: keyer},
	}, idp.URL, seed.DevIdPClient{Sealer: sealer, Secret: oidcSecret})
	if _, err := seed.Run(context.Background(), db, testkit.Now, testkit.Policies(t), tenants); err != nil {
		t.Fatal(err)
	}
	hc, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	var authority credential.Authority = o.authority
	if authority == nil && !o.none {
		if authority, err = credential.NewDevIdP("dev", hc); err != nil {
			t.Fatal(err)
		}
	}
	secrets := notify.NewSecrets()
	logs := &safeBuffer{}
	minDur := o.minDur
	if minDur == 0 {
		minDur = time.Millisecond
	}
	srv := New(Config{Store: db, Clock: clk.now, Policies: policy.NewLoader(policies.FS), Env: "test",
		AllowedOrigins: []string{"http://localhost:5173", oidcPublicURL}, PublicURL: oidcPublicURL, Sealer: sealer, OutboundHTTP: hc,
		Identifiers: keyer, Secrets: secrets, Credential: authority, ClaimMinDuration: minDur,
		RateLimits: noRateLimits, Logger: slog.New(slog.NewTextHandler(logs, nil))})
	mail := &capturedMail{}
	e := &claimEnv{t: t, clk: clk, idp: idp, srv: srv, h: srv.Handler(), db: db, secrets: secrets, mail: mail, logs: logs,
		tenant: seed.LarkspurID, slug: seed.LarkspurSlug}
	e.disp = &notify.Dispatcher{DB: db, Sender: mail, Clock: clk.now, BaseURL: oidcPublicURL, Secrets: secrets,
		Log: slog.New(slog.NewTextHandler(logs, nil)), Backoff: func(int) time.Duration { return time.Minute }}
	e.sponsor, e.sponsID = e.sponsorLogin()
	return e
}

// sponsorLogin signs in a platform user who is a plain employee of Larkspur
// (no lifecycle row), so the sponsor policy lets them sponsor.
func (e *claimEnv) sponsorLogin() (authtest.Login, int64) {
	e.t.Helper()
	var id int64
	err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		ids, err := tx.Identities()
		if err != nil {
			return err
		}
		for _, i := range ids {
			if i.Type != "human" || i.Status != "active" {
				continue
			}
			if _, err := tx.LifecycleFor(i.ID); err == nil {
				continue
			}
			id = i.ID
			break
		}
		return nil
	})
	if err != nil || id == 0 {
		e.t.Fatalf("no sponsor-eligible employee: %d %v", id, err)
	}
	return authtest.LoginAs(e.t, e.db, e.tenant, authtest.User{Email: "sponsor@larkspur.example", Display: "Sam Sponsor",
		Roles: []auth.Role{auth.RoleViewer}, IdentityID: &id}, authtest.Phr, e.clk.now()), id
}

func (e *claimEnv) do(l authtest.Login, method, path, body string) *httptest.ResponseRecorder {
	return reqDo(e.h, l, method, path, body)
}

// invite makes an invitation as the sponsor and returns the sponsorship.
func (e *claimEnv) invite(email, pop string) sponsorshipView {
	e.t.Helper()
	ends := e.clk.now().AddDate(0, 0, 10)
	rec := e.do(e.sponsor, "POST", "/api/guests/invitations", inviteJSON(email, pop, ends, ""))
	if rec.Code != http.StatusCreated {
		e.t.Fatalf("invite: %d %s", rec.Code, rec.Body)
	}
	var v sponsorshipView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		e.t.Fatal(err)
	}
	return v
}

// dispatch runs the notification dispatcher once.
func (e *claimEnv) dispatch() {
	e.t.Helper()
	if _, err := e.disp.RunOnce(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

var linkRE = regexp.MustCompile(`(https?://[^\s#]+)/claim#t=([A-Za-z0-9_-]{43})`)
var codeRE = regexp.MustCompile(`confirmation code: (\d{6})`)

// lastLink returns the newest claim link mailed to email, and its token.
func (e *claimEnv) lastLink(email string) (link, token string) {
	e.t.Helper()
	e.dispatch()
	mails := e.mail.all()
	for i := len(mails) - 1; i >= 0; i-- {
		if mails[i].To != email {
			continue
		}
		if m := linkRE.FindStringSubmatch(mails[i].Body); m != nil {
			return m[0], m[2]
		}
	}
	e.t.Fatalf("no claim link was mailed to %s (%d mails)", email, len(mails))
	return "", ""
}

func (e *claimEnv) lastCode(email string) string {
	e.t.Helper()
	e.dispatch()
	mails := e.mail.all()
	for i := len(mails) - 1; i >= 0; i-- {
		if mails[i].To != email {
			continue
		}
		if m := codeRE.FindStringSubmatch(mails[i].Body); m != nil {
			return m[1]
		}
	}
	e.t.Fatalf("no confirmation code was mailed to %s", email)
	return ""
}

// ---------------------------------------------------------------- the page

// page is the claim page: a non-extractable key (here a plain one), the cookie
// and the nonce of the session.
type page struct {
	e      *claimEnv
	key    *ecdsa.PrivateKey
	cookie *http.Cookie
	nonce  string
	slug   string
	ip     string
	origin string // default claimOrigin
	// skew shifts the clock the page signs with
	skew time.Duration
}

func (e *claimEnv) newPage() *page {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	return &page{e: e, key: k, slug: e.slug, ip: "192.0.2.10:4000", origin: claimOrigin}
}

func (p *page) jwk() string {
	b := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 32))) }
	return fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q,"ext":true,"key_ops":["verify"]}`, b(p.key.X), b(p.key.Y))
}

func (p *page) path(rest string) string { return "/public/t/" + p.slug + "/claim/" + rest }

// proof signs a request as the page does: seconds, then the signature over
// the method, path, time, nonce and the body's digest (no body: empty).
func (p *page) proof(method, path, nonce string, body ...string) string {
	ts := fmt.Sprint(p.e.clk.now().Add(p.skew).Unix())
	b := ""
	if len(body) > 0 {
		b = body[0]
	}
	msg := "tessera-claim-proof-v2\n" + method + "\n" + path + "\n" + ts + "\n" + nonce + "\n" + claim.BodyHash([]byte(b))
	sum := sha256.Sum256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, sum[:])
	if err != nil {
		p.e.t.Fatal(err)
	}
	raw := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return ts + "." + base64.RawURLEncoding.EncodeToString(raw)
}

// req builds a claim request with the cookie and a proof for the page's nonce.
func (p *page) req(method, rest, body string) *http.Request {
	path := p.path(rest)
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.RemoteAddr = p.ip
	if method != "GET" {
		r.Header.Set("Origin", p.origin)
	}
	if p.cookie != nil {
		r.AddCookie(p.cookie)
	}
	r.Header.Set("X-Claim-Proof", p.proof(method, path, p.nonce, body))
	return r
}

func (p *page) do(method, rest, body string) *httptest.ResponseRecorder {
	return serve(p.e.h, p.req(method, rest, body))
}

func (p *page) post(rest, body string) *httptest.ResponseRecorder { return p.do("POST", rest, body) }

// start posts the token with a proof for the empty nonce, as the page does.
func (p *page) start(token string) *httptest.ResponseRecorder {
	path := p.path("start")
	body := fmt.Sprintf(`{"token":%q,"key":%s}`, token, p.jwk())
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", p.origin)
	r.RemoteAddr = p.ip
	r.Header.Set("X-Claim-Proof", p.proof("POST", path, "", body))
	rec := serve(p.e.h, r)
	if c := cookieNamed(rec, ClaimCookieName); c != nil {
		p.cookie = c
		var out struct {
			Nonce string `json:"nonce"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		p.nonce = out.Nonce
	}
	return rec
}

func decodeMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("not JSON: %d %s", rec.Code, rec.Body)
	}
	return m
}

// verifyEmail sends and checks the confirmation code.
func (p *page) verifyEmail(email string) {
	p.e.t.Helper()
	if rec := p.post("verify/send", ""); rec.Code != 200 {
		p.e.t.Fatalf("verify/send: %d %s", rec.Code, rec.Body)
	}
	code := p.e.lastCode(email)
	rec := p.post("verify/check", fmt.Sprintf(`{"code":%q}`, code))
	if rec.Code != 200 {
		p.e.t.Fatalf("verify/check: %d %s", rec.Code, rec.Body)
	}
}

func (e *claimEnv) loginURL(rec *httptest.ResponseRecorder) (authURL string, loginCookie *http.Cookie) {
	e.t.Helper()
	m := decodeMap(e.t, rec)
	u, _ := m["redirect"].(string)
	if rec.Code != 200 || u == "" {
		e.t.Fatalf("credential: %d %s", rec.Code, rec.Body)
	}
	return u, cookieNamed(rec, LoginCookieName)
}

// signInAtIdP plays the browser at the dev IdP and then back at the callback;
// it returns the callback's response.
func (e *claimEnv) signInAtIdP(authURL string, lc *http.Cookie, sub string, m devidp.Method) *httptest.ResponseRecorder {
	e.t.Helper()
	cb := e.idp.NewBrowser(e.t).Authorize(e.t, authURL, sub, m, devidp.ProfileOkta)
	return e.get(cb.RequestURI(), lc)
}

func queryOf(u string) url.Values {
	p, _ := url.Parse(u)
	return query(p)
}

// get serves a GET with cookies.
func (e *claimEnv) get(target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", target, nil)
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	return serve(e.h, r)
}

// codeWord matches a confirmation code as a whole number.
func codeWord(code string) *regexp.Regexp {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(code) + `\b`)
}
