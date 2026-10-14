package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/claim"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// identityOf returns the guest's identity.
func (e *claimEnv) identityOf(id int64) *store.Identity {
	e.t.Helper()
	var out *store.Identity
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		var err error
		out, err = tx.Identity(id)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

// auditJSON is the tenant's whole ledger as one string (details included).
func (e *claimEnv) auditJSON() string {
	e.t.Helper()
	var sb strings.Builder
	for _, ev := range ledger(e.t, e.db, e.tenant) {
		b, _ := json.Marshal(ev)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// ---------------------------------------------------------------- the claim, end to end

// TestClaim_EndToEnd_DevIdP: invitation, email, start, code, the question, the
// credential at the dev IdP, completion. The identity is active, its
// affiliation active, the new platform user linked with no roles, the intake
// claimed and the sponsor told.
func TestClaim_EndToEnd_DevIdP(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	const email = "gwen@guest.example"
	v := e.invite(email, "visitor")
	if v.Invitation != "sent" || !v.CanResend || !v.CanRevoke || v.InvitationExpires == nil || v.Guest.Status != "invited" {
		t.Fatalf("invitation view = %+v", v)
	}
	link, token := e.lastLink(email)
	if want := oidcPublicURL + "/claim#t=" + token; link != want {
		t.Fatalf("link %q, want %q", link, want)
	}
	if !claim.WellFormed(token) {
		t.Errorf("token shape: %q", token)
	}
	pg := e.newPage()
	rec := pg.start(token)
	m := decodeMap(t, rec)
	st, _ := m["status"].(map[string]any)
	if rec.Code != 200 || m["next"] != "verify_contact" || m["nonce"] == "" || st["first_name"] != "Gwen" || st["tenant"] != "Larkspur Labs" ||
		st["population"] != "visitor" || st["sponsor"] == "" {
		t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}
	for k := range st {
		switch k {
		case "step", "steps", "first_name", "tenant", "sponsor", "population", "ends_at", "pending", "complete":
		default:
			t.Errorf("status leaks %q", k)
		}
	}
	c := pg.cookie
	if !c.HttpOnly || !c.Secure || c.Path != "/" || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 24*3600 || c.Name != "__Host-tessera_claim" || c.Domain != "" {
		t.Errorf("claim cookie %+v", c)
	}
	for _, h := range []string{"Cache-Control", "Referrer-Policy"} {
		if rec.Header().Get(h) == "" {
			t.Errorf("no %s on start", h)
		}
	}
	if got := decodeMap(t, pg.do("GET", "status", "")); got["step"] != "verify_contact" {
		t.Errorf("status = %v", got)
	}
	pg.verifyEmail(email)
	if got := decodeMap(t, pg.do("GET", "status", "")); got["step"] != "existing_account" {
		t.Errorf("status after code = %v", got)
	}
	if rec := pg.post("existing-account", `{"answer":"no"}`); rec.Code != 200 || decodeMap(t, rec)["step"] != "credential" {
		t.Fatalf("existing-account: %d %s", rec.Code, rec.Body)
	}
	authURL, lc := e.loginURL(pg.post("credential", ""))
	if q := queryOf(authURL); q.Get("login_hint") == "" || q.Get("prompt") != "login" || q.Get("max_age") != "600" {
		t.Errorf("authorize URL %s", authURL)
	}
	if lc == nil || !lc.HttpOnly {
		t.Fatalf("login cookie %+v", lc)
	}
	ref := strings.TrimPrefix(e.identityOf(v.Guest.ID).ExternalID, "guest:")
	cb := e.signInAtIdP(authURL, lc, "guest-"+ref, devidp.MethodPasskey)
	if cb.Code != http.StatusSeeOther || cb.Header().Get("Location") != "/claim?result=complete" {
		t.Fatalf("callback: %d %v %s", cb.Code, cb.Header(), cb.Body)
	}
	if cookieNamed(cb, "__Host-tessera_session") != nil {
		t.Error("the claim created a Tessera session")
	}
	// the state of the world
	g := e.identityOf(v.Guest.ID)
	if g.Status != "active" {
		t.Errorf("identity status %q", g.Status)
	}
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		affs, err := tx.AffiliationsFor(g.ID)
		if err != nil || len(affs) != 1 || affs[0].Status != store.AffActive {
			t.Errorf("affiliations = %v, %v", affs, err)
		}
		users, err := tx.UsersLinkedTo(g.ID)
		if err != nil || len(users) != 1 {
			t.Fatalf("users linked = %v, %v", users, err)
		}
		as, err := tx.RoleAssignments(uuid.MustParse(users[0]))
		if err != nil || len(as) != 0 {
			t.Errorf("the claimed user has roles: %v, %v", as, err)
		}
		ls, err := tx.ExternalLoginsForUser(uuid.MustParse(users[0]))
		if err != nil || len(ls) != 1 || ls[0].Subject != "guest-"+ref || ls[0].Issuer != e.idp.URL {
			t.Errorf("external logins = %+v, %v", ls, err)
		}
		in, err := tx.Intake(mustIntake(t, tx, g.ID))
		if err != nil || in.InvitationStatus != store.InvitationClaimed || in.ClaimedAt == nil || in.ExistingAccount == nil || *in.ExistingAccount != "no" {
			t.Errorf("intake = %+v, %v", in, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := decodeMap(t, pg.do("GET", "status", "")); got["step"] != "complete" || got["complete"] != true {
		t.Errorf("final status = %v", got)
	}
	// the sponsor is told, in the inbox
	var told bool
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		us, err := tx.UsersLinkedTo(e.sponsID)
		if err != nil {
			return err
		}
		for _, u := range us {
			ns, err := tx.Notifications(u, false, 50)
			if err != nil {
				return err
			}
			for _, n := range ns {
				told = told || n.Kind == "guest.claimed"
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !told {
		t.Error("the sponsor was not notified")
	}
	// the ledger tells the story and holds no secret
	log := e.auditJSON()
	for _, a := range []string{"claim.invitation.issue", "claim.start", "claim.code.send", "claim.verify_contact", "claim.existing_account",
		"claim.credential.start", "claim.complete"} {
		if !strings.Contains(log, `"`+a+`"`) {
			t.Errorf("no %s event", a)
		}
	}
	// every claim request is in the tenant's own chain, as an anonymous caller, by route pattern
	routes := map[string]bool{}
	for _, ev := range ledger(t, e.db, e.tenant) {
		if ev.Action == "http.request" && ev.ActorType == store.ActorAnonymous && strings.Contains(string(ev.HTTP), "/public/t/{slug}/claim/") {
			routes[strings.TrimSpace(string(ev.HTTP))] = true
		}
	}
	if len(routes) < 5 {
		t.Errorf("the claim requests are not in the tenant's ledger: %d distinct http.request events", len(routes))
	}
	// the invitation cannot be claimed twice, and the link is dead
	if rec := e.newPage().start(token); decodeMap(t, rec)["next"] != "check_link" {
		t.Errorf("a used link started again: %s", rec.Body)
	}
}

func mustIntake(t *testing.T, tx *store.TenantTx, guest int64) string {
	t.Helper()
	ss, err := tx.Sponsorships(store.SponsorshipFilter{Guest: guest})
	if err != nil || len(ss) == 0 {
		t.Fatalf("sponsorships = %v, %v", ss, err)
	}
	return ss[0].IntakeID
}

// started invites email, takes the link and starts a claim; it returns the page.
func (e *claimEnv) started(email string) (*page, string, sponsorshipView) {
	e.t.Helper()
	v := e.invite(email, "visitor")
	_, token := e.lastLink(email)
	pg := e.newPage()
	if rec := pg.start(token); decodeMap(e.t, rec)["next"] != "verify_contact" {
		e.t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}
	return pg, token, v
}

// sameResponse is what a refused start looks like to the caller.
type sameResponse struct {
	code   int
	body   string
	header http.Header
	took   time.Duration
}

func capture(rec *httptest.ResponseRecorder, took time.Duration) sameResponse {
	h := http.Header{}
	for k, v := range rec.Header() {
		if k == "X-Request-Id" {
			continue
		}
		h[k] = v
	}
	return sameResponse{rec.Code, rec.Body.String(), h, took}
}

// TestClaim_SameResponseForUnknownExpiredUsed (design §10.2): a made-up token,
// a malformed one, an expired one, a used one and a revoked one get one and
// the same answer (status, body and headers), after the same minimum time.
func TestClaim_SameResponseForUnknownExpiredUsed(t *testing.T) {
	const floor = 150 * time.Millisecond
	e := newClaimEnv(t, claimOpts{minDur: floor})
	mk := func(email string) (string, sponsorshipView) {
		v := e.invite(email, "visitor")
		_, token := e.lastLink(email)
		return token, v
	}
	used, _ := mk("used@guest.example")
	revoked, rv := mk("revoked@guest.example")
	expired, _ := mk("expired@guest.example")
	if rec := e.newPage().start(used); decodeMap(t, rec)["next"] != "verify_contact" {
		t.Fatalf("first start of a good link: %s", rec.Body)
	}
	if rec := e.do(e.sponsor, "POST", fmt.Sprintf("/api/guests/%d/revoke-invitation", rv.Guest.ID), ""); rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	e.clk.add(8 * 24 * time.Hour) // past the 7 days of a visitor's link, inside the sponsorship
	cases := map[string]string{"unknown": claim.NewToken(), "malformed": "short", "used": used, "revoked": revoked, "expired": expired}
	got := map[string]sameResponse{}
	i := 0
	for name, tok := range cases {
		i++
		pg := e.newPage()
		pg.ip = fmt.Sprintf("198.51.100.%d:5000", i)
		begin := time.Now()
		rec := pg.start(tok)
		got[name] = capture(rec, time.Since(begin))
	}
	var ref sameResponse
	var refName string
	for name, r := range got {
		if refName == "" {
			ref, refName = r, name
			continue
		}
		if r.code != ref.code || r.body != ref.body || fmt.Sprint(r.header) != fmt.Sprint(ref.header) {
			t.Errorf("%s differs from %s:\n%d %s %v\n%d %s %v", name, refName, r.code, r.body, r.header, ref.code, ref.body, ref.header)
		}
	}
	if ref.code != 200 || ref.body != `{"next":"check_link"}` {
		t.Errorf("the generic answer is %d %s", ref.code, ref.body)
	}
	if ref.header.Get("Set-Cookie") != "" || ref.header.Get("Cache-Control") != "no-store" || ref.header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("headers %v", ref.header)
	}
	lo, hi := time.Hour, time.Duration(0)
	for _, r := range got {
		lo, hi = min(lo, r.took), max(hi, r.took)
	}
	if lo < floor-5*time.Millisecond {
		t.Errorf("a refused start took %v, under the %v floor", lo, floor)
	}
	if hi-lo > 120*time.Millisecond {
		t.Errorf("timings differ too much: %v to %v (%v)", lo, hi, got)
	}
	// the reasons are in the ledger, the token never is
	log := e.auditJSON()
	for _, r := range []string{claim.ReasonUnknown, claim.ReasonUsed, claim.ReasonRevoked, claim.ReasonExpired} {
		if !strings.Contains(log, `"reason":"`+r+`"`) {
			t.Errorf("no claim.start.refused with reason %s", r)
		}
	}
	for _, tok := range []string{used, revoked, expired} {
		if strings.Contains(log, tok) {
			t.Error("a token is in the audit ledger")
		}
	}
}

// TestClaim_TokenSingleUseUnderConcurrency (design §10.2): a hundred starts
// at once with one link make exactly one session.
func TestClaim_TokenSingleUseUnderConcurrency(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	v := e.invite("race@guest.example", "visitor")
	_, token := e.lastLink("race@guest.example")
	var won, generic atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		pg := e.newPage()
		pg.ip = fmt.Sprintf("203.0.113.%d:%d", i%250+1, 6000+i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := pg.start(token)
			switch decodeMap(t, rec)["next"] {
			case "verify_contact":
				won.Add(1)
			case "check_link":
				generic.Add(1)
			default:
				t.Errorf("start: %d %s", rec.Code, rec.Body)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 || generic.Load() != 99 {
		t.Fatalf("%d starts won, %d refused; want 1 and 99", won.Load(), generic.Load())
	}
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		sess, err := tx.ClaimSessionsForIntake(mustIntake(t, tx, v.Guest.ID))
		if err != nil || len(sess) != 1 {
			t.Errorf("%d sessions, %v", len(sess), err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestClaim_CodeLockoutAfterFiveFailures (design §10.2): five wrong codes void
// the code; the right one no longer works.
func TestClaim_CodeLockoutAfterFiveFailures(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	const email = "lock@guest.example"
	pg, _, _ := e.started(email)
	if rec := pg.post("verify/send", ""); rec.Code != 200 {
		t.Fatal(rec.Body)
	}
	code := e.lastCode(email)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	var first string
	for i := 0; i < 5; i++ {
		rec := pg.post("verify/check", fmt.Sprintf(`{"code":%q}`, wrong))
		if rec.Code != 422 || !strings.Contains(rec.Body.String(), `"code_invalid"`) {
			t.Fatalf("wrong code %d: %d %s", i, rec.Code, rec.Body)
		}
		if i == 0 {
			first = rec.Body.String()
		} else if rec.Body.String() != first {
			t.Errorf("the failures differ: %s vs %s", rec.Body, first)
		}
	}
	rec := pg.post("verify/check", fmt.Sprintf(`{"code":%q}`, code))
	if rec.Code != 422 || rec.Body.String() != first {
		t.Errorf("the right code after the lockout: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(e.auditJSON(), `"claim.code.locked"`) {
		t.Error("the lockout is not in the ledger")
	}
	// a new code can be asked for, and works
	if rec := pg.post("verify/send", ""); rec.Code != 200 {
		t.Fatal(rec.Body)
	}
	fresh := e.lastCode(email)
	if rec := pg.post("verify/check", fmt.Sprintf(`{"code":%q}`, fresh)); rec.Code != 200 {
		t.Errorf("a fresh code: %d %s", rec.Code, rec.Body)
	}
}

// TestConfirmation_ExpiresAfterTenMinutes (design §10.2).
func TestConfirmation_ExpiresAfterTenMinutes(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	const email = "slow@guest.example"
	pg, _, _ := e.started(email)
	pg.post("verify/send", "")
	code := e.lastCode(email)
	e.clk.add(10*time.Minute + time.Second)
	if rec := pg.post("verify/check", fmt.Sprintf(`{"code":%q}`, code)); rec.Code != 422 {
		t.Errorf("a code after ten minutes: %d %s", rec.Code, rec.Body)
	}
	pg.post("verify/send", "")
	code = e.lastCode(email)
	e.clk.add(9*time.Minute + 30*time.Second)
	if rec := pg.post("verify/check", fmt.Sprintf(`{"code":%q}`, code)); rec.Code != 200 {
		t.Errorf("a code after 9m30s: %d %s", rec.Code, rec.Body)
	}
}

// TestClaim_SecretsNeverStored: the claim token and the confirmation code are
// in the emails and nowhere else: not the logs, the audit ledger, the
// notification rows, the delivery log, nor the claim tables.
func TestClaim_SecretsNeverStored(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	const email = "quiet@guest.example"
	v := e.invite(email, "visitor")
	// the notification rows before the dispatcher has sent them
	var pending strings.Builder
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		ns, err := tx.DueNotifications(e.clk.now().Add(time.Hour), 100)
		for _, n := range ns {
			b, _ := json.Marshal(n)
			pending.Write(b)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pending.String(), `"guest.invitation"`) {
		t.Fatalf("no invitation notification before sending: %s", pending.String())
	}
	_, token := e.lastLink(email)
	pg := e.newPage()
	pg.start(token)
	pg.post("verify/send", "")
	code := e.lastCode(email)
	pg.post("verify/check", fmt.Sprintf(`{"code":%q}`, code))
	var rows strings.Builder
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		ms, err := tx.EmailMessages(store.EmailFilter{Limit: 100})
		for _, m := range ms {
			b, _ := json.Marshal(m)
			rows.Write(b)
		}
		ts, err2 := tx.ClaimTokensForIntake(mustIntake(t, tx, v.Guest.ID))
		for _, x := range ts {
			b, _ := json.Marshal(x)
			rows.Write(b)
		}
		ss, err3 := tx.ClaimSessionsForIntake(mustIntake(t, tx, v.Guest.ID))
		for _, x := range ss {
			b, _ := json.Marshal(x)
			rows.Write(b)
		}
		cc, err4 := tx.LiveConfirmationCode(ss[0].IDHash)
		if err4 == nil {
			b, _ := json.Marshal(cc)
			rows.Write(b)
		}
		if err == nil {
			err = err2
		}
		if err == nil {
			err = err3
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if rows.Len() == 0 {
		t.Fatal("no rows to scan")
	}
	apiLog := ""
	if rec := e.do(e.sponsor, "GET", "/api/guests", ""); rec.Code == 200 {
		apiLog = rec.Body.String()
	}
	hay := map[string]string{"logs": e.logs.String(), "audit": e.auditJSON(), "pending notifications": pending.String(),
		"delivery log and claim rows": rows.String(), "guests API": apiLog}
	cookie := pg.cookie.Value
	for where, text := range hay {
		if strings.Contains(text, token) {
			t.Errorf("the claim token is in the %s", where)
		}
		if strings.Contains(text, cookie) {
			t.Errorf("the session cookie is in the %s", where)
		}
		if codeWord(code).MatchString(text) {
			t.Errorf("the confirmation code is in the %s", where)
		}
	}
	// and the email does carry them (so the test can tell)
	var link, mailedCode bool
	for _, m := range e.mail.all() {
		link = link || strings.Contains(m.Body, token)
		mailedCode = mailedCode || strings.Contains(m.Body, code)
		if strings.Contains(m.Subject, token) || strings.Contains(m.Subject, code) {
			t.Error("a secret is in a subject line")
		}
	}
	if !link || !mailedCode {
		t.Error("the emails do not carry the link and the code")
	}
	// the delivery log of the admin screen has no body
	adm := signIn(t, e.db, e.tenant, testAdmin, authtest.Phr, e.clk.now())
	if rec := e.do(adm, "GET", "/api/email/messages", ""); rec.Code != 200 || strings.Contains(rec.Body.String(), token) || codeWord(code).MatchString(rec.Body.String()) {
		t.Errorf("email delivery log: %d %.300s", rec.Code, rec.Body)
	}
	if e.secrets.Len() > 1 {
		t.Errorf("%d one-time secrets still held after delivery", e.secrets.Len())
	}
}

// TestClaim_ReissueRevokesOldToken: a new link kills the earlier ones; a
// revoked invitation cannot be started or resent; "send me a new link" is
// throttled at three a day and answers the same for an unknown address.
func TestClaim_ReissueRevokesOldToken(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	const email = "again@guest.example"
	v := e.invite(email, "visitor")
	_, t1 := e.lastLink(email)
	if rec := e.do(e.sponsor, "POST", fmt.Sprintf("/api/guests/%d/resend-invitation", v.Guest.ID), `{}`); rec.Code != 200 {
		t.Fatalf("resend: %d %s", rec.Code, rec.Body)
	}
	_, t2 := e.lastLink(email)
	if t1 == t2 {
		t.Fatal("the link did not change")
	}
	if rec := e.newPage().start(t1); decodeMap(t, rec)["next"] != "check_link" {
		t.Errorf("the old link still starts: %s", rec.Body)
	}
	// "send me a new link", by the guest
	resend := func(addr string) *httptest.ResponseRecorder {
		pg := e.newPage()
		return pg.post("resend", fmt.Sprintf(`{"email":%q}`, addr))
	}
	const msg = "If an invitation exists for this address, we have sent a new link."
	var sameBody string
	for i, addr := range []string{"nobody@guest.example", email, "not an address"} {
		rec := resend(addr)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), msg) {
			t.Fatalf("resend %q: %d %s", addr, rec.Code, rec.Body)
		}
		if i == 0 {
			sameBody = rec.Body.String()
		} else if rec.Body.String() != sameBody {
			t.Errorf("resend answers differ: %s vs %s", rec.Body, sameBody)
		}
	}
	_, t3 := e.lastLink(email)
	if t3 == t2 {
		t.Fatal("the requested link is not new")
	}
	if rec := e.newPage().start(t2); decodeMap(t, rec)["next"] != "check_link" {
		t.Errorf("the previous link still starts: %s", rec.Body)
	}
	// two more requests use up the three of the day; a fourth sends nothing, answers the same
	before := len(e.mail.all())
	resend(email)
	resend(email)
	e.dispatch()
	if got := len(e.mail.all()); got != before+2 { // the day's limit is three, one was used above
		t.Errorf("mails after two more requests: %d, want %d", got, before+2)
	}
	before += 2
	rec := resend(email)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), msg) {
		t.Errorf("a throttled resend: %d %s", rec.Code, rec.Body)
	}
	e.dispatch()
	if got := len(e.mail.all()); got != before {
		t.Errorf("a throttled resend sent mail: %d, want %d", got, before)
	}
	if !strings.Contains(e.auditJSON(), `"scope":"resend_email"`) {
		t.Error("the throttle is not in the ledger")
	}
	// revoke
	if rec := e.do(e.sponsor, "POST", fmt.Sprintf("/api/guests/%d/revoke-invitation", v.Guest.ID), `{}`); rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	var rv sponsorshipView
	_ = json.Unmarshal(e.do(e.sponsor, "GET", "/api/sponsorships/"+v.ID, "").Body.Bytes(), &rv)
	if rv.Invitation != "revoked" || rv.CanResend {
		t.Errorf("after revoke: %+v", rv)
	}
	_, last := e.lastLink(email)
	if rec := e.newPage().start(last); decodeMap(t, rec)["next"] != "check_link" {
		t.Errorf("a revoked link starts: %s", rec.Body)
	}
	if rec := e.do(e.sponsor, "POST", fmt.Sprintf("/api/guests/%d/resend-invitation", v.Guest.ID), `{}`); rec.Code != 409 {
		t.Errorf("resend after revoke: %d %s", rec.Code, rec.Body)
	}
	before = len(e.mail.all())
	resend(email) // the guest asking again does not undo the sponsor's revocation
	e.dispatch()
	if len(e.mail.all()) != before {
		t.Error("a revoked invitation was resent on the guest's request")
	}
}

// TestClaim_KeyBinding (T20): a cookie alone does nothing; the request needs a
// signature by the key bound at start, fresh, once.
func TestClaim_KeyBinding(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	pg, _, _ := e.started("bound@guest.example")
	denied := func(rec *httptest.ResponseRecorder, why string) {
		t.Helper()
		if rec.Code != 401 || strings.TrimSpace(rec.Body.String()) != `{"error":"session_required"}` {
			t.Errorf("%s: %d %s", why, rec.Code, rec.Body)
		}
	}
	// the same answer as no cookie at all
	noCookie := e.newPage()
	denied(noCookie.do("GET", "status", ""), "no cookie")
	// no proof
	r := pg.req("GET", "status", "")
	r.Header.Del("X-Claim-Proof")
	denied(serve(e.h, r), "no proof")
	// a proof by another key
	other := e.newPage()
	other.cookie, other.nonce = pg.cookie, pg.nonce
	denied(other.do("GET", "status", ""), "another key")
	// a proof for another path, another method, another nonce
	r = pg.req("GET", "status", "")
	r.Header.Set("X-Claim-Proof", pg.proof("GET", pg.path("verify/send"), pg.nonce))
	denied(serve(e.h, r), "another path")
	r = pg.req("GET", "status", "")
	r.Header.Set("X-Claim-Proof", pg.proof("POST", pg.path("status"), pg.nonce))
	denied(serve(e.h, r), "another method")
	r = pg.req("GET", "status", "")
	r.Header.Set("X-Claim-Proof", pg.proof("GET", pg.path("status"), "another-nonce"))
	denied(serve(e.h, r), "another nonce")
	// a stale and a future proof
	pg.skew = -2 * time.Minute
	denied(pg.do("GET", "status", ""), "stale")
	pg.skew = 2 * time.Minute
	denied(pg.do("GET", "status", ""), "from the future")
	pg.skew = 0
	// a replay
	r = pg.req("GET", "status", "")
	if rec := serve(e.h, r); rec.Code != 200 {
		t.Fatalf("a good request: %d %s", rec.Code, rec.Body)
	}
	replay := httptest.NewRequest("GET", r.URL.Path, nil)
	replay.AddCookie(pg.cookie)
	replay.Header.Set("X-Claim-Proof", r.Header.Get("X-Claim-Proof"))
	denied(serve(e.h, replay), "replay")
	// ECDSA malleability (review on #202): (r, N-s) is the same proof, not a new one
	ts, sig, _ := strings.Cut(r.Header.Get("X-Claim-Proof"), ".")
	rs, _ := base64.RawURLEncoding.DecodeString(sig)
	sv := new(big.Int).SetBytes(rs[32:])
	sv.Sub(elliptic.P256().Params().N, sv)
	mall := httptest.NewRequest("GET", r.URL.Path, nil)
	mall.AddCookie(pg.cookie)
	mall.Header.Set("X-Claim-Proof", ts+"."+base64.RawURLEncoding.EncodeToString(append(rs[:32:32], sv.FillBytes(make([]byte, 32))...)))
	denied(serve(e.h, mall), "malleated replay")
	// one use is recorded in the database: a fresh in-memory memory (a restart,
	// another process) still refuses the replay
	r = pg.req("GET", "status", "")
	if rec := serve(e.h, r); rec.Code != 200 {
		t.Fatalf("a good request: %d %s", rec.Code, rec.Body)
	}
	e.srv.claimSvc.Replays = claim.NewReplays()
	replay = httptest.NewRequest("GET", r.URL.Path, nil)
	replay.AddCookie(pg.cookie)
	replay.Header.Set("X-Claim-Proof", r.Header.Get("X-Claim-Proof"))
	denied(serve(e.h, replay), "replay after a restart")
	// the proof signs the body: a captured proof does not carry another body
	r = pg.req("POST", "verify/check", `{"code":"000000"}`)
	swapped := httptest.NewRequest("POST", r.URL.Path, strings.NewReader(`{"code":"111111"}`))
	swapped.Header = r.Header.Clone()
	swapped.RemoteAddr = r.RemoteAddr
	denied(serve(e.h, swapped), "another body")
	// the session is unharmed by all that
	if rec := pg.do("GET", "status", ""); rec.Code != 200 {
		t.Errorf("after the rejected requests: %d %s", rec.Code, rec.Body)
	}
	log := e.auditJSON()
	for _, why := range []string{"proof_missing", "proof_invalid", "proof_stale", "proof_replay"} {
		if !strings.Contains(log, `"reason":"`+why+`"`) {
			t.Errorf("no claim.proof.rejected with reason %s", why)
		}
	}
	// start itself needs a proof of the key it sends, and a private key is refused
	path := pg.path("start")
	post := func(body, proof string) int {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", claimOrigin)
		r.RemoteAddr = "192.0.2.77:1"
		if proof != "" {
			r.Header.Set("X-Claim-Proof", proof)
		}
		return serve(e.h, r).Code
	}
	np := e.newPage()
	if c := post(fmt.Sprintf(`{"token":"x","key":%s}`, np.jwk()), ""); c != 400 {
		t.Errorf("start without a proof: %d", c)
	}
	if body := fmt.Sprintf(`{"token":"x","key":%s}`, np.jwk()); post(body, pg.proof("POST", path, "", body)) != 400 {
		t.Error("start with a proof by another key was not refused")
	}
	priv := strings.Replace(np.jwk(), `"ext":true`, `"d":"AAAA"`, 1)
	if body := fmt.Sprintf(`{"token":"x","key":%s}`, priv); post(body, np.proof("POST", path, "", body)) != 400 {
		t.Error("start with a private key was not refused")
	}
}

// TestClaim_RateLimits (§6.4): the per-IP limit on start, the per-session
// limit on codes; the throttles are audited without a token or code.
func TestClaim_RateLimits(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	// start: 10 per IP
	var limited int
	for i := 0; i < 12; i++ {
		pg := e.newPage()
		pg.ip = "192.0.2.99:1234"
		if rec := pg.start(claim.NewToken()); rec.Code == 429 {
			limited++
			if rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), "rate_limited") {
				t.Errorf("throttle response %v %s", rec.Header(), rec.Body)
			}
		}
	}
	if limited != 2 {
		t.Errorf("%d of 12 starts from one address were limited, want 2", limited)
	}
	// a code: 3 per session per 10 minutes, the answer is the same
	const email = "busy@guest.example"
	pg, token, _ := e.started(email)
	var first string
	for i := 0; i < 5; i++ {
		rec := pg.post("verify/send", "")
		if rec.Code != 200 {
			t.Fatalf("send %d: %d %s", i, rec.Code, rec.Body)
		}
		if i == 0 {
			first = rec.Body.String()
		} else if rec.Body.String() != first {
			t.Errorf("send %d answers differently: %s", i, rec.Body)
		}
	}
	e.dispatch()
	codes := 0
	for _, m := range e.mail.all() {
		if m.To == email && strings.Contains(m.Body, "confirmation code") {
			codes++
		}
	}
	if codes != 3 {
		t.Errorf("%d codes were mailed, want 3", codes)
	}
	log := e.auditJSON()
	if !strings.Contains(log, `"scope":"send_session"`) || !strings.Contains(log, `"scope":"start_ip"`) || !strings.Contains(log, `"claim.throttled"`) {
		t.Error("the throttles are not in the ledger")
	}
	if strings.Contains(log, token) {
		t.Error("a token is in the ledger")
	}
}

// TestClaim_AALEnforced: the claim completes only for the sign-in the
// authority was told to expect, at the required assurance level. A weaker
// sign-in or a different account leaves the claim pending, and creates no user.
func TestClaim_AALEnforced(t *testing.T) {
	users := []devidp.User{
		{Sub: "guest-pw", Email: "pw@guest.example", Name: "Pw", Tenant: "larkspur", Authenticators: []devidp.Method{devidp.MethodPassword}},
		{Sub: "guest-pk", Email: "pk@guest.example", Name: "Pk", Tenant: "larkspur", Authenticators: []devidp.Method{devidp.MethodPasskey}},
		{Sub: "guest-other", Email: "other@guest.example", Name: "Other", Tenant: "larkspur", Authenticators: []devidp.Method{devidp.MethodPasskey}},
	}
	fake := &fakeAuthority{subject: "guest-pw"}
	e := newClaimEnv(t, claimOpts{authority: fake, users: users})
	const email = "weak@guest.example"
	pg, _, v := e.started(email)
	pg.verifyEmail(email)
	pg.post("existing-account", `{"answer":"no"}`)
	noUser := func() {
		t.Helper()
		if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
			us, err := tx.UsersLinkedTo(v.Guest.ID)
			if err != nil || len(us) != 0 {
				t.Errorf("a platform user was created: %v, %v", us, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if g := e.identityOf(v.Guest.ID); g.Status != "invited" {
			t.Errorf("identity status %q after a refused claim", g.Status)
		}
		if st := decodeMap(t, pg.do("GET", "status", "")); st["step"] != "credential" || st["complete"] != false {
			t.Errorf("status = %v", st)
		}
	}
	// a password only: AAL 1 < the sponsorship's 2
	authURL, lc := e.loginURL(pg.post("credential", ""))
	cb := e.signInAtIdP(authURL, lc, "guest-pw", devidp.MethodPassword)
	if cb.Code != 303 || cb.Header().Get("Location") != "/claim?result=failed" {
		t.Fatalf("a weak sign-in: %d %v", cb.Code, cb.Header())
	}
	if !strings.Contains(e.auditJSON(), `"reason":"aal_not_met"`) {
		t.Error("the refusal is not in the ledger")
	}
	noUser()
	if len(fake.calls) != 1 || fake.calls[0].Email != email || fake.calls[0].Tenant != "larkspur" {
		t.Errorf("authority calls = %+v", fake.calls)
	}
	// a strong sign-in, but as another account than the one set up
	authURL, lc = e.loginURL(pg.post("credential", ""))
	cb = e.signInAtIdP(authURL, lc, "guest-other", devidp.MethodPasskey)
	if cb.Code != 303 || cb.Header().Get("Location") != "/claim?result=failed" || !strings.Contains(e.auditJSON(), `"reason":"subject_mismatch"`) {
		t.Fatalf("another account: %d %v", cb.Code, cb.Header())
	}
	noUser()
	// the login transaction is single use
	if cb := e.get(queryRequestURI(authURL, cb), lc); cb.Code == 303 && cb.Header().Get("Location") == "/claim?result=complete" {
		t.Error("a replayed callback completed the claim")
	}
	// the right account at the right level completes it
	fake.subject = "guest-pk"
	authURL, lc = e.loginURL(pg.post("credential", ""))
	cb = e.signInAtIdP(authURL, lc, "guest-pk", devidp.MethodPasskey)
	if cb.Code != 303 || cb.Header().Get("Location") != "/claim?result=complete" {
		t.Fatalf("the right sign-in: %d %v %s", cb.Code, cb.Header(), cb.Body)
	}
	if g := e.identityOf(v.Guest.ID); g.Status != "active" {
		t.Errorf("identity status %q", g.Status)
	}
	// that sign-in now belongs to a user: another claim cannot use it
	v2 := e.invite("second@guest.example", "visitor")
	pg2, _, _ := e.startedFor("second@guest.example")
	pg2.verifyEmail("second@guest.example")
	pg2.post("existing-account", `{"answer":"no"}`)
	authURL, lc = e.loginURL(pg2.post("credential", ""))
	if cb := e.signInAtIdP(authURL, lc, "guest-pk", devidp.MethodPasskey); cb.Header().Get("Location") != "/claim?result=failed" ||
		!strings.Contains(e.auditJSON(), `"reason":"subject_already_bound"`) {
		t.Errorf("a bound account was reused: %d %v", cb.Code, cb.Header())
	}
	if g := e.identityOf(v2.Guest.ID); g.Status != "invited" {
		t.Errorf("second guest status %q", g.Status)
	}
}

func queryRequestURI(_ string, cb *httptest.ResponseRecorder) string {
	return cb.Header().Get("Location")
}

// startedFor starts a claim for an invitation that exists already.
func (e *claimEnv) startedFor(email string) (*page, string, struct{}) {
	e.t.Helper()
	_, token := e.lastLink(email)
	pg := e.newPage()
	if rec := pg.start(token); decodeMap(e.t, rec)["next"] != "verify_contact" {
		e.t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}
	return pg, token, struct{}{}
}

// TestClaim_NoAuthorityStaysPending: with no credential authority (production
// today) the claim stops at the credential step.
func TestClaim_NoAuthorityStaysPending(t *testing.T) {
	e := newClaimEnv(t, claimOpts{none: true})
	const email = "wait@guest.example"
	pg, _, v := e.started(email)
	pg.verifyEmail(email)
	pg.post("existing-account", `{"answer":"no"}`)
	st := decodeMap(t, pg.do("GET", "status", ""))
	if st["step"] != "credential" || st["pending"] != "organization" {
		t.Errorf("status = %v", st)
	}
	rec := pg.post("credential", "")
	m := decodeMap(t, rec)
	if rec.Code != 200 || m["status"] != "pending" || m["pending"] != "organization" || !strings.Contains(m["message"].(string), "organization will finish") {
		t.Errorf("credential: %d %s", rec.Code, rec.Body)
	}
	if g := e.identityOf(v.Guest.ID); g.Status != "invited" {
		t.Errorf("identity status %q", g.Status)
	}
	if !strings.Contains(e.auditJSON(), `"claim.credential.pending"`) {
		t.Error("the pending claim is not in the ledger")
	}
}

// TestClaim_ExistingAccountNeverLinks: "yes" is recorded for review and links nothing.
func TestClaim_ExistingAccountNeverLinks(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	const email = "hasone@guest.example"
	pg, _, v := e.started(email)
	if rec := pg.post("existing-account", `{"answer":"yes"}`); rec.Code != 409 {
		t.Errorf("the question before the code: %d %s", rec.Code, rec.Body)
	}
	pg.verifyEmail(email)
	if rec := pg.post("existing-account", `{"answer":"maybe"}`); rec.Code != 422 && rec.Code != 400 {
		t.Errorf("a bad answer: %d %s", rec.Code, rec.Body)
	}
	rec := pg.post("existing-account", `{"answer":"yes"}`)
	m := decodeMap(t, rec)
	if rec.Code != 200 || m["step"] != "credential" || !strings.Contains(m["message"].(string), "administrator will follow up") {
		t.Fatalf("yes: %d %s", rec.Code, rec.Body)
	}
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		in, err := tx.Intake(mustIntake(t, tx, v.Guest.ID))
		if err != nil || in.ExistingAccount == nil || *in.ExistingAccount != "yes" || in.ExistingAccountAt == nil {
			t.Errorf("intake = %+v, %v", in, err)
		}
		if us, _ := tx.UsersLinkedTo(v.Guest.ID); len(us) != 0 {
			t.Errorf("linked users: %v", us)
		}
		ids, _ := tx.Identities()
		for _, i := range ids {
			if i.ID != v.Guest.ID && i.Email != nil && *i.Email == email {
				t.Errorf("another identity has the guest's email")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.auditJSON(), `"linked":false`) {
		t.Error("the answer is not in the ledger")
	}
}

// TestClaim_SessionIsPerTenant: a session of one tenant is nothing at another,
// an unknown tenant answers like no session, and links do not cross tenants.
func TestClaim_SessionIsPerTenant(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	pg, token, _ := e.started("tenant@guest.example")
	for _, slug := range []string{seedGlobex(), "no-such-tenant"} {
		pg.slug = slug
		rec := pg.do("GET", "status", "")
		if rec.Code != 401 || strings.TrimSpace(rec.Body.String()) != `{"error":"session_required"}` {
			t.Errorf("%s: %d %s", slug, rec.Code, rec.Body)
		}
		other := e.newPage()
		other.slug = slug
		if rec := other.start(token); rec.Code != 200 || rec.Body.String() != `{"next":"check_link"}` {
			t.Errorf("%s: a link of another tenant: %d %s", slug, rec.Code, rec.Body)
		}
	}
	pg.slug = e.slug
	if rec := pg.do("GET", "status", ""); rec.Code != 200 {
		t.Errorf("home tenant: %d %s", rec.Code, rec.Body)
	}
}

func seedGlobex() string { return "globex" }

// TestClaim_SessionLifetimes: 60 minutes idle, 24 hours at most.
func TestClaim_SessionLifetimes(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	pg, _, _ := e.started("idle@guest.example")
	e.clk.add(59 * time.Minute)
	if rec := pg.do("GET", "status", ""); rec.Code != 200 {
		t.Fatalf("after 59 minutes: %d", rec.Code)
	}
	e.clk.add(59 * time.Minute) // activity slid the idle window
	if rec := pg.do("GET", "status", ""); rec.Code != 200 {
		t.Fatalf("after another 59 minutes: %d", rec.Code)
	}
	e.clk.add(61 * time.Minute)
	if rec := pg.do("GET", "status", ""); rec.Code != 401 {
		t.Errorf("after 61 idle minutes: %d", rec.Code)
	}
	// the absolute limit, with activity throughout
	e.sponsor, _ = e.sponsorLogin() // the sponsor's own session lapsed meanwhile
	pg, _, _ = e.started("busy2@guest.example")
	for i := 0; i < 47; i++ { // 23.5 hours in 30-minute steps
		e.clk.add(30 * time.Minute)
		if rec := pg.do("GET", "status", ""); rec.Code != 200 {
			t.Fatalf("step %d: %d", i, rec.Code)
		}
	}
	e.clk.add(31 * time.Minute) // past 24 hours since start
	if rec := pg.do("GET", "status", ""); rec.Code != 401 {
		t.Errorf("after 24 hours: %d", rec.Code)
	}
}

// TestClaim_InvitationLifecycle: ready/sent -> expired by the sweeper, resent,
// and revoked when the sponsorship ends.
func TestClaim_InvitationLifecycle(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	const email = "life@guest.example"
	v := e.invite(email, "visitor")
	view := func() sponsorshipView {
		var s sponsorshipView
		_ = json.Unmarshal(e.do(e.sponsor, "GET", "/api/sponsorships/"+v.ID, "").Body.Bytes(), &s)
		return s
	}
	if got := view(); got.Invitation != "sent" {
		t.Fatalf("invitation %q", got.Invitation)
	}
	e.clk.add(8 * 24 * time.Hour)
	e.sponsor, _ = e.sponsorLogin()
	if got := view(); got.Invitation != "expired" || !got.CanResend {
		t.Errorf("an old link reads %q (can resend %t)", got.Invitation, got.CanResend)
	}
	if err := e.srv.claimSvc.SweepAll(context.Background(), e.db, e.clk.now()); err != nil {
		t.Fatal(err)
	}
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		in, err := tx.Intake(mustIntake(t, tx, v.Guest.ID))
		if err != nil || in.InvitationStatus != store.InvitationExpired {
			t.Errorf("after the sweep: %+v, %v", in, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(e.sponsor, "POST", fmt.Sprintf("/api/guests/%d/resend-invitation", v.Guest.ID), `{}`); rec.Code != 200 {
		t.Fatalf("resend: %d %s", rec.Code, rec.Body)
	}
	if got := view(); got.Invitation != "sent" {
		t.Errorf("after a resend %q", got.Invitation)
	}
	_, token := e.lastLink(email)
	// the sponsor ends the sponsorship: the link dies and the invitation is revoked
	if rec := e.do(e.sponsor, "POST", "/api/sponsorships/"+v.ID+"/end", `{"reason":"no longer needed"}`); rec.Code != 200 {
		t.Fatalf("end: %d %s", rec.Code, rec.Body)
	}
	if got := view(); got.Invitation != "revoked" {
		t.Errorf("after the sponsorship ended %q", got.Invitation)
	}
	if rec := e.newPage().start(token); decodeMap(t, rec)["next"] != "check_link" {
		t.Errorf("a link of an ended sponsorship starts: %s", rec.Body)
	}
}

// TestClaim_NotConfigured: without TESSERA_PUBLIC_URL the claim is off: the
// public routes answer like an unknown link or no session, never an error, and
// an invitation stays "ready".
func TestClaim_NotConfigured(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	pg := &page{e: &claimEnv{t: t, clk: &mutableClock{t: testkit.Now.UTC()}, h: h}, slug: f.B.Slug, ip: "192.0.2.5:1", origin: "http://localhost:5173"}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pg.key = k
	pg.e.srv = srv
	rec := pg.start(claim.NewToken())
	if rec.Code != 200 && rec.Code != 400 {
		t.Errorf("start: %d %s", rec.Code, rec.Body)
	}
	if rec := serve(h, httptest.NewRequest("GET", pg.path("status"), nil)); rec.Code != 401 {
		t.Errorf("status: %d %s", rec.Code, rec.Body)
	}
	if rec := serve(h, func() *http.Request {
		r := httptest.NewRequest("POST", pg.path("resend"), strings.NewReader(`{"email":"a@b.example"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://localhost:5173")
		return r
	}()); rec.Code != 200 || !strings.Contains(rec.Body.String(), "If an invitation exists") {
		t.Errorf("resend: %d %s", rec.Code, rec.Body)
	}
}

// TestClaim_IALRequiredWaitsAtVerifyIdentity: a sponsorship that needs IAL 1 or
// more moves the claim to verify_identity after the contact check (the schema
// must accept that step; it used to fail the update with a 500).
func TestClaim_IALRequiredWaitsAtVerifyIdentity(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	const email = "ial@guest.example"
	pg, _, v := e.started(email)
	if err := e.db.InTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		s, err := tx.Sponsorship(v.ID)
		if err != nil {
			return err
		}
		s.RequiredIAL = 2
		return tx.SaveSponsorship(s, s.Status)
	}); err != nil {
		t.Fatal(err)
	}
	pg.verifyEmail(email)
	if st := decodeMap(t, pg.do("GET", "status", "")); st["step"] != "verify_identity" {
		t.Errorf("status after code = %v", st)
	}
}
