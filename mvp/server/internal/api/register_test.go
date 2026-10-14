package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/register"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The self-registration tests (issue #66): the public form, the sponsor's
// decision, and what an outsider can and cannot learn.

type regEnv struct {
	*claimEnv
	n int
}

func newRegEnv(t *testing.T, o claimOpts) *regEnv { return &regEnv{claimEnv: newClaimEnv(t, o)} }

func (e *regEnv) path(rest string) string { return "/public/t/" + e.slug + "/" + rest }

// handle is the sponsor's opaque handle as the public search shows it.
func (e *regEnv) handle() string {
	e.t.Helper()
	name := e.identityOf(e.sponsID).Name
	rec := e.get(e.path("register/sponsors?q=" + strings.ReplaceAll(name[:3], " ", "+")))
	var out struct {
		Sponsors []register.SponsorChoice `json:"sponsors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 {
		e.t.Fatalf("sponsor search: %d %s %v", rec.Code, rec.Body, err)
	}
	for _, s := range out.Sponsors {
		if s.Name == name {
			return s.Handle
		}
	}
	e.t.Fatalf("sponsor %q not found in %v", name, out.Sponsors)
	return ""
}

func (e *regEnv) body(email, sponsor, code string) string {
	ends := e.clk.now().AddDate(0, 0, 10).Format("2006-01-02")
	return fmt.Sprintf(`{"given_name":"Gwen","family_name":"Guest","email":%q,"purpose":"conference talk","ends_at":%q,"sponsor":%q,"code":%q,"challenge_token":"pass"}`,
		email, ends, sponsor, code)
}

// register posts the form from ip.
func (e *regEnv) register(ip, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", e.path("register"), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", claimOrigin)
	req.RemoteAddr = ip
	return serve(e.h, req)
}

// fresh posts from an address of its own, so the per-IP limit never gets in the way.
func (e *regEnv) fresh(body string) *httptest.ResponseRecorder {
	e.n++
	return e.register(fmt.Sprintf("198.51.100.%d:4000", e.n), body)
}

type regCounts struct{ identities, users, registrations int }

func (e *regEnv) counts() regCounts {
	e.t.Helper()
	var c regCounts
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		ids, err := tx.Identities()
		if err != nil {
			return err
		}
		us, err := tx.PlatformUsers()
		if err != nil {
			return err
		}
		rs, err := tx.RegistrationsForSponsor(e.sponsID, "")
		c = regCounts{len(ids), len(us), len(rs)}
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *regEnv) pending() []registrationView {
	e.t.Helper()
	rec := e.do(e.sponsor, "GET", "/api/guest-registrations", "")
	var out struct {
		Registrations []registrationView `json:"registrations"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		e.t.Fatalf("pending: %d %s", rec.Code, rec.Body)
	}
	return out.Registrations
}

func (e *regEnv) registrations() []*store.Registration {
	e.t.Helper()
	var out []*store.Registration
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		var err error
		out, err = tx.RegistrationsForSponsor(e.sponsID, "")
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *regEnv) mailsTo(email string) []string {
	e.t.Helper()
	e.dispatch()
	var out []string
	for _, m := range e.mail.all() {
		if m.To == email {
			out = append(out, m.Subject+"\n"+m.Body)
		}
	}
	return out
}

func (e *regEnv) sweep(at time.Time) {
	e.t.Helper()
	if err := e.srv.reg.SweepAll(audit.WithSystemActor(context.Background(), register.Sweeper), e.db, at); err != nil {
		e.t.Fatal(err)
	}
}

func TestRegister_NoAccountCreatedBeforeApproval(t *testing.T) {
	e := newRegEnv(t, claimOpts{})
	const email = "gwen@guest.example"
	before := e.counts()
	rec := e.fresh(e.body(email, e.handle(), ""))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	after := e.counts()
	if after.identities != before.identities || after.users != before.users || after.registrations != before.registrations+1 {
		t.Errorf("before %+v, after %+v: a request must create a request and nothing else", before, after)
	}
	// no claim link, no invitation: the visitor is only told that the request went to the sponsor
	for _, m := range e.mailsTo(email) {
		if strings.Contains(m, "/claim#t=") || strings.Contains(m, "invited") {
			t.Errorf("mail to the visitor before approval: %s", m)
		}
	}
	// the sponsor sees it, in the Inbox and by notification
	p := e.pending()
	if len(p) != 1 || p[0].GivenName == nil || *p[0].GivenName != "Gwen" || p[0].Via != "search" {
		t.Fatalf("pending = %+v", p)
	}
	if got := e.mailsTo("sponsor@larkspur.example"); len(got) == 0 && !e.notified("guest.registration") {
		t.Error("the sponsor was not told")
	}
	// denied and expired requests create nothing either
	if err := e.db.InTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		_, err := tx.Registration(p[0].ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if a := auditActionsByEnv(t, e.claimEnv); a["guest.registration.submit"] != 1 {
		t.Errorf("audit = %v", a)
	}
}

func auditActionsByEnv(t *testing.T, e *claimEnv) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, ev := range ledger(t, e.db, e.tenant) {
		out[ev.Action]++
	}
	return out
}

// notified reports whether the sponsor's identity has a notification of the kind.
func (e *regEnv) notified(kind string) bool {
	e.t.Helper()
	found := false
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		ns, err := tx.Notifications(e.sponsorUser(), false, 50)
		for _, n := range ns {
			found = found || n.Kind == kind
		}
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return found
}

func (e *regEnv) sponsorUser() string { return e.sponsor.UserID.String() }

func TestRegister_ExistingEmailGetsSignInMail(t *testing.T) {
	e := newRegEnv(t, claimOpts{})
	known := *e.identityOf(e.sponsID).Email
	before := e.counts()
	rec := e.fresh(e.body(known, e.handle(), ""))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	if after := e.counts(); after != before {
		t.Errorf("before %+v, after %+v: an existing address must create nothing", before, after)
	}
	mails := e.mailsTo(known)
	n := 0
	for _, m := range mails {
		if strings.Contains(m, "already have an account") && strings.Contains(m, oidcPublicURL) {
			n++
		}
		if strings.Contains(m, "/claim#t=") {
			t.Errorf("an existing address was sent a claim link: %s", m)
		}
	}
	if n != 1 {
		t.Errorf("sign-in mails to %s = %d (%v)", known, n, mails)
	}
	// asking again the same day does not mail again
	e.fresh(e.body(known, e.handle(), ""))
	if got := len(e.mailsTo(known)); got != len(mails) {
		t.Errorf("a repeat mailed again: %d -> %d", len(mails), got)
	}
}

// The answer to the form is the same for a new request, an address that has an
// account, a sponsor nobody knows, a code that does not exist, a repeat and an
// address in another case.
func TestRegister_EnumerationSameResponse(t *testing.T) {
	e := newRegEnv(t, claimOpts{})
	h := e.handle()
	known := *e.identityOf(e.sponsID).Email
	cases := map[string]string{
		"new":              e.body("a1@guest.example", h, ""),
		"repeat":           e.body("a1@guest.example", h, ""),
		"repeat, case":     e.body("A1@Guest.Example", h, ""),
		"existing":         e.body(known, h, ""),
		"existing, case":   e.body(strings.ToUpper(known), h, ""),
		"unknown sponsor":  e.body("a2@guest.example", strings.Repeat("0", 32), ""),
		"short handle":     e.body("a3@guest.example", "x", ""),
		"unknown code":     e.body("a4@guest.example", "", "ABCDE-FGHJK"),
		"code with handle": e.body("a5@guest.example", h, "ZZZZZ-ZZZZZ"),
	}
	var want *httptest.ResponseRecorder
	for _, name := range []string{"new", "repeat", "repeat, case", "existing", "existing, case", "unknown sponsor", "short handle", "unknown code", "code with handle"} {
		rec := e.fresh(cases[name])
		if want == nil {
			want = rec
			if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), "Check your email") {
				t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
			}
			continue
		}
		if rec.Code != want.Code || rec.Body.String() != want.Body.String() {
			t.Errorf("%s: %d %s, want %d %s", name, rec.Code, rec.Body, want.Code, want.Body)
		}
		for _, hd := range []string{"Content-Type", "Cache-Control", "Set-Cookie"} {
			if rec.Header().Get(hd) != want.Header().Get(hd) {
				t.Errorf("%s: header %s = %q, want %q", name, hd, rec.Header().Get(hd), want.Header().Get(hd))
			}
		}
	}
	// only the first and (case-insensitively) repeated address made one request; nothing else did
	if got := len(e.registrations()); got != 1 {
		t.Errorf("registrations = %d, want 1 (one per sponsor and address)", got)
	}
	// an unknown tenant answers the same, too
	req := httptest.NewRequest("POST", "/public/t/no-such-tenant/register", strings.NewReader(cases["new"]))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", claimOrigin)
	req.RemoteAddr = "198.51.100.200:1"
	if rec := serve(e.h, req); rec.Code != want.Code || rec.Body.String() != want.Body.String() {
		t.Errorf("unknown tenant: %d %s", rec.Code, rec.Body)
	}
	// every refusal is in the ledger, with a reason and without the address
	led := e.auditJSON()
	for _, s := range []string{"unknown_sponsor", "existing_identity", "duplicate"} {
		if !strings.Contains(led, s) {
			t.Errorf("ledger lacks %q", s)
		}
	}
	for _, s := range []string{"a1@guest.example", "a2@guest.example", known, "Gwen"} {
		if strings.Contains(led, s) {
			t.Errorf("ledger holds personal data %q", s)
		}
	}
}

// A form that is not valid is the visitor's own mistake and says so; it never depends on the target.
func TestRegister_InvalidFormIs400(t *testing.T) {
	e := newRegEnv(t, claimOpts{})
	h := e.handle()
	for name, body := range map[string]string{
		"no name":     strings.Replace(e.body("x@guest.example", h, ""), `"Gwen"`, `""`, 1),
		"bad email":   e.body("not-an-email", h, ""),
		"no sponsor":  e.body("x@guest.example", "", ""),
		"past end":    strings.Replace(e.body("x@guest.example", h, ""), e.clk.now().AddDate(0, 0, 10).Format("2006-01-02"), "2020-01-01", 1),
		"bad date":    strings.Replace(e.body("x@guest.example", h, ""), e.clk.now().AddDate(0, 0, 10).Format("2006-01-02"), "tomorrow", 1),
		"unknown key": strings.Replace(e.body("x@guest.example", h, ""), `{`, `{"admin":true,`, 1),
		"not json":    `nope`,
	} {
		if rec := e.fresh(body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if got := len(e.registrations()); got != 0 {
		t.Errorf("registrations = %d", got)
	}
}

func TestRegister_RateLimitPerIP(t *testing.T) {
	e := newRegEnv(t, claimOpts{})
	h := e.handle()
	const ip = "203.0.113.9:5000"
	for i := 0; i < 5; i++ {
		if rec := e.register(ip, e.body(fmt.Sprintf("r%d@guest.example", i), h, "")); rec.Code != http.StatusAccepted {
			t.Fatalf("request %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	rec := e.register(ip, e.body("r6@guest.example", h, ""))
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "rate_limited") {
		t.Fatalf("sixth request: %d %s", rec.Code, rec.Body)
	}
	if got := len(e.registrations()); got != 5 {
		t.Errorf("registrations = %d, want 5", got)
	}
	// another address is not limited, and the first one is again after a refill
	if rec := e.register("203.0.113.10:5000", e.body("r7@guest.example", h, "")); rec.Code != http.StatusAccepted {
		t.Errorf("other IP: %d", rec.Code)
	}
	e.clk.add(13 * time.Minute)
	if rec := e.register(ip, e.body("r8@guest.example", h, "")); rec.Code != http.StatusAccepted {
		t.Errorf("after a refill: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(e.auditJSON(), "register_ip") {
		t.Error("the throttle was not audited")
	}
}

// One address cannot be written to in a loop from many addresses: past a few
// requests an hour the rest are throttled (and audited) before anything is sent.
func TestRegister_RateLimitPerAddress(t *testing.T) {
	e := newRegEnv(t, claimOpts{})
	h := e.handle()
	for i := 0; i < 6; i++ {
		if rec := e.fresh(e.body("victim@guest.example", h, "")); rec.Code != http.StatusAccepted {
			t.Fatal(rec.Code)
		}
	}
	if n := strings.Count(e.auditJSON(), "register_email"); n != 3 {
		t.Errorf("per-address throttles = %d, want 3 (burst of 3, then refused)", n)
	}
	// the same answer all the way
	if rec := e.fresh(e.body("victim@guest.example", h, "")); rec.Code != http.StatusAccepted {
		t.Errorf("throttled answer: %d", rec.Code)
	}
}

func TestRegister_ChallengeIsEnforced(t *testing.T) {
	e := newRegEnv(t, claimOpts{challenge: register.Fake{Token: "pass"}})
	h := e.handle()
	bad := strings.Replace(e.body("c@guest.example", h, ""), `"pass"`, `"fail"`, 1)
	if rec := e.fresh(bad); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "challenge_failed") {
		t.Errorf("bad token: %d %s", rec.Code, rec.Body)
	}
	if rec := e.fresh(strings.Replace(bad, `,"challenge_token":"fail"`, ``, 1)); rec.Code != http.StatusForbidden {
		t.Errorf("no token: %d %s", rec.Code, rec.Body)
	}
	if got := len(e.registrations()); got != 0 {
		t.Errorf("registrations = %d after a failed challenge", got)
	}
	if rec := e.fresh(e.body("c@guest.example", h, "")); rec.Code != http.StatusAccepted {
		t.Errorf("good token: %d %s", rec.Code, rec.Body)
	}
	if got := len(e.registrations()); got != 1 {
		t.Errorf("registrations = %d", got)
	}
}

// Production without a configured challenge refuses rather than letting bots in.
func TestRegister_ProductionNeedsAChallenge(t *testing.T) {
	e := newRegEnv(t, claimOpts{})
	srv := New(Config{Store: e.db, Clock: e.clk.now, Policies: e.srv.cfg.Policies, Env: "prod", PublicURL: oidcPublicURL, PublicOrigin: oidcPublicURL,
		Identifiers: e.srv.cfg.Identifiers, Logger: e.srv.log, RateLimits: noRateLimits})
	if srv.reg.Ready() {
		t.Fatal("registration is ready in production with no challenge")
	}
	req := httptest.NewRequest("POST", e.path("register"), strings.NewReader(e.body("p@guest.example", e.handle(), "")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", claimOrigin)
	if rec := serve(srv.Handler(), req); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
}

func TestRegisterSponsors_NamesOnly(t *testing.T) {
	e := newRegEnv(t, claimOpts{})
	name := e.identityOf(e.sponsID).Name
	rec := e.get(e.path("register/sponsors?q=" + strings.ReplaceAll(name[:3], " ", "+")))
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var raw struct {
		Sponsors []map[string]any `json:"sponsors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil || len(raw.Sponsors) == 0 {
		t.Fatalf("%s %v", rec.Body, err)
	}
	for _, s := range raw.Sponsors {
		if len(s) != 2 || s["name"] == nil || s["handle"] == nil {
			t.Errorf("a sponsor shows %v: only name and handle may appear", s)
		}
	}
	body := rec.Body.String()
	var emails []string
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		ids, err := tx.Identities()
		for _, i := range ids {
			if i.Email != nil {
				emails = append(emails, *i.Email)
			}
			// the id, in any form, is not the handle
			if strings.Contains(body, fmt.Sprintf(`"handle":"%d"`, i.ID)) {
				t.Errorf("handle is the identity id %d", i.ID)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, m := range emails {
		if strings.Contains(body, m) {
			t.Errorf("the search leaks the address %s", m)
		}
	}
	if strings.Contains(body, "@") || strings.Contains(body, `"id"`) || strings.Contains(body, "email") {
		t.Errorf("the search leaks more than names: %s", body)
	}
	// a short query lists nobody; a name nobody has lists nobody
	for _, q := range []string{"", "a", "zzzzqqqq"} {
		var out struct {
			Sponsors []any `json:"sponsors"`
		}
		rec := e.get(e.path("register/sponsors?q=" + q))
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Sponsors == nil || len(out.Sponsors) != 0 {
			t.Errorf("q=%q: %d %s", q, rec.Code, rec.Body)
		}
	}
	// a handle from the other tenant means nothing here
	if err := e.db.ReadTenant(context.Background(), seed.GlobexID, func(tx *store.TenantTx) error {
		cs, err := e.srv.reg.SearchSponsors(tx, name[:3])
		for _, c := range cs {
			if c.Name == name {
				for _, mine := range raw.Sponsors {
					if mine["handle"] == c.Handle {
						t.Errorf("handles are not per tenant")
					}
				}
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRegister_ApprovalCreatesGuestAndClaimToken(t *testing.T) {
	e := newRegEnv(t, claimOpts{})
	const email = "gwen@guest.example"
	e.fresh(e.body(email, e.handle(), ""))
	p := e.pending()
	if len(p) != 1 {
		t.Fatalf("pending = %+v", p)
	}
	before := e.counts()
	rec := e.do(e.sponsor, "POST", "/api/guest-registrations/"+p[0].ID+"/approve", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		GuestIdentityID int64  `json:"guest_identity_id"`
		SponsorshipID   string `json:"sponsorship_id"`
		Status          string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Status != "approved" || out.GuestIdentityID == 0 {
		t.Fatalf("approve body: %s %v", rec.Body, err)
	}
	if after := e.counts(); after.identities != before.identities+1 {
		t.Errorf("identities %d -> %d", before.identities, after.identities)
	}
	g := e.identityOf(out.GuestIdentityID)
	if g.Status != "invited" || g.Email == nil || *g.Email != email || g.Name != "Gwen Guest" {
		t.Errorf("guest = %+v", g)
	}
	// the claim link goes through the ordinary claim flow
	link, token := e.lastLink(email)
	pg := e.newPage()
	if rec := pg.start(token); rec.Code != 200 || decodeMap(t, rec)["next"] != "verify_contact" {
		t.Fatalf("claim start with %s: %d %s", link, rec.Code, rec.Body)
	}
	// the request is closed, reduced to a tombstone, and no longer offered
	if len(e.pending()) != 0 {
		t.Error("an approved request is still pending")
	}
	rs := e.registrations()
	if len(rs) != 1 || rs[0].Status != store.RegApproved || rs[0].IdentityID == nil || *rs[0].IdentityID != out.GuestIdentityID ||
		rs[0].Email != nil || rs[0].GivenName != nil || rs[0].Purpose != nil || rs[0].RedactedAt == nil || rs[0].IntakeID == nil {
		t.Errorf("registration = %+v", rs)
	}
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		in, err := tx.Intake(*rs[0].IntakeID)
		if err == nil && (in.Channel != "self_registration" || in.MatchMode != store.MatchSelfAsserted) {
			t.Errorf("intake = %+v", in)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if a := auditActionsByEnv(t, e.claimEnv); a["guest.registration.approve"] != 1 || a["sponsorship.create"] != 1 || a["claim.invitation.issue"] != 1 {
		t.Errorf("audit = %v", a)
	}
	// deciding twice is refused
	if rec := e.do(e.sponsor, "POST", "/api/guest-registrations/"+p[0].ID+"/approve", `{}`); rec.Code != http.StatusConflict {
		t.Errorf("second approve: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(e.sponsor, "POST", "/api/guest-registrations/"+p[0].ID+"/deny", `{}`); rec.Code != http.StatusConflict {
		t.Errorf("deny after approve: %d %s", rec.Code, rec.Body)
	}
}

func TestRegister_DenialSendsNeutralMailAndCreatesNothing(t *testing.T) {
	e := newRegEnv(t, claimOpts{})
	const email = "gwen@guest.example"
	e.fresh(e.body(email, e.handle(), ""))
	p := e.pending()
	before := e.counts()
	rec := e.do(e.sponsor, "POST", "/api/guest-registrations/"+p[0].ID+"/deny", `{"reason":"I do not know this person"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body)
	}
	if after := e.counts(); after.identities != before.identities || after.users != before.users {
		t.Errorf("denial created something: %+v -> %+v", before, after)
	}
	var denied []string
	for _, m := range e.mailsTo(email) {
		if strings.Contains(m, "was not approved") {
			denied = append(denied, m)
		}
	}
	if len(denied) != 1 {
		t.Fatalf("denial mails = %d", len(denied))
	}
	sp := e.identityOf(e.sponsID)
	for _, leak := range []string{sp.Name, "I do not know", "Sam Sponsor", *sp.Email, "claim#"} {
		if strings.Contains(denied[0], leak) {
			t.Errorf("the denial mail says %q: %s", leak, denied[0])
		}
	}
	if len(e.pending()) != 0 {
		t.Error("a denied request is still pending")
	}
	// the personal data stays for the retention period, then goes
	rs := e.registrations()
	if len(rs) != 1 || rs[0].Status != store.RegDenied || rs[0].Email == nil || rs[0].RedactAfter == nil {
		t.Fatalf("registration = %+v", rs)
	}
	e.sweep(e.clk.now().Add(register.DefaultRetention - time.Hour))
	if rs := e.registrations(); rs[0].Email == nil {
		t.Error("reduced before its retention")
	}
	e.sweep(e.clk.now().Add(register.DefaultRetention + time.Hour))
	if rs := e.registrations(); rs[0].Email != nil || rs[0].GivenName != nil || rs[0].Purpose != nil || rs[0].RedactedAt == nil {
		t.Errorf("not reduced after its retention: %+v", rs[0])
	}
	// a denial leaves no way to approve afterwards
	if rec := e.do(e.sponsor, "POST", "/api/guest-registrations/"+p[0].ID+"/approve", `{}`); rec.Code != http.StatusConflict {
		t.Errorf("approve after deny: %d %s", rec.Code, rec.Body)
	}
}

func TestRegister_PendingRequestsExpire(t *testing.T) {
	e := newRegEnv(t, claimOpts{})
	e.fresh(e.body("gwen@guest.example", e.handle(), ""))
	p := e.pending()
	before := e.counts()
	// just before the deadline it is still decidable; after it, it is not offered and cannot be approved
	e.clk.add(register.DefaultTTL + time.Hour)
	e.sponsor, _ = e.sponsorLogin() // the earlier sign-in is as old as the clock
	if len(e.pending()) != 0 {
		t.Error("an expired request is offered")
	}
	if rec := e.do(e.sponsor, "POST", "/api/guest-registrations/"+p[0].ID+"/approve", `{}`); rec.Code != http.StatusConflict {
		t.Errorf("approve after expiry: %d %s", rec.Code, rec.Body)
	}
	e.sweep(e.clk.now())
	rs := e.registrations()
	if len(rs) != 1 || rs[0].Status != store.RegExpired || rs[0].DecidedAt == nil || rs[0].IdentityID != nil {
		t.Fatalf("registration = %+v", rs)
	}
	if after := e.counts(); after.identities != before.identities || after.users != before.users {
		t.Errorf("expiry created something")
	}
	if rs[0].Email == nil {
		t.Error("reduced at once: the retention period is for the sponsor's history")
	}
	e.sweep(e.clk.now().Add(register.DefaultRetention + time.Hour))
	if rs := e.registrations(); rs[0].Email != nil || rs[0].RedactedAt == nil {
		t.Errorf("expired request not reduced: %+v", rs[0])
	}
	if a := auditActionsByEnv(t, e.claimEnv); a["guest.registration.expire"] != 1 || a["guest.registration.purge"] != 1 {
		t.Errorf("audit = %v", a)
	}
	// nothing is left to sweep
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		n, err := tx.RegistrationsHoldingData()
		if n != 0 {
			t.Errorf("%d requests still hold personal data", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRegister_SponsorCode(t *testing.T) {
	e := newRegEnv(t, claimOpts{})
	rec := e.do(e.sponsor, "POST", "/api/guest-registrations/code", "")
	var c struct {
		Code      string `json:"code"`
		ExpiresAt string `json:"expires_at"`
	}
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &c) != nil || len(c.Code) != 11 || c.ExpiresAt == "" {
		t.Fatalf("code: %d %s", rec.Code, rec.Body)
	}
	e.fresh(e.body("gwen@guest.example", "", strings.ToLower(c.Code))) // typed in lower case
	if rs := e.registrations(); len(rs) != 1 || rs[0].Via != "code" {
		t.Fatalf("registrations = %+v", rs)
	}
	// the code is not stored
	if strings.Contains(e.auditJSON(), c.Code) {
		t.Error("the code is in the ledger")
	}
	// a new code replaces the old one, which then works for nobody (and answers the same)
	var c2 struct{ Code string }
	json.Unmarshal(e.do(e.sponsor, "POST", "/api/guest-registrations/code", "").Body.Bytes(), &c2)
	if c2.Code == "" || c2.Code == c.Code {
		t.Fatalf("second code = %q", c2.Code)
	}
	want := e.fresh(e.body("old@guest.example", "", c.Code))
	if rec := e.fresh(e.body("new@guest.example", "", c2.Code)); rec.Code != want.Code || rec.Body.String() != want.Body.String() {
		t.Errorf("answers differ: %d %s / %d %s", rec.Code, rec.Body, want.Code, want.Body)
	}
	if rs := e.registrations(); len(rs) != 2 {
		t.Errorf("registrations = %d, want 2 (the old code makes no request)", len(rs))
	}
}

// Only the sponsor a request names can see or decide it; another tenant's
// people see nothing, and a viewer without guests.sponsor is refused.
func TestRegisterAPI_OnlyTheNamedSponsorDecides(t *testing.T) {
	e := newRegEnv(t, claimOpts{})
	e.fresh(e.body("gwen@guest.example", e.handle(), ""))
	p := e.pending()
	other := e.otherSponsor()
	if rec := e.do(other, "GET", "/api/guest-registrations", ""); rec.Code != 200 || strings.Contains(rec.Body.String(), p[0].ID) {
		t.Errorf("another sponsor sees it: %d %s", rec.Code, rec.Body)
	}
	for _, act := range []string{"approve", "deny"} {
		if rec := e.do(other, "POST", "/api/guest-registrations/"+p[0].ID+"/"+act, `{}`); rec.Code != http.StatusNotFound {
			t.Errorf("another sponsor %ss: %d %s", act, rec.Code, rec.Body)
		}
	}
	gid := e.globexPerson()
	globex := authtest.LoginAs(t, e.db, seed.GlobexID, authtest.User{Email: "g@globex.example", Roles: []auth.Role{auth.RoleViewer}, IdentityID: &gid}, authtest.Phr, e.clk.now())
	if rec := e.do(globex, "GET", "/api/guest-registrations", ""); rec.Code != 200 || strings.Contains(rec.Body.String(), p[0].ID) {
		t.Errorf("another tenant sees it: %d %s", rec.Code, rec.Body)
	}
	for _, act := range []string{"approve", "deny"} {
		if rec := e.do(globex, "POST", "/api/guest-registrations/"+p[0].ID+"/"+act, `{}`); rec.Code != http.StatusNotFound {
			t.Errorf("another tenant %ss: %d %s", act, rec.Code, rec.Body)
		}
	}
	none := authtest.LoginAs(t, e.db, e.tenant, authtest.User{Email: "none@larkspur.example", Roles: []auth.Role{}}, authtest.Phr, e.clk.now())
	if rec := e.do(none, "GET", "/api/guest-registrations", ""); rec.Code != http.StatusForbidden {
		t.Errorf("no role: %d", rec.Code)
	}
	if len(e.pending()) != 1 {
		t.Error("the request changed")
	}
	// a stale sign-in cannot decide (step-up)
	stale := authtest.LoginAs(t, e.db, e.tenant, authtest.User{Email: "stale@larkspur.example", Roles: []auth.Role{auth.RoleViewer}, IdentityID: &e.sponsID},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: e.clk.now().Add(-20 * time.Minute)}, e.clk.now())
	if rec := e.do(stale, "POST", "/api/guest-registrations/"+p[0].ID+"/approve", `{}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale approve: %d %s", rec.Code, rec.Body)
	}
}

// otherSponsor is another employee of Larkspur who may sponsor.
func (e *regEnv) otherSponsor() authtest.Login {
	e.t.Helper()
	var id int64
	if err := e.db.InTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		email := "olive@larkspur.example"
		var err error
		id, err = tx.InsertIdentity(&store.Identity{TenantID: e.tenant, ExternalID: "emp:olive", Name: "Olive Other", Email: &email,
			Type: "human", Status: "active", CreatedAt: e.clk.now()})
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return authtest.LoginAs(e.t, e.db, e.tenant, authtest.User{Email: "other@larkspur.example", Roles: []auth.Role{auth.RoleViewer}, IdentityID: &id}, authtest.Phr, e.clk.now())
}

func (e *regEnv) globexPerson() int64 {
	e.t.Helper()
	var id int64
	if err := e.db.ReadTenant(context.Background(), seed.GlobexID, func(tx *store.TenantTx) error {
		ids, err := tx.Identities()
		if len(ids) > 0 {
			id = ids[0].ID
		}
		return err
	}); err != nil || id == 0 {
		e.t.Fatalf("no globex person: %d %v", id, err)
	}
	return id
}
