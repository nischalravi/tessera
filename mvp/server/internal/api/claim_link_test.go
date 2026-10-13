package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The claim's "do you already have an account?" step (design §6.5, §5.5, issue
// #68): "yes" signs in as the existing person at the tenant's identity
// provider; when that person is one of the candidates the matcher found for the
// invitation, the claim links to them (Tier A, link by sign-in) and sets up no
// credential; otherwise it goes on as a new identity.

// linkWorld is a Larkspur employee who is a candidate for an invitation (the
// invitation names their address), with a sign-in user of their own at the dev IdP.
type linkWorld struct {
	email  string
	person int64
	user   uuid.UUID
}

// two extra dev IdP users: the employee who is a candidate, and someone else.
const (
	empSub   = "00u-existing-emp"
	otherSub = "00u-existing-other"
)

var linkUsers = []devidp.User{
	{Sub: empSub, Email: "emp@larkspur.example", Name: "Existing Employee", Tenant: "larkspur", Authenticators: []devidp.Method{devidp.MethodPasskey}},
	{Sub: otherSub, Email: "other@larkspur.example", Name: "Someone Else", Tenant: "larkspur", Authenticators: []devidp.Method{devidp.MethodPasskey}},
}

// employee picks an active employee with a verified address, who is not the sponsor,
// and gives them a platform user whose external login is the dev IdP's subject.
func (e *claimEnv) employee(bindTo string) linkWorld {
	e.t.Helper()
	var w linkWorld
	err := e.db.InTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		ids, err := tx.Identities()
		if err != nil {
			return err
		}
		for _, i := range ids {
			if i.Type != "human" || i.Status != "active" || i.ID == e.sponsID || i.Email == nil || *i.Email == "" {
				continue
			}
			if xs, err := tx.IdentifiersFor(i.ID); err != nil || len(xs) == 0 {
				continue
			}
			w.person, w.email = i.ID, strings.ToLower(*i.Email)
			break
		}
		if w.person == 0 {
			e.t.Fatal("no employee with identifiers")
		}
		cs, err := tx.IdPConnections()
		if err != nil {
			return err
		}
		pid := w.person
		w.user = uuid.New()
		if err := tx.InsertPlatformUser(&store.PlatformUser{ID: w.user, DisplayName: "Existing Person", Status: "active", IdentityID: &pid,
			CreatedAt: e.clk.now()}); err != nil {
			return err
		}
		for _, c := range cs {
			if c.Profile == "dev_mock" || c.IsDefault {
				return tx.InsertExternalLogin(&store.ExternalLogin{UserID: w.user, IdPConnectionID: c.ID, Issuer: deref(c.Issuer),
					Subject: bindTo, CreatedAt: e.clk.now()})
			}
		}
		e.t.Fatal("no IdP connection")
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return w
}

// answerYes takes the claim to the question and answers yes; it returns the answer.
func (e *claimEnv) answerYes(pg *page, email string) *httptest.ResponseRecorder {
	pg.verifyEmail(email)
	return pg.post("existing-account", `{"answer":"yes"}`)
}

func (e *claimEnv) matches(status string) []*store.MatchResult {
	e.t.Helper()
	var out []*store.MatchResult
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		var err error
		out, err = tx.MatchResults(store.MatchFilter{Status: status})
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func TestClaim_LinkBySignIn_Success(t *testing.T) {
	e := newClaimEnv(t, claimOpts{users: linkUsers})
	w := e.employee(empSub)
	v := e.invite(w.email, "visitor")
	if got := e.matches(store.MatchReview); len(got) != 1 || got[0].CandidateID == nil || *got[0].CandidateID != w.person || got[0].Tier != "C" ||
		got[0].Outcome != store.MatchOutcomeSuspected {
		t.Fatalf("the invitation was not flagged: %+v", got)
	}
	_, token := e.lastLink(w.email)
	pg := e.newPage()
	if rec := pg.start(token); decodeMap(t, rec)["next"] != "verify_contact" {
		t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}
	rec := e.answerYes(pg, w.email)
	m := decodeMap(t, rec)
	if rec.Code != 200 || m["status"] != "redirect" || m["redirect"] == "" {
		t.Fatalf("yes: %d %s", rec.Code, rec.Body)
	}
	authURL, lc := e.loginURL(rec)
	if q := queryOf(authURL); q.Get("prompt") != "login" || q.Get("max_age") != "600" || q.Get("login_hint") != "" {
		t.Errorf("authorize URL %s", authURL)
	}
	cb := e.signInAtIdP(authURL, lc, empSub, devidp.MethodPasskey)
	if cb.Code != http.StatusSeeOther || cb.Header().Get("Location") != "/claim?result=complete" {
		t.Fatalf("callback: %d %v %s", cb.Code, cb.Header(), cb.Body)
	}
	if cookieNamed(cb, "__Host-tessera_session") != nil {
		t.Error("the link created a Tessera session")
	}
	if got := decodeMap(t, pg.do("GET", "status", "")); got["step"] != "complete" || got["complete"] != true || got["population"] != "visitor" {
		t.Errorf("status = %v", got)
	}
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		if g, _ := tx.Identity(v.Guest.ID); g.Status != store.IdentityStatusMerged {
			t.Errorf("the provisional person is %s", g.Status)
		}
		ss, err := tx.Sponsorships(store.SponsorshipFilter{Guest: w.person})
		if err != nil || len(ss) != 1 || ss[0].ID != v.ID {
			t.Errorf("the sponsorship did not follow the link: %v, %v", ss, err)
		}
		affs, _ := tx.AffiliationsFor(w.person)
		active := 0
		for _, a := range affs {
			if a.Type == store.AffGuestVisitor && a.Status == store.AffActive {
				active++
			}
		}
		if active != 1 {
			t.Errorf("the visitor affiliation is not active on the person: %v", affs)
		}
		// credentials: none created, none moved
		if us, _ := tx.UsersLinkedTo(w.person); len(us) != 1 || us[0] != w.user.String() {
			t.Errorf("the person's sign-in users = %v", us)
		}
		if us, _ := tx.UsersLinkedTo(v.Guest.ID); len(us) != 0 {
			t.Errorf("the provisional person has users: %v", us)
		}
		in, _ := tx.Intake(ss[0].IntakeID)
		if in.InvitationStatus != store.InvitationClaimed || in.Status != store.IntakeResolved {
			t.Errorf("intake = %+v", in)
		}
		rows, _ := tx.MatchResults(store.MatchFilter{Intake: in.ID})
		var linked, superseded int
		for _, r := range rows {
			switch r.Status {
			case store.MatchLinked:
				linked++
				if !strings.Contains(r.Rules, "signed_in_as_candidate") && r.Decision != nil && *r.Decision != "auto_link" {
					t.Errorf("link rules %s", r.Rules)
				}
			case store.MatchSuperseded:
				superseded++
			}
		}
		if linked != 1 || superseded != 1 {
			t.Errorf("results: %d linked %d superseded (%+v)", linked, superseded, rows)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a := e.auditJSON()
	for _, want := range []string{`"claim.link"`, `"identity.merge"`, `"identity.match.decide"`, `"linked_by_sign_in":true`} {
		if !strings.Contains(a, want) {
			t.Errorf("the ledger has no %s", want)
		}
	}
	// the same sign-in cannot link twice
	e.signInAtIdP(authURL, lc, empSub, devidp.MethodPasskey)
	if n := strings.Count(e.auditJSON(), `"identity.merge"`); n != 1 {
		t.Errorf("%d merges after a replayed callback", n)
	}
}

// Signing in as someone who is not a candidate links nothing: the claim goes on at the
// credential step with the suspicion still in the queue.
func TestClaim_LinkBySignIn_NotACandidate(t *testing.T) {
	e := newClaimEnv(t, claimOpts{users: linkUsers})
	w := e.employee(empSub)
	// a different person signs in, bound to an identity who is not a candidate
	other := e.otherEmployee(w.person, otherSub)
	v := e.invite(w.email, "visitor")
	_, token := e.lastLink(w.email)
	pg := e.newPage()
	pg.start(token)
	rec := e.answerYes(pg, w.email)
	authURL, lc := e.loginURL(rec)
	cb := e.signInAtIdP(authURL, lc, otherSub, devidp.MethodPasskey)
	if cb.Code != http.StatusSeeOther || cb.Header().Get("Location") != "/claim?result=continue" {
		t.Fatalf("callback: %d %v %s", cb.Code, cb.Header(), cb.Body)
	}
	if got := decodeMap(t, pg.do("GET", "status", "")); got["step"] != "credential" {
		t.Errorf("status = %v", got)
	}
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		if g, _ := tx.Identity(v.Guest.ID); g.Status != "invited" {
			t.Errorf("the provisional person is %s", g.Status)
		}
		if ss, _ := tx.Sponsorships(store.SponsorshipFilter{Guest: other}); len(ss) != 0 {
			t.Errorf("the sponsorship moved to someone who was not a candidate: %v", ss)
		}
		if ss, _ := tx.Sponsorships(store.SponsorshipFilter{Guest: v.Guest.ID}); len(ss) != 1 {
			t.Errorf("the sponsorship left the guest: %v", ss)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := e.matches(store.MatchReview); len(got) != 1 {
		t.Errorf("the suspicion left the queue: %+v", got)
	}
	if !strings.Contains(e.auditJSON(), `"not_a_candidate"`) {
		t.Error("the outcome is not in the ledger")
	}
	// and the claim can still finish as a new identity
	if rec := pg.post("credential", ""); rec.Code != 200 || decodeMap(t, rec)["redirect"] == "" {
		t.Errorf("credential after a link that did not link: %d %s", rec.Code, rec.Body)
	}
}

// otherEmployee binds another employee, who is not a candidate, to a dev IdP subject.
func (e *claimEnv) otherEmployee(not int64, sub string) int64 {
	e.t.Helper()
	var id int64
	if err := e.db.InTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		ids, err := tx.Identities()
		if err != nil {
			return err
		}
		for _, i := range ids {
			if i.Type == "human" && i.Status == "active" && i.ID != not && i.ID != e.sponsID {
				id = i.ID
				break
			}
		}
		cs, err := tx.IdPConnections()
		if err != nil {
			return err
		}
		uid := uuid.New()
		if err := tx.InsertPlatformUser(&store.PlatformUser{ID: uid, DisplayName: "Someone Else", Status: "active", IdentityID: &id,
			CreatedAt: e.clk.now()}); err != nil {
			return err
		}
		for _, c := range cs {
			if c.Profile == "dev_mock" || c.IsDefault {
				return tx.InsertExternalLogin(&store.ExternalLogin{UserID: uid, IdPConnectionID: c.ID, Issuer: deref(c.Issuer),
					Subject: sub, CreatedAt: e.clk.now()})
			}
		}
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// The question is asked of everyone and the answer looks the same whether or not
// the matcher found anything: a claimant with a suspected match and one without get
// the same response to "yes" (apart from the one-time values of the sign-in URL),
// and the same to "no".
func TestClaim_ExistingAccountResponsesIdentical(t *testing.T) {
	e := newClaimEnv(t, claimOpts{users: linkUsers})
	w := e.employee(empSub)
	norm := func(rec interface{ Bytes() []byte }) map[string]any {
		var m map[string]any
		if err := json.Unmarshal(rec.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		if _, ok := m["redirect"]; ok {
			m["redirect"] = "<sign-in url>"
		}
		return m
	}
	answers := map[string][]map[string]any{}
	headers := map[string][]string{}
	for _, c := range []struct{ name, email string }{{"match", w.email}, {"nomatch", "nobody-" + uuid.NewString()[:8] + "@guest.example"}} {
		for _, ans := range []string{"yes", "no"} {
			pg, _, _ := e.started(c.email)
			pg.verifyEmail(c.email)
			rec := pg.post("existing-account", `{"answer":"`+ans+`"}`)
			if rec.Code != 200 {
				t.Fatalf("%s %s: %d %s", c.name, ans, rec.Code, rec.Body)
			}
			answers[ans] = append(answers[ans], norm(rec.Body))
			headers[ans] = append(headers[ans], rec.Header().Get("Cache-Control")+"|"+rec.Header().Get("Referrer-Policy")+"|"+rec.Header().Get("Content-Type"))
			if ans == "yes" && cookieNamed(rec, LoginCookieName) == nil {
				t.Errorf("%s yes: no login cookie", c.name)
			}
		}
	}
	for ans, rs := range answers {
		a, _ := json.Marshal(rs[0])
		b, _ := json.Marshal(rs[1])
		if string(a) != string(b) {
			t.Errorf("answer %q differs with a match: %s vs %s", ans, a, b)
		}
		if headers[ans][0] != headers[ans][1] {
			t.Errorf("answer %q headers differ: %v", ans, headers[ans])
		}
	}
}
