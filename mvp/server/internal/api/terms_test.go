package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/credential"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/terms"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// ---------------------------------------------------------------- helpers

// admin signs in a policy admin (terms.manage) of the env's tenant.
func (e *claimEnv) admin() authtest.Login {
	e.t.Helper()
	return authtest.LoginAs(e.t, e.db, e.tenant, authtest.User{Email: "pa@larkspur.example", Display: "Pat Admin",
		Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, e.clk.now())
}

// helpDesk signs in an operator (guests.recover).
func (e *claimEnv) helpDesk() authtest.Login {
	e.t.Helper()
	return authtest.LoginAs(e.t, e.db, e.tenant, authtest.User{Email: "desk@larkspur.example", Display: "Hal Desk",
		Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, e.clk.now())
}

// guestLogin signs in a platform user who is the guest's person.
func (e *claimEnv) guestLogin(guest int64) authtest.Login {
	e.t.Helper()
	return authtest.LoginAs(e.t, e.db, e.tenant, authtest.User{Email: fmt.Sprintf("guest%d@guest.example", guest), Display: "Gwen Guest",
		Roles: []auth.Role{auth.RoleViewer}, IdentityID: &guest}, authtest.Phr, e.clk.now())
}

func (e *claimEnv) publish(l authtest.Login, key, body string, grace int) map[string]any {
	e.t.Helper()
	rec := e.do(l, "POST", "/api/admin/terms", fmt.Sprintf(`{"key":%q,"title":"Acceptable use","body":%q,"grace_days":%d}`, key, body, grace))
	if rec.Code != http.StatusCreated {
		e.t.Fatalf("publish: %d %s", rec.Code, rec.Body)
	}
	return decodeMap(e.t, rec)
}

func (e *claimEnv) assign(l authtest.Login, key, body string) {
	e.t.Helper()
	if rec := e.do(l, "PUT", "/api/admin/terms/"+key+"/assignments", body); rec.Code != http.StatusOK {
		e.t.Fatalf("assign: %d %s", rec.Code, rec.Body)
	}
}

// claimThrough runs a claim from the link to the question; the page is at the credential step.
func (e *claimEnv) claimThrough(email string) (*page, sponsorshipView) {
	e.t.Helper()
	pg, _, v := e.started(email)
	pg.verifyEmail(email)
	if rec := pg.post("existing-account", `{"answer":"no"}`); rec.Code != 200 {
		e.t.Fatalf("existing-account: %d %s", rec.Code, rec.Body)
	}
	return pg, v
}

// signIn takes the credential step to the dev IdP and back as the guest's own
// dev IdP subject; it returns the callback's Location.
func (e *claimEnv) signIn(pg *page, guest int64) string {
	e.t.Helper()
	return e.signInAs(pg, "guest-"+strings.TrimPrefix(e.identityOf(guest).ExternalID, "guest:"))
}

func (e *claimEnv) signInAs(pg *page, sub string) string {
	e.t.Helper()
	authURL, lc := e.loginURL(pg.post("credential", ""))
	cb := e.signInAtIdP(authURL, lc, sub, devidp.MethodPasskey)
	if cb.Code != http.StatusSeeOther {
		e.t.Fatalf("callback: %d %s", cb.Code, cb.Body)
	}
	return cb.Header().Get("Location")
}

// claimed is a finished claim: an active guest with a platform user.
func (e *claimEnv) claimed(email string) int64 {
	e.t.Helper()
	pg, v := e.claimThrough(email)
	if loc := e.signIn(pg, v.Guest.ID); loc != "/claim?result=complete" {
		e.t.Fatalf("claim result %s", loc)
	}
	return v.Guest.ID
}

func (e *claimEnv) acceptances(guest int64) []*store.TermsAcceptance {
	e.t.Helper()
	var out []*store.TermsAcceptance
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		var err error
		out, err = tx.TermsAcceptancesFor(guest)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *claimEnv) events(action string) []*store.AuditEvent {
	var out []*store.AuditEvent
	for _, ev := range ledger(e.t, e.db, e.tenant) {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}

// ---------------------------------------------------------------- terms

// TestTerms_AcceptanceBeforeBinding: the claim cannot start its credential, or
// complete one, until every document that applies is accepted; the acceptance
// is recorded with the text hash, in the table and in the ledger.
func TestTerms_AcceptanceBeforeBinding(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	adm := e.admin()
	v1 := e.publish(adm, "aup", "You will behave.", 14)
	e.assign(adm, "aup", `{"populations":["visitor"]}`)
	const email = "gwen@guest.example"
	pg, v := e.claimThrough(email)

	st := decodeMap(t, pg.do("GET", "status", ""))
	if st["step"] != "credential" || st["pending"] != "terms" {
		t.Fatalf("status = %v, want the credential step pending terms", st)
	}
	if rec := pg.post("credential", ""); rec.Code != http.StatusConflict || decodeMap(t, rec)["error"] != "terms_required" {
		t.Fatalf("credential before terms: %d %s", rec.Code, rec.Body)
	}
	tm := decodeMap(t, pg.do("GET", "terms", ""))
	docs, _ := tm["terms"].([]any)
	if len(docs) != 1 {
		t.Fatalf("terms = %v", tm)
	}
	d := docs[0].(map[string]any)
	if d["sha256"] != terms.Hash("You will behave.") || d["sha256"] != v1["sha256"] || d["body"] != "You will behave." {
		t.Errorf("the document shown = %v", d)
	}
	// the text must be the text the claimant saw
	if rec := pg.post("terms/accept", fmt.Sprintf(`{"documents":[{"id":%q,"sha256":%q}]}`, d["id"], strings.Repeat("0", 64))); rec.Code != http.StatusConflict {
		t.Errorf("accept with the wrong hash: %d %s", rec.Code, rec.Body)
	}
	if rec := pg.post("terms/accept", fmt.Sprintf(`{"documents":[{"id":%q,"sha256":%q}]}`, uuid.NewString(), d["sha256"])); rec.Code != http.StatusConflict {
		t.Errorf("accept of an unknown document: %d %s", rec.Code, rec.Body)
	}
	if n := len(e.acceptances(v.Guest.ID)); n != 0 {
		t.Fatalf("%d acceptances after refusals", n)
	}
	body := fmt.Sprintf(`{"documents":[{"id":%q,"sha256":%q}]}`, d["id"], d["sha256"])
	if rec := pg.post("terms/accept", body); rec.Code != 200 || decodeMap(t, rec)["remaining"] != float64(0) {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body)
	}
	accs := e.acceptances(v.Guest.ID)
	if len(accs) != 1 || accs[0].DocumentID != d["id"] || accs[0].Version != 1 || accs[0].TextSHA256 != terms.Hash("You will behave.") ||
		accs[0].Context != "claim" || accs[0].SessionHash == nil || accs[0].IPHash == "" || accs[0].UAHash != "" && len(accs[0].UAHash) != 64 {
		t.Fatalf("acceptances = %+v", accs)
	}
	if strings.Contains(accs[0].IPHash, "192.0.2.10") {
		t.Error("the client address is stored in clear")
	}
	evs := e.events("terms.accept")
	if len(evs) != 1 || !strings.Contains(string(evs[0].Detail), terms.Hash("You will behave.")) || !strings.Contains(string(evs[0].Detail), d["id"].(string)) ||
		!strings.Contains(string(evs[0].Detail), `"version":1`) {
		t.Fatalf("terms.accept events = %v", evs)
	}
	if st := decodeMap(t, pg.do("GET", "status", "")); st["pending"] == "terms" {
		t.Errorf("status still pending terms: %v", st)
	}
	// and the credential now starts and completes
	if loc := e.signIn(pg, v.Guest.ID); loc != "/claim?result=complete" {
		t.Fatalf("claim result %s", loc)
	}
	if g := e.identityOf(v.Guest.ID); g.Status != "active" {
		t.Errorf("identity %q", g.Status)
	}
}

// TestTerms_CallbackRefusesOutstanding: terms published after the credential
// started but before the sign-in came back still stop the binding.
func TestTerms_CallbackRefusesOutstanding(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	pg, v := e.claimThrough("gwen@guest.example")
	authURL, lc := e.loginURL(pg.post("credential", ""))
	adm := e.admin()
	e.publish(adm, "late", "New rules.", 14)
	e.assign(adm, "late", `{"populations":["visitor"]}`)
	ref := strings.TrimPrefix(e.identityOf(v.Guest.ID).ExternalID, "guest:")
	cb := e.signInAtIdP(authURL, lc, "guest-"+ref, devidp.MethodPasskey)
	if cb.Header().Get("Location") != "/claim?result=failed" {
		t.Fatalf("callback: %d %v", cb.Code, cb.Header())
	}
	if g := e.identityOf(v.Guest.ID); g.Status != "invited" {
		t.Errorf("identity %q after a refused binding", g.Status)
	}
	if !strings.Contains(e.auditJSON(), "terms_not_accepted") {
		t.Error("the refusal is not in the ledger")
	}
}

// TestTerms_ReacceptOnNewVersion: a new version needs re-acceptance by someone
// who accepted the old one, with the document's grace period; the old
// acceptance stays on record.
func TestTerms_ReacceptOnNewVersion(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	adm := e.admin()
	v1 := e.publish(adm, "aup", "Version one.", 7)
	e.assign(adm, "aup", `{"populations":["visitor"]}`)
	pg, v := e.claimThrough("gwen@guest.example")
	tm := decodeMap(t, pg.do("GET", "terms", ""))
	d := tm["terms"].([]any)[0].(map[string]any)
	if rec := pg.post("terms/accept", fmt.Sprintf(`{"documents":[{"id":%q,"sha256":%q}]}`, d["id"], d["sha256"])); rec.Code != 200 {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body)
	}
	if loc := e.signIn(pg, v.Guest.ID); loc != "/claim?result=complete" {
		t.Fatalf("claim result %s", loc)
	}
	guest := e.guestLogin(v.Guest.ID)
	me := decodeMap(t, e.do(guest, "GET", "/api/me/terms", ""))
	if me["blocked"] != false || me["documents"].([]any)[0].(map[string]any)["state"] != "accepted" {
		t.Fatalf("me/terms before the new version = %v", me)
	}
	// version 2, with a grace period
	v2 := e.publish(adm, "aup", "Version two, with changes.", 7)
	if v2["version"] != float64(2) || v2["sha256"] == v1["sha256"] {
		t.Fatalf("v2 = %v", v2)
	}
	me = decodeMap(t, e.do(guest, "GET", "/api/me/terms", ""))
	doc := me["documents"].([]any)[0].(map[string]any)
	if doc["version"] != float64(2) || doc["state"] != "grace" || doc["previously_accepted"] != true || doc["due_by"] == nil || me["blocked"] != false {
		t.Fatalf("me/terms after v2 = %v", me)
	}
	if rec := e.do(guest, "GET", "/api/guests", ""); rec.Code != 200 {
		t.Errorf("access during the grace period: %d %s", rec.Code, rec.Body)
	}
	// the claim page of a new claim shows v2 as outstanding too (a different guest)
	pg2, _ := e.claimThrough("hank@guest.example")
	if st := decodeMap(t, pg2.do("GET", "status", "")); st["pending"] != "terms" {
		t.Errorf("a new claimant is not asked to accept v2: %v", st)
	}
	// accept v2: the acceptance of v1 stays, v2 is added with its own hash
	if rec := e.do(guest, "POST", "/api/me/terms/accept", fmt.Sprintf(`{"documents":[{"id":%q,"sha256":%q}]}`, doc["id"], doc["sha256"])); rec.Code != 200 {
		t.Fatalf("accept v2: %d %s", rec.Code, rec.Body)
	}
	accs := e.acceptances(v.Guest.ID)
	if len(accs) != 2 || accs[0].Version != 1 || accs[1].Version != 2 || accs[1].TextSHA256 != terms.Hash("Version two, with changes.") || accs[1].Context != "signin" {
		t.Fatalf("acceptances = %+v", accs)
	}
	me = decodeMap(t, e.do(guest, "GET", "/api/me/terms", ""))
	if me["documents"].([]any)[0].(map[string]any)["state"] != "accepted" {
		t.Errorf("me/terms after accepting = %v", me)
	}
	if n := len(e.events("terms.accept")); n != 2 {
		t.Errorf("%d terms.accept events, want 2 (v1 at the claim, v2 at sign-in)", n)
	}
}

// TestTerms_GraceExpiryBlocks: after the grace period a guest is blocked from
// every route but sign-in, /api/me/terms and the session routes, until they accept.
func TestTerms_GraceExpiryBlocks(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	adm := e.admin()
	e.publish(adm, "aup", "Version one.", 7)
	e.assign(adm, "aup", `{"populations":["visitor"]}`)
	pg, v := e.claimThrough("gwen@guest.example")
	d := decodeMap(t, pg.do("GET", "terms", ""))["terms"].([]any)[0].(map[string]any)
	pg.post("terms/accept", fmt.Sprintf(`{"documents":[{"id":%q,"sha256":%q}]}`, d["id"], d["sha256"]))
	e.signIn(pg, v.Guest.ID)
	e.publish(adm, "aup", "Version two.", 3)

	e.clk.add(3*24*time.Hour - time.Minute)
	guest := e.guestLogin(v.Guest.ID)
	if rec := e.do(guest, "GET", "/api/guests", ""); rec.Code != 200 {
		t.Fatalf("one minute before the grace period ends: %d %s", rec.Code, rec.Body)
	}
	e.clk.add(2 * time.Minute)
	rec := e.do(guest, "GET", "/api/guests", "")
	if rec.Code != http.StatusForbidden || decodeMap(t, rec)["error"] != "terms_required" {
		t.Fatalf("after the grace period: %d %s", rec.Code, rec.Body)
	}
	me := e.do(guest, "GET", "/api/me/terms", "")
	m := decodeMap(t, me)
	if me.Code != 200 || m["blocked"] != true {
		t.Fatalf("me/terms while blocked: %d %s", me.Code, me.Body)
	}
	if rec := e.do(guest, "GET", "/api/auth/session", ""); rec.Code != 200 {
		t.Errorf("the session route while blocked: %d", rec.Code)
	}
	doc := m["documents"].([]any)[0].(map[string]any)
	if doc["state"] != "blocked" {
		t.Errorf("state = %v", doc["state"])
	}
	if rec := e.do(guest, "POST", "/api/me/terms/accept", fmt.Sprintf(`{"documents":[{"id":%q,"sha256":%q}]}`, doc["id"], doc["sha256"])); rec.Code != 200 {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(guest, "GET", "/api/guests", ""); rec.Code != 200 {
		t.Errorf("after accepting: %d %s", rec.Code, rec.Body)
	}
	// a person nothing is assigned to (the admin) is never blocked
	if rec := e.do(e.admin(), "GET", "/api/guests", ""); rec.Code != 200 {
		t.Errorf("the admin is blocked: %d", rec.Code)
	}
}

// TestTerms_AssignedToBundles: a document assigned to a bundle applies to a
// guest whose sponsorship includes the item, not to others.
func TestTerms_AssignedToBundle(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	adm := e.admin()
	var group int64
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		gs, err := tx.Groups()
		if err != nil {
			return err
		}
		for _, g := range gs {
			if _, err := tx.CatalogItemForGroup(g.ID); err == nil {
				group = g.ID
				break
			}
		}
		return nil
	}); err != nil || group == 0 {
		t.Fatalf("no catalog group: %v", err)
	}
	e.publish(adm, "bundle-nda", "Confidentiality.", 14)
	e.assign(adm, "bundle-nda", fmt.Sprintf(`{"bundles":[%d]}`, group))
	pg, _ := e.claimThrough("plain@guest.example")
	if st := decodeMap(t, pg.do("GET", "status", "")); st["pending"] == "terms" {
		t.Errorf("a guest without the bundle is asked to accept it: %v", st)
	}
	// the same document, assigned to the bundle, applies to a sponsorship that carries it
	rec := e.do(e.sponsor, "POST", "/api/guests/invitations", inviteJSON("bundled@guest.example", "visitor", e.clk.now().AddDate(0, 0, 10), fmt.Sprintf(`,"bundle":[%d]`, group)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("invite with bundle: %d %s", rec.Code, rec.Body)
	}
	_, token := e.lastLink("bundled@guest.example")
	pg2 := e.newPage()
	pg2.start(token)
	pg2.verifyEmail("bundled@guest.example")
	pg2.post("existing-account", `{"answer":"no"}`)
	if st := decodeMap(t, pg2.do("GET", "status", "")); st["pending"] != "terms" {
		t.Errorf("a guest with the bundle is not asked: %v", st)
	}
}

// TestTermsAPI_Admin: publishing, listing and assigning, with their refusals
// and permissions.
func TestTermsAPI_Admin(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	adm := e.admin()
	viewer := authtest.LoginAs(t, e.db, e.tenant, authtest.User{Email: "v@larkspur.example", Display: "V", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, e.clk.now())
	for name, c := range map[string]struct{ body, want string }{
		"bad key":        {`{"key":"Bad Key","title":"t","body":"b"}`, "invalid_key"},
		"no title":       {`{"key":"k","title":"","body":"b"}`, "invalid_title"},
		"no body":        {`{"key":"k","title":"t","body":"  "}`, "invalid_body"},
		"huge grace":     {`{"key":"k","title":"t","body":"b","grace_days":4000}`, "invalid_grace"},
		"negative grace": {`{"key":"k","title":"t","body":"b","grace_days":-1}`, "invalid_grace"},
	} {
		rec := e.do(adm, "POST", "/api/admin/terms", c.body)
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := e.do(viewer, "POST", "/api/admin/terms", `{"key":"k","title":"t","body":"b"}`); rec.Code != http.StatusForbidden {
		t.Errorf("a viewer published: %d", rec.Code)
	}
	if rec := e.do(viewer, "GET", "/api/admin/terms", ""); rec.Code != http.StatusForbidden {
		t.Errorf("a viewer listed: %d", rec.Code)
	}
	e.publish(adm, "aup", "One.", 14)
	if rec := e.do(adm, "POST", "/api/admin/terms", `{"key":"aup","title":"t","body":"One."}`); rec.Code != http.StatusConflict {
		t.Errorf("the same text again: %d %s", rec.Code, rec.Body)
	}
	e.publish(adm, "aup", "Two.", 3)
	for name, body := range map[string]string{"bad population": `{"populations":["alien"]}`, "unknown group": `{"bundles":[999999]}`} {
		if rec := e.do(adm, "PUT", "/api/admin/terms/aup/assignments", body); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := e.do(adm, "PUT", "/api/admin/terms/nosuch/assignments", `{"populations":["visitor"]}`); rec.Code != http.StatusNotFound {
		t.Errorf("assign an unknown document: %d", rec.Code)
	}
	e.assign(adm, "aup", `{"populations":["visitor","contractor","visitor"]}`)
	list := decodeMap(t, e.do(e.helpDesk(), "GET", "/api/admin/terms", ""))
	docs := list["documents"].([]any)
	if len(docs) != 1 {
		t.Fatalf("list = %v", list)
	}
	d := docs[0].(map[string]any)
	if d["latest_version"] != float64(2) || len(d["versions"].([]any)) != 2 || len(d["populations"].([]any)) != 2 || d["grace_days"] != float64(3) {
		t.Errorf("document = %v", d)
	}
	for _, a := range []string{"terms.publish", "terms.assign"} {
		if len(e.events(a)) == 0 {
			t.Errorf("no %s event", a)
		}
	}
}

// ---------------------------------------------------------------- consent

// federated is an authority that signs the guest in at their home IdP.
type federated struct{ *fakeAuthority }

func (federated) Kind() string { return "home_idp" }

// TestClaim_ConsentRecorded: a federated claim shows the attribute-release
// screen, the credential waits for the answer, and the answer (the required
// attributes always included) is recorded and audited.
func TestClaim_ConsentRecorded(t *testing.T) {
	users := []devidp.User{{Sub: "guest-fed", Email: "fed@guest.example", Name: "Fed", Tenant: "larkspur", Authenticators: []devidp.Method{devidp.MethodPasskey}}}
	var _ credential.Authority = federated{}
	e := newClaimEnv(t, claimOpts{authority: federated{&fakeAuthority{subject: "guest-fed"}}, users: users})
	pg, v := e.claimThrough("fed@guest.example")
	if st := decodeMap(t, pg.do("GET", "status", "")); st["pending"] != "consent" {
		t.Fatalf("status = %v", st)
	}
	if rec := pg.post("credential", ""); rec.Code != http.StatusConflict || decodeMap(t, rec)["error"] != "consent_required" {
		t.Fatalf("credential before consent: %d %s", rec.Code, rec.Body)
	}
	tm := decodeMap(t, pg.do("GET", "terms", ""))
	c := tm["consent"].(map[string]any)
	if c["applies"] != true || c["given"] != false || len(c["attributes"].([]any)) != len(terms.Attributes) {
		t.Fatalf("consent screen = %v", c)
	}
	if rec := pg.post("consent", `{"attributes":["shoe_size"]}`); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("an unknown attribute: %d %s", rec.Code, rec.Body)
	}
	if rec := pg.post("consent", `{"attributes":["name"]}`); rec.Code != 200 {
		t.Fatalf("consent: %d %s", rec.Code, rec.Body)
	}
	if rec := pg.post("consent", `{"attributes":["name","affiliation"]}`); rec.Code != http.StatusConflict {
		t.Errorf("a second answer: %d %s", rec.Code, rec.Body)
	}
	var got *store.AttributeConsent
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		cs, err := tx.AttributeConsentsFor(v.Guest.ID)
		if len(cs) == 1 {
			got = cs[0]
		}
		return err
	}); err != nil || got == nil {
		t.Fatalf("consent row: %v %v", got, err)
	}
	var consented []string
	_ = json.Unmarshal([]byte(got.Consented), &consented)
	if strings.Join(consented, ",") != "subject,email,name" || got.Authority != "home_idp" {
		t.Errorf("consented = %v (%s)", consented, got.Authority)
	}
	if evs := e.events("consent.attributes"); len(evs) != 1 || !strings.Contains(string(evs[0].Detail), `"consented":["subject","email","name"]`) {
		t.Errorf("consent events = %v", evs)
	}
	if st := decodeMap(t, pg.do("GET", "status", "")); st["pending"] == "consent" {
		t.Errorf("status still pending consent: %v", st)
	}
	if loc := e.signInAs(pg, "guest-fed"); loc != "/claim?result=complete" {
		t.Fatalf("claim result %s", loc)
	}
}

// ---------------------------------------------------------------- recovery

func (e *claimEnv) recoveryCase(guest int64) *store.RecoveryCase {
	e.t.Helper()
	var out *store.RecoveryCase
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		cs, err := tx.RecoveryCases(guest, "")
		if len(cs) > 0 {
			out = cs[0]
		}
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *claimEnv) issueRecovery(l authtest.Login, guest int64, body string) *httptest.ResponseRecorder {
	return e.do(l, "POST", fmt.Sprintf("/api/guests/%d/recovery", guest), body)
}

// recoveryPage follows the newest recovery link of email to the claim's credential
// (or as far as the case goes) and returns the page.
func (e *claimEnv) recoveryPage(email string) *page {
	e.t.Helper()
	_, token := e.lastLink(email)
	pg := e.newPage()
	if rec := pg.start(token); decodeMap(e.t, rec)["next"] != "verify_contact" {
		e.t.Fatalf("recovery start: %d %s", rec.Code, rec.Body)
	}
	pg.verifyEmail(email)
	return pg
}

func (e *claimEnv) linkedUsers(guest int64) []*store.PlatformUser {
	e.t.Helper()
	var out []*store.PlatformUser
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		ids, err := tx.UsersLinkedTo(guest)
		for _, id := range ids {
			u, err := tx.PlatformUser(uuid.MustParse(id))
			if err != nil {
				return err
			}
			out = append(out, u)
		}
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

// TestRecovery_RequiresOriginalIAL: a recovery re-verifies at the identity's
// recorded IAL, whatever the sponsorship asks now: an IAL 2 identity does not
// reach the credential step on a contact code alone.
func TestRecovery_RequiresOriginalIAL(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	const email = "gwen@guest.example"
	guest := e.claimed(email)
	if err := e.db.InTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		return tx.PutIdentityAssurance(&store.Assurance{IdentityID: guest, IAL: 2, AAL: 2, Source: "idv", RecordedAt: e.clk.now()})
	}); err != nil {
		t.Fatal(err)
	}
	rec := e.issueRecovery(e.helpDesk(), guest, `{"reason":"lost passkey"}`)
	m := decodeMap(t, rec)
	if rec.Code != http.StatusCreated || m["required_ial"] != float64(2) || m["via"] != "help_desk" {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body)
	}
	pg := e.recoveryPage(email)
	st := decodeMap(t, pg.do("GET", "status", ""))
	if st["step"] != "verify_identity" || st["pending"] != "identity_verification" || st["purpose"] != "recovery" {
		t.Fatalf("status = %v: a recovery of an IAL 2 identity must wait for identity verification", st)
	}
	if rec := pg.post("credential", ""); rec.Code != http.StatusConflict || decodeMap(t, rec)["error"] != "wrong_step" {
		t.Errorf("credential without identity verification: %d %s", rec.Code, rec.Body)
	}
	if rec := pg.post("existing-account", `{"answer":"no"}`); rec.Code != http.StatusConflict {
		t.Errorf("a recovery has no existing-account question: %d %s", rec.Code, rec.Body)
	}
	if c := e.recoveryCase(guest); c.Status != store.RecoveryStarted || c.RequiredIAL != 2 {
		t.Errorf("case = %+v", c)
	}
	// the sponsorship asking for less does not lower it: a lower claim for IAL 0 reaches the credential
	g2 := e.claimed("hank@guest.example")
	if rec := e.issueRecovery(e.sponsor, g2, ``); rec.Code != http.StatusCreated || decodeMap(t, rec)["required_ial"] != float64(0) {
		t.Fatalf("issue for an IAL 0 identity: %d %s", rec.Code, rec.Body)
	}
	if st := decodeMap(t, e.recoveryPage("hank@guest.example").do("GET", "status", "")); st["step"] != "credential" {
		t.Errorf("an IAL 0 recovery = %v, want the credential step", st)
	}
}

// TestRecovery_NotifiesAllChannels: issuing a recovery tells every channel on
// file (the guest's own address, each sign-in user's address and inbox, the
// sponsor), and only the guest's address gets the link.
func TestRecovery_NotifiesAllChannels(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	const email = "gwen@guest.example"
	guest := e.claimed(email)
	alt := "alt@guest.example"
	if err := e.db.InTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		return tx.InsertPlatformUser(&store.PlatformUser{ID: uuid.New(), DisplayName: "Gwen (second sign-in)", Email: &alt, Status: "active",
			IdentityID: &guest, CreatedAt: e.clk.now()})
	}); err != nil {
		t.Fatal(err)
	}
	e.dispatch()
	before := len(e.mail.all())
	if rec := e.issueRecovery(e.sponsor, guest, `{"reason":"lost phone"}`); rec.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body)
	}
	e.dispatch()
	got := map[string][]string{}
	for _, m := range e.mail.all()[before:] {
		got[m.To] = append(got[m.To], m.Subject+"\n"+m.Body)
	}
	wantSet := map[string]bool{email: true, alt: true, "sponsor@larkspur.example": true}
	for _, u := range e.linkedUsers(guest) {
		if u.Email != nil {
			wantSet[*u.Email] = true
		}
	}
	links := 0
	for to := range wantSet {
		notice := false
		for _, m := range got[to] {
			notice = notice || strings.Contains(m, "Account recovery started")
			if strings.Contains(m, "/claim#t=") {
				links++
				if to != email {
					t.Errorf("the recovery link went to %s", to)
				}
			}
		}
		if !notice {
			t.Errorf("no recovery notice to %s; mails: %v", to, got)
		}
	}
	if links != 1 {
		t.Errorf("%d mails carry the link, want 1", links)
	}
	// the users' inboxes, and the sponsor's
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		ids, _ := tx.UsersLinkedTo(guest)
		sp, _ := tx.UsersLinkedTo(e.sponsID)
		if len(ids) < 2 || len(sp) == 0 {
			t.Fatalf("users: %v %v", ids, sp)
		}
		for _, u := range append(ids, sp...) {
			ns, err := tx.Notifications(u, false, 50)
			if err != nil {
				return err
			}
			found := false
			for _, n := range ns {
				found = found || n.Kind == "guest.recovery"
			}
			if !found {
				t.Errorf("no recovery notice in the inbox of user %s", u)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestRecovery_Completes: a recovery adds the sign-in to the existing user, ends
// the case, tells every channel, and the link works once and is in no record.
func TestRecovery_Completes(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	const email = "gwen@guest.example"
	guest := e.claimed(email)
	before := e.linkedUsers(guest)
	if len(before) != 1 {
		t.Fatalf("users = %v", before)
	}
	if rec := e.issueRecovery(e.sponsor, guest, `{"reason":"lost phone"}`); rec.Code != http.StatusCreated || decodeMap(t, rec)["via"] != "sponsor" {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body)
	}
	link, token := e.lastLink(email)
	pg := e.newPage()
	pg.start(token)
	pg.verifyEmail(email)
	if st := decodeMap(t, pg.do("GET", "status", "")); st["step"] != "credential" || st["purpose"] != "recovery" {
		t.Fatalf("status = %v", st)
	}
	if loc := e.signIn(pg, guest); loc != "/claim?result=complete" {
		t.Fatalf("recovery result %s", loc)
	}
	c := e.recoveryCase(guest)
	if c.Status != store.RecoveryCompleted || c.CompletedAt == nil {
		t.Fatalf("case = %+v", c)
	}
	if after := e.linkedUsers(guest); len(after) != 1 || after[0].ID != before[0].ID {
		t.Errorf("a recovery made a new user: %v", after)
	}
	for _, a := range []string{"recovery.issue", "claim.start", "recovery.complete"} {
		if len(e.events(a)) == 0 {
			t.Errorf("no %s event", a)
		}
	}
	if j := e.auditJSON(); strings.Contains(j, token) {
		t.Error("the recovery token is in the ledger")
	}
	e.dispatch()
	finished := false
	for _, m := range e.mail.all() {
		finished = finished || strings.Contains(m.Subject, "Account recovery finished")
	}
	if !finished {
		t.Error("no completion notice")
	}
	// the link is single use
	if rec := e.newPage().start(token); decodeMap(t, rec)["next"] != "check_link" {
		t.Errorf("a used recovery link started again: %s", rec.Body)
	}
	_ = link
	// a recovery of someone with no live access is refused, and so is one for an invitation
	invited := e.invite("new@guest.example", "visitor")
	if rec := e.issueRecovery(e.helpDesk(), invited.Guest.ID, ``); rec.Code != http.StatusConflict {
		t.Errorf("recovery of an unclaimed guest: %d %s", rec.Code, rec.Body)
	}
}

func (e *claimEnv) externalLogins(user uuid.UUID) []*store.ExternalLogin {
	e.t.Helper()
	var out []*store.ExternalLogin
	if err := e.db.ReadTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		var err error
		out, err = tx.ExternalLoginsForUser(user)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

// TestRecovery_CoolingOffForPrivilegedBundles: an identity that holds a privileged
// bundle waits 24 hours between the new sign-in and its activation; it is
// notified, can be cancelled, and the sweeper binds it after the wait.
func TestRecovery_CoolingOffForPrivilegedBundles(t *testing.T) {
	users := []devidp.User{
		{Sub: "guest-orig", Email: "o@guest.example", Name: "O", Tenant: "larkspur", Authenticators: []devidp.Method{devidp.MethodPasskey}},
		{Sub: "guest-new", Email: "n@guest.example", Name: "N", Tenant: "larkspur", Authenticators: []devidp.Method{devidp.MethodPasskey}},
	}
	fake := &fakeAuthority{subject: "guest-orig"}
	e := newClaimEnv(t, claimOpts{authority: fake, users: users})
	const email = "gwen@guest.example"
	pg, v := e.claimThrough(email)
	if loc := e.signInAs(pg, "guest-orig"); loc != "/claim?result=complete" {
		t.Fatalf("claim result %s", loc)
	}
	guest := v.Guest.ID
	user := e.linkedUsers(guest)[0].ID
	// the guest holds a privileged bundle item
	if err := e.db.InTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		gs, err := tx.Groups()
		if err != nil {
			return err
		}
		ss, err := tx.Sponsorships(store.SponsorshipFilter{Guest: guest})
		if err != nil {
			return err
		}
		for _, g := range gs {
			if g.Privileged {
				return tx.InsertBundleItem(&store.BundleItem{ID: uuid.NewString(), SponsorshipID: ss[0].ID, GuestID: guest, GroupID: g.ID,
					System: g.System, Status: store.BundlePending, ExpiresAt: ss[0].EndsAt, CreatedAt: e.clk.now(), UpdatedAt: e.clk.now()})
			}
		}
		t.Fatal("no privileged group")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fake.subject = "guest-new"
	if rec := e.issueRecovery(e.helpDesk(), guest, `{"reason":"lost key"}`); rec.Code != http.StatusCreated || decodeMap(t, rec)["privileged"] != true {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body)
	}
	pg = e.recoveryPage(email)
	if loc := e.signInAs(pg, "guest-new"); loc != "/claim?result=cooling_off" {
		t.Fatalf("recovery result %s", loc)
	}
	c := e.recoveryCase(guest)
	if c.Status != store.RecoveryCooling || c.CoolingUntil == nil || !c.CoolingUntil.Equal(e.clk.now().Add(24*time.Hour)) {
		t.Fatalf("case = %+v", c)
	}
	if n := len(e.externalLogins(user)); n != 1 {
		t.Fatalf("the new sign-in is active during the cooling-off: %d logins", n)
	}
	if len(e.events("recovery.cooling_off")) != 1 || len(e.events("recovery.complete")) != 0 {
		t.Error("the ledger does not show a held recovery")
	}
	sweep := func() {
		t.Helper()
		if err := e.srv.claimSvc.SweepAll(context.Background(), e.db, e.clk.now()); err != nil {
			t.Fatal(err)
		}
	}
	e.clk.add(24*time.Hour - time.Minute)
	sweep()
	if n := len(e.externalLogins(user)); n != 1 || e.recoveryCase(guest).Status != store.RecoveryCooling {
		t.Fatalf("activated a minute early: %d logins, %+v", n, e.recoveryCase(guest))
	}
	e.clk.add(2 * time.Minute)
	sweep()
	if n := len(e.externalLogins(user)); n != 2 {
		t.Fatalf("not activated after the wait: %d logins", n)
	}
	if c := e.recoveryCase(guest); c.Status != store.RecoveryCompleted {
		t.Errorf("case = %+v", c)
	}
	if len(e.events("recovery.complete")) != 1 {
		t.Error("no recovery.complete event")
	}
	e.dispatch()
	var held, finished bool
	for _, m := range e.mail.all() {
		held = held || strings.Contains(m.Subject, "waiting 24 hours")
		finished = finished || strings.Contains(m.Subject, "Account recovery finished")
	}
	if !held || !finished {
		t.Errorf("notices: held=%v finished=%v", held, finished)
	}
}

// TestRecovery_CancelDuringCooling: a cancelled recovery never binds.
func TestRecovery_CancelDuringCooling(t *testing.T) {
	users := []devidp.User{
		{Sub: "guest-orig", Email: "o@guest.example", Name: "O", Tenant: "larkspur", Authenticators: []devidp.Method{devidp.MethodPasskey}},
		{Sub: "guest-new", Email: "n@guest.example", Name: "N", Tenant: "larkspur", Authenticators: []devidp.Method{devidp.MethodPasskey}},
	}
	fake := &fakeAuthority{subject: "guest-orig"}
	e := newClaimEnv(t, claimOpts{authority: fake, users: users})
	const email = "gwen@guest.example"
	pg, v := e.claimThrough(email)
	e.signInAs(pg, "guest-orig")
	guest := v.Guest.ID
	user := e.linkedUsers(guest)[0].ID
	if err := e.db.InTenant(context.Background(), e.tenant, func(tx *store.TenantTx) error {
		gs, _ := tx.Groups()
		ss, _ := tx.Sponsorships(store.SponsorshipFilter{Guest: guest})
		for _, g := range gs {
			if g.Privileged {
				return tx.InsertBundleItem(&store.BundleItem{ID: uuid.NewString(), SponsorshipID: ss[0].ID, GuestID: guest, GroupID: g.ID,
					System: g.System, Status: store.BundlePending, ExpiresAt: ss[0].EndsAt, CreatedAt: e.clk.now(), UpdatedAt: e.clk.now()})
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fake.subject = "guest-new"
	if rec := e.issueRecovery(e.helpDesk(), guest, ``); rec.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body)
	}
	pg = e.recoveryPage(email)
	e.signInAs(pg, "guest-new")
	c := e.recoveryCase(guest)
	// someone else (a plain viewer) may not cancel; the sponsor may
	viewer := authtest.LoginAs(t, e.db, e.tenant, authtest.User{Email: "v@larkspur.example", Display: "V", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, e.clk.now())
	if rec := e.do(viewer, "POST", "/api/guest-recoveries/"+c.ID+"/cancel", `{}`); rec.Code != http.StatusForbidden {
		t.Errorf("a stranger cancelled: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(e.sponsor, "POST", "/api/guest-recoveries/"+c.ID+"/cancel", `{"reason":"it was me, all is well"}`); rec.Code != 200 || decodeMap(t, rec)["status"] != "cancelled" {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(e.sponsor, "POST", "/api/guest-recoveries/"+c.ID+"/cancel", `{}`); rec.Code != http.StatusConflict {
		t.Errorf("a second cancel: %d %s", rec.Code, rec.Body)
	}
	e.clk.add(48 * time.Hour)
	if err := e.srv.claimSvc.SweepAll(context.Background(), e.db, e.clk.now()); err != nil {
		t.Fatal(err)
	}
	if n := len(e.externalLogins(user)); n != 1 {
		t.Errorf("a cancelled recovery was bound: %d logins", n)
	}
	if len(e.events("recovery.cancel")) != 1 {
		t.Error("no recovery.cancel event")
	}
	list := decodeMap(t, e.do(e.helpDesk(), "GET", "/api/guest-recoveries?status=cancelled", ""))
	if len(list["recoveries"].([]any)) != 1 {
		t.Errorf("recoveries = %v", list)
	}
}

// TestRecovery_PermissionsAndSupersede: only the guest's sponsor or the help desk
// issues a recovery; a new one replaces the old, whose link stops working.
func TestRecovery_PermissionsAndSupersede(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	const email = "gwen@guest.example"
	guest := e.claimed(email)
	viewer := authtest.LoginAs(t, e.db, e.tenant, authtest.User{Email: "v@larkspur.example", Display: "V", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, e.clk.now())
	if rec := e.issueRecovery(viewer, guest, `{}`); rec.Code != http.StatusForbidden {
		t.Errorf("a stranger issued a recovery: %d %s", rec.Code, rec.Body)
	}
	if rec := e.issueRecovery(e.sponsor, guest, strings.Repeat("x", 3)); rec.Code == http.StatusCreated {
		t.Error("a malformed body was accepted")
	}
	longReason := fmt.Sprintf(`{"reason":%q}`, strings.Repeat("r", 501))
	if rec := e.issueRecovery(e.helpDesk(), guest, longReason); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("a 501 character reason: %d %s", rec.Code, rec.Body)
	}
	if rec := e.issueRecovery(e.helpDesk(), 999999, `{}`); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown person: %d", rec.Code)
	}
	if rec := e.issueRecovery(e.helpDesk(), guest, `{}`); rec.Code != http.StatusCreated {
		t.Fatalf("first: %d %s", rec.Code, rec.Body)
	}
	_, first := e.lastLink(email)
	if rec := e.issueRecovery(e.sponsor, guest, `{}`); rec.Code != http.StatusCreated {
		t.Fatalf("second: %d %s", rec.Code, rec.Body)
	}
	if rec := e.newPage().start(first); decodeMap(t, rec)["next"] != "check_link" {
		t.Errorf("the superseded link still starts: %s", rec.Body)
	}
	_, second := e.lastLink(email)
	if second == first {
		t.Fatal("the new link is the old one")
	}
	if rec := e.newPage().start(second); decodeMap(t, rec)["next"] != "verify_contact" {
		t.Errorf("the new link does not start: %s", rec.Body)
	}
	cs := decodeMap(t, e.do(e.helpDesk(), "GET", "/api/guest-recoveries", ""))["recoveries"].([]any)
	if len(cs) != 2 {
		t.Fatalf("cases = %v", cs)
	}
	st := map[any]int{}
	for _, c := range cs {
		st[c.(map[string]any)["status"]]++
	}
	if st["cancelled"] != 1 || st["started"] != 1 {
		t.Errorf("statuses = %v", st)
	}
}

// TestTermsAPI_CrossTenant: another tenant's recovery case and document keys
// look nonexistent.
func TestTermsAPI_CrossTenant(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	adm := e.admin()
	e.publish(adm, "aup", "One.", 14)
	guest := e.claimed("gwen@guest.example")
	if rec := e.issueRecovery(e.helpDesk(), guest, `{}`); rec.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body)
	}
	c := e.recoveryCase(guest)
	other := authtest.LoginAs(t, e.db, seed.GlobexID, authtest.User{Email: "pa@globex.example", Display: "Globex Admin",
		Roles: []auth.Role{auth.RolePolicyAdmin, auth.RoleOperator}}, authtest.Phr, e.clk.now())
	if rec := e.do(other, "POST", "/api/guest-recoveries/"+c.ID+"/cancel", `{}`); rec.Code != http.StatusNotFound {
		t.Errorf("another tenant's case: %d %s", rec.Code, rec.Body)
	}
	missing := e.do(other, "POST", "/api/guest-recoveries/"+uuid.NewString()+"/cancel", `{}`)
	if missing.Code != http.StatusNotFound {
		t.Errorf("a missing case: %d", missing.Code)
	}
	if rec := e.do(other, "PUT", "/api/admin/terms/aup/assignments", `{"populations":["visitor"]}`); rec.Code != http.StatusNotFound {
		t.Errorf("another tenant's document key: %d %s", rec.Code, rec.Body)
	}
	if list := decodeMap(t, e.do(other, "GET", "/api/admin/terms", "")); len(list["documents"].([]any)) != 0 {
		t.Errorf("another tenant sees documents: %v", list)
	}
	if list := decodeMap(t, e.do(other, "GET", "/api/guest-recoveries", "")); len(list["recoveries"].([]any)) != 0 {
		t.Errorf("another tenant sees recoveries: %v", list)
	}
	if e.recoveryCase(guest).Status != store.RecoveryIssued {
		t.Error("another tenant changed the case")
	}
}

// hosted is an authority of the Tessera-hosted credential service.
type hosted struct{ *fakeAuthority }

func (hosted) Kind() string { return "hosted" }

// TestRecoveryCodes: ten single-use codes, shown once, stored only as keyed
// hashes, replaced as a batch.
func TestRecoveryCodes(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	guest := e.claimed("gwen@guest.example")
	other := e.claimed("hank@guest.example")
	now := e.clk.now()
	svc := e.srv.claimSvc
	var codes, again []string
	run := func(fn func(tx *store.TenantTx) error) {
		t.Helper()
		if err := e.db.InTenant(context.Background(), e.tenant, fn); err != nil {
			t.Fatal(err)
		}
	}
	run(func(tx *store.TenantTx) (err error) { codes, err = svc.GenerateRecoveryCodes(tx, guest, now); return })
	re := regexp.MustCompile(`^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`)
	seen := map[string]bool{}
	for _, c := range codes {
		if !re.MatchString(c) || seen[c] {
			t.Errorf("code %q is malformed or repeated", c)
		}
		seen[c] = true
	}
	if len(codes) != 10 {
		t.Fatalf("%d codes", len(codes))
	}
	// only hashes are stored: no code, in either form, is in the table or the ledger
	var stored []*store.RecoveryCode
	run(func(tx *store.TenantTx) (err error) { stored, err = tx.RecoveryCodesFor(guest); return })
	dump, _ := json.Marshal(stored)
	hay := string(dump) + e.auditJSON()
	for _, c := range codes {
		if strings.Contains(hay, c) || strings.Contains(hay, strings.ReplaceAll(c, "-", "")) {
			t.Fatalf("code %q is stored in clear", c)
		}
	}
	for _, s := range stored {
		if len(s.CodeHash) != 64 {
			t.Errorf("hash %q", s.CodeHash)
		}
	}
	use := func(id int64, code string) (ok bool) {
		run(func(tx *store.TenantTx) (err error) { ok, err = svc.UseRecoveryCode(tx, id, code, now); return })
		return ok
	}
	if !use(guest, codes[0]) {
		t.Error("a good code was refused")
	}
	if use(guest, codes[0]) {
		t.Error("a code worked twice")
	}
	if !use(guest, strings.ToLower(strings.ReplaceAll(codes[1], "-", " "))) {
		t.Error("a code typed in lower case with spaces was refused")
	}
	if use(guest, "AAAA-AAAA-AAAA") || use(other, codes[2]) {
		t.Error("a wrong code, or another person's code, worked")
	}
	var live int
	run(func(tx *store.TenantTx) (err error) { live, err = tx.CountLiveRecoveryCodes(guest); return })
	if live != 8 {
		t.Errorf("%d live codes after two uses, want 8", live)
	}
	// a new batch voids the old one
	run(func(tx *store.TenantTx) (err error) {
		again, err = svc.GenerateRecoveryCodes(tx, guest, now.Add(time.Minute))
		return
	})
	if use(guest, codes[3]) {
		t.Error("a code of the voided batch worked")
	}
	if !use(guest, again[0]) {
		t.Error("a code of the new batch was refused")
	}
	run(func(tx *store.TenantTx) (err error) { live, err = tx.CountLiveRecoveryCodes(guest); return })
	if live != 9 {
		t.Errorf("%d live codes, want 9", live)
	}
	if len(e.events("recovery.codes.generate")) != 2 {
		t.Error("the batches are not in the ledger")
	}
	outcomes := map[string]int{}
	for _, ev := range e.events("recovery.code.use") {
		outcomes[ev.Outcome]++
	}
	if outcomes[store.OutcomeSuccess] != 3 || outcomes[store.OutcomeFailure] != 4 {
		t.Errorf("use outcomes = %v", outcomes)
	}
}

// TestRecoveryCodes_API: the hosted guest asks for a batch and sees it once.
func TestRecoveryCodes_API(t *testing.T) {
	e := newClaimEnv(t, claimOpts{})
	guest := e.claimed("gwen@guest.example")
	gl := e.guestLogin(guest)
	if rec := e.do(gl, "POST", "/api/me/recovery-codes", ""); rec.Code != http.StatusConflict {
		t.Errorf("codes for an identity that is not hosted: %d %s", rec.Code, rec.Body)
	}
	e.srv.cfg.Credential = hosted{&fakeAuthority{}}
	rec := e.do(gl, "POST", "/api/me/recovery-codes", "")
	m := decodeMap(t, rec)
	if rec.Code != 200 || len(m["codes"].([]any)) != 10 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("codes: %d %v %v", rec.Code, rec.Header(), rec.Body)
	}
	first := m["codes"].([]any)[0].(string)
	m2 := decodeMap(t, e.do(gl, "POST", "/api/me/recovery-codes", ""))
	if m2["codes"].([]any)[0] == first {
		t.Error("a new batch repeats a code")
	}
	var ok bool
	if err := e.db.InTenant(context.Background(), e.tenant, func(tx *store.TenantTx) (err error) {
		ok, err = e.srv.claimSvc.UseRecoveryCode(tx, guest, first, e.clk.now())
		return
	}); err != nil || ok {
		t.Errorf("a code of the voided batch: %v %v", ok, err)
	}
	if strings.Contains(e.auditJSON(), first) {
		t.Error("a code is in the ledger")
	}
}
