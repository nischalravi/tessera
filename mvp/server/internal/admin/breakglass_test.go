package admin_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Break-glass (design §9.6, §15.4, §19 PR13). The authenticator is a
// software one (softauthn_test.go) that answers the server's WebAuthn
// options with a packed attestation signed by a certificate from a test CA.

const (
	bgRPID   = "localhost"
	bgOrigin = "http://localhost:5173"
)

var (
	modelA = uuid.MustParse("2fc0579f-8113-47ea-b116-bb5a8db9202a")
	modelB = uuid.MustParse("c5ef55ff-ad9a-4b9f-b580-adebafe026d0")
)

// bg is a tenant with two admins (alice requests, bob approves) and a
// security contact, with break-glass configured.
type bg struct {
	*harness
	alice, bob *store.PlatformUser
}

func newBG(t *testing.T) *bg {
	t.Helper()
	h := newHarness(t)
	wa, err := admin.NewWebAuthn(bgRPID, []string{bgOrigin})
	if err != nil {
		t.Fatal(err)
	}
	h.svc.WebAuthn = wa
	as := h.admins("alice", "bob")
	h.contacts("security@acme.example")
	return &bg{harness: h, alice: as[0], bob: as[1]}
}

func (b *bg) soft(model uuid.UUID) *softAuthn { return newSoftAuthn(b.t, bgRPID, bgOrigin, model) }

// enrolment files breakglass.register as alice (payload is its JSON), has bob
// approve it, waits out the cooling-off and applies it. It returns the
// applied request.
func (b *bg) enrolment(payload string) *store.AdminChange {
	b.t.Helper()
	ch := mustSubmit(b.t, b.harness, b.as(b.alice), admin.TypeBGRegister, payload)
	if _, err := b.svc.Approve(b.ctx, b.as(b.bob), ch.ID, ch.PayloadHash); err != nil {
		b.t.Fatal(err)
	}
	b.advance(admin.CoolingOff)
	if applied, failed, err := b.svc.ApplyDue(b.ctx, tenantID); err != nil || applied != 1 || failed != 0 {
		b.t.Fatalf("ApplyDue = %d applied, %d failed, %v", applied, failed, err)
	}
	got := b.change(ch.ID)
	if got.Status != store.ChangeApplied {
		b.t.Fatalf("enrolment is %s (%s)", got.Status, got.Failure)
	}
	return got
}

// register is enrolment followed by alice registering soft's key.
func (b *bg) register(label string, soft *softAuthn) (*store.AdminChange, *store.BreakGlassCredential) {
	b.t.Helper()
	ch := b.enrolment(fmt.Sprintf(`{"label":%q,"custodian":"Ops safe"}`, label))
	return ch, b.finish(ch, soft)
}

func (b *bg) finish(ch *store.AdminChange, soft *softAuthn) *store.BreakGlassCredential {
	b.t.Helper()
	creation, err := b.svc.BeginRegistration(b.ctx, b.as(b.alice), ch.ID)
	if err != nil {
		b.t.Fatal(err)
	}
	cred, err := b.svc.FinishRegistration(b.ctx, b.as(b.alice), ch.ID, soft.Register(creation))
	if err != nil {
		b.t.Fatal(err)
	}
	return cred
}

// options and verify are the two public sign-in calls.
func (b *bg) options() *protocol.CredentialAssertion {
	b.t.Helper()
	a, err := b.svc.BeginAssertion(b.ctx, tenantID)
	if err != nil {
		b.t.Fatal(err)
	}
	return a
}

func (b *bg) signIn(soft *softAuthn) (*admin.SignInResult, error) {
	b.t.Helper()
	return b.svc.SignIn(b.ctx, tenantID, soft.Assert(b.options()), admin.ClientInfo{})
}

func (b *bg) mustSignIn(soft *softAuthn) *admin.SignInResult {
	b.t.Helper()
	res, err := b.signIn(soft)
	if err != nil {
		b.t.Fatal(err)
	}
	return res
}

// authenticator resolves session cookies the way the API does.
func (b *bg) authenticator() *auth.Authenticator {
	return &auth.Authenticator{DB: b.db, Clock: b.clk.now, Cookies: auth.Cookies{}}
}

// authenticate resolves the session of res as a request would.
func (b *bg) authenticate(res *admin.SignInResult) (*auth.Principal, string) {
	b.t.Helper()
	a := b.authenticator()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(a.Cookies.Session(res.Issued.Secret))
	p, reason, err := a.Authenticate(r)
	if err != nil {
		b.t.Fatal(err)
	}
	return p, reason
}

func (b *bg) principal(res *admin.SignInResult) *auth.Principal {
	b.t.Helper()
	p, reason := b.authenticate(res)
	if p == nil {
		b.t.Fatalf("the break-glass session is not valid: %s", reason)
	}
	return p
}

func (b *bg) notifications() []*store.AdminNotification {
	b.t.Helper()
	var ns []*store.AdminNotification
	if err := b.db.ReadTenant(b.ctx, tenantID, func(tx *store.TenantTx) error {
		var err error
		ns, err = tx.AdminNotifications()
		return err
	}); err != nil {
		b.t.Fatal(err)
	}
	return ns
}

func (b *bg) ofKind(kind string) []*store.AdminNotification {
	var out []*store.AdminNotification
	for _, n := range b.notifications() {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	return out
}

func (b *bg) credentials() []*store.BreakGlassCredential {
	b.t.Helper()
	var cs []*store.BreakGlassCredential
	if err := b.db.ReadTenant(b.ctx, tenantID, func(tx *store.TenantTx) error {
		var err error
		cs, err = tx.BreakGlassCredentials()
		return err
	}); err != nil {
		b.t.Fatal(err)
	}
	return cs
}

func (b *bg) has(tenant tenancy.ID, action string) bool {
	return slices.Contains(b.audited(tenant), action)
}

func (b *bg) connection(id uuid.UUID) *store.IdPConnection {
	b.t.Helper()
	var c *store.IdPConnection
	if err := b.db.ReadTenant(b.ctx, tenantID, func(tx *store.TenantTx) error {
		var err error
		c, err = tx.IdPConnection(id)
		return err
	}); err != nil {
		b.t.Fatal(err)
	}
	return c
}

// uses counts the break-glass sign-ins on record.
func (b *bg) uses() int {
	b.t.Helper()
	n := 0
	if err := b.db.ReadTenant(b.ctx, tenantID, func(tx *store.TenantTx) error {
		us, err := tx.RecentBreakGlassUses(b.clk.now().Add(-1000 * time.Hour))
		n = len(us)
		return err
	}); err != nil {
		b.t.Fatal(err)
	}
	return n
}

// rejection is the detail of the latest auth.break_glass.rejected event.
func (b *bg) rejection() map[string]any {
	b.t.Helper()
	var detail map[string]any
	if err := b.db.ReadTenant(b.ctx, tenantID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditLog(-1)
		for _, e := range evs {
			if e.Action == "auth.break_glass.rejected" {
				detail = nil
				if err := json.Unmarshal(e.Detail, &detail); err != nil {
					return err
				}
				if e.Outcome != store.OutcomeFailure {
					b.t.Errorf("a rejection has outcome %s, want failure", e.Outcome)
				}
			}
		}
		return err
	}); err != nil {
		b.t.Fatal(err)
	}
	return detail
}

func TestBreakGlass_EnrolThenSignIn(t *testing.T) {
	b := newBG(t)
	soft := b.soft(modelA)
	ch, cred := b.register("Safe A, key 1", soft)

	// the enrolment created the break-glass user and its role
	var glass *store.PlatformUser
	b.tx(func(tx *store.TenantTx) error {
		var err error
		glass, err = tx.PlatformUser(cred.UserID)
		if err != nil {
			return err
		}
		as, err := tx.RoleAssignments(glass.ID)
		if err != nil || len(as) != 1 || as[0].Role != store.RoleBreakGlass || as[0].Source != store.RoleSourceBreakGlass ||
			as[0].ChangeRequestID == nil || *as[0].ChangeRequestID != ch.ID.String() {
			t.Errorf("roles of the break-glass user: %v %v", as, err)
		}
		return nil
	})
	if !glass.IsBreakGlass || glass.Email != nil || glass.Status != "active" {
		t.Errorf("break-glass user %+v", glass)
	}
	if cred.Label != "Safe A, key 1" || cred.Custodian != "Ops safe" || cred.AAGUID != modelA.String() || cred.BackupEligible ||
		cred.AttestationFormat != "packed" || cred.AttestationTrust != "basic" || cred.SignCount != 0 ||
		!slices.Equal(cred.Transports, []string{"usb"}) || cred.ChangeRequestID != ch.ID {
		t.Errorf("registered key %+v", cred)
	}
	for _, a := range []string{"breakglass.registration.started", "breakglass.registered"} {
		if !b.has(tenantID, a) {
			t.Errorf("no %s audit event: %v", a, b.audited(tenantID))
		}
	}
	if ns := b.ofKind("breakglass.registered"); len(ns) != 3 { // alice, bob, the contact
		t.Errorf("%d breakglass.registered notifications, want 3", len(ns))
	}

	// signing in
	b.advance(time.Hour)
	res := b.mustSignIn(soft)
	now := b.clk.now()
	s := res.Issued.Session
	if s.Kind != store.SessionBreakGlass || s.UserID != glass.ID || !s.AbsoluteExpiresAt.Equal(now.Add(60*time.Minute)) ||
		!s.IdleExpiresAt.Equal(now.Add(15*time.Minute)) {
		t.Errorf("session %+v: want kind break_glass, 15 min idle, 60 min absolute from %s", s, now)
	}
	rec := res.Authn
	if rec.Protocol != "webauthn" || rec.Purpose != "break_glass" || rec.AAL != 3 || !rec.PhishingResistant ||
		rec.PhrBasis != "webauthn_attested" || rec.TesseraACR != string(auth.ACRPhrh) || rec.IdPConnectionID != nil {
		t.Errorf("authentication context %+v", rec)
	}
	p := b.principal(res)
	if !p.ActiveRoles.Has(auth.RoleBreakGlass) || len(p.ActiveRoles) != 1 || len(p.InactiveRoles) != 0 {
		t.Errorf("roles: active %v inactive %v", p.ActiveRoles, p.InactiveRoles)
	}
	perms := auth.EffectivePermissions(p)
	if want := []auth.Permission{auth.PermAuthenticated, auth.PermAdminRead, auth.PermBreakGlassRecover}; len(perms) != len(want) ||
		!perms.Has(auth.PermAdminRead) || !perms.Has(auth.PermBreakGlassRecover) || !perms.Has(auth.PermAuthenticated) {
		t.Errorf("a break-glass session holds %v, want exactly %v", perms.Sorted(), want)
	}
	for _, denied := range []auth.Permission{auth.PermGraphRead, auth.PermAuditRead, auth.PermAdminChangeReq, auth.PermAdminChangeAppr,
		auth.PermGrantsRevoke, auth.PermJITDecide} {
		if perms.Has(denied) {
			t.Errorf("a break-glass session holds %s", denied)
		}
	}

	// audit events: in the tenant's chain and on the platform's
	if !b.has(tenantID, "auth.break_glass.used") || !b.has(tenancy.Platform, "auth.break_glass.used") {
		t.Errorf("auth.break_glass.used: tenant %v, platform %v", b.audited(tenantID), b.audited(tenancy.Platform))
	}
	// a critical notification to every admin, every contact and the operators
	used := b.ofKind(admin.KindBreakGlassUsed)
	got := map[string]bool{}
	for _, n := range used {
		got[n.RecipientType] = true
		if admin.NotificationSeverity(n.Kind) != "critical" || !strings.Contains(n.Subject, "CRITICAL") {
			t.Errorf("notification %q is not critical", n.Subject)
		}
	}
	if len(used) != 4 || !got[store.NotifyAdmin] || !got[store.NotifyContact] || !got[store.NotifyOperator] {
		t.Errorf("%d break-glass notifications %v, want alice, bob, the contact and %s", len(used), got, admin.SecurityOperations)
	}
	for _, n := range used {
		if n.RecipientType == store.NotifyOperator && n.RecipientAddress != admin.SecurityOperations {
			t.Errorf("operator recipient %q", n.RecipientAddress)
		}
	}
	// the key remembers the use; the use waits for its explanation
	if cs := b.credentials(); len(cs) != 1 || cs[0].SignCount != 1 || cs[0].LastUsedAt == nil || !cs[0].LastUsedAt.Equal(now) {
		t.Errorf("key after use: %+v", cs)
	}
	b.tx(func(tx *store.TenantTx) error {
		us, err := tx.RecentBreakGlassUses(now.Add(-time.Hour))
		if err != nil || len(us) != 1 || us[0].SessionID != s.ID || us[0].CredentialID != cred.ID || us[0].AnsweredAt != nil {
			t.Errorf("uses: %+v %v", us, err)
		}
		return nil
	})
}

// TestBreakGlass_RegistrationRefused: the §15.4 registration policy. Each
// case is refused with its code, stores no key, spends the challenge and is
// audited as breakglass.registration.rejected.
func TestBreakGlass_RegistrationRefused(t *testing.T) {
	for _, tc := range []struct {
		name      string
		allowlist []uuid.UUID
		tweak     func(*softAuthn)
		code      string
	}{
		{"backup-eligible flag set", nil, func(a *softAuthn) { a.backupEligible = true }, "backup_eligible_refused"},
		{"backup-eligible and backed up (a synced passkey)", nil, func(a *softAuthn) { a.backupEligible, a.backupState = true, true },
			"backup_eligible_refused"},
		{"none attestation", nil, func(a *softAuthn) { a.format = "none" }, "attestation_none_refused"},
		{"self attestation", nil, func(a *softAuthn) { a.format = "self" }, "attestation_self_refused"},
		{"AAGUID not in the allowlist", []uuid.UUID{modelB}, func(*softAuthn) {}, "aaguid_not_allowed"},
		{"no user verification", nil, func(a *softAuthn) { a.noUV = true }, "webauthn_verification_failed"},
		{"wrong origin", nil, func(a *softAuthn) { a.origin = "https://evil.example" }, "webauthn_verification_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBG(t)
			if len(tc.allowlist) > 0 {
				// through the settings change, which is how the allowlist is set
				ids := make([]string, len(tc.allowlist))
				for i, id := range tc.allowlist {
					ids[i] = fmt.Sprintf("%q", id.String())
				}
				ch := mustSubmit(t, b.harness, b.as(b.alice), admin.TypeTenantSettings,
					`{"breakglass_aaguid_allowlist":[`+strings.Join(ids, ",")+`]}`)
				if got := b.change(ch.ID); got.Status != store.ChangeApplied || got.TwoPerson {
					t.Fatalf("narrowing the allowlist is %s (two-person %v), want applied at once", got.Status, got.TwoPerson)
				}
			}
			ch := b.enrolment(`{"label":"Safe A, key 1","custodian":"Ops safe"}`)
			soft := b.soft(modelA)
			tc.tweak(soft)
			creation, err := b.svc.BeginRegistration(b.ctx, b.as(b.alice), ch.ID)
			if err != nil {
				t.Fatal(err)
			}
			body := soft.Register(creation)
			_, err = b.svc.FinishRegistration(b.ctx, b.as(b.alice), ch.ID, body)
			wantErr(t, err, http.StatusUnprocessableEntity, tc.code)
			if cs := b.credentials(); len(cs) != 0 {
				t.Errorf("a refused key was stored: %+v", cs)
			}
			if !b.has(tenantID, "breakglass.registration.rejected") || b.has(tenantID, "breakglass.registered") {
				t.Errorf("audit: %v", b.audited(tenantID))
			}
			// the challenge is spent: the same response cannot be tried again
			_, err = b.svc.FinishRegistration(b.ctx, b.as(b.alice), ch.ID, body)
			wantErr(t, err, http.StatusBadRequest, "challenge_invalid")
			// and nobody can sign in with it
			_, err = b.svc.BeginAssertion(b.ctx, tenantID)
			wantErr(t, err, http.StatusNotFound, "break_glass_unavailable")
		})
	}
}

// TestBreakGlass_RegistrationAcceptedWithAllowlist: a model on the list is
// accepted, with the allowlist set by a settings change.
func TestBreakGlass_RegistrationAcceptedWithAllowlist(t *testing.T) {
	b := newBG(t)
	mustSubmit(t, b.harness, b.as(b.alice), admin.TypeTenantSettings,
		`{"breakglass_aaguid_allowlist":["`+strings.ToUpper(modelA.String())+`","`+modelB.String()+`"]}`)
	var allow []string
	b.tx(func(tx *store.TenantTx) error {
		tr, err := tx.TenantRecord()
		allow = admin.AAGUIDAllowlist(tr)
		return err
	})
	if want := []string{modelA.String(), modelB.String()}; !slices.Equal(allow, want) {
		t.Fatalf("allowlist %v, want %v normalized and sorted", allow, want)
	}
	if _, cred := b.register("Safe A, key 1", b.soft(modelA)); cred.AAGUID != modelA.String() {
		t.Errorf("registered %+v", cred)
	}
}

// TestBreakGlass_AllowlistSetting: breakglass_aaguid_allowlist is accepted by
// tenant.settings.update; narrowing it is one admin and immediate, widening
// it (more models, or none at all) is two people and 24 h.
func TestBreakGlass_AllowlistSetting(t *testing.T) {
	b := newBG(t)
	a, c := modelA.String(), modelB.String()
	set := func(list string) *store.AdminChange {
		return mustSubmit(t, b.harness, b.as(b.alice), admin.TypeTenantSettings, `{"breakglass_aaguid_allowlist":`+list+`}`)
	}
	if ch := set(`["` + a + `"]`); !(ch.Status == store.ChangeApplied && !ch.TwoPerson) {
		t.Errorf("any model -> one model: %s two-person=%v, want applied at once", ch.Status, ch.TwoPerson)
	}
	if ch := set(`["` + a + `","` + c + `"]`); ch.Status != store.ChangePendingApproval || !ch.TwoPerson ||
		ch.CoolingOffSeconds != int64(admin.CoolingOff/time.Second) {
		t.Errorf("adding a model: %s two-person=%v cooling=%d, want two people and 24 h", ch.Status, ch.TwoPerson, ch.CoolingOffSeconds)
	}
	if ch := set(`[]`); !ch.TwoPerson {
		t.Errorf("lifting the limit is not two-person")
	}
	// the same list again changes nothing
	_, err := b.submit(b.as(b.alice), admin.TypeTenantSettings, `{"breakglass_aaguid_allowlist":["`+strings.ToUpper(a)+`"]}`)
	wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
	many := make([]string, 51)
	for i := range many {
		many[i] = `"` + uuid.NewString() + `"`
	}
	for name, list := range map[string]string{"not a uuid": `["nope"]`, "braces": `["{` + a + `}"]`, "number": `[1]`,
		"no dashes": `["2fc0579f811347eab116bb5a8db9202a"]`, "too many": "[" + strings.Join(many, ",") + "]"} {
		_, err := b.submit(b.as(b.alice), admin.TypeTenantSettings, `{"breakglass_aaguid_allowlist":`+list+`}`)
		wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
		_ = name
	}
}

// refusalEnv is a registered key and the sign-ins that succeeded before a
// refusal.
type refusalEnv struct {
	b       *bg
	soft    *softAuthn
	signIns int
}

// good signs in successfully.
func (e *refusalEnv) good() {
	e.b.mustSignIn(e.soft)
	e.signIns++
}

// TestBreakGlass_SignInRefused: a refused sign-in gives the caller only
// 401 break_glass_failed; the reason is in the auth.break_glass.rejected
// event and no session exists.
func TestBreakGlass_SignInRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason string
		run    func(e *refusalEnv) error
	}{
		{"sign-count regression", "sign_count_regression", func(e *refusalEnv) error {
			e.good() // count 1
			e.good() // count 2
			_, err := e.b.svc.SignIn(e.b.ctx, tenantID, e.soft.AssertWithCount(e.b.options(), 2), admin.ClientInfo{})
			return err
		}},
		{"sign count falls back to the first", "sign_count_regression", func(e *refusalEnv) error {
			e.good()
			_, err := e.b.svc.SignIn(e.b.ctx, tenantID, e.soft.AssertWithCount(e.b.options(), 1), admin.ClientInfo{})
			return err
		}},
		{"a counter that was running goes back to zero", "sign_count_regression", func(e *refusalEnv) error {
			e.good()
			_, err := e.b.svc.SignIn(e.b.ctx, tenantID, e.soft.AssertWithCount(e.b.options(), 0), admin.ClientInfo{})
			return err
		}},
		{"backup-eligible flag set", "backup_eligible", func(e *refusalEnv) error {
			e.soft.backupEligible = true
			_, err := e.b.signIn(e.soft)
			return err
		}},
		{"no user verification", "assertion_invalid", func(e *refusalEnv) error {
			e.soft.noUV = true
			_, err := e.b.signIn(e.soft)
			return err
		}},
		{"wrong origin", "assertion_invalid", func(e *refusalEnv) error {
			e.soft.origin = "https://evil.example"
			_, err := e.b.signIn(e.soft)
			return err
		}},
		{"replayed response", "challenge_expired_or_used", func(e *refusalEnv) error {
			body := e.soft.Assert(e.b.options())
			if _, err := e.b.svc.SignIn(e.b.ctx, tenantID, body, admin.ClientInfo{}); err != nil {
				e.b.t.Fatal(err)
			}
			e.signIns++
			_, err := e.b.svc.SignIn(e.b.ctx, tenantID, body, admin.ClientInfo{})
			return err
		}},
		{"expired challenge", "challenge_expired_or_used", func(e *refusalEnv) error {
			body := e.soft.Assert(e.b.options())
			e.b.advance(admin.CeremonyTTL + time.Second)
			_, err := e.b.svc.SignIn(e.b.ctx, tenantID, body, admin.ClientInfo{})
			return err
		}},
		{"challenge that was never issued", "unknown_challenge", func(e *refusalEnv) error {
			a := e.b.options()
			a.Response.Challenge = protocol.URLEncodedBase64(make([]byte, 32))
			_, err := e.b.svc.SignIn(e.b.ctx, tenantID, e.soft.Assert(a), admin.ClientInfo{})
			return err
		}},
		{"a key that is not registered", "unknown_credential", func(e *refusalEnv) error {
			_, err := e.b.signIn(e.b.soft(modelA))
			return err
		}},
		{"not a WebAuthn response", "malformed_response", func(e *refusalEnv) error {
			_, err := e.b.svc.SignIn(e.b.ctx, tenantID, []byte(`{"id":"x"}`), admin.ClientInfo{})
			return err
		}},
		{"a key revoked after the options were issued", "unknown_credential", func(e *refusalEnv) error {
			body := e.soft.Assert(e.b.options())
			var id uuid.UUID
			e.b.tx(func(tx *store.TenantTx) error {
				cs, err := tx.BreakGlassCredentials()
				id = cs[0].ID
				return err
			})
			mustSubmit(e.b.t, e.b.harness, e.b.as(e.b.alice), admin.TypeBGRevoke, `{"credential_id":"`+id.String()+`"}`)
			_, err := e.b.svc.SignIn(e.b.ctx, tenantID, body, admin.ClientInfo{})
			return err
		}},
		{"a break-glass user who was disabled", "user_not_eligible", func(e *refusalEnv) error {
			body := e.soft.Assert(e.b.options())
			e.b.tx(func(tx *store.TenantTx) error {
				cs, err := tx.BreakGlassCredentials()
				if err != nil {
					return err
				}
				return tx.DisableUser(cs[0].UserID, "left the company", e.b.clk.now())
			})
			_, err := e.b.svc.SignIn(e.b.ctx, tenantID, body, admin.ClientInfo{})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBG(t)
			soft := b.soft(modelA)
			b.register("Safe A, key 1", soft)
			e := &refusalEnv{b: b, soft: soft}
			err := tc.run(e)
			wantErr(t, err, http.StatusUnauthorized, "break_glass_failed")
			if d := b.rejection(); d == nil || d["reason"] != tc.reason {
				t.Errorf("rejection detail %v, want reason %s", d, tc.reason)
			}
			if !b.has(tenantID, "auth.break_glass.rejected") {
				t.Errorf("audit: %v", b.audited(tenantID))
			}
			// a refused response never made a session: the only uses are the earlier successes
			if n := b.uses(); n != e.signIns {
				t.Errorf("%d break-glass uses recorded, want the %d that succeeded", n, e.signIns)
			}
			cloned := len(b.ofKind(admin.KindBreakGlassCloned)) > 0
			if cloned != (tc.reason == "sign_count_regression") {
				t.Errorf("clone notification sent=%v for %s", cloned, tc.reason)
			}
		})
	}
}

// TestBreakGlass_SignCountRegressionNeverMovesTheCount: a cloned key's
// attempt leaves the stored count alone, tells everyone, and the real key
// (with a higher count) still works.
func TestBreakGlass_SignCountRegressionNeverMovesTheCount(t *testing.T) {
	b := newBG(t)
	soft := b.soft(modelA)
	b.register("Safe A, key 1", soft)
	soft.counter = 9
	b.mustSignIn(soft) // count 10
	if _, err := b.svc.SignIn(b.ctx, tenantID, soft.AssertWithCount(b.options(), 4), admin.ClientInfo{}); err == nil {
		t.Fatal("a count of 4 after 10 was accepted")
	}
	if cs := b.credentials(); cs[0].SignCount != 10 {
		t.Errorf("stored count %d, want 10", cs[0].SignCount)
	}
	ns := b.ofKind(admin.KindBreakGlassCloned)
	if len(ns) != 4 || admin.NotificationSeverity(admin.KindBreakGlassCloned) != "critical" {
		t.Errorf("%d clone notifications, want 4 critical", len(ns))
	}
	if _, err := b.svc.SignIn(b.ctx, tenantID, soft.AssertWithCount(b.options(), 11), admin.ClientInfo{}); err != nil {
		t.Errorf("the real key after the refused attempt: %v", err)
	}
}

// TestBreakGlass_KeyWithoutCounter: an authenticator whose count is always 0
// signs in (some FIDO keys keep no counter).
func TestBreakGlass_KeyWithoutCounter(t *testing.T) {
	b := newBG(t)
	soft := b.soft(modelA)
	b.register("Safe A, key 1", soft)
	for i := 0; i < 2; i++ {
		if _, err := b.svc.SignIn(b.ctx, tenantID, soft.AssertWithCount(b.options(), 0), admin.ClientInfo{}); err != nil {
			t.Fatalf("sign-in %d with a counterless key: %v", i+1, err)
		}
	}
}

// TestBreakGlass_UserHandle: a resident key returns the user handle; it must
// be the break-glass user's own, and a different one is refused.
func TestBreakGlass_UserHandle(t *testing.T) {
	b := newBG(t)
	soft := b.soft(modelA)
	_, cred := b.register("Safe A, key 1", soft)
	soft.userHandle = cred.UserID[:]
	b.mustSignIn(soft)
	other := uuid.New()
	soft.userHandle = other[:]
	_, err := b.signIn(soft)
	wantErr(t, err, http.StatusUnauthorized, "break_glass_failed")
	if d := b.rejection(); d["reason"] != "assertion_invalid" {
		t.Errorf("rejection %v", d)
	}
}

// TestBreakGlass_SessionExpires: 60 minutes absolute (however active) and 15
// minutes idle.
func TestBreakGlass_SessionExpires(t *testing.T) {
	t.Run("60 minutes absolute", func(t *testing.T) {
		b := newBG(t)
		soft := b.soft(modelA)
		b.register("Safe A, key 1", soft)
		res := b.mustSignIn(soft)
		for _, min := range []int{14, 28, 42, 56, 59} { // always active within the idle window
			b.clk.t = res.Issued.Session.CreatedAt.Add(time.Duration(min) * time.Minute)
			if p, reason := b.authenticate(res); p == nil {
				t.Fatalf("the session ended %d minutes in: %s", min, reason)
			}
		}
		b.clk.t = res.Issued.Session.CreatedAt.Add(60 * time.Minute)
		if p, reason := b.authenticate(res); p != nil || reason != auth.FailExpired {
			t.Errorf("at 60 minutes: principal %v reason %q, want %s", p, reason, auth.FailExpired)
		}
		b.clk.t = res.Issued.Session.CreatedAt.Add(61 * time.Minute)
		if p, reason := b.authenticate(res); p != nil {
			t.Errorf("a session of 61 minutes is valid (%s)", reason)
		}
		if s := b.session(res.Issued.Session.ID); s.Status == store.SessionActive {
			t.Errorf("the expired session is still %s", s.Status)
		}
	})
	t.Run("15 minutes idle", func(t *testing.T) {
		b := newBG(t)
		soft := b.soft(modelA)
		b.register("Safe A, key 1", soft)
		res := b.mustSignIn(soft)
		b.clk.t = res.Issued.Session.CreatedAt.Add(14 * time.Minute)
		if p, reason := b.authenticate(res); p == nil {
			t.Fatalf("the session ended after 14 idle minutes: %s", reason)
		}
		b.clk.t = res.Issued.Session.CreatedAt.Add(14*time.Minute + 15*time.Minute + time.Second)
		if p, reason := b.authenticate(res); p != nil || reason != auth.FailExpired {
			t.Errorf("after 15 idle minutes: principal %v reason %q", p, reason)
		}
	})
}

// TestBreakGlass_Actions: what a break-glass session may do (§15.4), and
// nothing else.
func TestBreakGlass_Actions(t *testing.T) {
	b := newBG(t)
	soft := b.soft(modelA)
	b.register("Safe A, key 1", soft)
	okta, entra := b.oidcConnection("okta"), b.oidcConnection("entra")
	carol := b.user("carol", store.RoleViewer)
	res := b.mustSignIn(soft)
	p := b.principal(res)
	act := func(action, payload string) (*admin.ActionResult, error) {
		return b.svc.BreakGlassAction(b.ctx, p, action, json.RawMessage(payload))
	}

	t.Run("disable a connection, with a one hour cooling-off and no approver", func(t *testing.T) {
		r, err := act(admin.ActionIdPDisable, `{"connection_id":"`+okta.ID.String()+`"}`)
		if err != nil {
			t.Fatal(err)
		}
		ch := b.change(r.Change.ID)
		if ch.Status != store.ChangeCoolingOff || ch.TwoPerson || ch.ApprovedBy != nil || ch.CoolingOffSeconds != 3600 ||
			ch.RequestedBy != res.User.ID || ch.Type != admin.TypeIdPDisable || ch.EffectiveAt == nil ||
			!ch.EffectiveAt.Equal(b.clk.now().Add(time.Hour)) {
			t.Errorf("request %+v", ch)
		}
		if !b.has(tenantID, "breakglass.action") || !b.has(tenantID, "admin.change.submitted") {
			t.Errorf("audit: %v", b.audited(tenantID))
		}
		ns := b.ofKind(admin.KindBreakGlassAction)
		if len(ns) != 4 || admin.NotificationSeverity(ns[0].Kind) != "critical" {
			t.Errorf("%d breakglass.action notifications, want 4 critical (alice, bob, the contact, operators)", len(ns))
		}
		// nothing happens early; an admin can cancel it
		_, err = b.svc.Apply(b.ctx, b.as(b.alice), ch.ID)
		wantErr(t, err, http.StatusConflict, "cooling_off_active")
		if c := b.connection(okta.ID); c.Status != "active" {
			t.Errorf("connection is %s before the cooling-off ended", c.Status)
		}
		if _, err := b.svc.Cancel(b.ctx, b.as(b.bob), ch.ID); err != nil {
			t.Fatal(err)
		}
		// filed again, it is applied by the sweeper after the hour
		r, err = act(admin.ActionIdPDisable, `{"connection_id":"`+okta.ID.String()+`"}`)
		if err != nil {
			t.Fatal(err)
		}
		b.advance(59 * time.Minute)
		if applied, _, _ := b.svc.ApplyDue(b.ctx, tenantID); applied != 0 {
			t.Error("applied before the hour was up")
		}
		b.advance(time.Minute)
		if applied, failed, err := b.svc.ApplyDue(b.ctx, tenantID); applied != 1 || failed != 0 || err != nil {
			t.Fatalf("ApplyDue = %d %d %v", applied, failed, err)
		}
		if c := b.connection(okta.ID); c.Status != "disabled" {
			t.Errorf("connection is %s after the cooling-off", c.Status)
		}
	})

	t.Run("change a connection's trust", func(t *testing.T) {
		r, err := act(admin.ActionIdPUpdateTrust, `{"connection_id":"`+entra.ID.String()+`","assume_phishing_resistant":false}`)
		if err != nil {
			t.Fatal(err)
		}
		if ch := b.change(r.Change.ID); ch.TwoPerson || ch.CoolingOffSeconds != 3600 || ch.Status != store.ChangeCoolingOff {
			t.Errorf("request %+v", ch)
		}
		_, err = act(admin.ActionIdPUpdateTrust, `{"connection_id":"`+entra.ID.String()+`","issuer":"not a url"}`)
		wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
	})

	t.Run("grant tenant_admin to a named user, and nothing else", func(t *testing.T) {
		r, err := act(admin.ActionGrantTenantAdmin, grant(carol, "tenant_admin"))
		if err != nil {
			t.Fatal(err)
		}
		if ch := b.change(r.Change.ID); ch.TwoPerson || ch.CoolingOffSeconds != 3600 || ch.Status != store.ChangeCoolingOff {
			t.Errorf("request %+v", ch)
		}
		if slices.Contains(b.roles(carol), "tenant_admin") {
			t.Error("the grant took effect before its cooling-off")
		}
		b.advance(time.Hour)
		if applied, _, _ := b.svc.ApplyDue(b.ctx, tenantID); applied != 2 { // the trust change is due too
			t.Errorf("applied %d, want the trust change and the grant", applied)
		}
		if !slices.Contains(b.roles(carol), "tenant_admin") {
			t.Error("the grant was not applied after its cooling-off")
		}
		for _, role := range []string{"policy_admin", "viewer", "break_glass", "operator"} {
			_, err := act(admin.ActionGrantTenantAdmin, grant(carol, role))
			wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
		}
		_, err = act(admin.ActionGrantTenantAdmin, `{"user_id":"`+uuid.NewString()+`","role":"tenant_admin"}`)
		wantErr(t, err, http.StatusNotFound, "not_found")
		_, err = act(admin.ActionGrantTenantAdmin, `{"user_id":"`+res.User.ID.String()+`","role":"tenant_admin"}`)
		wantErr(t, err, http.StatusConflict, "break_glass_user")
	})

	t.Run("revoke every other session", func(t *testing.T) {
		other := b.signedInVia(b.alice, nil)
		other2 := b.signedInVia(carol, nil)
		r, err := act(admin.ActionRevokeAllSessions, ``)
		if err != nil {
			t.Fatal(err)
		}
		if r.RevokedSessions < 2 || r.Change != nil {
			t.Errorf("result %+v", r)
		}
		for _, id := range []uuid.UUID{other, other2} {
			if s := b.session(id); s.Status != store.SessionRevoked || s.RevokedReason == nil || *s.RevokedReason != auth.RevokedBreakGlass {
				t.Errorf("session %s is %s", id, s.Status)
			}
		}
		if s := b.session(res.Issued.Session.ID); s.Status != store.SessionActive {
			t.Errorf("the break-glass session is %s: it must survive its own revoke-all", s.Status)
		}
		_, err = act(admin.ActionRevokeAllSessions, `{"all":true}`)
		wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
		if _, err := act(admin.ActionRevokeAllSessions, `{}`); err != nil {
			t.Errorf("an empty object payload: %v", err)
		}
		if ns := b.ofKind(admin.KindBreakGlassAction); len(ns) == 0 {
			t.Error("no break-glass action notification")
		}
	})

	t.Run("only those actions", func(t *testing.T) {
		for _, a := range []string{"idp_connection.create", "role.revoke", "tenant.settings.update", "breakglass.register", "users.disable", ""} {
			_, err := act(a, `{}`)
			wantErr(t, err, http.StatusNotFound, "unknown_action")
		}
		_, err := act(admin.ActionIdPDisable, ``)
		wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
		_, err = act(admin.ActionIdPDisable, `{"connection_id":"`+entra.ID.String()+`","extra":1}`)
		wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
	})

	t.Run("not for anyone else", func(t *testing.T) {
		_, err := b.svc.BreakGlassAction(b.ctx, nil, admin.ActionRevokeAllSessions, nil)
		wantErr(t, err, http.StatusUnauthorized, "login_required")
		_, err = b.svc.BreakGlassAction(b.ctx, b.as(b.alice), admin.ActionRevokeAllSessions, nil)
		wantErr(t, err, http.StatusForbidden, "forbidden")
		// a break_glass role that an IdP sign-in could not activate
		fake := b.as(b.alice)
		fake.AssignedRoles = auth.RoleSet{auth.RoleBreakGlass: true}
		_, err = b.svc.BreakGlassAction(b.ctx, fake, admin.ActionRevokeAllSessions, nil)
		wantErr(t, err, http.StatusForbidden, "role_inactive")
		// an active role without a WebAuthn context is not a break-glass session either
		fake.ActiveRoles = auth.RoleSet{auth.RoleBreakGlass: true}
		_, err = b.svc.BreakGlassAction(b.ctx, fake, admin.ActionRevokeAllSessions, nil)
		wantErr(t, err, http.StatusForbidden, "forbidden")
	})
}

// TestBreakGlass_AttestUse: "why was break-glass used" (§15.4): any tenant
// admin answers once; the break-glass session cannot answer for itself.
func TestBreakGlass_AttestUse(t *testing.T) {
	b := newBG(t)
	soft := b.soft(modelA)
	b.register("Safe A, key 1", soft)
	res := b.mustSignIn(soft)
	var use *store.BreakGlassUse
	b.tx(func(tx *store.TenantTx) error {
		us, err := tx.RecentBreakGlassUses(b.clk.now().Add(-time.Hour))
		use = us[0]
		return err
	})
	_, err := b.svc.AttestUse(b.ctx, b.principal(res), use.ID, "I wanted to look around, honest")
	wantErr(t, err, http.StatusForbidden, "forbidden")
	_, err = b.svc.AttestUse(b.ctx, b.as(b.alice), use.ID, "too short")
	wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
	_, err = b.svc.AttestUse(b.ctx, b.as(b.alice), uuid.New(), "Okta outage, ticket INC-4821")
	wantErr(t, err, http.StatusNotFound, "not_found")
	got, err := b.svc.AttestUse(b.ctx, b.as(b.alice), use.ID, "  Okta outage, ticket INC-4821  ")
	if err != nil {
		t.Fatal(err)
	}
	if got.AnsweredAt == nil || got.AnsweredBy == nil || *got.AnsweredBy != b.alice.ID || got.Reason == nil ||
		*got.Reason != "Okta outage, ticket INC-4821" {
		t.Errorf("answered use %+v", got)
	}
	if !b.has(tenantID, "breakglass.use.attested") {
		t.Errorf("audit: %v", b.audited(tenantID))
	}
	_, err = b.svc.AttestUse(b.ctx, b.as(b.bob), use.ID, "Okta outage, ticket INC-4821 again")
	wantErr(t, err, http.StatusConflict, "already_attested")
	// a viewer cannot
	viewer := b.user("vera", store.RoleViewer)
	_, err = b.svc.AttestUse(b.ctx, b.as(viewer), use.ID, "Okta outage, ticket INC-4821")
	wantErr(t, err, http.StatusForbidden, "forbidden")
}

// TestBreakGlass_RevokeKey: breakglass.revoke is one admin and immediate; it
// ends the sessions the key signed in and removes the key from the options.
func TestBreakGlass_RevokeKey(t *testing.T) {
	b := newBG(t)
	soft := b.soft(modelA)
	_, cred := b.register("Safe A, key 1", soft)
	res := b.mustSignIn(soft)
	ch := mustSubmit(t, b.harness, b.as(b.bob), admin.TypeBGRevoke, `{"credential_id":"`+cred.ID.String()+`"}`)
	if got := b.change(ch.ID); got.Status != store.ChangeApplied || got.TwoPerson {
		t.Errorf("revocation is %s (two-person %v), want applied at once by one admin", got.Status, got.TwoPerson)
	}
	if cs := b.credentials(); cs[0].RevokedAt == nil {
		t.Error("the key is not revoked")
	}
	if s := b.session(res.Issued.Session.ID); s.Status != store.SessionRevoked || s.RevokedReason == nil ||
		*s.RevokedReason != auth.RevokedBreakGlassKey {
		t.Errorf("the key's session is %s", s.Status)
	}
	if p, _ := b.authenticate(res); p != nil {
		t.Error("the revoked key's session still authenticates")
	}
	_, err := b.svc.BeginAssertion(b.ctx, tenantID)
	wantErr(t, err, http.StatusNotFound, "break_glass_unavailable")
	_, err = b.submit(b.as(b.alice), admin.TypeBGRevoke, `{"credential_id":"`+cred.ID.String()+`"}`)
	wantErr(t, err, http.StatusConflict, "already_revoked")
	_, err = b.submit(b.as(b.alice), admin.TypeBGRevoke, `{"credential_id":"`+uuid.NewString()+`"}`)
	wantErr(t, err, http.StatusNotFound, "not_found")
	if !b.has(tenantID, "admin.change.applied") {
		t.Errorf("audit: %v", b.audited(tenantID))
	}
}

// TestBreakGlass_RegistrationGuards: who may register a key, and when.
func TestBreakGlass_RegistrationGuards(t *testing.T) {
	b := newBG(t)
	payload := `{"label":"Safe A, key 1","custodian":"Ops safe"}`
	ch := mustSubmit(t, b.harness, b.as(b.alice), admin.TypeBGRegister, payload)
	ch2 := mustSubmit(t, b.harness, b.as(b.alice), admin.TypeBGRegister, `{"label":"Safe B, key 1","custodian":"Ops safe"}`)
	// not yet applied
	_, err := b.svc.BeginRegistration(b.ctx, b.as(b.alice), ch.ID)
	wantErr(t, err, http.StatusConflict, "registration_not_open")
	for _, c := range []*store.AdminChange{ch, ch2} {
		if _, err := b.svc.Approve(b.ctx, b.as(b.bob), c.ID, c.PayloadHash); err != nil {
			t.Fatal(err)
		}
	}
	b.advance(admin.CoolingOff)
	if applied, _, err := b.svc.ApplyDue(b.ctx, tenantID); applied != 2 || err != nil {
		t.Fatal(applied, err)
	}
	// only the requester, with a fresh step-up
	_, err = b.svc.BeginRegistration(b.ctx, b.as(b.bob), ch.ID)
	wantErr(t, err, http.StatusForbidden, "registration_requester_only")
	_, err = b.svc.BeginRegistration(b.ctx, b.asAged(b.alice, 10*time.Minute), ch.ID)
	wantStepUp(t, err)
	_, err = b.svc.FinishRegistration(b.ctx, b.asAged(b.alice, 10*time.Minute), ch.ID, []byte(`{}`))
	wantStepUp(t, err)
	viewer := b.user("vera", store.RoleViewer)
	_, err = b.svc.BeginRegistration(b.ctx, b.as(viewer), ch.ID)
	wantErr(t, err, http.StatusForbidden, "forbidden")
	// a request of another type, and an unknown one
	other := mustSubmit(t, b.harness, b.as(b.alice), admin.TypeTenantSettings, `{"device_grant_enabled":false}`)
	_, err = b.svc.BeginRegistration(b.ctx, b.as(b.alice), other.ID)
	wantErr(t, err, http.StatusNotFound, "not_found")
	_, err = b.svc.BeginRegistration(b.ctx, b.as(b.alice), uuid.New())
	wantErr(t, err, http.StatusNotFound, "not_found")
	// the response must answer this request's challenge: another enrolment's is refused
	creation, err := b.svc.BeginRegistration(b.ctx, b.as(b.alice), ch.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.svc.FinishRegistration(b.ctx, b.as(b.alice), ch2.ID, b.soft(modelA).Register(creation))
	wantErr(t, err, http.StatusBadRequest, "challenge_invalid")
	// garbage
	_, err = b.svc.FinishRegistration(b.ctx, b.as(b.alice), ch.ID, []byte(`not json`))
	wantErr(t, err, http.StatusBadRequest, "invalid_credential")
	// the key registers once; a second response for the same request is refused
	// (the first request was applied 24 h ago + a bit: its window is checked below)
	soft := b.soft(modelA)
	creation, err = b.svc.BeginRegistration(b.ctx, b.as(b.alice), ch2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.svc.FinishRegistration(b.ctx, b.as(b.alice), ch2.ID, soft.Register(creation)); err != nil {
		t.Fatal(err)
	}
	_, err = b.svc.BeginRegistration(b.ctx, b.as(b.alice), ch2.ID)
	wantErr(t, err, http.StatusConflict, "already_registered")
	// the window of the first request closes 24 h after it was applied
	b.advance(admin.RegistrationWindow)
	_, err = b.svc.BeginRegistration(b.ctx, b.as(b.alice), ch.ID)
	wantErr(t, err, http.StatusConflict, "registration_window_closed")
}

// TestBreakGlass_SecondKey: a second enrolment for an existing break-glass
// user adds a second key (different custodian); both sign in, and the
// per-user limit holds.
func TestBreakGlass_SecondKey(t *testing.T) {
	b := newBG(t)
	soft1, soft2 := b.soft(modelA), b.soft(modelB)
	_, first := b.register("Safe A, key 1", soft1)
	ch := b.enrolment(fmt.Sprintf(`{"user_id":%q,"label":"Safe B, key 2","custodian":"Other site"}`, first.UserID))
	second := b.finish(ch, soft2)
	if second.UserID != first.UserID || second.AAGUID != modelB.String() {
		t.Errorf("second key %+v", second)
	}
	b.mustSignIn(soft1)
	b.mustSignIn(soft2)
	// another user's key: a regular user is not a break-glass user
	_, err := b.submit(b.as(b.alice), admin.TypeBGRegister, fmt.Sprintf(`{"user_id":%q,"label":"x","custodian":"y"}`, b.bob.ID))
	wantErr(t, err, http.StatusConflict, "not_break_glass_user")
	for _, bad := range []string{`{"label":"","custodian":"Ops"}`, `{"label":"x","custodian":""}`, `{"label":"x\u0007","custodian":"Ops"}`,
		`{"label":"` + strings.Repeat("l", 101) + `","custodian":"Ops"}`, `{"label":"x","custodian":"Ops","extra":true}`} {
		_, err := b.submit(b.as(b.alice), admin.TypeBGRegister, bad)
		wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
	}
	// the enrolment is two-person with a 24 h cooling-off, like any admin-role change
	ch2 := mustSubmit(t, b.harness, b.as(b.alice), admin.TypeBGRegister, `{"label":"x","custodian":"y"}`)
	if !ch2.TwoPerson || ch2.CoolingOffSeconds != int64(admin.CoolingOff/time.Second) || ch2.Status != store.ChangePendingApproval {
		t.Errorf("enrolment request %+v", ch2)
	}
	_, err = b.svc.Approve(b.ctx, b.as(b.alice), ch2.ID, ch2.PayloadHash)
	wantErr(t, err, http.StatusForbidden, "self_approval_refused")
}

// TestBreakGlass_Unavailable: without a relying party the ceremonies answer
// 503, and a tenant with no key answers 404, so nobody learns more.
func TestBreakGlass_Unavailable(t *testing.T) {
	b := newBG(t)
	_, err := b.svc.BeginAssertion(b.ctx, tenantID)
	wantErr(t, err, http.StatusNotFound, "break_glass_unavailable")
	b.svc.WebAuthn = nil
	_, err = b.svc.BeginAssertion(b.ctx, tenantID)
	wantErr(t, err, http.StatusServiceUnavailable, "break_glass_unavailable")
	_, err = b.svc.SignIn(b.ctx, tenantID, []byte(`{}`), admin.ClientInfo{})
	wantErr(t, err, http.StatusServiceUnavailable, "break_glass_unavailable")
	_, err = b.svc.BeginRegistration(b.ctx, b.as(b.alice), uuid.New())
	wantErr(t, err, http.StatusServiceUnavailable, "break_glass_unavailable")
	if b.svc.Available() {
		t.Error("Available() is true without a relying party")
	}
}

// TestBreakGlass_RolePermissions: the role's permission set is exactly the
// §15.4 one, and it is an admin role (phr floor, never from an IdP group).
func TestBreakGlass_RolePermissions(t *testing.T) {
	got := auth.RolePermissions(auth.RoleBreakGlass)
	if len(got) != 2 || !slices.Contains(got, auth.PermAdminRead) || !slices.Contains(got, auth.PermBreakGlassRecover) {
		t.Errorf("break_glass permissions %v, want admin.read and breakglass.recover only", got)
	}
	if !auth.RoleBreakGlass.IsAdmin() {
		t.Error("break_glass is not an admin role")
	}
	// no other role holds the break-glass permission
	for _, r := range auth.AllRoles() {
		if r != auth.RoleBreakGlass && slices.Contains(auth.RolePermissions(r), auth.PermBreakGlassRecover) {
			t.Errorf("%s holds breakglass.recover", r)
		}
	}
}
