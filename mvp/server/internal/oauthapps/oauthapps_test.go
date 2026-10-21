package oauthapps_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps"
	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps/oauthfake"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func (r *rig) sync(t *testing.T, only ...string) *oauthapps.SyncReport {
	t.Helper()
	rep, err := r.svc.Sync(context.Background(), r.f.DB, r.f.A.ID, "tester", only...)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func (r *rig) read(t *testing.T, fn func(tx *store.TenantTx)) {
	t.Helper()
	if err := r.f.DB.ReadTenant(context.Background(), r.f.A.ID, func(tx *store.TenantTx) error { fn(tx); return nil }); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) app(t *testing.T, provider, clientID string) (app *store.OAuthApp, grants []*store.OAuthGrant) {
	t.Helper()
	r.read(t, func(tx *store.TenantTx) {
		var err error
		if app, err = tx.OAuthAppByKey(provider, clientID); err != nil {
			t.Fatalf("app %s/%s: %v", provider, clientID, err)
		}
		if grants, err = tx.OAuthGrantsOf(app.ID); err != nil {
			t.Fatal(err)
		}
	})
	return app, grants
}

func (r *rig) actions(t *testing.T) []string {
	t.Helper()
	var out []string
	r.read(t, func(tx *store.TenantTx) {
		log, err := tx.AuditLog(-1)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range log {
			raw, _ := json.Marshal(e)
			if strings.Contains(string(raw), oauthfake.Token) {
				t.Errorf("audit event %s carries a provider token", e.Action)
			}
			out = append(out, e.Action)
		}
	})
	return out
}

func scopesOf(gs []*store.OAuthGrant) []string {
	var out []string
	for _, g := range gs {
		out = append(out, g.Scopes...)
	}
	slices.Sort(out)
	return out
}

// Every reader lists its provider's apps and grants through safehttp and the
// stored credential, follows paging, and the sync stores them with risk.
func TestSyncReadsEveryProvider(t *testing.T) {
	r := newRig(t)
	r.seed()
	rep := r.sync(t)
	if len(rep.Providers) != 4 {
		t.Fatalf("report %+v", rep)
	}
	for _, p := range rep.Providers {
		if p.Status != oauthapps.SyncOK {
			t.Errorf("%s: %s %s", p.Provider, p.Status, p.Error)
		}
	}

	// Google: three users over two pages; Drift holds a full-mailbox token for two of them.
	drift, gs := r.app(t, oauthapps.Google, "drift.apps.googleusercontent.com")
	if len(gs) != 2 || drift.Name != "Salesloft Drift" || !drift.Verified || drift.RiskScore < 60 || drift.Status != store.OAuthActive {
		t.Errorf("google drift = %+v %d grants", drift, len(gs))
	}
	if gs[0].Kind != oauthapps.KindToken || gs[0].UserRef != "g1" || gs[0].ProviderRef != "g1" {
		t.Errorf("google grant = %+v", gs[0])
	}
	if !strings.Contains(strings.Join(drift.RiskReasons, "|"), "full access to all mail") {
		t.Errorf("reasons = %v", drift.RiskReasons)
	}

	// Entra: delegated (per user and tenant-wide) and application permissions, role ids resolved to values.
	gain, gs := r.app(t, oauthapps.Entra, "app-gainsight")
	if len(gs) != 3 || gain.Publisher != "Gainsight Inc" || gain.Verified || gain.RiskScore < 60+15 {
		t.Errorf("entra gainsight = %+v %d grants", gain, len(gs))
	}
	if got := scopesOf(gs); !slices.Equal(got, []string{"Directory.ReadWrite.All", "Files.Read.All", "Mail.Read", "offline_access"}) {
		t.Errorf("entra scopes = %v", got)
	}
	var sawUser, sawAdmin, sawRole bool
	for _, g := range gs {
		sawUser = sawUser || (g.Kind == oauthapps.KindDelegated && g.ConsentType == "user" && g.UserRef == "u-alice")
		sawAdmin = sawAdmin || (g.Kind == oauthapps.KindDelegated && g.ConsentType == "admin" && g.UserRef == "")
		sawRole = sawRole || (g.Kind == oauthapps.KindAppRole && g.ProviderRef == "sp-gain/ra1" && g.GrantedAt != nil)
	}
	if !sawUser || !sawAdmin || !sawRole {
		t.Errorf("entra grant kinds: user=%t admin=%t role=%t", sawUser, sawAdmin, sawRole)
	}
	if klue, _ := r.app(t, oauthapps.Entra, "app-klue"); !klue.Verified {
		t.Error("klue has a verified publisher")
	}
	r.read(t, func(tx *store.TenantTx) {
		if _, err := tx.OAuthAppByKey(oauthapps.Entra, "app-idle"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("an app with no grant is stored: %v", err)
		}
	})

	// Salesforce: two pages of tokens, one connected app with two users.
	sfd, gs := r.app(t, oauthapps.Salesforce, oauthfake.ID("0Aa", 1))
	if len(gs) != 2 || sfd.Name != "Salesloft Drift" || sfd.LastUsed == nil || sfd.RiskScore < 75 {
		t.Errorf("salesforce drift = %+v %d grants", sfd, len(gs))
	}
	if !gs[1].GranterAdmin && !gs[0].GranterAdmin {
		t.Error("the user whose profile modifies all data is an administrator")
	}

	// GitHub: an installation and the credential authorizations, grouped by type.
	dep, gs := r.app(t, oauthapps.GitHub, "app:deploy-bot")
	if len(gs) != 1 || dep.Publisher != "acme-tools" || gs[0].Kind != oauthapps.KindInstallation ||
		!slices.Equal(gs[0].Scopes, []string{"contents:write", "metadata:read"}) {
		t.Errorf("github installation = %+v %+v", dep, gs)
	}
	oa, gs := r.app(t, oauthapps.GitHub, "credential:oauth_app_token")
	if len(gs) != 2 || oa.Name != "GitHub OAuth app token" || oa.LastUsed == nil {
		t.Errorf("github oauth credentials = %+v %d grants", oa, len(gs))
	}

	// the sync state and the audit trail
	r.read(t, func(tx *store.TenantTx) {
		st, err := tx.OAuthSyncStates()
		if err != nil || len(st) != 4 {
			t.Fatalf("sync states %v %v", st, err)
		}
		for _, s := range st {
			if s.Status != "ok" || s.SucceededAt == nil || s.Apps == 0 {
				t.Errorf("state %+v", s)
			}
		}
	})
	if got := r.actions(t); strings.Count(strings.Join(got, ","), "oauthapps.synced") != 4 {
		t.Errorf("audit actions %v", got)
	}
}

// The risk of an app comes from its live grants: it is recomputed on sync, and
// an app with no live grant is marked removed.
func TestSyncRemovalMarksGrantsAndApps(t *testing.T) {
	r := newRig(t, oauthapps.Google)
	r.seed()
	r.sync(t)
	r.advance(time.Hour)
	// bob revoked his Drift token directly at Google; alice's calendar app is gone too
	r.google.With(func() {
		r.google.Users[1].Tokens = nil
		r.google.Users[0].Tokens = r.google.Users[0].Tokens[:1]
	})
	r.sync(t)
	drift, gs := r.app(t, oauthapps.Google, "drift.apps.googleusercontent.com")
	if drift.Status != store.OAuthActive || len(gs) != 2 || gs[0].Status != store.OAuthActive || gs[1].Status != store.OAuthRemoved {
		t.Errorf("drift %s grants %s/%s", drift.Status, gs[0].Status, gs[1].Status)
	}
	cal, gs := r.app(t, oauthapps.Google, "cal.apps.googleusercontent.com")
	if cal.Status != store.OAuthRemoved || gs[0].Status != store.OAuthRemoved {
		t.Errorf("cal %s grant %s", cal.Status, gs[0].Status)
	}
	// seen again: active again
	r.advance(time.Hour)
	r.google.With(func() {
		r.google.Users[1].Tokens = []oauthfake.GoogleToken{{ClientID: "drift.apps.googleusercontent.com", DisplayText: "Salesloft Drift",
			Scopes: []string{"https://mail.google.com/"}}}
	})
	r.sync(t)
	if _, gs := r.app(t, oauthapps.Google, "drift.apps.googleusercontent.com"); gs[1].Status != store.OAuthActive {
		t.Errorf("a grant seen again is %s", gs[1].Status)
	}
}

// A provider read that fails part-way never replaces what is stored: the grants
// stay, the failure is recorded, and the failure is audited.
func TestFailedSyncKeepsInventory(t *testing.T) {
	r := newRig(t, oauthapps.Entra, oauthapps.Google)
	r.seed()
	r.sync(t)
	r.advance(time.Hour)
	r.entra.FailReads.Store(true)
	rep := r.sync(t)
	var entra, google oauthapps.ProviderReport
	for _, p := range rep.Providers {
		switch p.Provider {
		case oauthapps.Entra:
			entra = p
		case oauthapps.Google:
			google = p
		}
	}
	if entra.Status != oauthapps.SyncFailed || !strings.Contains(entra.Error, "500") || google.Status != oauthapps.SyncOK {
		t.Fatalf("entra %+v google %+v", entra, google)
	}
	if _, gs := r.app(t, oauthapps.Entra, "app-gainsight"); len(gs) != 3 || gs[0].Status != store.OAuthActive {
		t.Errorf("a failed sync changed the grants: %d", len(gs))
	}
	r.read(t, func(tx *store.TenantTx) {
		st, _ := tx.OAuthSyncStates()
		for _, s := range st {
			if s.Provider == oauthapps.Entra && (s.Status != "failed" || s.SucceededAt == nil || s.Grants == 0 || s.Error == "") {
				t.Errorf("entra state %+v", s)
			}
		}
	})
	if !slices.Contains(r.actions(t), "oauthapps.sync_failed") {
		t.Error("no oauthapps.sync_failed event")
	}
}

// A provider with no live connection or credential is skipped: nothing is
// called and nothing is stored, and that is not a failure.
func TestSyncSkipsWithoutCredential(t *testing.T) {
	r := newRig(t, oauthapps.Google)
	r.seed()
	rep := r.sync(t)
	for _, p := range rep.Providers {
		if p.Provider != oauthapps.Google && (p.Status != oauthapps.SyncSkipped || p.Error == "") {
			t.Errorf("%+v", p)
		}
	}
	if len(r.entra.Calls())+len(r.sf.Calls())+len(r.gh.Calls()) != 0 {
		t.Error("a provider without a credential was called")
	}
	if !rep.Changed() {
		t.Error("google was read")
	}
	if (&oauthapps.SyncReport{Providers: []oauthapps.ProviderReport{{Status: oauthapps.SyncSkipped}}}).Changed() {
		t.Error("a sync that skipped everything changed nothing")
	}
}

// The granting user is correlated to the account (by login or external id) and
// its identity; the first granting identity becomes the app's owner.
func TestSyncCorrelatesUsersAndDefaultsOwner(t *testing.T) {
	r := newRig(t, oauthapps.Google)
	r.seed()
	var alice int64
	err := r.f.DB.InTenant(context.Background(), r.f.A.ID, func(tx *store.TenantTx) error {
		alice = r.f.A.IDs["alice"]
		_, err := tx.InsertAccount(&store.Account{System: "google", ExternalID: "g1", IdentityID: &alice, Username: "Alice@A.example", Kind: "human", Status: "active"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	r.sync(t)
	drift, gs := r.app(t, oauthapps.Google, "drift.apps.googleusercontent.com")
	if gs[0].IdentityID == nil || *gs[0].IdentityID != alice || gs[0].AccountID == nil || gs[1].IdentityID != nil {
		t.Errorf("grants = %+v / %+v", gs[0], gs[1])
	}
	if drift.OwnerIdentityID == nil || *drift.OwnerIdentityID != alice {
		t.Errorf("owner = %v", drift.OwnerIdentityID)
	}
}

func planOf(t *testing.T, r *rig, scope, appID, target string) *oauthapps.Plan {
	t.Helper()
	var p *oauthapps.Plan
	r.read(t, func(tx *store.TenantTx) {
		var err error
		if p, err = oauthapps.BuildPlan(tx, scope, appID, target, r.now); err != nil {
			t.Fatalf("plan %s: %v", scope, err)
		}
	})
	return p
}

func TestBuildPlan(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.sync(t)
	drift, gs := r.app(t, oauthapps.Google, "drift.apps.googleusercontent.com")

	p := planOf(t, r, oauthapps.ScopeApp, drift.ID, "")
	if len(p.Items) != 2 || p.Apps != 1 || !p.HighRisk || !p.FourEyes() || p.Target != drift.ID {
		t.Errorf("app plan = %+v", p)
	}
	one := planOf(t, r, oauthapps.ScopeGrant, drift.ID, gs[0].ID)
	if len(one.Items) != 1 || one.FourEyes() {
		t.Errorf("a single grant needs no second admin: %+v", one)
	}
	// the vendor "Salesloft Drift" spans Google and Salesforce, matched by app name
	v := planOf(t, r, oauthapps.ScopeVendor, "", " SALESLOFT drift ")
	if len(v.Items) != 4 || v.Apps != 2 || v.Target != "salesloft drift" || !v.FourEyes() {
		t.Errorf("vendor plan = %d items, %d apps, %q", len(v.Items), v.Apps, v.Target)
	}
	// a publisher match (Entra)
	if g := planOf(t, r, oauthapps.ScopeVendor, "", "gainsight inc"); len(g.Items) != 3 {
		t.Errorf("publisher plan = %d items", len(g.Items))
	}

	r.read(t, func(tx *store.TenantTx) {
		for name, tc := range map[string]struct {
			scope, app, target string
			want               error
		}{
			"unknown vendor":    {oauthapps.ScopeVendor, "", "nobody", oauthapps.ErrNotFound},
			"unknown app":       {oauthapps.ScopeApp, "nope", "", oauthapps.ErrNotFound},
			"grant of other":    {oauthapps.ScopeGrant, drift.ID, "nope", oauthapps.ErrNotFound},
			"empty vendor name": {oauthapps.ScopeVendor, "", "  ", oauthapps.ErrNotFound},
		} {
			if _, err := oauthapps.BuildPlan(tx, tc.scope, tc.app, tc.target, r.now); !errors.Is(err, tc.want) {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
}

func (r *rig) execute(t *testing.T, p *oauthapps.Plan) *oauthapps.RevokeReport {
	t.Helper()
	rep, err := r.svc.Execute(context.Background(), r.f.DB, r.f.A.ID, p, "admin", "vendor breached")
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestRevokeAppVerifiesByReread(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.sync(t)
	drift, _ := r.app(t, oauthapps.Google, "drift.apps.googleusercontent.com")
	rep := r.execute(t, planOf(t, r, oauthapps.ScopeApp, drift.ID, ""))
	if !rep.OK || rep.Revoked != 2 || rep.Failed+rep.Manual+rep.Skipped != 0 {
		t.Fatalf("report %+v", rep)
	}
	app, gs := r.app(t, oauthapps.Google, "drift.apps.googleusercontent.com")
	if app.Status != store.OAuthRevoked || app.RevokedBy == nil || *app.RevokedBy != "admin" || gs[0].Status != store.OAuthRevoked || gs[1].Status != store.OAuthRevoked {
		t.Errorf("app %s %v grants %s %s", app.Status, app.RevokedBy, gs[0].Status, gs[1].Status)
	}
	if app.RiskScore >= 60 {
		t.Errorf("a revoked app keeps scoring its revoked grants: %d", app.RiskScore)
	}
	// the fake no longer lists Drift tokens, and the calls were delete then re-read
	for _, u := range r.google.Users {
		for _, tk := range u.Tokens {
			if strings.HasPrefix(tk.ClientID, "drift") {
				t.Errorf("%s still holds a drift token", u.Email)
			}
		}
	}
	if got := r.actions(t); !slices.Contains(got, "oauthapps.revoke_started") || !slices.Contains(got, "oauthapps.revoked") {
		t.Errorf("audit %v", got)
	}
	// revoking again finds nothing live
	r.read(t, func(tx *store.TenantTx) {
		if _, err := oauthapps.BuildPlan(tx, oauthapps.ScopeApp, drift.ID, "", r.now); !errors.Is(err, oauthapps.ErrNothingToRevoke) {
			t.Errorf("second plan: %v", err)
		}
	})
	// the next sync keeps the app revoked (the provider lists nothing)
	r.advance(time.Hour)
	r.sync(t, oauthapps.Google)
	if app, _ := r.app(t, oauthapps.Google, "drift.apps.googleusercontent.com"); app.Status != store.OAuthRevoked {
		t.Errorf("after a sync the app is %s", app.Status)
	}
}

func TestRevokeVendorAcrossProviders(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.sync(t)
	rep := r.execute(t, planOf(t, r, oauthapps.ScopeVendor, "", "Salesloft Drift"))
	if !rep.OK || rep.Revoked != 4 {
		t.Fatalf("report %+v", rep)
	}
	if len(r.sf.Tokens) != 1 || r.sf.Tokens[0].AppName != "Quiet app" {
		t.Errorf("salesforce tokens left: %+v", r.sf.Tokens)
	}
	// Entra and GitHub were not touched
	if r.entra.Deleted()+r.gh.Deleted() != 0 {
		t.Error("another vendor's grants were revoked")
	}
}

// What cannot be verified or revoked is never reported as done.
func TestRevokeOutcomes(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		client   string
		setup    func(r *rig)
		outcome  string
		detail   string
	}{
		{"provider refuses", oauthapps.Google, "drift.apps.googleusercontent.com", func(r *rig) { r.google.Refuse.Store(true) }, oauthapps.OutcomeFailed, "403"},
		{"accepted but still there", oauthapps.Salesforce, oauthfake.ID("0Aa", 1), func(r *rig) { r.sf.Sticky.Store(true) }, oauthapps.OutcomeFailed, "still shows the grant"},
		{"entra delegated consent", oauthapps.Entra, "app-klue", func(r *rig) {}, oauthapps.OutcomeRevoked, ""},
		{"github installation is manual", oauthapps.GitHub, "app:deploy-bot", func(r *rig) {}, oauthapps.OutcomeManual, "no API"},
		{"github credential", oauthapps.GitHub, "credential:personal_access_token", func(r *rig) {}, oauthapps.OutcomeRevoked, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.seed()
			r.sync(t)
			tc.setup(r)
			app, _ := r.app(t, tc.provider, tc.client)
			rep := r.execute(t, planOf(t, r, oauthapps.ScopeApp, app.ID, ""))
			got := rep.Items[0]
			if got.Outcome != tc.outcome || !strings.Contains(got.Detail, tc.detail) {
				t.Fatalf("outcome %s %q, want %s %q", got.Outcome, got.Detail, tc.outcome, tc.detail)
			}
			after, gs := r.app(t, tc.provider, tc.client)
			if tc.outcome == oauthapps.OutcomeRevoked {
				if after.Status != store.OAuthRevoked || !rep.OK {
					t.Errorf("app %s ok=%t", after.Status, rep.OK)
				}
				return
			}
			if rep.OK || after.Status == store.OAuthRevoked || gs[0].Status != store.OAuthRevokeFailed || gs[0].RevokeError == "" {
				t.Errorf("app %s ok=%t grant %s %q", after.Status, rep.OK, gs[0].Status, gs[0].RevokeError)
			}
			// a failed revoke stays visible across the next sync
			r.advance(time.Hour)
			r.sync(t, tc.provider)
			if _, gs := r.app(t, tc.provider, tc.client); gs[0].Status != store.OAuthRevokeFailed && gs[0].Status != store.OAuthRemoved {
				t.Errorf("after sync the grant is %s", gs[0].Status)
			}
		})
	}
}

func TestRevokeWithoutCredentialIsManual(t *testing.T) {
	r := newRig(t, oauthapps.Google, oauthapps.Entra)
	r.seed()
	r.sync(t)
	// the credential goes away after the inventory was read
	err := r.f.DB.InTenant(context.Background(), r.f.A.ID, func(tx *store.TenantTx) error {
		conns, err := tx.Connections()
		if err != nil {
			return err
		}
		for _, c := range conns {
			if c.System == oauthapps.Entra {
				if err := tx.MarkConnectionRetired(c.ID, r.now); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	app, _ := r.app(t, oauthapps.Entra, "app-klue")
	rep := r.execute(t, planOf(t, r, oauthapps.ScopeApp, app.ID, ""))
	if rep.OK || rep.Manual != 1 || rep.Items[0].Outcome != oauthapps.OutcomeManual || r.entra.Deleted() != 0 {
		t.Errorf("report %+v", rep)
	}
}

func TestRevokeTimeBudgetSkipsTheRest(t *testing.T) {
	r := newRig(t, oauthapps.Google)
	r.seed()
	r.sync(t)
	r.svc.Budget = time.Nanosecond
	drift, _ := r.app(t, oauthapps.Google, "drift.apps.googleusercontent.com")
	rep := r.execute(t, planOf(t, r, oauthapps.ScopeApp, drift.ID, ""))
	if rep.OK || rep.Skipped == 0 || rep.Revoked+rep.Failed+rep.Skipped != 2 {
		t.Errorf("report %+v", rep)
	}
	if app, _ := r.app(t, oauthapps.Google, "drift.apps.googleusercontent.com"); app.Status == store.OAuthRevoked {
		t.Error("an app with skipped grants is not revoked")
	}
}

func TestGateFourEyes(t *testing.T) {
	r := newRig(t, oauthapps.Google)
	r.seed()
	r.sync(t)
	drift, gs := r.app(t, oauthapps.Google, "drift.apps.googleusercontent.com")
	var first, second uuid.UUID
	err := r.f.DB.InTenant(context.Background(), r.f.A.ID, func(tx *store.TenantTx) error {
		for i, id := range []*uuid.UUID{&first, &second} {
			u := &store.PlatformUser{DisplayName: []string{"first", "second"}[i], CreatedAt: r.now}
			if err := tx.InsertPlatformUser(u); err != nil {
				return err
			}
			*id = u.ID
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	gate := func(p *oauthapps.Plan, by uuid.UUID, name string, at time.Time) (string, *store.OAuthRevokeRequest) {
		var d string
		var req *store.OAuthRevokeRequest
		err := r.f.DB.InTenant(context.Background(), r.f.A.ID, func(tx *store.TenantTx) error {
			var err error
			d, req, err = oauthapps.Gate(tx, p, by, name, "vendor breached", at)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return d, req
	}
	app := planOf(t, r, oauthapps.ScopeApp, drift.ID, "")
	one := planOf(t, r, oauthapps.ScopeGrant, drift.ID, gs[0].ID)
	if d, _ := gate(one, first, "first", r.now); d != oauthapps.GateExecute {
		t.Errorf("single grant: %s", d)
	}
	d, req := gate(app, first, "first", r.now)
	if d != oauthapps.GatePending || req.Grants != 2 || req.Apps != 1 {
		t.Fatalf("first request: %s %+v", d, req)
	}
	if d, _ := gate(app, first, "first", r.now.Add(time.Minute)); d != oauthapps.GateSameApprover {
		t.Errorf("same admin: %s", d)
	}
	if d, got := gate(app, second, "second", r.now.Add(2*time.Minute)); d != oauthapps.GateExecute || got.ID != req.ID {
		t.Errorf("second admin: %s", d)
	}
	// the request is consumed: a repeat starts a new one
	if d, _ := gate(app, second, "second", r.now.Add(3*time.Minute)); d != oauthapps.GatePending {
		t.Errorf("after execution: %s", d)
	}
	// a pending request past its window is not approved by anyone
	if d, _ := gate(app, first, "first", r.now.Add(oauthapps.ApprovalWindow+time.Hour)); d != oauthapps.GatePending {
		t.Errorf("expired request approved: %s", d)
	}
	got := r.actions(t)
	for _, want := range []string{"oauthapps.revoke_requested", "oauthapps.revoke_approved"} {
		if !slices.Contains(got, want) {
			t.Errorf("no %s event", want)
		}
	}
}

func TestFlags(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	old, recent := now.Add(-100*24*time.Hour), now.Add(-time.Hour)
	live := func(admin bool, consent string, used *time.Time, scopes ...string) *store.OAuthGrant {
		return &store.OAuthGrant{Status: store.OAuthActive, GranterAdmin: admin, ConsentType: consent, Scopes: scopes, LastUsed: used}
	}
	cases := []struct {
		name   string
		app    store.OAuthApp
		grants []*store.OAuthGrant
		want   []string
	}{
		{"high-risk scope by a non-admin", store.OAuthApp{Provider: "google", Verified: true},
			[]*store.OAuthGrant{live(false, "user", nil, "https://mail.google.com/")}, []string{oauthapps.FlagHighRiskNonAdmin}},
		{"same scope by an admin", store.OAuthApp{Provider: "google", Verified: true},
			[]*store.OAuthGrant{live(true, "user", nil, "https://mail.google.com/")}, []string{}},
		{"admin consent is not a non-admin grant", store.OAuthApp{Provider: "entra", Verified: true},
			[]*store.OAuthGrant{live(false, "admin", nil, "Directory.ReadWrite.All")}, []string{}},
		{"low-risk scope", store.OAuthApp{Provider: "google", Verified: true},
			[]*store.OAuthGrant{live(false, "user", nil, "openid")}, []string{}},
		{"a removed grant does not count", store.OAuthApp{Provider: "google", Verified: true},
			[]*store.OAuthGrant{{Status: store.OAuthRemoved, ConsentType: "user", Scopes: []string{"https://mail.google.com/"}}}, []string{}},
		{"unused", store.OAuthApp{Provider: "google", Verified: true, LastUsed: &old},
			[]*store.OAuthGrant{live(false, "user", nil, "openid")}, []string{oauthapps.FlagUnused}},
		{"used by a grant recently", store.OAuthApp{Provider: "google", Verified: true, LastUsed: &old},
			[]*store.OAuthGrant{live(false, "user", &recent, "openid")}, []string{}},
		{"unknown last use is not unused", store.OAuthApp{Provider: "google"},
			[]*store.OAuthGrant{live(false, "user", nil, "openid")}, []string{oauthapps.FlagUnverified}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := oauthapps.Flags(&tc.app, tc.grants, now, oauthapps.DefaultUnusedDays); !slices.Equal(got, tc.want) {
				t.Errorf("flags = %v, want %v", got, tc.want)
			}
		})
	}
	if got := oauthapps.Flags(&store.OAuthApp{Verified: true, LastUsed: &old}, nil, now, 0); len(got) != 0 {
		t.Errorf("unused days 0 turns the flag off: %v", got)
	}
}

func TestMatchesVendor(t *testing.T) {
	a := &store.OAuthApp{Name: "Salesloft Drift", Publisher: "Salesloft, Inc."}
	for v, want := range map[string]bool{"salesloft drift": true, " SALESLOFT, INC. ": true, "salesloft": false, "": false, "  ": false} {
		if got := oauthapps.MatchesVendor(a, v); got != want {
			t.Errorf("MatchesVendor(%q) = %t", v, got)
		}
	}
}

// A provider that names a host other than its own in a paging link never
// receives the token.
func TestReadersRefuseForeignPagingLinks(t *testing.T) {
	r := newRig(t, oauthapps.Entra)
	r.seed()
	r.entra.BaseURL = "http://127.0.0.1:1" // the next link points elsewhere
	rep := r.sync(t, oauthapps.Entra)
	if rep.Providers[0].Status != oauthapps.SyncFailed || !strings.Contains(rep.Providers[0].Error, "another host") {
		t.Errorf("report %+v", rep.Providers[0])
	}
}
