package oauthapps_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps"
	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps/oauthfake"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Detection of credentials, permissions and owners added to OAuth apps, and
// their containment (issue #474), against the stateful Entra fake.

// entraRig is a rig with Entra only and Gainsight holding a secret and an owner.
func entraRig(t *testing.T) *rig {
	r := newRig(t, oauthapps.Entra)
	r.seed()
	r.entra.Apps = []*oauthfake.EntraApplication{{ID: "obj-gain", AppID: "app-gainsight",
		Secrets: []oauthfake.EntraKey{{ID: "key-1", Name: "prod secret", Start: "2026-06-01T00:00:00Z"}},
		Owners:  []oauthfake.EntraOwner{{ID: "u-alice", UPN: "alice@a.example"}}}}
	return r
}

func (r *rig) changes(t *testing.T) []*store.OAuthChange {
	t.Helper()
	var out []*store.OAuthChange
	r.read(t, func(tx *store.TenantTx) {
		var err error
		if out, err = tx.OpenOAuthChanges(); err != nil {
			t.Fatal(err)
		}
	})
	return out
}

func kinds(cs []*store.OAuthChange) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Kind)
	}
	slices.Sort(out)
	return out
}

// What an app held at the first sync is the baseline, not a change.
func TestChangesFirstSyncIsBaseline(t *testing.T) {
	r := entraRig(t)
	rep := r.sync(t, oauthapps.Entra)
	if rep.Providers[0].Status != oauthapps.SyncOK || rep.Providers[0].Changes != 0 {
		t.Fatalf("report %+v", rep.Providers[0])
	}
	if cs := r.changes(t); len(cs) != 0 {
		t.Errorf("first sync raised %d changes", len(cs))
	}
	app, _ := r.app(t, oauthapps.Entra, "app-gainsight")
	r.read(t, func(tx *store.TenantTx) {
		fs, err := tx.OAuthFactsOf(app.ID)
		if err != nil {
			t.Fatal(err)
		}
		var secrets, owners, baseline int
		for _, f := range fs {
			switch f.Kind {
			case store.OAuthFactSecret:
				secrets++
				if f.Label != "prod secret" || f.AddedAt == nil {
					t.Errorf("secret fact %+v", f)
				}
			case store.OAuthFactOwner:
				owners++
			case store.OAuthFactBaseline:
				baseline++
			}
		}
		if secrets != 1 || owners != 1 || baseline != 1 {
			t.Errorf("facts: %d secrets, %d owners, %d baseline", secrets, owners, baseline)
		}
	})
	// the same state again changes nothing
	r.advance(time.Hour)
	if rep := r.sync(t, oauthapps.Entra); rep.Providers[0].Changes != 0 || len(r.changes(t)) != 0 {
		t.Errorf("an unchanged provider reported changes: %+v", rep.Providers[0])
	}
}

func TestChangesDetected(t *testing.T) {
	r := entraRig(t)
	r.sync(t, oauthapps.Entra)
	r.advance(time.Hour)
	r.entra.With(func() {
		r.entra.Apps[0].Secrets = append(r.entra.Apps[0].Secrets, oauthfake.EntraKey{ID: "key-2", Name: "backdoor", Start: "2026-10-21T00:00:00Z"})
		r.entra.Apps[0].Certs = []oauthfake.EntraKey{{ID: "cert-1", Name: "cert", Start: "2026-10-21T01:00:00Z"}}
		r.entra.Apps[0].Owners = []oauthfake.EntraOwner{{ID: "u-mallory", UPN: "mallory@evil.example"}} // alice out, mallory in
		r.entra.SPs[2].Secrets = []oauthfake.EntraKey{{ID: "sp-key", Name: "klue sp secret"}}           // Klue's service principal
		r.entra.Roles = append(r.entra.Roles, &oauthfake.EntraRole{ID: "ra2", ClientSP: "sp-gain", Resource: "sp-graph", RoleID: "role-dir", Created: "2026-10-21T02:00:00Z"})
		r.entra.Delegated = append(r.entra.Delegated,
			&oauthfake.EntraDelegated{ID: "d4", ClientSP: "sp-gain", ConsentType: "AllPrincipals", Scope: "Mail.ReadWrite"},                   // tenant-wide: reported
			&oauthfake.EntraDelegated{ID: "d5", ClientSP: "sp-gain", ConsentType: "Principal", Principal: "u-alice", Scope: "Calendars.Read"}) // one user's consent: not
	})
	rep := r.sync(t, oauthapps.Entra)
	if rep.Providers[0].Changes != 7 {
		t.Fatalf("changes = %d, want 7 (3 credentials... got %+v)", rep.Providers[0].Changes, rep.Providers[0])
	}
	cs := r.changes(t)
	want := []string{"credential_added", "credential_added", "credential_added", "owner_changed", "owner_changed", "permission_granted", "permission_granted"}
	if got := kinds(cs); !slices.Equal(got, want) {
		t.Fatalf("kinds = %v, want %v", got, want)
	}
	var text []string
	for _, c := range cs {
		text = append(text, c.Summary)
		if strings.Contains(string(c.Detail), oauthfake.Token) {
			t.Errorf("detail carries the provider token: %s", c.Detail)
		}
	}
	all := strings.Join(text, "\n")
	for _, w := range []string{`secret "backdoor"`, `certificate "cert"`, `secret "klue sp secret"`, "mallory@evil.example was added as an owner",
		"alice@a.example was removed as an owner", "Application permission", "Tenant-wide consent"} {
		if !strings.Contains(all, w) {
			t.Errorf("no change says %q in:\n%s", w, all)
		}
	}
	if strings.Contains(all, "Calendars.Read") {
		t.Error("a single user's consent is not a permission change")
	}
	if n := countAction(r.actions(t), oauthapps.ActionChangeDetected); n != 7 {
		t.Errorf("%d change_detected events, want 7", n)
	}
	// a further sync of the same state records nothing new
	r.advance(time.Hour)
	if rep := r.sync(t, oauthapps.Entra); rep.Providers[0].Changes != 0 || len(r.changes(t)) != 7 {
		t.Errorf("repeat sync: %+v, %d open", rep.Providers[0], len(r.changes(t)))
	}
}

func countAction(actions []string, a string) int {
	n := 0
	for _, x := range actions {
		if x == a {
			n++
		}
	}
	return n
}

// A change is closed when its credential or permission is gone at the provider.
func TestChangesResolveWhenGone(t *testing.T) {
	r := entraRig(t)
	r.sync(t, oauthapps.Entra)
	r.advance(time.Hour)
	r.entra.With(func() {
		r.entra.Apps[0].Secrets = append(r.entra.Apps[0].Secrets, oauthfake.EntraKey{ID: "key-2", Name: "backdoor"})
		r.entra.Roles = append(r.entra.Roles, &oauthfake.EntraRole{ID: "ra2", ClientSP: "sp-gain", Resource: "sp-graph", RoleID: "role-dir"})
	})
	r.sync(t, oauthapps.Entra)
	if got := kinds(r.changes(t)); len(got) != 2 {
		t.Fatalf("open = %v", got)
	}
	r.advance(time.Hour)
	r.entra.With(func() {
		r.entra.Apps[0].Secrets = r.entra.Apps[0].Secrets[:1]
		r.entra.Roles = r.entra.Roles[:1]
	})
	r.sync(t, oauthapps.Entra)
	if got := r.changes(t); len(got) != 0 {
		t.Errorf("open after both are gone = %v", kinds(got))
	}
}

// The oauth_app_change rule raises one alert per detected change, and none for the baseline.
func TestChangesRaiseAlerts(t *testing.T) {
	r := entraRig(t)
	eval := func() alerts.Result {
		var res alerts.Result
		if err := r.f.DB.InTenant(context.Background(), r.f.A.ID, func(tx *store.TenantTx) error {
			var err error
			res, err = alerts.Evaluate(tx, r.now, false)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return res
	}
	eval() // the first evaluation starts at the head
	r.sync(t, oauthapps.Entra)
	if res := eval(); res.Raised != 0 {
		t.Fatalf("the baseline raised %d alerts", res.Raised)
	}
	r.advance(time.Hour)
	r.entra.With(func() {
		r.entra.Apps[0].Secrets = append(r.entra.Apps[0].Secrets, oauthfake.EntraKey{ID: "key-2", Name: "backdoor"})
	})
	r.sync(t, oauthapps.Entra)
	if res := eval(); res.Raised != 1 {
		t.Fatalf("raised = %d, want 1", res.Raised)
	}
	r.read(t, func(tx *store.TenantTx) {
		as, err := tx.Alerts(store.AlertFilter{RuleID: "oauth_app_change"})
		if err != nil || len(as) != 1 || as[0].Severity != "high" || !strings.Contains(as[0].Title, `secret "backdoor"`) {
			t.Errorf("alerts = %+v, %v", as, err)
		}
	})
}

func (r *rig) removeCred(t *testing.T, app *store.OAuthApp, kind string) (*oauthapps.CredentialReport, error) {
	t.Helper()
	var id string
	r.read(t, func(tx *store.TenantTx) {
		fs, err := tx.OAuthFactsOf(app.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			if f.Kind == kind && f.Status == "active" {
				id = f.ID
			}
		}
	})
	return r.svc.RemoveCredential(context.Background(), r.f.DB, r.f.A.ID, app.ID, id, "admin", "storm-0940 response")
}

func TestRemoveCredential(t *testing.T) {
	r := entraRig(t)
	r.sync(t, oauthapps.Entra)
	r.advance(time.Hour)
	r.entra.With(func() {
		r.entra.Apps[0].Secrets = append(r.entra.Apps[0].Secrets, oauthfake.EntraKey{ID: "key-2", Name: "backdoor"})
		r.entra.Apps[0].Certs = []oauthfake.EntraKey{{ID: "cert-1", Name: "cert"}}
	})
	r.sync(t, oauthapps.Entra)
	app, _ := r.app(t, oauthapps.Entra, "app-gainsight")
	var backdoor string
	r.read(t, func(tx *store.TenantTx) {
		fs, _ := tx.OAuthFactsOf(app.ID)
		for _, f := range fs {
			if f.Label == "backdoor" {
				backdoor = f.ID
			}
		}
	})

	// a refusing provider: failed, and the credential stays active and the change open
	r.entra.Refuse.Store(true)
	rep, err := r.svc.RemoveCredential(context.Background(), r.f.DB, r.f.A.ID, app.ID, backdoor, "admin", "reason text here")
	if err != nil || rep.OK || rep.Outcome != oauthapps.OutcomeFailed {
		t.Fatalf("refused: %+v, %v", rep, err)
	}
	r.entra.Refuse.Store(false)
	// a provider that answers 204 and keeps the credential: the re-read catches it
	r.entra.Sticky.Store(true)
	if rep, err = r.svc.RemoveCredential(context.Background(), r.f.DB, r.f.A.ID, app.ID, backdoor, "admin", "reason text here"); err != nil || rep.OK ||
		!strings.Contains(rep.Detail, "still shows") {
		t.Fatalf("sticky: %+v, %v", rep, err)
	}
	r.entra.Sticky.Store(false)
	if n := len(r.changes(t)); n != 2 {
		t.Fatalf("open changes after failures = %d", n)
	}

	rep, err = r.svc.RemoveCredential(context.Background(), r.f.DB, r.f.A.ID, app.ID, backdoor, "admin", "reason text here")
	if err != nil || !rep.OK || rep.Outcome != oauthapps.OutcomeRemoved {
		t.Fatalf("remove: %+v, %v", rep, err)
	}
	if secrets := r.entra.Apps[0].Secrets; len(secrets) != 1 || secrets[0].ID != "key-1" {
		t.Errorf("provider still holds %+v", secrets)
	}
	if got := kinds(r.changes(t)); !slices.Equal(got, []string{"credential_added"}) { // the certificate's change is still open
		t.Errorf("open after removal = %v", got)
	}
	acts := r.actions(t)
	if !slices.Contains(acts, "oauthapps.credential_remove_started") || countAction(acts, "oauthapps.credential_removed") != 3 {
		t.Errorf("audit %v", acts)
	}
	// removing it again: no longer an active credential
	if _, err := r.svc.RemoveCredential(context.Background(), r.f.DB, r.f.A.ID, app.ID, backdoor, "admin", "reason text here"); !errors.Is(err, oauthapps.ErrNoCredential) {
		t.Errorf("second removal = %v", err)
	}
	// a certificate is a manual task, never reported as done
	rep, err = r.removeCred(t, app, store.OAuthFactCertificate)
	if err != nil || rep.OK || rep.Outcome != oauthapps.OutcomeManual || !strings.Contains(rep.Detail, "Entra admin center") {
		t.Errorf("certificate: %+v, %v", rep, err)
	}
	// an owner is not a credential; an unknown id and another app's credential are not found
	if _, err := r.removeCred(t, app, store.OAuthFactOwner); !errors.Is(err, oauthapps.ErrNoCredential) {
		t.Errorf("owner = %v", err)
	}
	if _, err := r.svc.RemoveCredential(context.Background(), r.f.DB, r.f.A.ID, app.ID, "nope", "admin", "reason text here"); !errors.Is(err, oauthapps.ErrNotFound) {
		t.Errorf("unknown = %v", err)
	}
	klue, _ := r.app(t, oauthapps.Entra, "app-klue")
	if _, err := r.svc.RemoveCredential(context.Background(), r.f.DB, r.f.A.ID, klue.ID, backdoor, "admin", "reason text here"); !errors.Is(err, oauthapps.ErrNoCredential) {
		t.Errorf("another app's credential = %v", err)
	}
}

// Without a provider credential the removal is manual, and a provider with no
// removal API (Google) says so.
func TestRemoveCredentialManualWithoutAPI(t *testing.T) {
	r := newRig(t, oauthapps.Google)
	r.seed()
	r.sync(t, oauthapps.Google)
	app, _ := r.app(t, oauthapps.Google, "drift.apps.googleusercontent.com")
	var id string
	r.f.DB.InTenant(context.Background(), r.f.A.ID, func(tx *store.TenantTx) error {
		f := &store.OAuthFact{AppID: app.ID, Kind: store.OAuthFactSecret, Key: "k", Label: "x", ProviderRef: "x/y/z"}
		_, err := tx.UpsertOAuthFact(f, r.now)
		id = f.ID
		return err
	})
	rep, err := r.svc.RemoveCredential(context.Background(), r.f.DB, r.f.A.ID, app.ID, id, "admin", "reason text here")
	if err != nil || rep.OK || rep.Outcome != oauthapps.OutcomeManual {
		t.Errorf("google: %+v, %v", rep, err)
	}
}

// Widening an existing tenant-wide consent keeps its grant id (#492).
func TestChangesWidenedConsentDetected(t *testing.T) {
	r := entraRig(t)
	r.sync(t, oauthapps.Entra)
	r.advance(time.Hour)
	r.entra.With(func() { r.entra.Delegated[1].Scope = "User.Read Mail.ReadWrite Files.ReadWrite.All" })
	rep := r.sync(t, oauthapps.Entra)
	cs := r.changes(t)
	if rep.Providers[0].Changes != 1 || len(cs) != 1 || cs[0].Kind != "permission_granted" {
		t.Fatalf("report %+v, changes %v", rep.Providers[0], kinds(cs))
	}
	if !strings.Contains(cs[0].Summary, "Files.ReadWrite.All Mail.ReadWrite") || strings.Contains(cs[0].Summary, "User.Read ") {
		t.Errorf("summary should name only the added scopes: %s", cs[0].Summary)
	}
	// the same widened state again, and narrowing, are not new changes
	r.advance(time.Hour)
	r.entra.With(func() { r.entra.Delegated[1].Scope = "User.Read" })
	if rep := r.sync(t, oauthapps.Entra); rep.Providers[0].Changes != 0 {
		t.Errorf("narrowing reported %d changes", rep.Providers[0].Changes)
	}
}

// Re-consent after the grant disappeared reuses the grant id (#492).
func TestChangesReconsentAfterRemovalDetected(t *testing.T) {
	r := entraRig(t)
	r.sync(t, oauthapps.Entra)
	r.advance(time.Hour)
	d2 := r.entra.Delegated[1]
	r.entra.With(func() { r.entra.Delegated = append(r.entra.Delegated[:1:1], r.entra.Delegated[2:]...) })
	r.sync(t, oauthapps.Entra)
	if cs := r.changes(t); len(cs) != 0 {
		t.Fatalf("removal raised %v", kinds(cs))
	}
	r.advance(time.Hour)
	r.entra.With(func() { r.entra.Delegated = append(r.entra.Delegated, d2) })
	rep := r.sync(t, oauthapps.Entra)
	if cs := r.changes(t); rep.Providers[0].Changes != 1 || len(cs) != 1 || !strings.Contains(cs[0].Summary, "granted again") {
		t.Fatalf("report %+v, changes %v", rep.Providers[0], kinds(cs))
	}
}

// An app that first enters the inventory after the provider's baseline sync
// with a new app role and secret is reported; state older than the previous
// sync is still baseline (#492).
func TestChangesNewAppAfterBaselineDetected(t *testing.T) {
	r := entraRig(t)
	r.sync(t, oauthapps.Entra)
	r.advance(time.Hour)
	r.entra.With(func() {
		r.entra.Roles = append(r.entra.Roles, &oauthfake.EntraRole{ID: "ra-idle", ClientSP: "sp-idle", Resource: "sp-graph", RoleID: "role-dir"})
		r.entra.Apps = append(r.entra.Apps, &oauthfake.EntraApplication{ID: "obj-idle", AppID: "app-idle",
			Secrets: []oauthfake.EntraKey{{ID: "key-evil", Name: "evil"}, {ID: "key-old", Name: "old", Start: "2020-01-01T00:00:00Z"}}})
	})
	rep := r.sync(t, oauthapps.Entra)
	cs := r.changes(t)
	if rep.Providers[0].Changes != 2 || !slices.Equal(kinds(cs), []string{"credential_added", "permission_granted"}) {
		t.Fatalf("report %+v, changes %v", rep.Providers[0], kinds(cs))
	}
	for _, c := range cs {
		if strings.Contains(c.Summary, `"old"`) {
			t.Errorf("a credential that predates the last sync was reported: %s", c.Summary)
		}
	}
}
