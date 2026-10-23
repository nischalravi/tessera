package oauthapps

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Detection of what changed in an app between two syncs (issue #474).
// Storm-0940 added credentials to customers' OAuth apps through compromised
// vendor cloud-app identities: a new secret or certificate, a new application
// permission and a changed owner are how an attacker keeps access to an app.
//
// A change is reported only for an app a sync has already seen: the first sync
// that sees an app (or the first after this feature) records what it holds as
// the baseline (a 'baseline' fact) and reports nothing, so the first sync of a
// tenant is not a flood of alerts. Each change is stored in oauth_app_changes
// and audited as oauthapps.change_detected; the oauth_app_change alert rule
// (internal/alerts) raises on that event.

// ActionChangeDetected is the audit action of a detected change.
const ActionChangeDetected = "oauthapps.change_detected"

// grantChange is a grant a sync saw for the first time, saw again after it was
// revoked or removed, or saw with more scopes than before. scopes are the ones
// to report (the added ones for a widened grant).
type grantChange struct {
	g      *store.OAuthGrant
	scopes []string
	why    string // "", "widened" or "granted again"
}

// baseline says how a sync treats an app's first appearance. since is the
// provider's last successful sync (nil: this is the provider's first sync, so
// everything is baseline). existed says the app row was in the inventory
// before this sync, without a baseline fact (it predates change detection).
type baseline struct {
	existed bool
	since   *time.Time
}

// predates reports whether state stamped at t is older than the last sync, so
// the app held it before Tessera last looked. No timestamp means unknown, which
// is reported.
func (b baseline) predates(t *time.Time) bool {
	return b.since != nil && t != nil && !t.After(*b.since)
}

// addedScopes returns the scopes of next that prev lacks, sorted.
func addedScopes(prev, next []string) []string {
	var out []string
	for _, s := range next {
		if !slices.Contains(prev, s) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

// changeNote is what a sync reports on one app.
type changeNote struct {
	kind, subject, summary string
	detail                 ojson.Object
}

// track stores the credentials and owners the provider reports for one app and
// records the changes since the last sync. newGrants are the grants this sync
// saw for the first time, again after a revoke, or widened. It returns the number of changes recorded.
func track(tx *store.TenantTx, app *store.OAuthApp, a *App, newGrants []grantChange, now time.Time, actor string, bl baseline) (int, error) {
	base := &store.OAuthFact{AppID: app.ID, Kind: store.OAuthFactBaseline, Key: "-"}
	first, err := tx.UpsertOAuthFact(base, now)
	if err != nil {
		return 0, err
	}
	known, err := tx.OAuthFactsOf(app.ID)
	if err != nil {
		return 0, err
	}
	// An app first seen after the provider's baseline sync reports what it
	// holds unless that predates the last sync; an app that was already in the
	// inventory before change detection, or any app of the provider's first
	// sync, is silent.
	silent := first && (bl.existed || bl.since == nil)
	fresh := first && !silent
	var notes []changeNote
	stamp := strconv.FormatInt(now.Unix(), 10)
	for _, c := range a.Credentials {
		f := &store.OAuthFact{AppID: app.ID, Kind: c.Kind, Key: c.Key, Label: c.Label, ProviderRef: c.Ref, AddedAt: c.AddedAt}
		isNew, err := tx.UpsertOAuthFact(f, now)
		if err != nil {
			return 0, err
		}
		if isNew && !(fresh && bl.predates(c.AddedAt)) {
			notes = append(notes, changeNote{store.OAuthChangeCredential, f.ID + "@" + stamp,
				fmt.Sprintf("New %s %q added to %s (%s)", c.Kind, c.Label, app.Name, app.Provider),
				ojson.Object{{Key: "fact_id", Value: f.ID}, {Key: "credential_kind", Value: c.Kind}, {Key: "label", Value: c.Label},
					{Key: "added_at", Value: timeText(c.AddedAt)}}})
		}
	}
	seen := map[string]bool{}
	for _, o := range a.Owners {
		seen[o.Ref] = true
		f := &store.OAuthFact{AppID: app.ID, Kind: store.OAuthFactOwner, Key: o.Ref, Label: o.Label, ProviderRef: o.Ref}
		isNew, err := tx.UpsertOAuthFact(f, now)
		if err != nil {
			return 0, err
		}
		if isNew && !fresh {
			notes = append(notes, changeNote{store.OAuthChangeOwner, "added:" + o.Ref + "@" + stamp,
				fmt.Sprintf("%s was added as an owner of %s (%s)", orRef(o), app.Name, app.Provider),
				ojson.Object{{Key: "owner", Value: orRef(o)}, {Key: "change", Value: "added"}}})
		}
	}
	for _, f := range known {
		if f.Kind != store.OAuthFactOwner || f.Status != "active" || seen[f.Key] {
			continue
		}
		if err := tx.SetOAuthFactStatus(f.ID, "removed"); err != nil {
			return 0, err
		}
		notes = append(notes, changeNote{store.OAuthChangeOwner, "removed:" + f.Key + "@" + stamp,
			fmt.Sprintf("%s was removed as an owner of %s (%s)", orStr(f.Label, f.Key), app.Name, app.Provider),
			ojson.Object{{Key: "owner", Value: orStr(f.Label, f.Key)}, {Key: "change", Value: "removed"}}})
	}
	for _, gc := range newGrants {
		g := gc.g
		if g.Kind != KindAppRole && !(g.Kind == KindDelegated && g.ConsentType == ConsentAdmin) {
			continue
		}
		if fresh && bl.predates(g.GrantedAt) {
			continue
		}
		what := "Application permission"
		if g.Kind == KindDelegated {
			what = "Tenant-wide consent"
		}
		scopes := slices.Clone(gc.scopes)
		slices.Sort(scopes)
		summary := fmt.Sprintf("%s %v granted to %s (%s)", what, scopes, app.Name, app.Provider)
		if gc.why != "" {
			summary = fmt.Sprintf("%s %v %s on %s (%s)", what, scopes, gc.why, app.Name, app.Provider)
		}
		notes = append(notes, changeNote{store.OAuthChangePermission, g.ID + ":" + strings.Join(scopes, " ") + "@" + stamp, summary,
			ojson.Object{{Key: "grant_id", Value: g.ID}, {Key: "grant_kind", Value: g.Kind}, {Key: "scopes", Value: scopes}}})
	}
	if silent {
		return 0, nil
	}
	n := 0
	for _, c := range notes {
		detail := append(ojson.Object{{Key: "app_id", Value: app.ID}, {Key: "app", Value: app.Name}, {Key: "provider", Value: app.Provider}}, c.detail...)
		raw, err := json.Marshal(detail)
		if err != nil {
			return n, err
		}
		ch := &store.OAuthChange{AppID: app.ID, Kind: c.kind, Subject: c.subject, Summary: c.summary, Detail: raw, DetectedAt: now}
		ok, err := tx.InsertOAuthChange(ch)
		if err != nil {
			return n, err
		}
		if !ok {
			continue
		}
		n++
		ev := append(ojson.Object{{Key: "change_id", Value: ch.ID}, {Key: "kind", Value: c.kind}, {Key: "summary", Value: c.summary}}, detail...)
		if err := tx.Audit(now, actor, ActionChangeDetected, ev); err != nil {
			return n, err
		}
	}
	return n, nil
}

// resolveChanges closes the open changes of the provider's apps whose subject
// no longer exists: a credential the provider no longer lists, a grant that is
// no longer live. An owner change stays open until a person acknowledges it.
func resolveChanges(tx *store.TenantTx, provider string, now time.Time) error {
	apps, err := tx.OAuthApps()
	if err != nil {
		return err
	}
	byID := map[string]*store.OAuthApp{}
	for _, a := range apps {
		if a.Provider == provider {
			byID[a.ID] = a
		}
	}
	open, err := tx.OpenOAuthChanges()
	if err != nil {
		return err
	}
	for _, c := range open {
		if byID[c.AppID] == nil {
			continue
		}
		var d struct {
			FactID  string `json:"fact_id"`
			GrantID string `json:"grant_id"`
		}
		if json.Unmarshal(c.Detail, &d) != nil {
			continue
		}
		gone, why := false, ""
		switch {
		case c.Kind == store.OAuthChangeCredential && d.FactID != "":
			f, err := tx.OAuthFact(d.FactID)
			gone, why = err == nil && f.Status == "removed", "the credential is no longer on the app"
		case c.Kind == store.OAuthChangePermission && d.GrantID != "":
			g, err := tx.OAuthGrant(d.GrantID)
			gone, why = err == nil && !live(g), "the permission is no longer granted"
		}
		if gone {
			if err := tx.ResolveOAuthChangeID(c.ID, why, now); err != nil {
				return err
			}
		}
	}
	return nil
}

func timeText(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func orRef(o Owner) string { return orStr(o.Label, o.Ref) }

func orStr(v ...string) string {
	if i := slices.IndexFunc(v, func(s string) bool { return s != "" }); i >= 0 {
		return v[i]
	}
	return ""
}
