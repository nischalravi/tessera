package oauthapps

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Service reads and revokes OAuth apps with the credentials of identity
// containment. Without a Containment service (or without its outbound client)
// nothing can be called: a sync skips every provider.
type Service struct {
	Containment *containment.Service
	Clock       timeutil.Clock
	// Budget bounds the provider calls of one revoke (default 20s).
	Budget time.Duration
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return timeutil.System()
}

func (s *Service) budget() time.Duration {
	if s.Budget > 0 {
		return s.Budget
	}
	return 20 * time.Second
}

// provider builds the reader of one provider from a stored credential.
func (s *Service) provider(name string, cred *containment.Credential) (Provider, error) {
	if s.Containment == nil {
		return nil, errors.New("containment is not configured")
	}
	hc, sleep := s.Containment.Outbound()
	if hc == nil {
		return nil, errors.New("outbound HTTP is not configured")
	}
	return New(name, hc, *cred, sleep)
}

// credential returns the provider's credential, or why there is none.
func (s *Service) credential(ctx context.Context, db *store.DB, tenant tenancy.ID, name string) (*containment.Credential, string, error) {
	if s.Containment == nil {
		return nil, "containment is not configured", nil
	}
	var cred *containment.Credential
	var why string
	err := db.ReadTenant(ctx, tenant, func(tx *store.TenantTx) error {
		var err error
		cred, why, err = s.Containment.CredentialFor(tx, name)
		return err
	})
	return cred, why, err
}

// Sync statuses.
const (
	SyncOK      = "ok"
	SyncFailed  = "failed"
	SyncSkipped = "skipped" // no live connection or credential: nothing was called and nothing stored
)

// ProviderReport is the result of one provider's sync.
type ProviderReport struct {
	Provider string   `json:"provider"`
	Status   string   `json:"status"`
	Apps     int      `json:"apps"`
	Grants   int      `json:"grants"`
	Removed  int      `json:"removed"`
	Error    string   `json:"error,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

// SyncReport is the result of a sync.
type SyncReport struct {
	Providers []ProviderReport `json:"providers"`
}

// Changed reports whether any provider was read or failed (a sync that skipped
// every provider did nothing worth a job run).
func (r *SyncReport) Changed() bool {
	for _, p := range r.Providers {
		if p.Status != SyncSkipped {
			return true
		}
	}
	return false
}

// Sync refreshes the inventory of the named providers (all when none). Each
// provider is read with no transaction open, then its snapshot is applied in
// one transaction, so a read that fails part-way never replaces what is stored:
// the failure is recorded in the provider's sync state and the audit ledger.
func (s *Service) Sync(ctx context.Context, db *store.DB, tenant tenancy.ID, actor string, only ...string) (*SyncReport, error) {
	rep := &SyncReport{}
	for _, name := range Providers {
		if len(only) > 0 && !slices.Contains(only, name) {
			continue
		}
		pr := ProviderReport{Provider: name}
		cred, why, err := s.credential(ctx, db, tenant, name)
		if err != nil {
			return rep, err
		}
		if cred == nil {
			pr.Status, pr.Error = SyncSkipped, why
			rep.Providers = append(rep.Providers, pr)
			continue
		}
		started := s.now()
		var snap *Snapshot
		prov, err := s.provider(name, cred)
		if err == nil {
			snap, err = prov.Read(ctx)
		}
		if err != nil {
			pr.Status, pr.Error = SyncFailed, errText(err)
			if werr := db.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
				return recordFailure(tx, name, started, pr.Error, actor)
			}); werr != nil {
				return rep, werr
			}
			rep.Providers = append(rep.Providers, pr)
			continue
		}
		err = db.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
			var aerr error
			pr, aerr = Apply(tx, snap, s.now(), actor)
			return aerr
		})
		if err != nil {
			return rep, err
		}
		rep.Providers = append(rep.Providers, pr)
	}
	return rep, nil
}

func recordFailure(tx *store.TenantTx, provider string, at time.Time, msg, actor string) error {
	if err := tx.PutOAuthSyncState(&store.OAuthSyncState{Provider: provider, Status: "failed", AttemptedAt: at, Error: msg}); err != nil {
		return err
	}
	return tx.Audit(at, actor, "oauthapps.sync_failed", ojson.Object{{Key: "provider", Value: provider}, {Key: "error", Value: msg}})
}

func errText(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "the provider did not answer in time"
	}
	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

// Apply stores a complete snapshot of one provider in the caller's
// transaction: upserts apps and grants, marks the grants the snapshot no
// longer holds as removed, correlates each granting user to an account and
// identity, scores each app, defaults its owner, records the sync state and
// audits it.
func Apply(tx *store.TenantTx, snap *Snapshot, now time.Time, actor string) (ProviderReport, error) {
	pr := ProviderReport{Provider: snap.Provider, Status: SyncOK, Notes: snap.Notes}
	accounts, err := tx.AccountsBySystemUsername(&snap.Provider)
	if err != nil {
		return pr, err
	}
	byName, byXID := map[string]*store.Account{}, map[string]*store.Account{}
	for _, a := range accounts {
		byName[strings.ToLower(a.Username)] = a
		byXID[a.ExternalID] = a
	}
	for _, a := range snap.Apps {
		app := &store.OAuthApp{Provider: snap.Provider, ClientID: a.ClientID, Name: a.Name, Publisher: a.Publisher,
			Verified: a.Verified, LastUsed: a.LastUsed}
		if err := tx.UpsertOAuthApp(app, now); err != nil {
			return pr, err
		}
		for _, g := range a.Grants {
			row := &store.OAuthGrant{AppID: app.ID, Provider: snap.Provider, GrantKey: g.Key, ProviderRef: g.Ref, Kind: g.Kind,
				UserRef: g.UserRef, GranterAdmin: g.GranterAdmin, Scopes: g.Scopes, ConsentType: g.Consent, GrantedAt: g.GrantedAt,
				LastUsed: g.LastUsed}
			if row.Scopes == nil {
				row.Scopes = []string{}
			}
			acct := byXID[g.UserRef]
			if acct == nil && g.UserEmail != "" {
				acct = byName[strings.ToLower(g.UserEmail)]
			}
			if acct != nil {
				id := acct.ID
				row.AccountID, row.IdentityID = &id, acct.IdentityID
			}
			if err := tx.UpsertOAuthGrant(row, now); err != nil {
				return pr, err
			}
			pr.Grants++
		}
		pr.Apps++
	}
	if pr.Removed, err = tx.RemoveUnseenOAuthGrants(snap.Provider, now); err != nil {
		return pr, err
	}
	apps, err := tx.OAuthApps()
	if err != nil {
		return pr, err
	}
	for _, app := range apps {
		if app.Provider != snap.Provider {
			continue
		}
		if err := Refresh(tx, app, now); err != nil {
			return pr, err
		}
	}
	if err := tx.PutOAuthSyncState(&store.OAuthSyncState{Provider: snap.Provider, Status: "ok", AttemptedAt: now, SucceededAt: &now,
		Apps: pr.Apps, Grants: pr.Grants, Removed: pr.Removed}); err != nil {
		return pr, err
	}
	return pr, tx.Audit(now, actor, "oauthapps.synced", ojson.Object{{Key: "provider", Value: snap.Provider},
		{Key: "apps", Value: pr.Apps}, {Key: "grants", Value: pr.Grants}, {Key: "removed", Value: pr.Removed},
		{Key: "catalog_version", Value: CatalogVersion}})
}

// live reports whether a grant still exists at the provider as far as Tessera knows.
func live(g *store.OAuthGrant) bool {
	return g.Status == store.OAuthActive || g.Status == store.OAuthRevokeFailed
}

// AssessApp scores an app from its live grants and returns how many there are.
func AssessApp(app *store.OAuthApp, grants []*store.OAuthGrant, now time.Time) (Assessment, int) {
	var scopes []string
	users := map[string]bool{}
	admin := false
	lastUsed := app.LastUsed
	n := 0
	for _, g := range grants {
		if !live(g) {
			continue
		}
		n++
		scopes = append(scopes, g.Scopes...)
		if u := g.UserRef; u != "" {
			users[u] = true
		}
		admin = admin || g.ConsentType == ConsentAdmin
		lastUsed = later(lastUsed, g.LastUsed)
	}
	return Assess(Subject{Provider: app.Provider, Scopes: scopes, Verified: app.Verified, AdminGrant: admin, LastUsed: lastUsed,
		Users: len(users)}, now), n
}

// Refresh recomputes the app's risk and status from its grants, and defaults
// its owner to the identity that granted first.
func Refresh(tx *store.TenantTx, app *store.OAuthApp, now time.Time) error {
	grants, err := tx.OAuthGrantsOf(app.ID)
	if err != nil {
		return err
	}
	as, n := AssessApp(app, grants, now)
	status := store.OAuthActive
	if n == 0 {
		status = store.OAuthRemoved
	}
	lastUsed := app.LastUsed
	for _, g := range grants {
		if live(g) {
			lastUsed = later(lastUsed, g.LastUsed)
		}
	}
	if err := tx.SetOAuthAppRisk(app.ID, as.Score, as.Reasons, lastUsed, status); err != nil {
		return err
	}
	if app.OwnerIdentityID != nil {
		return nil
	}
	var first *store.OAuthGrant
	for _, g := range grants {
		if !live(g) || g.IdentityID == nil {
			continue
		}
		if first == nil || (g.GrantedAt != nil && (first.GrantedAt == nil || g.GrantedAt.Before(*first.GrantedAt))) {
			first = g
		}
	}
	if first != nil {
		return tx.DefaultOAuthAppOwner(app.ID, *first.IdentityID)
	}
	return nil
}
