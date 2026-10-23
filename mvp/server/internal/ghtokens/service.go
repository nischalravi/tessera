package ghtokens

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Service reads the organization with the GitHub credential of identity
// containment (the same token, base URL and safehttp client the OAuth app
// inventory uses). Without a Containment service nothing is called.
type Service struct {
	Containment *containment.Service
	Clock       timeutil.Clock
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return timeutil.System()
}

// Sync statuses.
const (
	SyncOK      = "ok"
	SyncFailed  = "failed"
	SyncSkipped = "skipped" // no live GitHub connection or credential: nothing was called
)

// Report is the result of a sync.
type Report struct {
	Status string   `json:"status"`
	Tokens int      `json:"tokens"`
	Error  string   `json:"error,omitempty"`
	Notes  []string `json:"notes,omitempty"`
}

// Sync reads the organization with no transaction open, then applies the
// snapshot in one transaction, so a read that fails part-way never replaces
// what is stored: the failure is audited and the old inventory stays.
func (s *Service) Sync(ctx context.Context, db *store.DB, tenant tenancy.ID, actor string) (*Report, error) {
	if s.Containment == nil {
		return &Report{Status: SyncSkipped, Error: "containment is not configured"}, nil
	}
	var cred *containment.Credential
	var why string
	if err := db.ReadTenant(ctx, tenant, func(tx *store.TenantTx) error {
		var err error
		cred, why, err = s.Containment.CredentialFor(tx, System)
		return err
	}); err != nil {
		return nil, err
	}
	if cred == nil {
		return &Report{Status: SyncSkipped, Error: why}, nil
	}
	snap, err := s.read(ctx, cred)
	if err != nil {
		rep := &Report{Status: SyncFailed, Error: errText(err)}
		if werr := db.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
			return tx.Audit(s.now(), actor, "ghtokens.sync_failed", ojson.Object{{Key: "error", Value: rep.Error}})
		}); werr != nil {
			return rep, werr
		}
		return rep, nil
	}
	var rep *Report
	err = db.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		var aerr error
		rep, aerr = Apply(tx, snap, s.now(), actor)
		return aerr
	})
	return rep, err
}

func (s *Service) read(ctx context.Context, cred *containment.Credential) (*Snapshot, error) {
	hc, sleep := s.Containment.Outbound()
	if hc == nil {
		return nil, errors.New("outbound HTTP is not configured")
	}
	c, err := containment.NewClient(hc, cred.BaseURL, DefaultAPIURL, "Bearer", cred.Token, sleep)
	if err != nil {
		return nil, err
	}
	r, err := NewReader(c, cred.Org)
	if err != nil {
		return nil, err
	}
	return r.Read(ctx)
}

func errText(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "GitHub did not answer in time"
	}
	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

// Apply stores a complete snapshot in the caller's transaction: it upserts the
// credentials, correlates each owner login to a GitHub account and identity,
// marks the credentials the snapshot no longer holds as removed, and audits it.
func Apply(tx *store.TenantTx, snap *Snapshot, now time.Time, actor string) (*Report, error) {
	system := System
	accounts, err := tx.AccountsBySystemUsername(&system)
	if err != nil {
		return nil, err
	}
	byLogin := map[string]*store.Account{}
	for _, a := range accounts {
		byLogin[strings.ToLower(a.Username)] = a
	}
	rep := &Report{Status: SyncOK, Notes: snap.Notes}
	for _, t := range snap.Tokens {
		row := &store.GitHubToken{Key: t.Key, Kind: t.Kind, Name: t.Name, OwnerLogin: t.OwnerLogin, Scopes: t.Scopes,
			Visibility: t.Visibility, CreatedAt: t.CreatedAt, RotatedAt: t.RotatedAt, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt}
		if a := byLogin[strings.ToLower(t.OwnerLogin)]; a != nil && t.OwnerLogin != "" {
			row.OwnerIdentityID = a.IdentityID
		}
		if err := tx.UpsertGitHubToken(row, now); err != nil {
			return nil, err
		}
		rep.Tokens++
	}
	if err := tx.RemoveUnseenGitHubTokens(now); err != nil {
		return nil, err
	}
	return rep, tx.Audit(now, actor, "ghtokens.synced", ojson.Object{{Key: "tokens", Value: rep.Tokens}})
}
