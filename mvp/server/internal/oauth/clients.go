package oauth

import (
	"context"
	"errors"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// CLIScopes are the scopes the first-party CLI may ask for. What a token can
// do is still the intersection of the user's active roles and its scopes
// (§12.3), so asking for tessera:admin gives a non-admin nothing.
var CLIScopes = []string{"tessera:read", "tessera:write", "tessera:audit", "tessera:admin"}

// EnsureCLIClient creates the tenant's first-party CLI client (a public
// client: no secret, DPoP always required) if it does not exist. It never
// changes an existing client, so an operator's disabling of it stays.
func EnsureCLIClient(tx *store.TenantTx, now time.Time) error {
	_, err := tx.APIClientByClientID(CLIClientID)
	if err == nil || !errors.Is(err, store.ErrNotFound) {
		return err
	}
	err = tx.InsertAPIClient(&store.APIClient{ClientID: CLIClientID, Name: "Tessera CLI", Kind: store.ClientFirstPartyCLI,
		GrantTypes: []string{GrantDeviceCode, GrantRefresh}, TokenEndpointAuthMethod: "none", DPoPRequired: true,
		AllowedScopes: CLIScopes, Status: store.ClientActive, CreatedAt: now.UTC()})
	if errors.Is(err, store.ErrDuplicate) {
		return nil
	}
	return err
}

// EnsureCLIClients gives every active tenant its CLI client (server start and
// the daily key loop, next to keys.EnsureAll).
func EnsureCLIClients(ctx context.Context, db *store.DB, now time.Time) error {
	return db.ForEachActiveTenant(ctx, func(_ context.Context, tx *store.TenantTx) error {
		return EnsureCLIClient(tx, now)
	})
}
