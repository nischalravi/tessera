package provision

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Completions of the engine's own: plain graph edits.
const (
	CompleteEdgeRemove     = "graph.edge_remove"
	CompleteAccountDisable = "graph.account_disable"
	CompleteGrantRevoke    = "grant.revoke"
	// CompleteAccountDelete marks an account deleted once the target confirms the
	// delete (the guest lifecycle's grace period, issue #74).
	CompleteAccountDelete = "graph.account_delete"
)

// EdgeData is the argument of CompleteEdgeRemove.
type EdgeData struct {
	EdgeID int64 `json:"edge_id"`
}

// AccountData is the argument of CompleteAccountDisable.
type AccountData struct {
	AccountID int64 `json:"account_id"`
}

// GrantRevokeData is the argument of CompleteGrantRevoke (the least-privilege
// revoke): it removes the edge and writes the grant.revoke audit event the
// direct path writes.
type GrantRevokeData struct {
	EdgeID             int64  `json:"edge_id"`
	Grant              string `json:"grant"`
	PermissionsRemoved int    `json:"permissions_removed"`
}

func init() {
	// Removals leave a revoked_grants tombstone, like the direct paths, so a
	// connector sync does not bring the grant back (UAT #134).
	RegisterCompletion(CompleteEdgeRemove, func(tx *store.TenantTx, now time.Time, raw json.RawMessage) error {
		var d EdgeData
		if err := json.Unmarshal(raw, &d); err != nil {
			return err
		}
		return tx.RevokeEdge(d.EdgeID, now, "jml")
	})
	RegisterCompletion(CompleteAccountDisable, func(tx *store.TenantTx, _ time.Time, raw json.RawMessage) error {
		var d AccountData
		if err := json.Unmarshal(raw, &d); err != nil {
			return err
		}
		return tx.DisableAccount(d.AccountID)
	})
	RegisterCompletion(CompleteAccountDelete, func(tx *store.TenantTx, _ time.Time, raw json.RawMessage) error {
		var d AccountData
		if err := json.Unmarshal(raw, &d); err != nil {
			return err
		}
		return tx.SetAccountStatus(d.AccountID, "deleted")
	})
	RegisterCompletion(CompleteGrantRevoke, func(tx *store.TenantTx, now time.Time, raw json.RawMessage) error {
		var d GrantRevokeData
		if err := json.Unmarshal(raw, &d); err != nil {
			return err
		}
		if _, err := tx.Edge(d.EdgeID); errors.Is(err, store.ErrNotFound) {
			return nil // already gone
		} else if err != nil {
			return err
		}
		if err := tx.Audit(now, "system", "grant.revoke", ojson.Object{{Key: "edge_id", Value: d.EdgeID},
			{Key: "grant", Value: d.Grant}, {Key: "permissions_removed", Value: d.PermissionsRemoved}}); err != nil {
			return err
		}
		return tx.RevokeEdge(d.EdgeID, now, "least-privilege")
	})
}
