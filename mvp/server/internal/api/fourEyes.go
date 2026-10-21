package api

import (
	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// sameActor reports whether two platform users are the same admin for a
// four-eyes check: the ids match, or both link to the same identity_id
// (issue #402). Other packages call store.TenantTx.SameActor, which this wraps.
func sameActor(tx *store.TenantTx, a, b uuid.UUID) (bool, error) {
	return tx.SameActor(a.String(), b.String())
}
