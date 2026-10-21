package store

import (
	"errors"

	"github.com/google/uuid"
)

// SameActor reports whether two platform user ids are the same admin for a
// four-eyes rule (issue #402): the ids match, or both users are linked to the
// same identity. One person can hold several platform users (sign-in makes one
// per IdP connection and subject), so comparing ids alone lets them approve
// their own request from a second account. An id that is not a platform user's
// (a service key, say) is the same actor only as itself. It reads
// platform_users through the tenant-scoped handle.
func (tx *TenantTx) SameActor(a, b string) (bool, error) {
	if a == b {
		return true, nil
	}
	ua, err := uuid.Parse(a)
	if err != nil {
		return false, nil
	}
	ub, err := uuid.Parse(b)
	if err != nil {
		return false, nil
	}
	pa, err := tx.PlatformUser(ua)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	pb, err := tx.PlatformUser(ub)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return pa.IdentityID != nil && pb.IdentityID != nil && *pa.IdentityID == *pb.IdentityID, nil
}
