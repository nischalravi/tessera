package privs

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// ErrNoUser is the reason a background job cannot act as a platform user: the
// user no longer exists or can no longer sign in.
var ErrNoUser = errors.New("the user is no longer an active user")

// SubjectOfUser is the privilege subject of a platform user at now, for work
// that acts in the background on the authority of whoever saved it (a rule, an
// attestation or deprovisioning setting, a scheduled report): the identity the
// user is linked to, and tenant_admin when the user holds that role (assigned
// and unexpired: there is no session whose step-up could activate it).
func SubjectOfUser(tx *store.TenantTx, userID string, now time.Time) (Subject, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return Subject{}, ErrNoUser
	}
	u, err := tx.PlatformUser(id)
	if errors.Is(err, store.ErrNotFound) {
		return Subject{}, ErrNoUser
	}
	if err != nil {
		return Subject{}, err
	}
	if u.Status != "active" {
		return Subject{}, ErrNoUser
	}
	as, err := tx.RoleAssignments(u.ID)
	if err != nil {
		return Subject{}, err
	}
	return Subject{Identity: u.IdentityID, TenantAdmin: auth.AssignedRoles(as, now).Has(auth.RoleTenantAdmin)}, nil
}
