package erp

import (
	"context"
	"errors"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

// Target is the provisioning target of an ERP: it assigns and removes roles.
// The entitlement is Group.ExternalID, the role id Discover emits;
// Account.Username is the ERP user. Accounts are not created, changed or
// disabled here: an ERP's users come from its own identity management.
type Target struct{ S System }

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	var nf *NotFoundError
	var se *connsync.StatusError
	switch {
	case errors.As(err, &nf):
		return target.Permanent("%s: %v", op, err)
	case errors.As(err, &se):
		return target.Fail(op, se.Status, se.Code)
	}
	return target.Transport(op, err)
}

func holds(u *User, role string) bool {
	if u == nil {
		return false
	}
	for _, a := range u.Roles {
		if a.Role == role {
			return true
		}
	}
	return false
}

func checkKind(r target.Request) error {
	if r.Kind != target.AddEntitlement && r.Kind != target.RemoveEntitlement {
		return target.Permanent("%s is not supported by an ERP target: only role assignment is", r.Kind)
	}
	if r.Group.ExternalID == "" {
		return target.Permanent("the entitlement needs a role id")
	}
	return nil
}

// Apply sends the change. It reads first: adding a held role or removing one not held does nothing.
func (t *Target) Apply(ctx context.Context, r target.Request) error {
	if err := checkKind(r); err != nil {
		return err
	}
	u, err := t.S.User(ctx, r.Account.Username)
	if err != nil {
		return wrap("read user", err)
	}
	if u == nil && r.Kind == target.AddEntitlement {
		return target.Permanent("add role: %s has no user %s", t.S.Vendor(), r.Account.Username)
	}
	have := holds(u, r.Group.ExternalID)
	switch {
	case r.Kind == target.AddEntitlement && !have:
		return wrap("add role", t.S.AssignRole(ctx, r.Account.Username, r.Group.ExternalID))
	case r.Kind == target.RemoveEntitlement && have:
		return wrap("remove role", t.S.RemoveRole(ctx, r.Account.Username, r.Group.ExternalID))
	}
	return nil
}

// Verify re-reads the user.
func (t *Target) Verify(ctx context.Context, r target.Request) (target.Verdict, error) {
	if err := checkKind(r); err != nil {
		return target.Verdict{}, err
	}
	u, err := t.S.User(ctx, r.Account.Username)
	if err != nil {
		return target.Verdict{}, wrap("read user", err)
	}
	have := holds(u, r.Group.ExternalID)
	obs := "does not hold the role"
	if have {
		obs = "holds the role"
	}
	if r.Kind == target.AddEntitlement {
		return target.Verdict{OK: have, Expected: "holds the role", Observed: obs}, nil
	}
	return target.Verdict{OK: !have, Expected: "does not hold the role", Observed: obs}, nil
}
