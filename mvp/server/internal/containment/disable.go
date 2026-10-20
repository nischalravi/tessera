package containment

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Disable and Enable of an identity.
//
// Disable is containment plus a local decision. The containment run (the same
// steps as the kill switch: revoke sessions, refresh tokens and OAuth grants
// at each connected provider) is built and run by the caller, then Disable
// records, in one transaction, that Tessera treats the person as disabled:
// every active account is set to disabled, the identity's status becomes
// disabled and the audit event is written. Tessera does not suspend the
// account at the provider (there is no provisioning connector for that yet);
// the person is cut off by the revoked sessions and by the graph no longer
// counting a disabled identity's access.
//
// Enable undoes exactly the local part. It sets back the accounts Disable
// disabled and that are still disabled, and the identity status. It cannot
// bring back what was revoked at a provider: sessions, refresh tokens and
// OAuth grants stay revoked, so the person signs in and consents again.

// Disable and enable refusals.
var (
	ErrNotActive   = errors.New("containment: only an active identity can be disabled")
	ErrNotDisabled = errors.New("containment: the identity is not disabled by Tessera")
)

// AccountRef names an account in a result.
type AccountRef struct {
	ID       int64  `json:"id"`
	System   string `json:"system"`
	Username string `json:"username"`
}

// DisableResult is what Disable changed.
type DisableResult struct {
	Disable  *store.IdentityDisable
	Accounts []AccountRef // accounts set to disabled
	// Users are the Tessera users linked to the identity, signed out and
	// blocked from signing in while it is disabled.
	Users           []string
	SessionsRevoked int64
}

// Disable records the disable of identityID in the caller's write transaction.
// status is the roll-up of the containment run that went with it ("none" when
// there was nothing to run). ErrNotActive when the identity is not active.
func Disable(c *store.TenantTx, identityID int64, by, reason, status string, now time.Time) (*DisableResult, error) {
	ident, err := c.Identity(identityID)
	if err != nil {
		return nil, err
	}
	if ident.Status != "active" {
		return nil, ErrNotActive
	}
	accts, err := c.IdentityAccounts(identityID)
	if err != nil {
		return nil, err
	}
	d := &store.IdentityDisable{IdentityID: identityID, Reason: reason, DisabledBy: by, DisabledAt: now, ContainmentStatus: status}
	res := &DisableResult{Disable: d, Accounts: []AccountRef{}}
	for _, a := range accts {
		if a.Status != "active" {
			continue
		}
		if err := c.DisableAccount(a.ID); err != nil {
			return nil, err
		}
		d.AccountIDs = append(d.AccountIDs, a.ID)
		res.Accounts = append(res.Accounts, AccountRef{a.ID, a.System, a.Username})
	}
	if err := c.SetIdentityStatusFrom(identityID, "active", "disabled"); err != nil {
		return nil, err
	}
	if err := c.InsertIdentityDisable(d); err != nil {
		return nil, err
	}
	// The Tessera users linked to the identity lose their sessions now; the
	// sign-in paths and the session middleware refuse them while the identity
	// stays disabled (auth.IdentityInactive).
	users, err := c.UsersLinkedTo(identityID)
	if err != nil {
		return nil, err
	}
	res.Users = []string{}
	for _, u := range users {
		uid, err := uuid.Parse(u)
		if err != nil {
			return nil, err
		}
		n, err := c.RevokeUserSessions(uid, auth.RevokedIdentityDisabled, now)
		if err != nil {
			return nil, err
		}
		res.Users = append(res.Users, u)
		res.SessionsRevoked += n
	}
	return res, c.Audit(now, by, "identity.disable", ojson.Object{{Key: "identity_id", Value: identityID},
		{Key: "identity", Value: ident.Name}, {Key: "reason", Value: reason}, {Key: "disable_id", Value: d.ID},
		{Key: "accounts_disabled", Value: len(res.Accounts)}, {Key: "containment", Value: status},
		{Key: "linked_users", Value: res.Users}, {Key: "sessions_revoked", Value: res.SessionsRevoked}})
}

// EnableResult is what Enable changed and what it could not.
type EnableResult struct {
	Disable  *store.IdentityDisable
	Restored []AccountRef // accounts set back to active
	Skipped  []AccountRef // accounts that were no longer disabled (changed since by something else)
}

// RefuseSelfDisable: the caller is a Tessera user linked to the identity they
// tried to disable, which would sign them out and lock them out (#335).
const RefuseSelfDisable = "self_disable_not_allowed"

// DisableRefusal reports why byUser may not disable identityID, or "" when
// they may. Nobody disables the identity their own Tessera user is linked to:
// another admin must (#335).
func DisableRefusal(identityID int64, byUser *store.PlatformUser) string {
	if byUser != nil && byUser.IdentityID != nil && *byUser.IdentityID == identityID {
		return RefuseSelfDisable
	}
	return ""
}

// Enable refusals (separation of duties, #316).
const (
	// RefuseSelfEnable: the caller is a Tessera user linked to the identity.
	RefuseSelfEnable = "self_enable_not_allowed"
	// RefuseFourEyes: enabling would give a linked Tessera user their sign-in
	// back, which (like an admin change that widens access) needs a second
	// person, and the caller is the one who disabled it.
	RefuseFourEyes = "four_eyes_required"
)

// EnableRefusal reports why the caller may not enable identityID, or "" when
// they may. byUser is the caller's platform user (nil for a non-user
// principal) and by the actor name Disable recorded as disabled_by.
//
//   - Nobody linked to the identity may enable it (no self re-enable).
//   - When the identity is linked to a Tessera user, enabling restores their
//     sign-in, so four eyes apply: the person who disabled it cannot also
//     enable it. An identity with no linked user only gets its local account
//     status back, and its disabler may undo their own disable.
func EnableRefusal(c *store.TenantTx, identityID int64, byUser *store.PlatformUser, by string) (string, error) {
	if byUser != nil && byUser.IdentityID != nil && *byUser.IdentityID == identityID {
		return RefuseSelfEnable, nil
	}
	d, err := c.OpenIdentityDisable(identityID)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil // Enable reports ErrNotDisabled
	}
	if err != nil {
		return "", err
	}
	linked, err := c.UsersLinkedTo(identityID)
	if err != nil {
		return "", err
	}
	if len(linked) > 0 && d.DisabledBy == by {
		return RefuseFourEyes, nil
	}
	return "", nil
}

// Enable undoes Disable in the caller's write transaction. ErrNotDisabled
// when the identity has no open disable.
func Enable(c *store.TenantTx, identityID int64, by, reason string, now time.Time) (*EnableResult, error) {
	ident, err := c.Identity(identityID)
	if err != nil {
		return nil, err
	}
	d, err := c.OpenIdentityDisable(identityID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && ident.Status != "disabled") {
		return nil, ErrNotDisabled
	}
	if err != nil {
		return nil, err
	}
	res := &EnableResult{Disable: d, Restored: []AccountRef{}, Skipped: []AccountRef{}}
	for _, id := range d.AccountIDs {
		a, err := c.Account(id)
		if err != nil {
			return nil, err
		}
		ref := AccountRef{a.ID, a.System, a.Username}
		ok, err := c.EnableAccount(id)
		if err != nil {
			return nil, err
		}
		if ok {
			res.Restored = append(res.Restored, ref)
		} else {
			res.Skipped = append(res.Skipped, ref)
		}
	}
	if err := c.SetIdentityStatusFrom(identityID, "disabled", "active"); err != nil {
		return nil, err
	}
	if err := c.CloseIdentityDisable(d.ID, by, reason, now); err != nil {
		return nil, err
	}
	d.EnabledBy, d.EnabledAt, d.EnableReason = &by, &now, &reason
	return res, c.Audit(now, by, "identity.enable", ojson.Object{{Key: "identity_id", Value: identityID},
		{Key: "identity", Value: ident.Name}, {Key: "reason", Value: reason}, {Key: "disable_id", Value: d.ID},
		{Key: "accounts_restored", Value: len(res.Restored)}, {Key: "accounts_skipped", Value: len(res.Skipped)}})
}
