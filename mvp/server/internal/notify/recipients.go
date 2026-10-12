package notify

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func emailOf(e *string) string {
	if e == nil {
		return ""
	}
	return strings.TrimSpace(*e)
}

// User is the recipient for an active platform user; false if there is none.
func User(tx *store.TenantTx, userID string) (Recipient, bool, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return Recipient{}, false, nil
	}
	u, err := tx.PlatformUser(id)
	if errors.Is(err, store.ErrNotFound) || err == nil && u.Status != "active" {
		return Recipient{}, false, nil
	} else if err != nil {
		return Recipient{}, false, err
	}
	return Recipient{UserID: userID, Email: emailOf(u.Email)}, true, nil
}

// Identity returns the recipients for an active identity: each active
// platform user who is that person (they see it in the bell), or, when
// nobody signs in as them, the identity itself, reached at its email address.
func Identity(tx *store.TenantTx, identityID int64) ([]Recipient, error) {
	ident, err := tx.Identity(identityID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if ident.Status != "active" {
		return nil, nil
	}
	users, err := tx.UsersLinkedTo(identityID)
	if err != nil {
		return nil, err
	}
	var out []Recipient
	for _, u := range users {
		if r, ok, err := User(tx, u); err != nil {
			return nil, err
		} else if ok {
			out = append(out, r)
		}
	}
	if len(out) == 0 && emailOf(ident.Email) != "" {
		out = append(out, Recipient{IdentityID: identityID, Email: emailOf(ident.Email)})
	}
	return out, nil
}

// identityUsers returns the active platform users who are the identity.
func identityUsers(tx *store.TenantTx, identityID int64) ([]string, error) {
	return tx.UsersLinkedTo(identityID)
}

// deciderRoles are the roles whose permissions include requests.decide.
func deciderRoles() []string {
	var out []string
	for _, r := range auth.AllRoles() {
		if slices.Contains(auth.RolePermissions(r), auth.PermRequestsDecide) {
			out = append(out, string(r))
		}
	}
	return out
}

// Deciders returns the recipients for every active user who holds
// requests.decide through an unexpired role.
func Deciders(tx *store.TenantTx, now time.Time) ([]Recipient, error) {
	roles, err := tx.ActiveUserRoles(now)
	if err != nil {
		return nil, err
	}
	want := deciderRoles()
	var out []Recipient
	seen := map[string]bool{}
	for _, ur := range roles {
		if !slices.Contains(want, ur.Role) || seen[ur.UserID] {
			continue
		}
		seen[ur.UserID] = true
		if r, ok, err := User(tx, ur.UserID); err != nil {
			return nil, err
		} else if ok {
			out = append(out, r)
		}
	}
	return out, nil
}
