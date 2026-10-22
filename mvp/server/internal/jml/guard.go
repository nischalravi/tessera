package jml

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The deletion threshold guard (internal/deleteguard) for leavers: ending an identity counts
// against the identities threshold, and disabling an account here (an app with no connector to
// route to) against the accounts threshold.

// Kinds of the items the leaver paths hold.
const (
	ItemLeaver         = "identity_leaver"
	ItemAccountDisable = "account_disable"
)

// guardLeaver vets ending an active identity; held says it was held and must be left as it is.
func guardLeaver(c *store.TenantTx, now time.Time, ident *store.Identity) (held bool, err error) {
	// leavers of one hour join one hold, so a bad feed that ends hundreds is one decision
	d, err := deleteguard.AdmitFrom(c, now, deleteguard.CatIdentities, deleteguard.SourceLifecycle, "leaver", "leaver:"+now.UTC().Format("2006-01-02T15"),
		deleteguard.Item{Kind: ItemLeaver, Ref: strconv.FormatInt(ident.ID, 10), Label: fmt.Sprintf("%s (%s) ends as a leaver", ident.Name, ident.ExternalID)})
	if err != nil {
		return false, err
	}
	return len(d.Held) > 0, nil
}

func guardAccountDisable(c *store.TenantTx, now time.Time, accountID int64) (held bool, err error) {
	a, err := getOrNil(c.Account(accountID))
	if err != nil || a == nil || a.Status != "active" {
		return false, err
	}
	d, err := deleteguard.AdmitFrom(c, now, deleteguard.CatAccounts, deleteguard.SourceLifecycle, "leaver", "leaver-accounts:"+now.UTC().Format("2006-01-02T15"),
		deleteguard.Item{Kind: ItemAccountDisable, Ref: strconv.FormatInt(accountID, 10), Label: fmt.Sprintf("account %s in %s (leaver)", a.Username, a.System)})
	if err != nil {
		return false, err
	}
	return len(d.Held) > 0, nil
}

// ReleaseLeaver applies a held leaver: the whole leaver plan runs and the identity is ended,
// if it is still active.
func ReleaseLeaver(c *store.TenantTx, now time.Time, it *store.DeletionHoldItem) (outcome, note string, err error) {
	id, err := strconv.ParseInt(it.Ref, 10, 64)
	if err != nil {
		return "", "", fmt.Errorf("jml: bad held leaver %q", it.Ref)
	}
	ident, err := c.Identity(id)
	if errors.Is(err, store.ErrNotFound) {
		return deleteguard.ItemGone, "the identity no longer exists", nil
	}
	if err != nil {
		return "", "", err
	}
	if ident.Status != "active" {
		return deleteguard.ItemGone, "the identity is already " + ident.Status, nil
	}
	if _, err := ExecuteLeaver(c, now, id); err != nil {
		return "", "", err
	}
	return deleteguard.ItemReleased, "", nil
}

// ReleaseAccountDisable applies a held account disable, if the account is still active.
func ReleaseAccountDisable(c *store.TenantTx, now time.Time, it *store.DeletionHoldItem) (outcome, note string, err error) {
	id, err := strconv.ParseInt(it.Ref, 10, 64)
	if err != nil {
		return "", "", fmt.Errorf("jml: bad held account %q", it.Ref)
	}
	a, err := getOrNil(c.Account(id))
	if err != nil {
		return "", "", err
	}
	if a == nil {
		return deleteguard.ItemGone, "the account no longer exists", nil
	}
	if a.Status != "active" {
		return deleteguard.ItemGone, "the account is already " + a.Status, nil
	}
	if err := c.DisableAccount(id); err != nil {
		return "", "", err
	}
	return deleteguard.ItemReleased, "", flatfile.AccountDisabled(c, now, "system", id, "leaver")
}
