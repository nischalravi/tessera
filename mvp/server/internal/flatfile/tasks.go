package flatfile

import (
	"errors"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Error is a refusal the caller turns into a 4xx answer.
type Error struct{ Code, Msg string }

func (e *Error) Error() string { return e.Msg }

// Errors the API answers specifically.
var (
	ErrNoMapping   = &Error{"no_mapping", "this app has no column mapping yet"}
	ErrTaskNotOpen = &Error{"task_not_open", "the task is already closed"}
)

// Task kinds.
const (
	TaskDisableAccount    = "disable_account"
	TaskRemoveEntitlement = "remove_entitlement"
)

// entPrefix starts the external id of the permission an entitlement becomes.
const entPrefix = "ent:"

// EntitlementPermXID is the external id of an entitlement's permission.
func EntitlementPermXID(code string) string { return entPrefix + code }

// isApp reports whether system is a disconnected app (has a saved mapping).
func isApp(c *store.TenantTx, system string) (bool, error) {
	_, err := c.FlatMapping(system)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// AccountDisabled is called where Tessera disables an account (a leaver
// plan). Tessera cannot disable an account of a disconnected app, so it
// opens a manual task, in the caller's transaction. Accounts of any other
// system are not its business.
func AccountDisabled(c *store.TenantTx, now time.Time, by string, accountID int64, trigger string) error {
	a, err := c.Account(accountID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if ok, err := isApp(c, a.System); err != nil || !ok {
		return err
	}
	return openTask(c, now, by, a, TaskDisableAccount, "", trigger)
}

// GrantRevoked is called before Tessera revokes a grant edge (a leaver plan,
// an access review, a least-privilege revoke). When the edge is an entitlement
// of a disconnected app's account, it opens a manual task to remove it there.
// An account that already has an open disable task needs no second task.
func GrantRevoked(c *store.TenantTx, now time.Time, by string, edgeID int64, trigger string) error {
	e, err := c.Edge(edgeID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	sk, sid, err := graph.ParseKey(e.Src)
	if err != nil || sk != "account" {
		return nil
	}
	dk, did, err := graph.ParseKey(e.Dst)
	if err != nil || dk != "perm" {
		return nil
	}
	a, err := c.Account(sid)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if ok, err := isApp(c, a.System); err != nil || !ok {
		return err
	}
	p, err := c.Permission(did)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if p.System != a.System || !strings.HasPrefix(p.ExternalID, entPrefix) {
		return nil
	}
	if _, err := c.OpenFlatTask(a.ID, TaskDisableAccount, ""); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return openTask(c, now, by, a, TaskRemoveEntitlement, strings.TrimPrefix(p.ExternalID, entPrefix), trigger)
}

func openTask(c *store.TenantTx, now time.Time, by string, a *store.Account, kind, entitlement, trigger string) error {
	if _, err := c.OpenFlatTask(a.ID, kind, entitlement); err == nil {
		return nil // already open
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	t := &store.FlatTask{System: a.System, Kind: kind, AccountID: a.ID, AccountXID: a.ExternalID, AccountLabel: a.Username,
		Entitlement: entitlement, IdentityID: a.IdentityID, Trigger: trigger, CreatedBy: by, CreatedAt: now}
	if err := c.InsertFlatTask(t); err != nil {
		return err
	}
	return c.Audit(now, by, "flatfile.task_created", ojson.Object{{Key: "task_id", Value: t.ID}, {Key: "system", Value: t.System},
		{Key: "kind", Value: kind}, {Key: "account", Value: a.ExternalID}, {Key: "entitlement", Value: entitlement},
		{Key: "trigger", Value: trigger}})
}

// CloseTask closes an open task by hand, with the reason a person gives (the
// access was already removed, or the task does not apply). The usual end of a
// task is the next import confirming the access is gone; closing by hand is
// recorded as such, with who and why.
func CloseTask(c *store.TenantTx, now time.Time, by, id, reason string) (*store.FlatTask, error) {
	t, err := c.FlatTask(id)
	if err != nil {
		return nil, err
	}
	if t.Status != store.FlatTaskOpen {
		return nil, ErrTaskNotOpen
	}
	if err := c.CloseFlatTask(id, store.FlatTaskClosed, by, now, reason, nil); err != nil {
		return nil, err
	}
	if err := c.Audit(now, by, "flatfile.task_closed", ojson.Object{{Key: "task_id", Value: t.ID}, {Key: "system", Value: t.System},
		{Key: "kind", Value: t.Kind}, {Key: "account", Value: t.AccountXID}, {Key: "entitlement", Value: t.Entitlement},
		{Key: "reason", Value: reason}}); err != nil {
		return nil, err
	}
	return c.FlatTask(id)
}

// dueTasks are the open tasks of system that the snapshots, as an upload of
// kind leaves them, show done. An accounts upload is evidence about accounts
// (and, when an account is gone, about its entitlements); an entitlements
// upload only about entitlements. A disabled account counts as gone.
func dueTasks(open []*store.FlatTask, kind string, accounts map[string]string, ents map[string]bool) []*store.FlatTask {
	var due []*store.FlatTask
	for _, t := range open {
		status, present := accounts[t.AccountXID]
		gone := !present || status == "disabled"
		switch {
		case t.Kind == TaskDisableAccount && kind == KindAccounts && gone:
			due = append(due, t)
		case t.Kind == TaskRemoveEntitlement && kind == KindAccounts && !present:
			due = append(due, t)
		case t.Kind == TaskRemoveEntitlement && kind == KindEntitlements && !ents[EntitlementKey(t.AccountXID, t.Entitlement)]:
			due = append(due, t)
		}
	}
	return due
}
