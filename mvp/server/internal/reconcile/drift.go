package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The drift engine (issue #301) compares intended access (what Tessera decided
// someone should have: store.IntendedGrant) with observed access (what the
// connectors last reported: store.ObservedEntitlement) and keeps one
// store.AccessDrift row per difference:
//
//	missing  intended and active, but the system does not show it
//	rogue    the system shows it, and there is no intent for it
//	orphan   the system shows an account that belongs to no identity
//	stale    the system shows it, and the intent for it has ended
//
// A run is idempotent: it opens a row for a new difference, reopens one that
// came back, resolves one that is gone, and writes nothing for one that did not
// change. Remediation follows the tenant's policy for the difference (see
// store.RemediationPolicy): auto-provision and auto-revoke go through the
// provisioning engine, an owner task goes to the Inbox, report-only records and
// stops. Without a policy the action is report-only. Every action is audited in
// the transaction of the run.
//
// The engine reads intent and observation and writes only drift rows (and, by
// policy, provisioning operations and notifications); it never creates intent
// and never creates an observation.

// Name of the provisioning completion that removes the grant edge of a revoked entitlement.
const completeDriftRevoke = "drift.revoke"

// SourceDrift is the provisioning source of an operation a drift policy queued.
const sourceDrift = provision.SourceDrift

func init() {
	provision.RegisterCompletion(completeDriftRevoke, func(tx *store.TenantTx, now time.Time, raw json.RawMessage) error {
		var d struct {
			EdgeID int64 `json:"edge_id"`
		}
		if err := json.Unmarshal(raw, &d); err != nil {
			return err
		}
		return tx.RevokeEdge(d.EdgeID, now, "drift") // a no-op when the edge is already gone
	})
}

// DriftRun is what one run changed.
type DriftRun struct {
	Opened, Reopened, Updated, Resolved int
	// Actions counts remediation actions taken (report-only is a record, not an action).
	Actions int
}

// Changed reports whether the run wrote anything.
func (r DriftRun) Changed() bool {
	return r.Opened+r.Reopened+r.Updated+r.Resolved+r.Actions > 0
}

// Error is a caller error (maps to HTTP 4xx).
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

type candidate struct {
	key, class, system, kind, ref, accountRef string
	accountID, identityID, observedID, owner  *int64
	intendedID                                *string
}

func entKey(kind, system, ref string) string { return kind + "|" + system + "|" + ref }

func i64(v int64) *int64 { return &v }

func sameInt(a, b *int64) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func sameStr(a, b *string) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

// RunDrift classifies the differences between intended and observed access
// of the transaction's tenant and remediates them by policy. actor names the
// caller in audit events ("system" for a sync or the sweeper).
func RunDrift(tx *store.TenantTx, now time.Time, actor string) (DriftRun, error) {
	var res DriftRun
	if _, err := tx.BackfillAccessModel(now); err != nil {
		return res, err
	}
	cands, err := classify(tx, now)
	if err != nil {
		return res, err
	}
	existing, err := tx.AccessDrifts(store.DriftFilter{})
	if err != nil {
		return res, err
	}
	rows := make(map[string]*store.AccessDrift, len(existing))
	for _, d := range existing {
		rows[d.Key] = d
	}
	seen := map[string]bool{}
	keys := make([]string, 0, len(cands))
	for k := range cands {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c := cands[k]
		seen[k] = true
		d := rows[k]
		switch {
		case d == nil:
			d = &store.AccessDrift{ID: store.NewID(), Key: k, Class: c.class, System: c.system, EntitlementKind: c.kind,
				EntitlementRef: c.ref, AccountRef: c.accountRef, AccountID: c.accountID, IdentityID: c.identityID,
				IntendedID: c.intendedID, ObservedID: c.observedID, OwnerIdentityID: c.owner, Status: store.DriftOpen,
				DetectedAt: now, UpdatedAt: now, Action: store.ActionNone}
			d.TenantID = tx.Tenant()
			if _, err := tx.InsertAccessDrift(d); err != nil {
				return res, err
			}
			rows[k] = d
			res.Opened++
		case d.Status == store.DriftResolved:
			setRefs(d, c)
			d.Status, d.ResolvedAt, d.DetectedAt, d.UpdatedAt = store.DriftOpen, nil, now, now
			d.Action, d.RemediationRef, d.RemediationNote, d.RemediationAt = store.ActionNone, nil, nil, nil
			d.AcceptedBy, d.AcceptedReason = nil, nil
			if err := tx.UpdateAccessDrift(d); err != nil {
				return res, err
			}
			res.Reopened++
		case refsDiffer(d, c):
			setRefs(d, c)
			d.UpdatedAt = now
			if err := tx.UpdateAccessDrift(d); err != nil {
				return res, err
			}
			res.Updated++
		}
	}
	for _, d := range existing {
		if seen[d.Key] || d.Status == store.DriftResolved {
			continue
		}
		d.Status, d.ResolvedAt, d.UpdatedAt = store.DriftResolved, &now, now
		if err := tx.UpdateAccessDrift(d); err != nil {
			return res, err
		}
		res.Resolved++
	}
	n, err := remediate(tx, now, actor, rows)
	res.Actions = n
	return res, err
}

func setRefs(d *store.AccessDrift, c *candidate) {
	d.AccountID, d.IdentityID, d.IntendedID, d.ObservedID, d.OwnerIdentityID = c.accountID, c.identityID, c.intendedID,
		c.observedID, c.owner
}

func refsDiffer(d *store.AccessDrift, c *candidate) bool {
	return !sameInt(d.AccountID, c.accountID) || !sameInt(d.IdentityID, c.identityID) || !sameStr(d.IntendedID, c.intendedID) ||
		!sameInt(d.ObservedID, c.observedID) || !sameInt(d.OwnerIdentityID, c.owner)
}

// classify returns the differences that exist now, by drift key.
func classify(tx *store.TenantTx, now time.Time) (map[string]*candidate, error) {
	obs, err := tx.ObservedEntitlements()
	if err != nil {
		return nil, err
	}
	intended, err := tx.IntendedGrants()
	if err != nil {
		return nil, err
	}
	runs, err := tx.ObservedRuns()
	if err != nil {
		return nil, err
	}
	idents, err := tx.Identities()
	if err != nil {
		return nil, err
	}
	owners := map[int64]*int64{}
	for _, i := range idents {
		o := i.OwnerID
		if o == nil {
			o = i.ManagerID
		}
		owners[i.ID] = o
	}
	runAt := map[string]time.Time{}
	for _, r := range runs {
		if r.ObservedAt.After(runAt[r.System]) {
			runAt[r.System] = r.ObservedAt
		}
	}
	type pair struct{ active, ended *store.IntendedGrant }
	byIdent := map[string]*pair{}
	for _, g := range intended {
		k := strconv.FormatInt(g.IdentityID, 10) + "|" + entKey(g.TargetKind, g.TargetSystem, g.TargetRef)
		p := byIdent[k]
		if p == nil {
			p = &pair{}
			byIdent[k] = p
		}
		switch {
		case g.Active(now):
			if p.active == nil {
				p.active = g
			}
		case g.ClosedAt != nil || (g.ValidUntil != nil && !g.ValidUntil.After(now)):
			if p.ended == nil || endedAt(g).After(endedAt(p.ended)) {
				p.ended = g
			}
		}
	}
	out := map[string]*candidate{}
	present := map[string]bool{}
	for _, o := range obs {
		if o.IdentityID == nil {
			k := "orphan|" + o.System + "|" + o.AccountRef
			if _, dup := out[k]; !dup {
				out[k] = &candidate{key: k, class: store.DriftOrphan, system: o.System, kind: o.EntitlementKind,
					accountRef: o.AccountRef, accountID: o.AccountID, observedID: i64(o.ID)}
			}
			continue
		}
		ik := strconv.FormatInt(*o.IdentityID, 10) + "|" + entKey(o.EntitlementKind, o.EntitlementSystem, o.EntitlementRef)
		present[ik] = true
		p := byIdent[ik]
		if p != nil && p.active != nil {
			continue
		}
		c := &candidate{system: o.System, kind: o.EntitlementKind, ref: o.EntitlementRef, accountRef: o.AccountRef,
			accountID: o.AccountID, identityID: o.IdentityID, observedID: i64(o.ID), owner: owners[*o.IdentityID]}
		sk := o.System + "|" + o.AccountRef + "|" + entKey(o.EntitlementKind, o.EntitlementSystem, o.EntitlementRef)
		if p != nil && p.ended != nil {
			c.class, c.key, c.intendedID, c.owner = store.DriftStale, "stale|"+sk, &p.ended.ID, firstOwner(p.ended.OwnerIdentityID, c.owner)
		} else {
			c.class, c.key = store.DriftRogue, "rogue|"+sk
		}
		out[c.key] = c
	}
	for ik, p := range byIdent {
		g := p.active
		if g == nil || present[ik] {
			continue
		}
		at, ok := runAt[g.TargetSystem]
		if !ok || g.CreatedAt.After(at) { // the system was never read, or not since this was granted
			continue
		}
		c := &candidate{key: "missing|" + ik, class: store.DriftMissing, system: g.TargetSystem, kind: g.TargetKind,
			ref: g.TargetRef, accountID: g.AccountID, identityID: i64(g.IdentityID), intendedID: &g.ID,
			owner: firstOwner(g.OwnerIdentityID, owners[g.IdentityID])}
		out[c.key] = c
	}
	return out, nil
}

func endedAt(g *store.IntendedGrant) time.Time {
	if g.ClosedAt != nil {
		return *g.ClosedAt
	}
	if g.ValidUntil != nil {
		return *g.ValidUntil
	}
	return g.CreatedAt
}

func firstOwner(a, b *int64) *int64 {
	if a != nil {
		return a
	}
	return b
}

// ---------------------------------------------------------------- remediation

// PolicyAction is the action the tenant's policies give a class of drift on an
// entitlement of a system: the entitlement's own policy, else the system's,
// else report-only.
func PolicyAction(policies []*store.RemediationPolicy, class, system, ref string) string {
	sys := ""
	for _, p := range policies {
		if p.DriftClass != class || p.System != system {
			continue
		}
		if p.EntitlementRef != "" && p.EntitlementRef == ref {
			return p.Action
		}
		if p.EntitlementRef == "" {
			sys = p.Action
		}
	}
	if sys != "" {
		return sys
	}
	return store.ActionReportOnly
}

// ValidAction reports whether an action makes sense for a class: provisioning
// puts back what is missing, revoking takes away what should not be there.
func ValidAction(class, action string) bool {
	switch action {
	case store.ActionOwnerTask, store.ActionReportOnly:
		return true
	case store.ActionAutoProvision:
		return class == store.DriftMissing
	case store.ActionAutoRevoke:
		return class != store.DriftMissing
	}
	return false
}

// remediate applies the policy to every open row whose action is not the
// policy's yet, and settles the rows whose provisioning operation ended.
func remediate(tx *store.TenantTx, now time.Time, actor string, rows map[string]*store.AccessDrift) (int, error) {
	policies, err := tx.RemediationPolicies()
	if err != nil {
		return 0, err
	}
	keys := make([]string, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	acted := 0
	for _, k := range keys {
		d := rows[k]
		switch d.Status {
		case store.DriftRemediating:
			if err := settle(tx, now, actor, d); err != nil {
				return acted, err
			}
			if d.Status == store.DriftOpen { // the operation did not take: fall back to a task
				done, err := apply(tx, now, actor, d, store.ActionOwnerTask)
				if err != nil {
					return acted, err
				}
				if done {
					acted++
				}
			}
		case store.DriftOpen:
			want := PolicyAction(policies, d.Class, d.System, d.EntitlementRef)
			if !ValidAction(d.Class, want) {
				want = store.ActionReportOnly
			}
			if want == d.Action {
				continue
			}
			done, err := apply(tx, now, actor, d, want)
			if err != nil {
				return acted, err
			}
			if done {
				acted++
			}
		}
	}
	return acted, nil
}

// settle looks at the provisioning operation of a remediating row: one that
// failed, mismatched or was cancelled puts the row back to open.
func settle(tx *store.TenantTx, now time.Time, actor string, d *store.AccessDrift) error {
	if d.RemediationRef == nil || d.Action == store.ActionOwnerTask {
		return nil
	}
	op, err := tx.ProvOp(*d.RemediationRef)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	switch op.Status {
	case provision.Failed, provision.Mismatch, provision.Cancelled:
		note := "the " + op.Kind + " operation ended " + op.Status
		d.Status, d.UpdatedAt, d.RemediationNote = store.DriftOpen, now, &note
		d.Action = store.ActionNone
		return tx.UpdateAccessDrift(d)
	}
	return nil
}

// apply performs an action on a drift row, records it on the row and audits
// it. It reports whether an action (not just a record) was taken.
func apply(tx *store.TenantTx, now time.Time, actor string, d *store.AccessDrift, action string) (bool, error) {
	note, ref, status, took := "", "", d.Status, false
	var err error
	switch action {
	case store.ActionReportOnly:
		note = "recorded; no remediation policy applies"
	case store.ActionOwnerTask:
		note, ref, status, err = ownerTask(tx, now, d)
		took = true
	case store.ActionAutoProvision, store.ActionAutoRevoke:
		var routed bool
		note, ref, routed, err = autoChange(tx, now, d, action)
		took = true
		if err == nil && !routed { // nothing can write to the system: ask a person
			var fnote string
			fnote, ref, status, err = ownerTask(tx, now, d)
			note = note + "; " + fnote
			action = store.ActionOwnerTask
		} else if err == nil {
			status = store.DriftRemediating
		}
	default:
		return false, fmt.Errorf("reconcile: unknown action %q", action)
	}
	if err != nil {
		return false, err
	}
	d.Action, d.Status, d.UpdatedAt, d.RemediationAt = action, status, now, &now
	d.RemediationNote = &note
	d.RemediationRef = nil
	if ref != "" {
		d.RemediationRef = &ref
	}
	if err := tx.UpdateAccessDrift(d); err != nil {
		return false, err
	}
	if !took {
		return false, nil
	}
	return true, tx.Audit(now, actor, "drift.remediate", ojson.Object{{Key: "drift_id", Value: d.ID},
		{Key: "class", Value: d.Class}, {Key: "system", Value: d.System}, {Key: "entitlement", Value: d.EntitlementRef},
		{Key: "action", Value: action}, {Key: "status", Value: status}, {Key: "reference", Value: ref}, {Key: "note", Value: note}})
}

// ownerTask puts a task in the Inbox of the drift's owner, or of the people
// who decide access when it has none.
func ownerTask(tx *store.TenantTx, now time.Time, d *store.AccessDrift) (note, ref string, status string, err error) {
	var to []notify.Recipient
	if d.OwnerIdentityID != nil {
		if to, err = notify.Identity(tx, *d.OwnerIdentityID); err != nil {
			return "", "", "", err
		}
	}
	who := "the owner"
	if len(to) == 0 {
		who = "the access deciders"
		if to, err = notify.Deciders(tx, now); err != nil {
			return "", "", "", err
		}
	}
	ref = "drift:" + d.ID + ":" + strconv.FormatInt(d.DetectedAt.Unix(), 10)
	subject := "Access drift: " + d.Class + " access in " + d.System
	body := "Reconciliation found " + d.Class + " access (" + describe(d) + "). Review it in Governance, Drift."
	n, err := notify.SecurityAlert(tx, now, ref, clip(subject, notify.MaxSubject), clip(body, notify.MaxBody), "/governance/drift", to...)
	if err != nil {
		return "", "", "", err
	}
	if n == 0 && len(to) == 0 {
		return "no one to tell: the drift stays open", ref, store.DriftOpen, nil
	}
	return "task sent to " + who, ref, store.DriftRemediating, nil
}

func describe(d *store.AccessDrift) string {
	parts := []string{d.Class}
	if d.AccountRef != "" {
		parts = append(parts, "account "+d.AccountRef)
	}
	if d.EntitlementRef != "" {
		parts = append(parts, d.EntitlementRef)
	}
	return strings.Join(parts[1:], ", ")
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// autoChange queues the provisioning operation of an auto action. It reports
// routed=false, with the reason as the note, when the system has no write-back
// connection (or the drift lacks what the operation needs).
func autoChange(tx *store.TenantTx, now time.Time, d *store.AccessDrift, action string) (note, ref string, routed bool, err error) {
	t, err := provision.Route(tx, d.System)
	if err != nil {
		return "", "", false, err
	}
	if t == nil {
		return "no write-back connection for " + d.System, "", false, nil
	}
	var acct *store.Account
	if d.AccountID != nil {
		if acct, err = tx.Account(*d.AccountID); errors.Is(err, store.ErrNotFound) {
			acct, err = nil, nil
		} else if err != nil {
			return "", "", false, err
		}
	}
	var grp *store.Group
	if d.EntitlementRef != "" {
		if grp, err = groupOf(tx, d.System, d.EntitlementRef); err != nil {
			return "", "", false, err
		}
	}
	key := "drift:" + d.ID + ":" + strconv.FormatInt(d.DetectedAt.Unix(), 10) + ":" + action
	ch := provision.Change{System: d.System, Source: sourceDrift, Key: key, NoRequeue: true}
	switch {
	case action == store.ActionAutoProvision:
		if acct == nil && d.IdentityID != nil {
			if acct, err = activeAccount(tx, *d.IdentityID, d.System); err != nil {
				return "", "", false, err
			}
		}
		if acct == nil || grp == nil {
			return "no account or entitlement to provision", "", false, nil
		}
		ch.Kind = target.AddEntitlement
	case d.Class == store.DriftOrphan:
		if acct == nil {
			return "the orphan account is unknown", "", false, nil
		}
		ch.Kind, ch.Completion, ch.Data = target.DisableAccount, provision.CompleteAccountDisable, provision.AccountData{AccountID: acct.ID}
	default: // revoke rogue or stale access
		if acct == nil || grp == nil {
			return "no account or entitlement to revoke", "", false, nil
		}
		ch.Kind = target.RemoveEntitlement
		src, dst := "account:"+strconv.FormatInt(acct.ID, 10), "group:"+strconv.FormatInt(grp.ID, 10)
		if e, err := tx.EdgeBetween(src, dst); err == nil {
			ch.Completion, ch.Data = completeDriftRevoke, struct {
				EdgeID int64 `json:"edge_id"`
			}{e.ID}
		} else if !errors.Is(err, store.ErrNotFound) {
			return "", "", false, err
		}
	}
	ch.Account = target.Account{Username: acct.Username, ExternalID: acct.ExternalID}
	if grp != nil {
		ch.Group = target.Group{ExternalID: grp.ExternalID, Name: grp.Name}
	}
	op, err := provision.Enqueue(tx, now, t.ConnectionID, ch)
	if err != nil {
		return "", "", false, err
	}
	return "queued " + op.Kind + " operation " + op.ID, op.ID, true, nil
}

func groupOf(tx *store.TenantTx, system, ref string) (*store.Group, error) {
	gs, err := tx.Groups()
	if err != nil {
		return nil, err
	}
	for _, g := range gs {
		if g.System == system && g.ExternalID == ref {
			return g, nil
		}
	}
	return nil, nil
}

func activeAccount(tx *store.TenantTx, identity int64, system string) (*store.Account, error) {
	as, err := tx.IdentityAccounts(identity)
	if err != nil {
		return nil, err
	}
	for _, a := range as {
		if a.System == system && a.Status == "active" {
			return a, nil
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------- operator actions

// Remediate applies an action to one drift row at an operator's request,
// whatever the policy says. The row must be open.
func Remediate(tx *store.TenantTx, now time.Time, actor, id, action string) (*store.AccessDrift, error) {
	d, err := tx.AccessDrift(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &Error{404, "not_found", "no such drift"}
	}
	if err != nil {
		return nil, err
	}
	if !ValidAction(d.Class, action) {
		return nil, &Error{400, "invalid_action", action + " does not apply to " + d.Class + " drift"}
	}
	if d.Status != store.DriftOpen {
		return nil, &Error{409, "not_open", "only open drift can be remediated (this one is " + d.Status + ")"}
	}
	if _, err := apply(tx, now, actor, d, action); err != nil {
		return nil, err
	}
	return tx.AccessDrift(id)
}

// Accept records a person's decision to accept the risk of a difference.
func Accept(tx *store.TenantTx, now time.Time, actor, id, reason string) (*store.AccessDrift, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len([]rune(reason)) > 500 {
		return nil, &Error{400, "invalid_reason", "a reason of at most 500 characters is required"}
	}
	d, err := tx.AccessDrift(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &Error{404, "not_found", "no such drift"}
	}
	if err != nil {
		return nil, err
	}
	if d.Status != store.DriftOpen && d.Status != store.DriftRemediating {
		return nil, &Error{409, "not_acceptable", "only open drift can be accepted (this one is " + d.Status + ")"}
	}
	d.Status, d.AcceptedBy, d.AcceptedReason, d.UpdatedAt = store.DriftAccepted, &actor, &reason, now
	if err := tx.UpdateAccessDrift(d); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, actor, "drift.accept", ojson.Object{{Key: "drift_id", Value: d.ID}, {Key: "class", Value: d.Class},
		{Key: "system", Value: d.System}, {Key: "entitlement", Value: d.EntitlementRef}, {Key: "reason", Value: reason}}); err != nil {
		return nil, err
	}
	return d, nil
}

// ---------------------------------------------------------------- schedule

// SweepDrift runs the engine for every active tenant, each in its own
// transaction. A failure in one tenant does not stop the others; the errors
// come back joined (store.ForEachActiveTenant's contract).
func SweepDrift(ctx context.Context, db *store.DB, now time.Time, actor string) error {
	return db.ForEachActiveTenant(ctx, func(_ context.Context, tx *store.TenantTx) error {
		_, err := RunDrift(tx, now, actor)
		return err
	})
}
