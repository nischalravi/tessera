package roles

import (
	"errors"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Birthright exclusions (issue #214). A reviewer who revokes a rule member
// cannot remove the person while the rule still matches them, so the person
// goes on the role's exclusion list: birthright evaluation (every save and
// Reconcile) skips them, and the rule membership is removed with the grants
// only it justified. The list is versioned per role, every add and removal
// takes the next version, rows are never deleted, and each change is an
// audit event in the caller's transaction.

// excludedVersion is the role's current exclusion-list version (0: never changed).
func excludedVersion(xs []*store.RoleExclusion) int {
	v := 0
	for _, x := range xs {
		v = max(v, x.Version)
		if x.RemovedVersion != nil {
			v = max(v, *x.RemovedVersion)
		}
	}
	return v
}

// Exclude puts a person on a role's exclusion list. A rule member is removed
// from the role with the grants no other role justifies (the plan, as for
// Unassign); a person who holds the role another way keeps it. reviewItemID
// links the review decision that asked for it (nil: none). A dry run returns
// the plan and changes nothing.
func Exclude(tx *store.TenantTx, id string, identityID int64, reason string, reviewItemID *int64, by Actor, dryRun bool,
	now time.Time) (*Result, error) {
	rp, err := reasonPtr(reason, true)
	if err != nil {
		return nil, err
	}
	w, err := load(tx, now)
	if err != nil {
		return nil, err
	}
	r, err := w.active(id)
	if err != nil {
		return nil, err
	}
	rule, err := ParseRule(r.Birthright)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, refuse(409, "no_rule", "%s has no birthright rule to exclude anyone from", r.Name)
	}
	person, err := w.identity(identityID)
	if err != nil {
		return nil, err
	}
	if person == nil {
		return nil, refuse(404, "identity_not_found", "person not found")
	}
	if w.excluded[id][identityID] {
		return nil, refuse(409, "already_excluded", "%s is already excluded from %s", person.Name, r.Name)
	}
	before := snapshotMembers(w)
	if m, ok := w.members[identityID][id]; ok && m.Source == store.MemberRule {
		w.drop(id, identityID)
	}
	p, err := w.plan(before)
	if err != nil {
		return nil, err
	}
	p.DryRun = dryRun
	if dryRun {
		return w.result(r, p), nil
	}
	hist, err := tx.RoleExclusions(id)
	if err != nil {
		return nil, err
	}
	ver := excludedVersion(hist) + 1
	if err := tx.InsertRoleExclusion(&store.RoleExclusion{RoleID: id, IdentityID: identityID, Reason: *rp, Version: ver,
		ExcludedBy: uidp(by), ExcludedActor: by.Display, ExcludedAt: now, ReviewItemID: reviewItemID}); err != nil {
		return nil, err
	}
	if err := w.finish(before, p); err != nil {
		return nil, err
	}
	rd, err := roleDetail(r, p)
	if err != nil {
		return nil, err
	}
	d := append(rd, ojson.KV{Key: "identity_id", Value: identityID},
		ojson.KV{Key: "exclusion_version", Value: ver}, ojson.KV{Key: "reason", Value: *rp})
	if reviewItemID != nil {
		d = append(d, ojson.KV{Key: "review_item_id", Value: *reviewItemID})
	}
	return w.result(r, p), tx.Audit(now, by.Display, "role.exclude", d)
}

// Unexclude takes a person off the exclusion list. It does not assign the
// role: the next save or Reconcile does, if the rule still matches them.
func Unexclude(tx *store.TenantTx, id string, identityID int64, reason string, by Actor, now time.Time) (int, error) {
	rp, err := reasonPtr(reason, true)
	if err != nil {
		return 0, err
	}
	if _, err := tx.BusinessRole(id); errors.Is(err, store.ErrNotFound) {
		return 0, refuse(404, "role_not_found", "role not found")
	} else if err != nil {
		return 0, err
	}
	hist, err := tx.RoleExclusions(id)
	if err != nil {
		return 0, err
	}
	ver := excludedVersion(hist) + 1
	err = tx.RemoveRoleExclusion(id, identityID, ver, now, uidp(by), *rp)
	if errors.Is(err, store.ErrNotFound) {
		return 0, refuse(404, "not_excluded", "the person is not on the exclusion list")
	}
	if err != nil {
		return 0, err
	}
	return ver, tx.Audit(now, by.Display, "role.unexclude", ojson.Object{{Key: "role_id", Value: id},
		{Key: "identity_id", Value: identityID}, {Key: "exclusion_version", Value: ver}, {Key: "reason", Value: *rp}})
}

// Justification is a role that grants a person a group.
type Justification struct {
	Role   *store.BusinessRole
	Member *store.RoleMember
}

// Justifying returns the person's active roles that grant the group: why a
// "role" grant edge exists. None means the edge is no longer justified.
func Justifying(tx *store.TenantTx, identityID, groupID int64, now time.Time) ([]Justification, error) {
	w, err := load(tx, now)
	if err != nil {
		return nil, err
	}
	var out []Justification
	for _, rid := range sortedKeys(w.members[identityID], nil) {
		r := w.roles[rid]
		if r == nil || r.Status != store.RoleActive {
			continue
		}
		for _, g := range w.ents[rid] {
			if g == groupID {
				out = append(out, Justification{r, w.members[identityID][rid]})
				break
			}
		}
	}
	return out, nil
}
