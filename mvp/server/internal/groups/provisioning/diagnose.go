package provisioning

import (
	"context"
	"errors"
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Diagnostics (G-68): why a group or an identity will or will not be
// provisioned, and the exact ops a sync would produce for the group, without
// applying them.

// DiagOp is one op a sync would run.
type DiagOp struct {
	Op     OpKind              `json:"op"`
	Group  string              `json:"group"`
	Attrs  map[string][]string `json:"attrs,omitempty"`
	Add    []string            `json:"add,omitempty"`
	Remove []string            `json:"remove,omitempty"`
	// More is how many adds and removes were left out of the lists (they show at most 100 each).
	More int `json:"more,omitempty"`
}

// DiagIdentity explains one identity's part in the group.
type DiagIdentity struct {
	IdentityID int64 `json:"identity_id"`
	// Member: the identity is an effective member of the group.
	Member bool `json:"member"`
	// Account says whether the identity has an active account in the target system.
	Account bool `json:"account"`
	// Reference is the member reference its account translates to.
	Reference string `json:"reference,omitempty"`
	// OnTarget: the reference is a member of the group on the target.
	OnTarget *bool  `json:"on_target,omitempty"`
	Verdict  string `json:"verdict"`
}

// Diagnosis is the answer of Diagnose.
type Diagnosis struct {
	GroupID     string        `json:"group_id"`
	Group       string        `json:"group"`
	Provisioned bool          `json:"provisioned"`
	Why         string        `json:"why"`
	Mode        string        `json:"mode"`
	TargetName  string        `json:"target_name,omitempty"`
	Owned       string        `json:"owned_status,omitempty"`
	Members     int           `json:"desired_members"`
	Unmapped    int           `json:"unmapped_members"`
	Identity    *DiagIdentity `json:"identity,omitempty"`
	Ops         []DiagOp      `json:"ops"`
	Notes       []string      `json:"notes"`
	// WouldApply says whether the ops would be applied in the provisioner's
	// current mode (adopt and dry_run record them and change nothing).
	WouldApply bool `json:"would_apply"`
}

const diagList = 100

// Diagnose explains a group (and optionally one identity) for a provisioner.
// The only network call is a targeted read of the group.
func (s *Service) Diagnose(ctx context.Context, tenant tenancy.ID, id, groupID string, identity int64) (*Diagnosis, error) {
	d := &Diagnosis{GroupID: groupID, Ops: []DiagOp{}, Notes: []string{}}
	var snap *snapshot
	var cov Coverage
	var owned *store.SyncGroup
	var ident *DiagIdentity
	err := s.DB.ReadTenant(ctx, tenant, func(tx *store.TenantTx) error {
		p, err := tx.Provisioner(id)
		if err != nil {
			return err
		}
		cc, err := ParseCommon(p.Config)
		if err != nil {
			return err
		}
		sec, err := s.openSecret(tenant, p)
		if err != nil {
			return err
		}
		g, err := tx.GrpGroup(store.GroupID(groupID))
		if err != nil {
			return err
		}
		d.Group, d.Mode = g.Name, p.Mode
		res, err := NewResolver(tx, id)
		if err != nil {
			return err
		}
		cov = res.Resolve(g)
		des := newDesired()
		if g.Status != store.GroupDeleted {
			if des, err = Compute(tx, p, cc, map[string]bool{groupID: true}); err != nil {
				return err
			}
		}
		if sg, err := tx.SyncGroup(id, groupID); err == nil {
			owned = sg
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		snap = &snapshot{prov: p, cc: cc, secret: sec, desired: des, owned: map[string]*store.SyncGroup{}, ownedKey: map[string]string{}}
		if owned != nil {
			snap.owned[groupID] = owned
			if owned.Status != "removed" && owned.TargetName != "" {
				snap.ownedKey[Key(owned.TargetName)] = groupID
			}
		}
		if identity > 0 {
			ident = &DiagIdentity{IdentityID: identity}
			if _, err := tx.Identity(identity); err != nil {
				return err
			}
			sup, err := tx.GrpEffectiveSupport(g.ID, store.MembersListID(tenant), identity)
			if err != nil {
				return err
			}
			ident.Member = sup > 0 && g.Status == store.GroupActive
			accts, err := accountsBySystem(tx, cc.AccountSystem)
			if err != nil {
				return err
			}
			if a := accts[identity]; a != nil {
				ident.Account = true
				if ident.Reference, err = cc.Member(MemberData{IdentityID: identity, Username: a.Username, ExternalID: a.ExternalID}); err != nil {
					ident.Reference = ""
					d.Notes = append(d.Notes, "member_ref failed for this identity: "+err.Error())
				}
			}
		}
		if g.Status == store.GroupDeleted {
			d.Why = "the group is deleted"
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	dg := snap.desired.ByGroup[groupID]
	switch {
	case d.Why != "":
	case !cov.Include && cov.Why == "no mark":
		d.Why = "no mark covers this group: mark the group, or a folder above it with scope sub (or one for its own groups)"
	case !cov.Include:
		d.Why = "excluded: " + cov.Why + " has include=false"
	case containsStr(snap.desired.Deferred, groupID):
		d.Why = "covered by the " + cov.Why + ", but the engine is still recomputing its membership: it is left alone until that finishes"
	case snap.desired.Errors[groupID] != "":
		d.Why = "covered by the " + cov.Why + ", but a template failed: " + snap.desired.Errors[groupID]
	case dg == nil:
		d.Why = "covered by the " + cov.Why + ", but its target name collides with another group's: neither is provisioned"
	default:
		d.Provisioned = true
		d.Why = "covered by the " + cov.Why
		d.TargetName, d.Members, d.Unmapped = dg.Name, len(dg.Members), len(dg.Unmapped)
		if dg.Unmapped != nil {
			d.Notes = append(d.Notes, fmt.Sprintf("%d member(s) have no active account in %q and cannot be provisioned", len(dg.Unmapped), snap.cc.AccountSystem))
		}
	}
	if owned != nil {
		d.Owned = owned.Status
	}
	d.WouldApply = snap.prov.Mode == store.ProvModeActive
	if !d.Provisioned && (owned == nil || owned.Status == "removed") {
		s.finishIdentity(d, ident, nil)
		return d, nil
	}
	// the targeted read, and the ops it leads to
	spec := TargetSpec{Tenant: tenant, ProvisionerID: id, Type: snap.prov.TargetType, Common: snap.cc, Secret: snap.secret, Deps: s.Deps}
	target, err := s.open(ctx, spec)
	if err != nil {
		d.Notes = append(d.Notes, "the target could not be opened: "+truncate(err.Error(), 200))
		s.finishIdentity(d, ident, nil)
		return d, nil
	}
	defer target.Close()
	caps := target.Capabilities()
	var ref TargetRef
	if d.Provisioned {
		ref = TargetRef{Name: dg.Name}
		if owned != nil && owned.Status != "removed" && Key(owned.TargetName) == Key(dg.Name) {
			ref.ID = owned.TargetID
		}
	} else {
		ref = TargetRef{Name: owned.TargetName, ID: owned.TargetID}
	}
	var ag *TargetGroup
	if caps.Readable {
		st, err := target.Read(ctx, []TargetRef{ref})
		if err != nil {
			d.Notes = append(d.Notes, "the target could not be read: "+truncate(err.Error(), 200))
			s.finishIdentity(d, ident, nil)
			return d, nil
		}
		ag = st.Groups[Key(ref.Name)]
	} else {
		d.Notes = append(d.Notes, "this target cannot be read back: the ops are planned against the last state it acknowledged, and sync results stay \"applied\"")
		if owned != nil && owned.StateCache != nil {
			ag = groupFromCache(ref, owned)
		}
	}
	var plan []*PlannedOp
	if d.Provisioned {
		plan = planGroup(caps, dg, ag, ref)
	} else {
		plan = planDelete(caps, groupID, ref, ag)
		d.Notes = append(d.Notes, "the group is not provisioned any more but the provisioner still owns it on the target: a sync would remove it")
	}
	for _, po := range plan {
		op := DiagOp{Op: po.Op.Kind, Group: po.Op.Ref.Name, Attrs: po.Op.Attrs}
		op.Add, op.Remove = capList(po.Op.Add, &op.More), capList(po.Op.Remove, &op.More)
		d.Ops = append(d.Ops, op)
	}
	if len(plan) == 0 {
		d.Notes = append(d.Notes, "the target already matches: a sync would change nothing")
	}
	if snap.prov.Mode != store.ProvModeActive {
		d.Notes = append(d.Notes, fmt.Sprintf("the provisioner is in %s mode: a sync records these ops and applies none", snap.prov.Mode))
	}
	s.finishIdentity(d, ident, ag)
	return d, nil
}

func (s *Service) finishIdentity(d *Diagnosis, ident *DiagIdentity, ag *TargetGroup) {
	if ident == nil {
		return
	}
	if ag != nil && ident.Reference != "" {
		on := false
		for _, m := range ag.Members {
			if NormMember(m) == NormMember(ident.Reference) {
				on = true
			}
		}
		ident.OnTarget = &on
	}
	switch {
	case !d.Provisioned:
		ident.Verdict = "the group is not provisioned, so nothing is written for this identity"
	case !ident.Member:
		ident.Verdict = "the identity is not a member of the group, so it is not provisioned into it"
	case !ident.Account:
		ident.Verdict = "the identity is a member but has no active account in the target system: it cannot be provisioned until it has one"
	case ident.OnTarget != nil && *ident.OnTarget:
		ident.Verdict = "the identity is a member and is already on the target"
	default:
		ident.Verdict = "the identity is a member with an account: a sync adds it to the group on the target"
	}
	d.Identity = ident
}

func capList(in []string, more *int) []string {
	if len(in) <= diagList {
		return in
	}
	*more += len(in) - diagList
	return in[:diagList]
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
