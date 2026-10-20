package provisioning

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Diffing desired state against a target read, and the failsafes.

// PlannedOp is an Op with what the framework records about it.
type PlannedOp struct {
	Op      Op
	GroupID string
	// Removes counts the members the op takes away (a delete counts the group's members).
	Removes int
	Adds    int
	// CauseSeq is the newest event behind an incremental op (0: none).
	CauseSeq int64
	// GroupDelete marks the ops that remove a whole group, also on a target
	// where that means removing its members, for the failsafe.
	GroupDelete bool
}

// Hash is the SHA-256 of the op's canonical payload (the kind, the target name,
// the sorted attributes and members), recorded as payload_hash. It identifies
// what the op asked for without storing member references.
func (p *PlannedOp) Hash() string {
	type payload struct {
		Kind   OpKind              `json:"kind"`
		Name   string              `json:"name"`
		Attrs  map[string][]string `json:"attrs,omitempty"`
		Add    []string            `json:"add,omitempty"`
		Remove []string            `json:"remove,omitempty"`
	}
	add, remove := slices.Clone(p.Op.Add), slices.Clone(p.Op.Remove)
	slices.Sort(add)
	slices.Sort(remove)
	b, _ := json.Marshal(payload{p.Op.Kind, Key(p.Op.Ref.Name), p.Op.Attrs, add, remove}) // maps marshal with sorted keys
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// diffMembers returns the members to add (in the desired form) and to remove
// (in the form the target returned them).
func diffMembers(desired, actual []string) (add, remove []string) {
	want := make(map[string]string, len(desired))
	for _, m := range desired {
		want[NormMember(m)] = m
	}
	have := make(map[string]string, len(actual))
	for _, m := range actual {
		have[NormMember(m)] = m
	}
	for k, m := range want {
		if _, ok := have[k]; !ok {
			add = append(add, m)
		}
	}
	for k, m := range have {
		if _, ok := want[k]; !ok {
			remove = append(remove, m)
		}
	}
	slices.Sort(add)
	slices.Sort(remove)
	return add, remove
}

// attrsDiffer reports whether any desired attribute differs from the target's.
func attrsDiffer(desired, actual map[string][]string) bool {
	for k, want := range desired {
		var got []string
		for ak, av := range actual {
			if strings.EqualFold(ak, k) {
				got = av
				break
			}
		}
		if !sameValues(want, got) {
			return true
		}
	}
	return false
}

func sameValues(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// planGroup is the ops that bring one target group to its desired state: none
// when it already matches. ag is nil when the group is absent from the target.
func planGroup(caps Capabilities, dg *DesiredGroup, ag *TargetGroup, ref TargetRef) []*PlannedOp {
	if ag == nil {
		if caps.Groups {
			return []*PlannedOp{{Op: Op{Kind: OpCreate, Ref: ref, Attrs: dg.Attrs, Add: dg.Members}, GroupID: dg.GroupID, Adds: len(dg.Members)}}
		}
		if len(dg.Members) == 0 {
			return nil
		}
		return []*PlannedOp{{Op: Op{Kind: OpMembers, Ref: ref, Add: dg.Members}, GroupID: dg.GroupID, Adds: len(dg.Members)}}
	}
	if ag.Ref.ID != "" {
		ref.ID = ag.Ref.ID
	}
	var ops []*PlannedOp
	if caps.Groups && attrsDiffer(dg.Attrs, ag.Attrs) {
		ops = append(ops, &PlannedOp{Op: Op{Kind: OpUpdate, Ref: ref, Attrs: dg.Attrs}, GroupID: dg.GroupID})
	}
	if add, remove := diffMembers(dg.Members, ag.Members); len(add)+len(remove) > 0 {
		ops = append(ops, &PlannedOp{Op: Op{Kind: OpMembers, Ref: ref, Add: add, Remove: remove}, GroupID: dg.GroupID,
			Adds: len(add), Removes: len(remove)})
	}
	return ops
}

// planDelete is the op that removes a group the provisioner owns and no longer
// wants. ag is nil when the target no longer has it.
func planDelete(caps Capabilities, groupID string, ref TargetRef, ag *TargetGroup) []*PlannedOp {
	if ag == nil {
		return nil
	}
	if ag.Ref.ID != "" {
		ref.ID = ag.Ref.ID
	}
	if caps.Groups {
		return []*PlannedOp{{Op: Op{Kind: OpDelete, Ref: ref}, GroupID: groupID, Removes: len(ag.Members)}}
	}
	if len(ag.Members) == 0 {
		return nil
	}
	return []*PlannedOp{{Op: Op{Kind: OpMembers, Ref: ref, Remove: slices.Clone(ag.Members)}, GroupID: groupID, Removes: len(ag.Members),
		GroupDelete: true}}
}

// Totals summarises a plan.
type Totals struct {
	Creates, Updates, MemberOps, Deletes int
	MemberAdds, MemberRemoves            int
	GroupDeletes                         int
}

func totalsOf(ops []*PlannedOp) Totals {
	var t Totals
	for _, p := range ops {
		switch p.Op.Kind {
		case OpCreate:
			t.Creates++
		case OpUpdate:
			t.Updates++
		case OpMembers:
			t.MemberOps++
			if p.GroupDelete {
				t.GroupDeletes++
			}
		case OpDelete:
			t.Deletes++
			t.GroupDeletes++
		}
		t.MemberAdds += p.Adds
		t.MemberRemoves += p.Removes
	}
	return t
}

// orderOps puts creates before updates before member changes before deletes,
// and keeps the groups in name order inside each kind.
func orderOps(ops []*PlannedOp) {
	rank := map[OpKind]int{OpCreate: 0, OpUpdate: 1, OpMembers: 2, OpDelete: 3}
	slices.SortStableFunc(ops, func(a, b *PlannedOp) int {
		if ra, rb := rank[a.Op.Kind], rank[b.Op.Kind]; ra != rb {
			return ra - rb
		}
		return strings.Compare(Key(a.Op.Ref.Name), Key(b.Op.Ref.Name))
	})
}

// failsafe checks a plan against the limits (design §9.2): the most member
// removals one run may do, as a number and as a share of the target's
// memberships (full runs only, and only on a target with PercentFloor or more
// memberships), and the most groups it may delete. It returns the reasons the
// plan is refused; none means it may run.
func (l Limits) failsafe(t Totals, targetMemberships int, full bool) []string {
	var why []string
	if t.MemberRemoves > l.MaxDeletes {
		why = append(why, fmt.Sprintf("%d member removals exceed the limit of %d", t.MemberRemoves, l.MaxDeletes))
	}
	if full && l.MaxDeletePercent > 0 && targetMemberships >= PercentFloor &&
		float64(t.MemberRemoves)*100 > l.MaxDeletePercent*float64(targetMemberships) {
		why = append(why, fmt.Sprintf("%d member removals are more than %.4g%% of the target's %d memberships",
			t.MemberRemoves, l.MaxDeletePercent, targetMemberships))
	}
	if t.GroupDeletes > l.MaxGroupDeletes {
		why = append(why, fmt.Sprintf("%d group deletions exceed the limit of %d (deleting groups needs approval)", t.GroupDeletes, l.MaxGroupDeletes))
	}
	return why
}

// stateHash is a digest of one group's attributes and members as read.
func stateHash(g *TargetGroup) string {
	members := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		members = append(members, NormMember(m))
	}
	slices.Sort(members)
	b, _ := json.Marshal(struct {
		Name    string              `json:"name"`
		Attrs   map[string][]string `json:"attrs"`
		Members []string            `json:"members"`
	}{Key(g.Ref.Name), g.Attrs, members})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
