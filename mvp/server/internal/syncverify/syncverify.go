// Package syncverify is the prediction check of a merge sync (issue #657, AC-11). Before a policy bundle is applied, the
// blast-radius preview (internal/blast, internal/simulate) predicts what it changes: the effective permissions each identity
// gains and loses, and the policy violations it introduces and resolves. Predict keeps that as data. After the apply,
// Capture reads the same two things from the store, and Compare says where what happened is not what was predicted.
//
// Capture runs in the apply's own transaction, once before the writes and once after. Both are the store's view
// (graph.Build, then the tenant's policies), so a write that was lost or changed on the way to the store shows as a
// difference; a connector re-collect adds its own view through the observer hook of internal/admin. The package reads
// through a tenant transaction and writes nothing.
package syncverify

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/simulate"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Limits: a prediction is stored in a change request payload, so its lists are cut (the counts are exact).
const (
	MaxPerms      = 2000
	MaxViolations = 500
	// MaxFindings bounds the findings one check records.
	MaxFindings = 100
)

// PermChange is one predicted change to an identity's effective permissions.
type PermChange struct {
	IdentityID int64  `json:"identity_id"`
	Identity   string `json:"identity"`
	Perm       string `json:"perm"`
	Gain       bool   `json:"gain"`
}

// Prediction is what the preview said the bundle would do.
type Prediction struct {
	// DiffSHA256 is the digest of the blast-radius answer it came from.
	DiffSHA256 string       `json:"diff_sha256"`
	Perms      []PermChange `json:"perms"`
	// PermsTotal counts every predicted permission change; Perms holds the first MaxPerms (sorted).
	PermsTotal         int      `json:"perms_total"`
	IdentitiesAffected int      `json:"identities_affected"`
	ViolationsBefore   int      `json:"violations_before"`
	ViolationsAfter    int      `json:"violations_after"`
	Introduced         []string `json:"introduced"`
	Resolved           []string `json:"resolved"`
	IntroducedTotal    int      `json:"introduced_total"`
	ResolvedTotal      int      `json:"resolved_total"`
}

// Valid refuses a prediction whose lists and totals do not fit the way Predict makes them: a list is cut only at its cap, so a
// total larger than its list with the list under the cap is a forged or damaged prediction (it would turn off the checks of
// what was not predicted).
func (p *Prediction) Valid() error {
	chk := func(name string, n, total, cap int) error {
		switch {
		case total < n || n > cap:
			return fmt.Errorf("syncverify: %s: %d listed of %d", name, n, total)
		case total > n && n != cap:
			return fmt.Errorf("syncverify: %s: %d listed of %d, but a list is cut only at %d", name, n, total, cap)
		}
		return nil
	}
	for _, e := range []error{chk("perms", len(p.Perms), p.PermsTotal, MaxPerms), chk("introduced", len(p.Introduced), p.IntroducedTotal, MaxViolations),
		chk("resolved", len(p.Resolved), p.ResolvedTotal, MaxViolations)} {
		if e != nil {
			return e
		}
	}
	return nil
}

// Truncated reports that a list of the prediction was cut, so unpredicted changes cannot be told from cut ones.
func (p *Prediction) Truncated() bool {
	return p.PermsTotal > len(p.Perms) || p.IntroducedTotal > len(p.Introduced) || p.ResolvedTotal > len(p.Resolved)
}

// Predict turns a simulation of the bundle into a Prediction. res is nil for a bundle that edits no graph edge.
func Predict(res *simulate.Result, diffSHA string) *Prediction {
	p := &Prediction{DiffSHA256: diffSHA, Perms: []PermChange{}, Introduced: []string{}, Resolved: []string{}}
	if res == nil {
		return p
	}
	for _, ic := range res.Identities {
		for _, a := range ic.Added {
			p.Perms = append(p.Perms, PermChange{IdentityID: ic.IdentityID, Identity: ic.Name, Perm: a.PermKey, Gain: true})
		}
		for _, r := range ic.Removed {
			p.Perms = append(p.Perms, PermChange{IdentityID: ic.IdentityID, Identity: ic.Name, Perm: r.PermKey})
		}
	}
	sort.Slice(p.Perms, func(i, j int) bool {
		a, b := p.Perms[i], p.Perms[j]
		if a.IdentityID != b.IdentityID {
			return a.IdentityID < b.IdentityID
		}
		if a.Perm != b.Perm {
			return a.Perm < b.Perm
		}
		return a.Gain && !b.Gain
	})
	p.PermsTotal = len(p.Perms)
	if len(p.Perms) > MaxPerms {
		p.Perms = p.Perms[:MaxPerms]
	}
	p.IdentitiesAffected = res.Summary.IdentitiesAffected
	p.ViolationsBefore, p.ViolationsAfter = res.Summary.ViolationsBefore, res.Summary.ViolationsAfter
	for _, v := range res.Violations.Introduced {
		p.Introduced = append(p.Introduced, v.Key)
	}
	for _, v := range res.Violations.Resolved {
		p.Resolved = append(p.Resolved, v.Key)
	}
	sort.Strings(p.Introduced)
	sort.Strings(p.Resolved)
	p.IntroducedTotal, p.ResolvedTotal = len(p.Introduced), len(p.Resolved)
	if len(p.Introduced) > MaxViolations {
		p.Introduced = p.Introduced[:MaxViolations]
	}
	if len(p.Resolved) > MaxViolations {
		p.Resolved = p.Resolved[:MaxViolations]
	}
	return p
}

// State is what the store shows at one moment: each identity's effective permission keys and the violation keys.
type State struct {
	Perms map[int64]map[string]bool
	Names map[int64]string
	// Violations are the keys of the policy findings; Checked is false when no policies were given, in which case
	// violations are not compared.
	Violations map[string]bool
	Checked    bool
}

// Capture reads the tenant's state. policies are the effective policies of the tenant now (nil: violations are not read).
func Capture(tx *store.TenantTx, policies []*policy.Policy, now time.Time) (*State, error) {
	g, err := graph.Build(tx, now)
	if err != nil {
		return nil, err
	}
	st := &State{Perms: map[int64]map[string]bool{}, Names: map[int64]string{}, Violations: map[string]bool{}}
	for iid, eff := range g.AllEffective() {
		set := make(map[string]bool, len(eff.Keys))
		for _, k := range eff.Keys {
			set[k] = true
		}
		st.Perms[iid] = set
		if n := g.Node(graph.Key("identity", iid)); n != nil {
			st.Names[iid] = n.Label
		}
	}
	if policies != nil {
		vs, err := policy.Evaluate(policies, policy.NewContext(g, tx, now))
		if err != nil {
			return nil, fmt.Errorf("syncverify: evaluate: %w", err)
		}
		st.Checked = true
		for _, v := range vs {
			st.Violations[v.Key] = true
		}
	}
	return st, nil
}

// Mismatch is one place where the observation is not the prediction.
type Mismatch struct {
	Kind      string `json:"kind"`
	Subject   string `json:"subject"`
	Predicted string `json:"predicted"`
	Observed  string `json:"observed"`
}

// The kinds of mismatch.
const (
	KindGainMissing      = "permission_gain_missing"
	KindLossMissing      = "permission_loss_missing"
	KindUnexpectedGain   = "permission_gain_unexpected"
	KindUnexpectedLoss   = "permission_loss_unexpected"
	KindViolationMissing = "violation_missing"
	KindViolationExtra   = "violation_unexpected"
	KindViolationStays   = "violation_not_resolved"
	KindViolationGone    = "violation_resolved_unexpectedly"
)

func clip(s string) string {
	if len(s) > 380 {
		return s[:380] + "..."
	}
	return s
}

// Compare says where after is not what the prediction expected of before. For every predicted identity the permissions
// gained must be present and those lost absent; an identity or permission the prediction does not name must not have
// changed (unless a list of the prediction was cut, when only the named ones are checked); the introduced violations must
// be there, the resolved ones gone, and no other violation may have appeared or disappeared. At most MaxFindings
// mismatches are returned (the count is in total), in a stable order.
func Compare(p *Prediction, before, after *State) (ms []Mismatch, total int) {
	add := func(m Mismatch) {
		total++
		if len(ms) < MaxFindings {
			m.Subject, m.Predicted, m.Observed = clip(m.Subject), clip(m.Predicted), clip(m.Observed)
			ms = append(ms, m)
		}
	}
	name := func(iid int64) string {
		n := after.Names[iid]
		if n == "" {
			n = before.Names[iid]
		}
		if n == "" {
			n = "identity"
		}
		return fmt.Sprintf("%s (#%d)", n, iid)
	}
	type key struct {
		iid  int64
		perm string
	}
	wantGain, wantLoss := map[key]bool{}, map[key]bool{}
	for _, c := range p.Perms {
		if c.Gain {
			wantGain[key{c.IdentityID, c.Perm}] = true
		} else {
			wantLoss[key{c.IdentityID, c.Perm}] = true
		}
	}
	// the permissions that were predicted
	keys := make([]key, 0, len(wantGain)+len(wantLoss))
	for k := range wantGain {
		keys = append(keys, k)
	}
	for k := range wantLoss {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].iid != keys[j].iid {
			return keys[i].iid < keys[j].iid
		}
		return keys[i].perm < keys[j].perm
	})
	for _, k := range keys {
		has := after.Perms[k.iid][k.perm]
		switch {
		case wantGain[k] && !has:
			add(Mismatch{KindGainMissing, name(k.iid) + ": " + k.perm, "gained", "not held"})
		case wantLoss[k] && has:
			add(Mismatch{KindLossMissing, name(k.iid) + ": " + k.perm, "lost", "still held"})
		}
	}
	// the permissions that changed without being predicted
	if !p.Truncated() {
		ids := map[int64]bool{}
		for iid := range before.Perms {
			ids[iid] = true
		}
		for iid := range after.Perms {
			ids[iid] = true
		}
		sorted := make([]int64, 0, len(ids))
		for iid := range ids {
			sorted = append(sorted, iid)
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		for _, iid := range sorted {
			b, a := before.Perms[iid], after.Perms[iid]
			var gained, lost []string
			for k := range a {
				if !b[k] && !wantGain[key{iid, k}] {
					gained = append(gained, k)
				}
			}
			for k := range b {
				if !a[k] && !wantLoss[key{iid, k}] {
					lost = append(lost, k)
				}
			}
			sort.Strings(gained)
			sort.Strings(lost)
			for _, k := range gained {
				add(Mismatch{KindUnexpectedGain, name(iid) + ": " + k, "no change", "gained"})
			}
			for _, k := range lost {
				add(Mismatch{KindUnexpectedLoss, name(iid) + ": " + k, "no change", "lost"})
			}
		}
	}
	// the violations
	if before.Checked && after.Checked {
		wantNew, wantGone := map[string]bool{}, map[string]bool{}
		for _, k := range p.Introduced {
			wantNew[k] = true
		}
		for _, k := range p.Resolved {
			wantGone[k] = true
		}
		for _, k := range p.Introduced {
			if !after.Violations[k] {
				add(Mismatch{KindViolationMissing, k, "introduced", "absent"})
			}
		}
		for _, k := range p.Resolved {
			if after.Violations[k] {
				add(Mismatch{KindViolationStays, k, "resolved", "still present"})
			}
		}
		if !p.Truncated() {
			var extra, vanished []string
			for k := range after.Violations {
				if !before.Violations[k] && !wantNew[k] {
					extra = append(extra, k)
				}
			}
			for k := range before.Violations {
				if !after.Violations[k] && !wantGone[k] {
					vanished = append(vanished, k)
				}
			}
			sort.Strings(extra)
			sort.Strings(vanished)
			for _, k := range extra {
				add(Mismatch{KindViolationExtra, k, "no change", "introduced"})
			}
			for _, k := range vanished {
				add(Mismatch{KindViolationGone, k, "no change", "resolved"})
			}
		}
	}
	return ms, total
}

// Describe is one line of what a Mismatch says.
func (m Mismatch) Describe() string {
	return strings.TrimSpace(fmt.Sprintf("%s: %s (predicted %s, observed %s)", m.Kind, m.Subject, m.Predicted, m.Observed))
}
