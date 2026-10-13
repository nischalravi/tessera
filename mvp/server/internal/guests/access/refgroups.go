package access

import (
	"slices"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Reference groups (design §9.3, issue #75): system-managed groups of people
// that policies and access reviews can name ("a guest with an active visitor
// affiliation", "everyone with IAL 2", "who may sponsor"). Until the groups
// engine lands (GR-1/GR-2) Tessera keeps them itself: they live in the
// built-in system "tessera" as groups of kind "reference", every member has an
// account there and a member_of edge with source "refgroup". Membership is
// derived, never edited: it is recomputed from the people's affiliations,
// status, assurance and sponsor eligibility on every affiliation, claim and
// sponsorship change and on the sweeper's periodic reconcile, and a change
// made by hand is undone by the next recompute. They are not provisioned to
// any target. ref:applicant, ref:admit and ref:prehire need the SIS and HRIS
// intake (GU-4) and ref:partner:<org> needs partner organizations (GU-14).

// RefSystem is the built-in system that holds the reference groups.
const RefSystem = "tessera"

// RefKind is the kind of a reference group.
const RefKind = "reference"

// Reference group keys.
const (
	RefGuestActive        = "ref:guest:active"
	RefGuestVisitor       = "ref:guest:visitor"
	RefGuestContractor    = "ref:guest:contractor"
	RefGuestVolunteer     = "ref:guest:volunteer"
	RefPartnerActive      = "ref:partner:active"
	RefIAL2               = "ref:ial:2"
	RefSponsorEligible    = "ref:sponsor:eligible"
	ialEmployeeEquivalent = 2 // a person from the HR or student system was vetted at hire
	// EmployeeEquivalentIAL is that level, for callers that compare assurance (identity merges).
	EmployeeEquivalentIAL = ialEmployeeEquivalent
)

// RefGroup describes one reference group.
type RefGroup struct {
	Key         string
	Description string
}

// RefGroups are the groups Tessera maintains, in display order.
var RefGroups = []RefGroup{
	{RefGuestActive, "People with an active guest affiliation (visitor, contractor or volunteer) who have claimed their account."},
	{RefGuestVisitor, "Active visitors."},
	{RefGuestContractor, "Active contractors."},
	{RefGuestVolunteer, "Active volunteers."},
	{RefPartnerActive, "People with an active partner affiliation who have claimed their account."},
	{RefIAL2, "Active people whose identity was proofed at IAL 2 (or who come from the HR or student system)."},
	{RefSponsorEligible, "Active people the sponsor policy lets sponsor guests."},
}

// Eligibility says whether a person may sponsor (the sponsor policy); nil
// leaves ref:sponsor:eligible as it is.
type Eligibility func(tx *store.TenantTx, identityID int64) (bool, error)

// RefResult counts what a recompute did.
type RefResult struct {
	Added, Removed, GroupsCreated int
}

// Changed reports whether anything changed.
func (r RefResult) Changed() bool { return r.Added+r.Removed+r.GroupsCreated > 0 }

// membership is the reference groups a person belongs to now.
func membership(ident *store.Identity, affs []*store.Affiliation, ial int, eligible, haveEligible bool, now time.Time) []string {
	if ident.Type != "human" || ident.Status != "active" {
		return nil
	}
	var out []string
	add := func(k string) {
		if !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	authoritative := false
	for _, a := range affs {
		if a.Status != store.AffActive || a.StartsAt.After(now) || a.EndsAt != nil && !a.EndsAt.After(now) {
			continue
		}
		switch a.Type {
		case store.AffGuestVisitor:
			add(RefGuestActive)
			add(RefGuestVisitor)
		case store.AffContractor:
			add(RefGuestActive)
			add(RefGuestContractor)
		case store.AffVolunteer:
			add(RefGuestActive)
			add(RefGuestVolunteer)
		case store.AffPartner:
			add(RefPartnerActive)
		}
		if a.Source == store.AffSourceHRIS || a.Source == store.AffSourceSIS {
			authoritative = true
		}
	}
	if authoritative {
		ial = max(ial, ialEmployeeEquivalent)
	}
	if ial >= 2 {
		add(RefIAL2)
	}
	if haveEligible && eligible {
		add(RefSponsorEligible)
	}
	return out
}

// EnsureRefGroups creates the reference groups that do not exist yet and
// returns them by key and how many it created.
func EnsureRefGroups(tx *store.TenantTx) (map[string]*store.Group, int, error) {
	out := map[string]*store.Group{}
	created := 0
	for _, d := range RefGroups {
		g, err := getOrNil(tx.GroupByXID(RefSystem, d.Key))
		if err != nil {
			return nil, 0, err
		}
		if g == nil {
			desc := d.Description
			if err := tx.UpsertGroup(&store.Group{TenantID: tx.Tenant(), System: RefSystem, ExternalID: d.Key, Name: d.Key,
				Kind: RefKind, Description: &desc}); err != nil {
				return nil, 0, err
			}
			if g, err = tx.GroupByXID(RefSystem, d.Key); err != nil {
				return nil, 0, err
			}
			created++
		}
		out[d.Key] = g
	}
	return out, created, nil
}

// IsRefGroup reports whether a group is a system-managed reference group.
func IsRefGroup(g *store.Group) bool { return g.System == RefSystem && g.Kind == RefKind }

type member struct {
	person int64
	key    string
}

// refPlan is the difference between the reference groups and the people.
type refPlan struct {
	missing  int // groups to create
	drop     []member
	add      []member
	have     map[member]*store.GrantEdge
	accounts []*store.Account
	people   map[int64]*store.Identity
}

func (p *refPlan) empty() bool { return p.missing == 0 && len(p.drop) == 0 && len(p.add) == 0 }

func sortMembers(s []member) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].person != s[j].person {
			return s[i].person < s[j].person
		}
		return s[i].key < s[j].key
	})
}

// diff computes what a recompute would change, without writing.
func diff(tx *store.TenantTx, now time.Time, only int64, eligible Eligibility) (*refPlan, error) {
	p := &refPlan{have: map[member]*store.GrantEdge{}, people: map[int64]*store.Identity{}}
	ids := map[int64]string{} // group id -> key, for the groups that exist
	for _, d := range RefGroups {
		g, err := getOrNil(tx.GroupByXID(RefSystem, d.Key))
		if err != nil {
			return nil, err
		}
		if g == nil {
			p.missing++
		} else {
			ids[g.ID] = d.Key
		}
	}
	people, err := tx.Identities()
	if err != nil {
		return nil, err
	}
	for _, x := range people {
		p.people[x.ID] = x
	}
	affs, err := tx.Affiliations()
	if err != nil {
		return nil, err
	}
	affsOf := map[int64][]*store.Affiliation{}
	for _, a := range affs {
		affsOf[a.IdentityID] = append(affsOf[a.IdentityID], a)
	}
	as, err := tx.IdentityAssurances()
	if err != nil {
		return nil, err
	}
	ialOf := map[int64]int{}
	for _, a := range as {
		ialOf[a.IdentityID] = a.IAL
	}
	sys := RefSystem
	if p.accounts, err = tx.AccountsBySystemUsername(&sys); err != nil {
		return nil, err
	}
	owner := map[int64]int64{}
	for _, a := range p.accounts {
		if a.IdentityID != nil {
			owner[a.ID] = *a.IdentityID
		}
	}
	edges, err := tx.EdgesBySource(store.EdgeSourceRefGroup)
	if err != nil {
		return nil, err
	}
	for _, e := range edges {
		k, aid, err := graph.ParseKey(e.Src)
		if err != nil || k != "account" {
			continue
		}
		_, gid, err := graph.ParseKey(e.Dst)
		if err != nil {
			continue
		}
		if key, ok := ids[gid]; ok && owner[aid] != 0 {
			p.have[member{owner[aid], key}] = e
		}
	}
	want := map[member]bool{}
	for _, x := range people {
		if only != 0 && x.ID != only {
			continue
		}
		el, haveEl := false, false
		if eligible != nil && x.Type == "human" && x.Status == "active" {
			if el, err = eligible(tx, x.ID); err != nil {
				return nil, err
			}
			haveEl = true
		}
		for _, k := range membership(x, affsOf[x.ID], ialOf[x.ID], el, haveEl, now) {
			want[member{x.ID, k}] = true
		}
		if !haveEl { // sponsor eligibility was not asked: leave what is there
			if _, ok := p.have[member{x.ID, RefSponsorEligible}]; ok {
				want[member{x.ID, RefSponsorEligible}] = true
			}
		}
	}
	for m := range p.have {
		if (only == 0 || m.person == only) && !want[m] {
			p.drop = append(p.drop, m)
		}
	}
	active, disabled := map[int64]bool{}, map[int64]bool{}
	for _, a := range p.accounts {
		if a.IdentityID != nil {
			if a.Status == "active" {
				active[*a.IdentityID] = true
			} else {
				disabled[*a.IdentityID] = true
			}
		}
	}
	for m := range want {
		if _, ok := p.have[m]; !ok && (active[m.person] || !disabled[m.person]) {
			p.add = append(p.add, m)
		}
	}
	sortMembers(p.drop)
	sortMembers(p.add)
	return p, nil
}

// NeedsRecompute reports, without writing, whether a full recompute would
// change anything (the sweeper's cheap check).
func NeedsRecompute(tx *store.TenantTx, now time.Time, eligible Eligibility) (bool, error) {
	p, err := diff(tx, now, 0, eligible)
	if err != nil {
		return false, err
	}
	return !p.empty(), nil
}

// Recompute brings the reference groups in line with the people. only is one
// person's id (after a change that concerns them) or 0 for everyone (the
// sweeper). It writes one audit event when something changed.
func Recompute(tx *store.TenantTx, now time.Time, actor string, only int64, eligible Eligibility) (RefResult, error) {
	var res RefResult
	p, err := diff(tx, now, only, eligible)
	if err != nil {
		return res, err
	}
	if p.empty() {
		return res, nil
	}
	groups, created, err := EnsureRefGroups(tx)
	if err != nil {
		return res, err
	}
	res.GroupsCreated = created
	for _, m := range p.drop {
		if err := tx.DeleteEdge(p.have[m].ID); err != nil {
			return res, err
		}
		res.Removed++
	}
	for _, m := range p.add {
		acct, err := refAccount(tx, p.accounts, p.people[m.person], now)
		if err != nil {
			return res, err
		}
		if acct == nil {
			continue // a disabled account of an earlier term: no membership
		}
		p.accounts = append(p.accounts, acct)
		src, dst := graph.Key("account", acct.ID), graph.Key("group", groups[m.key].ID)
		if e, err := getOrNil(tx.EdgeBetween(src, dst)); err != nil {
			return res, err
		} else if e != nil {
			continue
		}
		if _, err := tx.InsertEdge(&store.GrantEdge{TenantID: tx.Tenant(), Src: src, Dst: dst, Relation: "member_of",
			Source: store.EdgeSourceRefGroup, CreatedAt: now}); err != nil {
			return res, err
		}
		res.Added++
	}
	if created > 0 {
		if err := tx.Audit(now, actor, "refgroup.create", ojson.Object{{Key: "groups", Value: created}}); err != nil {
			return res, err
		}
	}
	if res.Added+res.Removed > 0 {
		scope := "all"
		if only != 0 {
			scope = "identity"
		}
		return res, tx.Audit(now, actor, "refgroup.reconcile", ojson.Object{{Key: "scope", Value: scope},
			{Key: "identity_id", Value: only}, {Key: "added", Value: res.Added}, {Key: "removed", Value: res.Removed}})
	}
	return res, nil
}

// refAccount is the person's account in the reference system, created when
// they have none; nil when their account there was disabled.
func refAccount(tx *store.TenantTx, accts []*store.Account, p *store.Identity, now time.Time) (*store.Account, error) {
	var disabled bool
	for _, a := range accts {
		if a.IdentityID != nil && *a.IdentityID == p.ID {
			if a.Status == "active" {
				return a, nil
			}
			disabled = true
		}
	}
	if disabled {
		return nil, nil
	}
	iid := p.ID
	id, err := tx.InsertAccount(&store.Account{System: RefSystem, ExternalID: "tessera-ref-" + p.ExternalID, IdentityID: &iid,
		Username: p.ExternalID, Kind: "user", Status: "active", CreatedAt: &now})
	if err != nil {
		return nil, err
	}
	return tx.Account(id)
}
