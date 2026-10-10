package reconcile

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Sample is one example object of a finding: an id, a display name and the
// reason it matched. Nothing else about the object is kept (§5.2).
type Sample struct {
	Ref    string `json:"ref"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Impact states what a finding reaches (§6.4).
type Impact struct {
	AffectedIdentities int    `json:"affected_identities"`
	AffectedAccounts   int    `json:"affected_accounts"`
	PrivilegedGrants   int    `json:"privileged_grants"`
	DownstreamPerms    int    `json:"downstream_perms"`
	ReviewItems        int    `json:"review_items"`
	Sentence           string `json:"sentence"`
}

// Cause is a probable cause and its fix (§6.5).
type Cause struct {
	Analyser string         `json:"analyser"`
	Sentence string         `json:"sentence"`
	Numbers  map[string]any `json:"numbers"`
	FixItem  string         `json:"fix_item,omitempty"`
	Probable bool           `json:"probable"`
}

// Finding is one reconciliation finding.
type Finding struct {
	Code        string   `json:"code"`
	Variant     string   `json:"variant"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Count       int      `json:"count"`
	Denominator int      `json:"denominator"`
	Samples     []Sample `json:"samples"`
	Impact      Impact   `json:"impact"`
	Cause       *Cause   `json:"cause"`
	ItemID      string   `json:"item_id,omitempty"`
}

// Key identifies a finding across dry runs.
func (f *Finding) Key() string { return f.Code + "|" + f.Variant }

// Input is everything Analyze reads.
type Input struct {
	Snap   *Snapshot
	People map[int64]Person // authoritative HR people by identity id
	// Elsewhere counts, per identity id, enabled accounts in other live systems.
	Elsewhere map[int64]int
	// Owned holds the external ids of live non-human identities with an owner.
	Owned  map[string]bool
	Impact *ImpactGraph
}

type analysis struct {
	in    Input
	r     *Rules
	snap  *Snapshot
	now   time.Time
	cap   int
	out   []Finding
	byXID map[string]*store.StagedAccount
}

func (a *analysis) threshold(key string, def float64) float64 {
	if v, ok := a.snap.Meta.Thresholds[key]; ok {
		return v
	}
	if v, ok := a.r.Thresholds[key]; ok {
		return v
	}
	return def
}

func (a *analysis) severity(code string, privileged bool) string {
	rule := a.r.Rules[code]
	if privileged && rule.Privileged != "" {
		return rule.Privileged
	}
	return rule.Severity
}

func (a *analysis) title(code string) string { return a.r.Rules[code].Title }

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func percent(n, d int) int {
	if d == 0 {
		return 0
	}
	return int(math.Round(100 * float64(n) / float64(d)))
}

// impact computes the impact of a set of accounts.
func (a *analysis) impact(accts []*store.StagedAccount) Impact {
	im := Impact{AffectedAccounts: len(accts)}
	people := map[int64]bool{}
	var groups []string
	for _, x := range accts {
		if x.IdentityID != nil {
			people[*x.IdentityID] = true
		} else if x.ProposedIdentityID != nil {
			people[*x.ProposedIdentityID] = true
		}
		eff := a.snap.EffectiveGroups(x.ExternalID)
		groups = append(groups, eff...)
		im.ReviewItems += len(eff)
		im.PrivilegedGrants += len(a.snap.PrivilegedGroups(x.ExternalID))
	}
	slices.Sort(groups)
	groups = slices.Compact(groups)
	im.AffectedIdentities = len(people)
	im.DownstreamPerms = a.in.Impact.Permissions(a.snap.Meta.System, groups)
	return im
}

func (a *analysis) impactSentence(im *Impact, what string) {
	many := what + "s"
	if strings.HasSuffix(what, "ch") {
		many = what + "es"
	}
	parts := []string{plural(im.AffectedAccounts, what, many)}
	if im.PrivilegedGrants > 0 {
		parts = append(parts, plural(im.PrivilegedGrants, "privileged membership", "privileged memberships"))
	}
	s := strings.Join(parts, " with ")
	if im.DownstreamPerms > 0 {
		s += fmt.Sprintf(", reaching %s through mapped groups", plural(im.DownstreamPerms, "permission", "permissions"))
	}
	im.Sentence = s + "."
}

func (a *analysis) samples(accts []*store.StagedAccount, reason func(*store.StagedAccount) string) []Sample {
	out := []Sample{}
	for _, x := range accts {
		if len(out) >= a.cap {
			break
		}
		out = append(out, Sample{Ref: x.ExternalID, Name: x.Username, Reason: reason(x)})
	}
	return out
}

func (a *analysis) privileged(accts []*store.StagedAccount) bool {
	for _, x := range accts {
		if len(a.snap.PrivilegedGroups(x.ExternalID)) > 0 {
			return true
		}
	}
	return false
}

func (a *analysis) add(f Finding) {
	if f.Count == 0 {
		return
	}
	if f.Samples == nil {
		f.Samples = []Sample{}
	}
	a.out = append(a.out, f)
}

// Analyze computes the findings of a staged dry run (§6.3).
func Analyze(in Input) ([]Finding, error) {
	r, err := LoadRules()
	if err != nil {
		return nil, err
	}
	snap := in.Snap
	a := &analysis{in: in, r: r, snap: snap, now: snap.Meta.Now, byXID: map[string]*store.StagedAccount{}}
	a.cap = int(a.threshold("sample_cap", 10))
	for _, x := range snap.Accounts {
		a.byXID[x.ExternalID] = x
	}
	var users, enabledUsers, enabled []*store.StagedAccount
	for _, x := range snap.Accounts {
		if Enabled(x, a.now) {
			enabled = append(enabled, x)
		}
		if !IsService(x) {
			users = append(users, x)
			if Enabled(x, a.now) {
				enabledUsers = append(enabledUsers, x)
			}
		}
	}
	authoritative := snap.Meta.Role == "authoritative"
	if !authoritative {
		a.orphans(enabledUsers)
		a.peopleWithoutAccount(users)
		a.duplicates(users)
		a.leavers()
		a.proposals(users)
	}
	a.sparse()
	a.outOfScope()
	a.disabledWithAccess()
	a.stale(enabled)
	a.privilegedMembers()
	a.serviceOwners()
	a.neverExpires()
	a.counts(users)
	sort.SliceStable(a.out, func(i, j int) bool {
		if SeverityRank(a.out[i].Severity) != SeverityRank(a.out[j].Severity) {
			return SeverityRank(a.out[i].Severity) < SeverityRank(a.out[j].Severity)
		}
		return a.out[i].Key() < a.out[j].Key()
	})
	return a.out, nil
}

// RF-01: enabled accounts that match no person (uncorrelated, or only
// proposed by email), excluding service accounts.
func (a *analysis) orphans(enabledUsers []*store.StagedAccount) {
	var hits []*store.StagedAccount
	for _, x := range enabledUsers {
		if x.Correlation == Uncorrelated || x.Correlation == Proposed {
			hits = append(hits, x)
		}
	}
	priv := a.privileged(hits)
	f := Finding{Code: "RF-01", Title: a.title("RF-01"), Severity: a.severity("RF-01", priv), Count: len(hits),
		Denominator: len(enabledUsers), ItemID: a.snap.Meta.HRItem, Impact: a.impact(hits)}
	f.Samples = a.samples(hits, func(x *store.StagedAccount) string {
		if x.Correlation == Proposed {
			return "no HR id match; matches a person by email (needs review)"
		}
		if x.Attributes[a.snap.Meta.HRAttribute] != "" {
			return "its " + a.snap.Meta.HRAttribute + " matches no person in the HR source"
		}
		return "no " + a.snap.Meta.HRAttribute + " and no email match"
	})
	a.impactSentence(&f.Impact, "orphan account")
	f.Cause = a.unmappedKey(hits, false)
	a.add(f)
}

// RF-02: active people in the HR source with no correlated account here.
func (a *analysis) peopleWithoutAccount(users []*store.StagedAccount) {
	switch a.snap.Meta.TemplateID {
	case "ad", "ldap", "entra", "okta", "google": // directories: every active employee is expected
	default:
		return
	}
	has := map[int64]bool{}
	for _, x := range users {
		if x.Correlation == Correlated && x.IdentityID != nil {
			has[*x.IdentityID] = true
		}
	}
	var missing, active []Person
	for _, p := range sortedPeople(a.in.People) {
		if p.Status != "active" {
			continue
		}
		active = append(active, p)
		if !has[p.ID] {
			missing = append(missing, p)
		}
	}
	f := Finding{Code: "RF-02", Title: a.title("RF-02"), Severity: a.severity("RF-02", false), Count: len(missing),
		Denominator: len(active), ItemID: a.snap.Meta.HRItem,
		Impact: Impact{AffectedIdentities: len(missing), Sentence: plural(len(missing), "active person has", "active people have") +
			" no account correlated to them in " + a.snap.Meta.SystemName + "."}}
	for _, p := range missing {
		if len(f.Samples) >= a.cap {
			break
		}
		f.Samples = append(f.Samples, Sample{Ref: p.ExternalID, Name: p.Name, Reason: "active in HR; no account correlated here"})
	}
	f.Cause = scopeConcentration(missing, active)
	a.add(f)
}

// RF-03: ambiguous correlations and people with several accounts of one kind.
func (a *analysis) duplicates(users []*store.StagedAccount) {
	var hits []*store.StagedAccount
	for _, x := range users {
		if x.Correlation == Ambiguous {
			hits = append(hits, x)
		}
	}
	f := Finding{Code: "RF-03", Title: a.title("RF-03"), Severity: a.severity("RF-03", false), Count: len(hits),
		Denominator: len(users), ItemID: "base.correlation.key", Impact: a.impact(hits)}
	f.Samples = a.samples(hits, func(x *store.StagedAccount) string {
		return "matches the same person as another account, or several people"
	})
	a.impactSentence(&f.Impact, "ambiguous account")
	a.add(f)
}

// RF-04: mapped attributes empty on too many records.
func (a *analysis) sparse() {
	class := "user"
	if a.snap.Meta.Role == "authoritative" && a.snap.ClassTotal("worker") > 0 {
		class = "worker"
	}
	total := a.snap.ClassTotal(class)
	if total == 0 {
		return
	}
	check := func(attrs []string, limit float64, recommended bool) {
		for _, attr := range attrs {
			st, _ := a.snap.Stat(class, attr)
			empty := total - st.Present
			if float64(empty)/float64(total) <= limit {
				continue
			}
			sev := a.severity("RF-04", false)
			item := "base.attrs.required"
			if recommended {
				sev = a.r.Rules["RF-04"].Recommended
				item = ""
				if attr == a.snap.Meta.HRAttribute {
					item = a.snap.Meta.HRItem
				}
			}
			a.add(Finding{Code: "RF-04", Variant: attr, Title: a.title("RF-04") + ": " + attr, Severity: sev, Count: empty,
				Denominator: total, ItemID: item, Samples: []Sample{},
				Impact: Impact{AffectedAccounts: empty, Sentence: fmt.Sprintf("%s is empty on %d%% of %s records.", attr, percent(empty, total), class)}})
		}
	}
	check(a.snap.Meta.RequiredAttrs, a.threshold("sparse_required", 0.05), false)
	check(a.snap.Meta.RecommendedAttrs, a.threshold("sparse_recommended", 0.25), true)
}

// RF-05: memberships pointing at groups outside the snapshot's scope.
func (a *analysis) outOfScope() {
	missing := map[string]int{}
	var members []*store.StagedAccount
	seen := map[string]bool{}
	total := map[string]bool{}
	for _, m := range a.snap.Memberships {
		total[m.GroupXID] = true
		if _, ok := a.snap.Group(m.GroupXID); ok {
			continue
		}
		missing[m.GroupXID]++
		if x := a.byXID[m.MemberXID]; x != nil && !seen[x.ExternalID] {
			seen[x.ExternalID] = true
			members = append(members, x)
		}
	}
	groups := make([]string, 0, len(missing))
	for g := range missing {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	f := Finding{Code: "RF-05", Title: a.title("RF-05"), Severity: a.severity("RF-05", false), Count: len(groups),
		Denominator: len(total), ItemID: "", Samples: []Sample{}}
	for _, g := range groups {
		if len(f.Samples) >= a.cap {
			break
		}
		name := g
		if strings.HasPrefix(strings.ToUpper(g), "CN=") {
			name, _, _ = strings.Cut(g[3:], ",")
		}
		f.Samples = append(f.Samples, Sample{Ref: g, Name: name, Reason: plural(missing[g], "membership points", "memberships point") + " at it; it is not in the snapshot"})
	}
	f.Impact = Impact{AffectedAccounts: len(members), ReviewItems: len(members),
		Sentence: plural(len(members), "account belongs", "accounts belong") + " to groups Tessera cannot see, so their access is understated."}
	f.Cause = scopeExclusion(groups)
	if a.snap.Meta.TemplateID == "ad" {
		f.ItemID = "ad.scope.base_dns"
	}
	a.add(f)
}

// RF-06(a): disabled or expired accounts that still hold group memberships.
func (a *analysis) disabledWithAccess() {
	var hits []*store.StagedAccount
	inactive := 0
	for _, x := range a.snap.Accounts {
		if Enabled(x, a.now) {
			continue
		}
		inactive++
		if len(a.snap.EffectiveGroups(x.ExternalID)) > 0 {
			hits = append(hits, x)
		}
	}
	priv := a.privileged(hits)
	f := Finding{Code: "RF-06", Variant: "a", Title: a.title("RF-06a"), Severity: a.severity("RF-06a", priv), Count: len(hits),
		Denominator: inactive, Impact: a.impact(hits)}
	f.Samples = a.samples(hits, func(x *store.StagedAccount) string {
		if Expired(x, a.now) {
			return "expired, still in " + plural(len(a.snap.EffectiveGroups(x.ExternalID)), "group", "groups")
		}
		return "disabled, still in " + plural(len(a.snap.EffectiveGroups(x.ExternalID)), "group", "groups")
	})
	a.impactSentence(&f.Impact, "inactive account")
	a.add(f)
}

// RF-06(b): people terminated in HR whose account here is enabled.
func (a *analysis) leavers() {
	var hits []*store.StagedAccount
	leavers := 0
	for _, p := range a.in.People {
		if p.Status == "terminated" {
			leavers++
		}
	}
	for _, x := range a.snap.Accounts {
		if x.Correlation != Correlated || x.IdentityID == nil || !Enabled(x, a.now) {
			continue
		}
		if p, ok := a.in.People[*x.IdentityID]; ok && p.Status == "terminated" {
			hits = append(hits, x)
		}
	}
	priv := a.privileged(hits)
	f := Finding{Code: "RF-06", Variant: "b", Severity: a.severity("RF-06b", priv), Count: len(hits), Denominator: leavers,
		Title: "Departed in HR but enabled in " + a.snap.Meta.SystemName, Impact: a.impact(hits)}
	f.Samples = a.samples(hits, func(x *store.StagedAccount) string {
		p := a.in.People[*x.IdentityID]
		if d := a.daysSince(p.TerminatedAt); d >= 0 {
			return fmt.Sprintf("terminated in HR %d days ago; enabled here", d)
		}
		return "terminated in HR; enabled here"
	})
	a.impactSentence(&f.Impact, "leaver account")
	f.Cause = a.leaverProcess(hits)
	a.add(f)
}

func (a *analysis) daysSince(ts *string) int {
	if ts == nil {
		return -1
	}
	t, err := time.Parse("2006-01-02 15:04:05.000000", *ts)
	if err != nil {
		if t, err = time.Parse(time.RFC3339Nano, *ts); err != nil {
			return -1
		}
	}
	return int(a.now.Sub(t).Hours() / 24)
}

// RF-07: enabled accounts not used for longer than the dormancy threshold.
func (a *analysis) stale(enabled []*store.StagedAccount) {
	days := a.snap.Meta.StaleDays
	if days <= 0 {
		days = int(a.threshold("stale_days", 90))
	}
	lag := int(a.threshold("stale_lag_days", 0))
	cutoff := a.now.AddDate(0, 0, -(days + lag))
	never := a.now.AddDate(0, 0, -int(a.threshold("never_logged_in_days", 30)))
	var hits []*store.StagedAccount
	for _, x := range enabled {
		switch {
		case x.LastLoginAt != nil && x.LastLoginAt.Before(cutoff):
			hits = append(hits, x)
		case x.LastLoginAt == nil && x.CreatedAt != nil && x.CreatedAt.Before(never):
			hits = append(hits, x)
		}
	}
	f := Finding{Code: "RF-07", Title: a.title("RF-07"), Severity: a.severity("RF-07", false), Count: len(hits),
		Denominator: len(enabled), ItemID: "base.stale.threshold", Impact: a.impact(hits)}
	f.Samples = a.samples(hits, func(x *store.StagedAccount) string {
		if x.LastLoginAt == nil {
			return "never logged in"
		}
		return fmt.Sprintf("last login %d days ago", int(a.now.Sub(*x.LastLoginAt).Hours()/24))
	})
	a.impactSentence(&f.Impact, "stale account")
	a.add(f)
}

// RF-08: privileged members not on the expected list, or disabled members.
func (a *analysis) privilegedMembers() {
	type hit struct {
		x     *store.StagedAccount
		group string
		why   string
	}
	var hits []hit
	memberships := 0
	for _, x := range a.snap.Accounts {
		for _, g := range a.snap.PrivilegedGroups(x.ExternalID) {
			memberships++
			expected, listed := a.snap.Meta.Privileged[g.Name]
			switch {
			case !Enabled(x, a.now):
				hits = append(hits, hit{x, g.Name, "disabled or expired member of " + g.Name})
			case listed && !expectedMember(x, expected):
				hits = append(hits, hit{x, g.Name, "not on the expected member list of " + g.Name})
			}
		}
	}
	accts := make([]*store.StagedAccount, 0, len(hits))
	f := Finding{Code: "RF-08", Title: a.title("RF-08"), Severity: a.severity("RF-08", true), Count: len(hits),
		Denominator: memberships, Samples: []Sample{}}
	for _, h := range hits {
		accts = append(accts, h.x)
		if len(f.Samples) < a.cap {
			f.Samples = append(f.Samples, Sample{Ref: h.x.ExternalID, Name: h.x.Username, Reason: h.why})
		}
	}
	f.Impact = a.impact(accts)
	f.Impact.Sentence = plural(len(hits), "unexpected privileged membership", "unexpected privileged memberships")
	if len(hits) > 0 {
		f.Impact.Sentence += " in " + hits[0].group
		if f.Impact.DownstreamPerms > 0 {
			f.Impact.Sentence += fmt.Sprintf(", reaching %s", plural(f.Impact.DownstreamPerms, "permission", "permissions"))
		}
	}
	f.Impact.Sentence += "."
	switch a.snap.Meta.TemplateID {
	case "ad":
		f.ItemID = "ad.groups.privileged"
	case "okta":
		f.ItemID = "okta.roles.admins"
	case "entra":
		f.ItemID = "entra.roles"
	case "google":
		f.ItemID = "gws.roles"
	}
	f.Cause = a.privilegedPolicyGap(accts, hits0(hits, func(h hit) string { return h.group }))
	a.add(f)
}

func hits0[T any](xs []T, f func(T) string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = f(x)
	}
	return out
}

func expectedMember(x *store.StagedAccount, expected []string) bool {
	names := []string{strings.ToLower(x.Username), strings.ToLower(x.ExternalID)}
	for _, k := range []string{"sAMAccountName", "login", "email", "mail", "userPrincipalName"} {
		if v := x.Attributes[k]; v != "" {
			names = append(names, strings.ToLower(v))
		}
	}
	for _, e := range expected {
		if slices.Contains(names, strings.ToLower(strings.TrimSpace(e))) {
			return true
		}
	}
	return false
}

// RF-09: service accounts with no owner.
func (a *analysis) serviceOwners() {
	var hits, svc []*store.StagedAccount
	for _, x := range a.snap.Accounts {
		if !IsService(x) {
			continue
		}
		svc = append(svc, x)
		owned := x.Attributes["managedBy"] != "" || x.Attributes["owner"] != "" || a.in.Owned[x.Attributes["owner_ref"]]
		if !owned {
			hits = append(hits, x)
		}
	}
	priv := a.privileged(hits)
	f := Finding{Code: "RF-09", Title: a.title("RF-09"), Severity: a.severity("RF-09", priv), Count: len(hits),
		Denominator: len(svc), Impact: a.impact(hits)}
	f.Samples = a.samples(hits, func(x *store.StagedAccount) string {
		if len(a.snap.PrivilegedGroups(x.ExternalID)) > 0 {
			return "no owner; member of a privileged group"
		}
		return "no owner recorded"
	})
	a.impactSentence(&f.Impact, "unowned service account")
	a.add(f)
}

// RF-10: accounts matched only by email or UPN (awaiting review).
func (a *analysis) proposals(users []*store.StagedAccount) {
	var hits []*store.StagedAccount
	for _, x := range users {
		if x.Correlation == Proposed {
			hits = append(hits, x)
		}
	}
	f := Finding{Code: "RF-10", Title: a.title("RF-10"), Severity: a.severity("RF-10", false), Count: len(hits),
		Denominator: len(users), ItemID: a.snap.Meta.HRItem, Impact: a.impact(hits)}
	f.Samples = a.samples(hits, func(*store.StagedAccount) string { return "matches a person by email only; needs review" })
	a.impactSentence(&f.Impact, "proposed match")
	f.Cause = a.unmappedKey(hits, true)
	a.add(f)
}

// RF-11: privileged accounts whose password never expires.
func (a *analysis) neverExpires() {
	var hits, priv []*store.StagedAccount
	for _, x := range a.snap.Accounts {
		if len(a.snap.PrivilegedGroups(x.ExternalID)) == 0 {
			continue
		}
		priv = append(priv, x)
		uac, _ := strconv.Atoi(x.Attributes["userAccountControl"])
		if uac&0x10000 != 0 || strings.EqualFold(x.Attributes["pwdPolicyExempt"], "true") {
			hits = append(hits, x)
		}
	}
	f := Finding{Code: "RF-11", Title: a.title("RF-11"), Severity: a.severity("RF-11", true), Count: len(hits),
		Denominator: len(priv), ItemID: "", Impact: a.impact(hits)}
	if a.snap.Meta.TemplateID == "ad" {
		f.ItemID = "ad.status.pwdlastset"
	}
	f.Samples = a.samples(hits, func(*store.StagedAccount) string { return "privileged; DONT_EXPIRE_PASSWORD set" })
	a.impactSentence(&f.Impact, "privileged account")
	a.add(f)
}

// RF-12: staged counts outside the tolerance of the attested expected counts.
func (a *analysis) counts(users []*store.StagedAccount) {
	tol := a.threshold("count_tolerance", 0.02)
	check := func(variant string, expected *int, staged int) {
		if expected == nil || *expected <= 0 {
			return
		}
		diff := staged - *expected
		if math.Abs(float64(diff))/float64(*expected) <= tol {
			return
		}
		abs := int(math.Abs(float64(diff)))
		a.add(Finding{Code: "RF-12", Variant: variant, Title: a.title("RF-12") + ": " + variant, Severity: a.severity("RF-12", false),
			Count: abs, Denominator: *expected, ItemID: "base.scope.count", Samples: []Sample{},
			Impact: Impact{Sentence: fmt.Sprintf("Staged %d %s; the owner expects %d (%+d, tolerance %.0f%%).", staged, variant, *expected, diff, tol*100)}})
	}
	check("users", a.snap.Meta.ExpectedUsers, len(users))
	check("groups", a.snap.Meta.ExpectedGroups, len(a.snap.Groups))
}

func sortedPeople(m map[int64]Person) []Person {
	out := make([]Person, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
