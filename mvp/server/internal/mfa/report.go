package mfa

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Best-method values besides the Strength classes.
const (
	// Unknown: none of the identity's accounts is in a system whose methods
	// could be read, so nothing is known about its MFA. It is never reported as
	// "no MFA".
	Unknown Strength = "unknown"
)

// Source status values (store.AuthMethodSource.Status).
const (
	SourceOK          = "ok"
	SourceUnavailable = "unavailable"
)

// Snapshot dimensions.
const (
	DimAll             = "all"
	DimDepartment      = "department"
	DimPrivilegedGroup = "privileged_group"
)

// NoDepartment is the department of an identity that has none.
const NoDepartment = "(none)"

// Input is what the posture is computed from: plain store rows.
type Input struct {
	Now        time.Time
	Identities []*store.Identity
	Accounts   []*store.Account
	Groups     []*store.Group
	Edges      []*store.GrantEdge
	Perms      []*store.Permission
	Methods    []*store.AuthMethod
	Sources    []*store.AuthMethodSource
	Signals    []*store.AccountAuthSignals
	Snapshots  []*store.MFASnapshot
}

// Method is one registered method as the report shows it.
type Method struct {
	System     string     `json:"system"`
	Username   string     `json:"account"`
	Kind       string     `json:"kind"`
	Strength   Strength   `json:"strength"`
	Label      string     `json:"label"`
	EnrolledAt *time.Time `json:"enrolled_at"`
}

// Identity is one person's posture.
type Identity struct {
	ID               int64    `json:"id"`
	Name             string   `json:"name"`
	Department       string   `json:"department"`
	Title            string   `json:"title"`
	Privileged       bool     `json:"privileged"`
	PrivilegedGroups []string `json:"privileged_groups"` // names of the privileged groups held, "system: name"
	PrivilegedVia    []string `json:"privileged_via"`    // why the identity counts as privileged
	Best             Strength `json:"best"`              // a Strength, None or Unknown
	Passkey          bool     `json:"passkey"`
	Methods          []Method `json:"methods"`
	Systems          []string `json:"systems"` // systems whose methods cover this identity
}

// Counts are identities by best method class.
type Counts struct {
	Total             int `json:"total"`
	PhishingResistant int `json:"phishing_resistant"`
	PushNumberMatch   int `json:"push_number_match"`
	Push              int `json:"push"`
	OTP               int `json:"otp"`
	SMSVoice          int `json:"sms_voice"`
	NoMFA             int `json:"no_mfa"`
	Unknown           int `json:"unknown"`
	PasskeyEnrolled   int `json:"passkey_enrolled"`
}

// Group is Counts for one department or privileged group.
type Group struct {
	Key string `json:"key"`
	Counts
}

// Source is the state of one IdP's method listing.
type Source struct {
	System    string    `json:"system"`
	Status    string    `json:"status"`
	Detail    string    `json:"detail"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AppFinding is an app or data-platform account that bypasses SSO or MFA.
type AppFinding struct {
	AccountID    int64    `json:"account_id"`
	System       string   `json:"system"`
	Username     string   `json:"username"`
	IdentityID   *int64   `json:"identity_id"`
	IdentityName string   `json:"identity_name"`
	Privileged   bool     `json:"privileged"`
	Issues       []string `json:"issues"` // local_password | no_mfa | sso_not_enforced
}

// AppSystem is how much a connected app tells about its sign-ins. Accounts is
// the number of active accounts, WithSignals how many have any reported flag:
// a system with none is a data gap, not a clean bill of health.
type AppSystem struct {
	System      string `json:"system"`
	Accounts    int    `json:"accounts"`
	WithSignals int    `json:"with_signals"`
	Flagged     int    `json:"flagged"`
}

// Data is the computed posture, before any filter.
type Data struct {
	Identities []*Identity
	Sources    []Source
	Findings   []AppFinding
	Apps       []AppSystem
	Trend      []*store.MFASnapshot // dimension "all", oldest first
}

// Issue names of an AppFinding.
const (
	IssueLocalPassword  = "local_password"
	IssueNoMFA          = "no_mfa"
	IssueSSONotEnforced = "sso_not_enforced"
)

func nodeID(prefix, s string) (int64, bool) {
	rest, ok := strings.CutPrefix(s, prefix+":")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	return n, err == nil
}

// Compute builds the posture of the active people in in.
func Compute(in Input) *Data {
	d := &Data{}
	sourceOK := map[string]bool{}
	for _, s := range in.Sources {
		d.Sources = append(d.Sources, Source{System: s.System, Status: s.Status, Detail: s.Detail, UpdatedAt: s.UpdatedAt})
		sourceOK[s.System] = s.Status == SourceOK
	}
	sort.Slice(d.Sources, func(i, j int) bool { return d.Sources[i].System < d.Sources[j].System })

	groups := map[int64]*store.Group{}
	for _, g := range in.Groups {
		groups[g.ID] = g
	}
	privPerm := map[int64]*store.Permission{}
	for _, p := range in.Perms {
		if p.Privileged {
			privPerm[p.ID] = p
		}
	}
	// parents[x] are the groups x is a member of or maps to; grants[x] the privileged
	// permissions x is granted, for x = "account:N" or "group:N". An edge past
	// its expiry no longer counts.
	parents := map[string][]int64{}
	grants := map[string][]*store.Permission{}
	for _, e := range in.Edges {
		if e.ExpiresAt != nil && !e.ExpiresAt.After(in.Now) {
			continue
		}
		// member_of is membership; maps_to is a federation mapping (an Okta
		// group to an AWS role) that gives the members the target's access.
		if gid, ok := nodeID("group", e.Dst); ok && (e.Relation == "member_of" || e.Relation == "maps_to") {
			parents[e.Src] = append(parents[e.Src], gid)
		}
		if pid, ok := nodeID("perm", e.Dst); ok && privPerm[pid] != nil {
			grants[e.Src] = append(grants[e.Src], privPerm[pid])
		}
	}
	groupLabel := func(g *store.Group) string { return g.System + ": " + g.Name }

	// the groups (transitively) containing an account, and the privileged
	// permissions it reaches
	reach := func(acct string) (map[int64]bool, []*store.Permission) {
		seen := map[int64]bool{}
		perms := append([]*store.Permission(nil), grants[acct]...)
		queue := append([]int64(nil), parents[acct]...)
		for len(queue) > 0 {
			gid := queue[0]
			queue = queue[1:]
			if seen[gid] {
				continue
			}
			seen[gid] = true
			key := "group:" + strconv.FormatInt(gid, 10)
			perms = append(perms, grants[key]...)
			queue = append(queue, parents[key]...)
		}
		return seen, perms
	}

	accountsOf := map[int64][]*store.Account{}
	for _, a := range in.Accounts {
		if a.IdentityID != nil {
			accountsOf[*a.IdentityID] = append(accountsOf[*a.IdentityID], a)
		}
	}
	methodsOf := map[int64][]*store.AuthMethod{}
	for _, m := range in.Methods {
		methodsOf[m.AccountID] = append(methodsOf[m.AccountID], m)
	}
	acctByID := map[int64]*store.Account{}
	for _, a := range in.Accounts {
		acctByID[a.ID] = a
	}

	people := map[int64]*Identity{}
	for _, i := range in.Identities {
		if i.Type != "human" || i.Status != "active" {
			continue
		}
		v := &Identity{ID: i.ID, Name: i.Name, Department: NoDepartment, Best: Unknown, Methods: []Method{},
			PrivilegedGroups: []string{}, PrivilegedVia: []string{}, Systems: []string{}}
		if i.Department != nil && *i.Department != "" {
			v.Department = *i.Department
		}
		if i.Title != nil {
			v.Title = *i.Title
		}
		systems := map[string]bool{}
		viaSeen := map[string]bool{}
		groupSeen := map[string]bool{}
		for _, a := range accountsOf[i.ID] {
			if a.Status == "disabled" {
				continue
			}
			if _, isIdP := sourceStatus(d.Sources, a.System); isIdP && sourceOK[a.System] {
				systems[a.System] = true
			}
			for _, m := range methodsOf[a.ID] {
				v.Methods = append(v.Methods, Method{System: a.System, Username: a.Username, Kind: m.Kind,
					Strength: Strength(m.Strength), Label: m.Label, EnrolledAt: m.EnrolledAt})
				if IsPasskey(m.Kind) {
					v.Passkey = true
				}
			}
			gids, perms := reach("account:" + strconv.FormatInt(a.ID, 10))
			for gid := range gids {
				g := groups[gid]
				if g == nil || !g.Privileged {
					continue
				}
				if l := groupLabel(g); !groupSeen[l] {
					groupSeen[l] = true
					v.PrivilegedGroups = append(v.PrivilegedGroups, l)
				}
			}
			for _, p := range perms {
				if l := fmt.Sprintf("%s: %s", p.System, p.Action); !viaSeen[l] {
					viaSeen[l] = true
					v.PrivilegedVia = append(v.PrivilegedVia, "privileged permission "+l)
				}
			}
		}
		sort.Strings(v.PrivilegedGroups)
		for _, g := range v.PrivilegedGroups {
			v.PrivilegedVia = append(v.PrivilegedVia, "member of "+g)
		}
		sort.Strings(v.PrivilegedVia)
		v.Privileged = len(v.PrivilegedGroups) > 0 || len(v.PrivilegedVia) > 0
		for s := range systems {
			v.Systems = append(v.Systems, s)
		}
		sort.Strings(v.Systems)
		sort.SliceStable(v.Methods, func(a, b int) bool {
			ra, rb := v.Methods[a].Strength.Rank(), v.Methods[b].Strength.Rank()
			if ra != rb {
				return ra > rb
			}
			if v.Methods[a].System != v.Methods[b].System {
				return v.Methods[a].System < v.Methods[b].System
			}
			return v.Methods[a].Kind < v.Methods[b].Kind
		})
		switch {
		case len(v.Methods) > 0:
			v.Best = v.Methods[0].Strength
		case len(v.Systems) > 0:
			v.Best = None
		}
		people[i.ID] = v
		d.Identities = append(d.Identities, v)
	}
	sort.SliceStable(d.Identities, func(a, b int) bool {
		x, y := d.Identities[a], d.Identities[b]
		if x.Best.Rank() != y.Best.Rank() {
			return x.Best.Rank() < y.Best.Rank() // weakest first
		}
		return x.Name < y.Name
	})

	// apps and data platforms: the systems that are not an IdP with methods
	signals := map[int64]*store.AccountAuthSignals{}
	for _, g := range in.Signals {
		signals[g.AccountID] = g
	}
	apps := map[string]*AppSystem{}
	for _, a := range in.Accounts {
		if _, isIdP := sourceStatus(d.Sources, a.System); isIdP || a.Status == "disabled" || a.Kind == "service" {
			continue
		}
		s := apps[a.System]
		if s == nil {
			s = &AppSystem{System: a.System}
			apps[a.System] = s
		}
		s.Accounts++
		g := signals[a.ID]
		if g == nil || (g.HasLocalPassword == nil && g.MFAEnabled == nil && g.SSOEnforced == nil) {
			continue
		}
		s.WithSignals++
		var issues []string
		if g.HasLocalPassword != nil && *g.HasLocalPassword {
			issues = append(issues, IssueLocalPassword)
		}
		if g.MFAEnabled != nil && !*g.MFAEnabled {
			issues = append(issues, IssueNoMFA)
		}
		if g.SSOEnforced != nil && !*g.SSOEnforced {
			issues = append(issues, IssueSSONotEnforced)
		}
		if len(issues) == 0 {
			continue
		}
		s.Flagged++
		f := AppFinding{AccountID: a.ID, System: a.System, Username: a.Username, IdentityID: a.IdentityID, Issues: issues}
		if a.IdentityID != nil {
			if p := people[*a.IdentityID]; p != nil {
				f.IdentityName, f.Privileged = p.Name, p.Privileged
			}
		}
		d.Findings = append(d.Findings, f)
	}
	for _, s := range apps {
		d.Apps = append(d.Apps, *s)
	}
	sort.Slice(d.Apps, func(i, j int) bool { return d.Apps[i].System < d.Apps[j].System })
	sort.SliceStable(d.Findings, func(i, j int) bool {
		a, b := d.Findings[i], d.Findings[j]
		if a.Privileged != b.Privileged {
			return a.Privileged
		}
		if len(a.Issues) != len(b.Issues) {
			return len(a.Issues) > len(b.Issues)
		}
		if a.System != b.System {
			return a.System < b.System
		}
		return a.Username < b.Username
	})
	for _, s := range in.Snapshots {
		if s.Dimension == DimAll {
			d.Trend = append(d.Trend, s)
		}
	}
	return d
}

func sourceStatus(sources []Source, system string) (string, bool) {
	for _, s := range sources {
		if s.System == system {
			return s.Status, true
		}
	}
	return "", false
}

func (c *Counts) add(v *Identity) {
	c.Total++
	switch v.Best {
	case PhishingResistant:
		c.PhishingResistant++
	case PushNumberMatch:
		c.PushNumberMatch++
	case Push:
		c.Push++
	case OTP:
		c.OTP++
	case SMSVoice:
		c.SMSVoice++
	case None:
		c.NoMFA++
	default:
		c.Unknown++
	}
	if v.Passkey {
		c.PasskeyEnrolled++
	}
}

// Summary counts a set of identities overall, per department and per
// privileged group (an identity in two privileged groups counts in both).
type Summary struct {
	Totals           Counts  `json:"totals"`
	ByDepartment     []Group `json:"by_department"`
	ByPrivilegedGrp  []Group `json:"by_privileged_group"`
	PrivilegedTotals Counts  `json:"privileged_totals"`
}

// Summarize counts the identities.
func Summarize(idents []*Identity) Summary {
	var s Summary
	dept := map[string]*Group{}
	grp := map[string]*Group{}
	for _, v := range idents {
		s.Totals.add(v)
		if v.Privileged {
			s.PrivilegedTotals.add(v)
		}
		g := dept[v.Department]
		if g == nil {
			g = &Group{Key: v.Department}
			dept[v.Department] = g
		}
		g.add(v)
		for _, name := range v.PrivilegedGroups {
			pg := grp[name]
			if pg == nil {
				pg = &Group{Key: name}
				grp[name] = pg
			}
			pg.add(v)
		}
	}
	s.ByDepartment, s.ByPrivilegedGrp = sortedGroups(dept), sortedGroups(grp)
	return s
}

func sortedGroups(m map[string]*Group) []Group {
	out := make([]Group, 0, len(m))
	for _, g := range m {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// SnapshotRows are the rows of the daily snapshot table for date.
func (d *Data) SnapshotRows(date string) []store.MFASnapshot {
	sum := Summarize(d.Identities)
	row := func(dim, key string, c Counts) store.MFASnapshot {
		return store.MFASnapshot{Date: date, Dimension: dim, GroupKey: key, Total: c.Total, PhishingResistant: c.PhishingResistant,
			PushNumberMatch: c.PushNumberMatch, Push: c.Push, OTP: c.OTP, SMSVoice: c.SMSVoice, NoMFA: c.NoMFA,
			Unknown: c.Unknown, PasskeyEnrolled: c.PasskeyEnrolled}
	}
	out := []store.MFASnapshot{row(DimAll, "all", sum.Totals)}
	for _, g := range sum.ByDepartment {
		out = append(out, row(DimDepartment, g.Key, g.Counts))
	}
	for _, g := range sum.ByPrivilegedGrp {
		out = append(out, row(DimPrivilegedGroup, g.Key, g.Counts))
	}
	return out
}

// TrendDays is how far back the report's trend reaches.
const TrendDays = 90

// LoadInput reads the tenant's rows that the posture is computed from.
func LoadInput(c *store.TenantTx, now time.Time) (Input, error) {
	in := Input{Now: now}
	var err error
	if in.Identities, err = c.Identities(); err != nil {
		return in, err
	}
	if in.Accounts, err = c.Accounts(); err != nil {
		return in, err
	}
	if in.Groups, err = c.Groups(); err != nil {
		return in, err
	}
	if in.Edges, err = c.Edges(); err != nil {
		return in, err
	}
	if in.Perms, err = c.Permissions(); err != nil {
		return in, err
	}
	if in.Methods, err = c.AuthMethods(); err != nil {
		return in, err
	}
	if in.Sources, err = c.AuthMethodSources(); err != nil {
		return in, err
	}
	if in.Signals, err = c.AccountAuthSignalRows(); err != nil {
		return in, err
	}
	since := now.AddDate(0, 0, -TrendDays).UTC().Format("2006-01-02")
	in.Snapshots, err = c.MFASnapshots(since)
	return in, err
}

// Load reads the tenant's data and computes its posture.
func Load(c *store.TenantTx, now time.Time) (*Data, error) {
	in, err := LoadInput(c, now)
	if err != nil {
		return nil, err
	}
	return Compute(in), nil
}

// RecordSnapshot stores today's coverage (UTC date of now), replacing a row
// written earlier the same day, so a day's last sync is its snapshot. It does
// nothing until a system has reported its methods: a snapshot of "unknown"
// would only draw a flat line.
func RecordSnapshot(c *store.TenantTx, now time.Time) error {
	d, err := Load(c, now)
	if err != nil {
		return err
	}
	if len(d.Sources) == 0 {
		return nil
	}
	for _, r := range d.SnapshotRows(now.UTC().Format("2006-01-02")) {
		if err := c.PutMFASnapshot(r); err != nil {
			return err
		}
	}
	return nil
}
