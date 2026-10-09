package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The simulated Active Directory of the demo company (design §12), used by
// the deployment-readiness walkthrough. It is built from DemoCompany's people
// without drawing from the company's random generator, so the default demo
// spec (and every parity fixture) is unchanged. It is not part of the
// "demo" connector set: it is staged by dry runs and syncs into the live
// graph only if its connection is activated.
//
// Planted deployment gaps:
//   - employeeID filled on 61% of user accounts (tier-1 correlation for the rest fails)
//   - four accounts that match no person, one expired, one never logged on
//   - a second account for Alice Okafor (duplicate correlation)
//   - Domain Admins with one unexpected member (Callum Ferreira)
//   - three service accounts with no owner (managedBy empty)
//   - stale accounts, leavers' disabled accounts still in groups, memberships
//     in groups outside the base DNs, and a privileged account whose
//     password never expires

// DemoADSystem is the graph system name of the simulated AD.
const DemoADSystem = "ad-corp"

const adDomain = "DC=corp,DC=larkspur,DC=example"

type demoAD struct {
	company *DemoCompany
	once    sync.Once
	res     *DiscoveryResult
}

// NewDemoAD returns the simulated AD connector over a demo company.
func NewDemoAD(company *DemoCompany) Connector { return &demoAD{company: company} }

func (d *demoAD) System() string      { return DemoADSystem }
func (d *demoAD) DisplayName() string { return "Active Directory (demo)" }
func (d *demoAD) TypeName() string    { return "DemoADConnector" }

func (d *demoAD) Discover(ctx context.Context) (*DiscoveryResult, error) {
	d.once.Do(func() { d.res = buildDemoAD(d.company) })
	return d.res, ctx.Err()
}

func (d *demoAD) StreamEvents(ctx context.Context, _ *time.Time, _ func(Event) error) error {
	return ctx.Err()
}

// DemoConnectorFor returns the demo connector behind a demo connection type
// ("demo-ad", "demo-okta", "demo-workday").
func DemoConnectorFor(connectorType string, now time.Time) (Connector, bool) {
	company := GetCompany(DemoSeed, now)
	switch connectorType {
	case "demo-ad":
		return NewDemoAD(company), true
	case "demo-okta":
		return newDemo("okta", company), true
	case "demo-workday":
		return newDemo("workday", company), true
	}
	return nil, false
}

func hash32(s string) uint32 {
	h := sha256.Sum256([]byte(s))
	return binary.BigEndian.Uint32(h[:4])
}

// adGUID derives a stable objectGUID-shaped id.
func adGUID(seed string) string {
	h := sha256.Sum256([]byte("ad-corp/" + seed))
	x := hex.EncodeToString(h[:16])
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

// fileTime renders a time as an AD FILETIME (100 ns intervals since 1601).
func fileTime(t time.Time) string {
	const epochDiff = 11644473600 // seconds between 1601-01-01 and 1970-01-01
	return strconv.FormatInt((t.Unix()+epochDiff)*10_000_000, 10)
}

func samName(first, last string) string {
	r := strings.NewReplacer(" ", "", "-", "")
	return strings.ToLower(r.Replace(first) + "." + r.Replace(last))
}

// userAccountControl flags.
const (
	uacDisabled      = 0x2
	uacNormal        = 0x200
	uacDontExpirePwd = 0x10000
)

func buildDemoAD(c *DemoCompany) *DiscoveryResult {
	res := &DiscoveryResult{}
	now := c.Now
	day := func(n int) time.Time { return now.AddDate(0, 0, -n) }
	ptr := func(t time.Time) *time.Time { return &t }

	type group struct {
		cn         string
		privileged bool
		members    []string // sAMAccountNames
	}
	groups := []*group{
		{cn: "Domain Admins", privileged: true}, {cn: "Enterprise Admins", privileged: true},
		{cn: "IT-Helpdesk-L2"}, {cn: "All-Staff-Legacy"}, {cn: "VPN-Users"},
	}
	byCN := map[string]*group{}
	for _, g := range groups {
		byCN[g.cn] = g
	}
	deptGroup := func(dept string) *group {
		if g, ok := byCN[dept]; ok {
			return g
		}
		g := &group{cn: dept}
		groups = append(groups, g)
		byCN[dept] = g
		return g
	}
	join := func(sam string, cns ...string) {
		for _, cn := range cns {
			g := byCN[cn]
			if g == nil {
				g = deptGroup(cn)
			}
			g.members = append(g.members, sam)
		}
	}

	pinnedNames := map[string]bool{}
	for _, n := range pinned {
		pinnedNames[n[0]+" "+n[1]] = true
	}
	var others []*Person
	for _, p := range c.People {
		if !pinnedNames[p.Name()] {
			others = append(others, p)
		}
	}
	sort.Slice(others, func(i, j int) bool { return hash32("emp:"+others[i].EID) < hash32("emp:"+others[j].EID) })
	fillEmp, stale := map[string]bool{}, map[string]bool{}
	for i, p := range others {
		if i < 17 { // 20 pinned + 17 = 37 people; with the orphans, 40 of 65 user accounts (61%)
			fillEmp[p.EID] = true
		} else if i < 20 {
			stale[p.EID] = true // three people whose accounts went quiet
		}
	}
	managerDN := map[string]string{}
	for _, p := range c.People {
		managerDN[p.EID] = "CN=" + p.Name() + ",OU=People," + adDomain
	}
	type acct struct {
		rec   AccountRecord
		class string
	}
	var accts []acct
	add := func(sam, kind, class string, ident *IdentityRef, uac int, created time.Time, last *time.Time, attrs map[string]string) {
		attrs["objectGUID"] = adGUID(sam)
		attrs["sAMAccountName"] = sam
		attrs["userAccountControl"] = strconv.Itoa(uac)
		attrs["whenCreated"] = created.Format(time.RFC3339)
		attrs["msDS-User-Account-Control-Computed"] = "0"
		attrs["primaryGroupID"] = "513"
		attrs["objectClass"] = class
		if _, ok := attrs["accountExpires"]; !ok {
			attrs["accountExpires"] = "0"
		}
		attrs["pwdLastSet"] = fileTime(created.AddDate(0, 0, 30))
		if last != nil {
			attrs["lastLogonTimestamp"] = fileTime(*last)
		}
		status := "active"
		if uac&uacDisabled != 0 {
			status = "disabled"
		}
		accts = append(accts, acct{AccountRecord{System: DemoADSystem, ExternalID: attrs["objectGUID"], Username: sam,
			Identity: ident, Kind: kind, Status: status, CreatedAt: ptr(created), LastLoginAt: last, Attributes: attrs}, class})
	}

	for _, p := range c.People {
		sam := samName(p.First, p.Last)
		attrs := map[string]string{"userPrincipalName": sam + "@corp.larkspur.example", "mail": p.Email(),
			"department": p.Dept, "memberOf": "1"}
		if p.ManagerEID != "" {
			attrs["manager"] = managerDN[p.ManagerEID]
		}
		var ident *IdentityRef
		if pinnedNames[p.Name()] || fillEmp[p.EID] {
			attrs["employeeID"] = p.EID
			ident = &IdentityRef{ExternalID: p.EID} // tier 1 only: never correlate by email (K12)
		}
		uac := uacNormal
		last := ptr(day(int(hash32("logon:"+p.EID) % 5)))
		if p.Status == "terminated" {
			uac |= uacDisabled
			last = ptr(p.TerminatedAt.AddDate(0, 0, -1))
		}
		if stale[p.EID] {
			last = ptr(day(120 + int(hash32("stale:"+p.EID)%80)))
		}
		if p.Name() == "Ingrid Lindqvist" {
			uac |= uacDontExpirePwd // privileged, password never expires
		}
		add(sam, "user", "user", ident, uac, p.HiredAt, last, attrs)
		join(sam, "All-Staff-Legacy", p.Dept)
		switch p.Team {
		case "backend", "frontend", "platform", "security", "support":
			join(sam, "VPN-Users")
		}
		if p.Team == "support" {
			join(sam, "IT-Helpdesk-L2")
		}
	}
	for _, n := range []string{"Thandiwe Mokoena", "Ingrid Lindqvist", "Callum Ferreira"} {
		p := c.P(n)
		join(samName(p.First, p.Last), "Domain Admins")
	}
	join(samName("Ingrid", "Lindqvist"), "Enterprise Admins")

	// Accounts that match no person in Workday.
	mgr := managerDN[c.P("Callum Ferreira").EID]
	add("temp.contractor1", "user", "user", &IdentityRef{ExternalID: "emp-0901"}, uacNormal, day(400), ptr(day(12)),
		map[string]string{"employeeID": "emp-0901", "mail": "temp.contractor1@" + Domain, "manager": mgr,
			"userPrincipalName": "temp.contractor1@corp.larkspur.example", "accountExpires": fileTime(day(10)),
			"memberOf": "1"})
	join("temp.contractor1", "VPN-Users")
	add("jdoe.old", "user", "user", &IdentityRef{ExternalID: "emp-0777"}, uacNormal, day(1500), ptr(day(200)),
		map[string]string{"employeeID": "emp-0777", "manager": mgr, "userPrincipalName": "jdoe.old@corp.larkspur.example",
			"memberOf": "1"})
	add("test.user", "user", "user", nil, uacNormal, day(300), ptr(day(2)),
		map[string]string{"mail": "test.user@" + Domain, "manager": mgr, "userPrincipalName": "test.user@corp.larkspur.example",
			"memberOf": "0"})
	add("kiosk-lobby", "user", "user", nil, uacNormal, day(200), nil,
		map[string]string{"userPrincipalName": "kiosk-lobby@corp.larkspur.example", "memberOf": "0", "manager": mgr})
	// A second, enabled account for Alice Okafor: duplicate correlation.
	alice := c.P("Alice Okafor")
	add("a.okafor2", "user", "user", &IdentityRef{ExternalID: alice.EID}, uacNormal, day(90), ptr(day(1)),
		map[string]string{"employeeID": alice.EID, "manager": managerDN[alice.ManagerEID],
			"userPrincipalName": "a.okafor2@corp.larkspur.example", "mail": "a.okafor2@" + Domain, "memberOf": "1"})
	join("a.okafor2", "Engineering")

	// Service accounts; three have no owner (managedBy empty).
	ownerDN := func(name string) string { return managerDN[c.P(name).EID] }
	svc := []struct {
		sam, owner, class string
		uac               int
	}{
		{"svc-backup", ownerDN("Marcus Bellweather"), "user", uacNormal},
		{"svc-sharepoint", ownerDN("Ingrid Lindqvist"), "user", uacNormal},
		{"gmsa-adsync$", ownerDN("Ingrid Lindqvist"), "msDS-GroupManagedServiceAccount", uacNormal},
		{"svc-print", "", "user", uacNormal},
		{"svc-sql-reporting", "", "user", uacNormal},
		{"svc-legacy-ftp", "", "user", uacNormal | uacDontExpirePwd},
	}
	for _, s := range svc {
		attrs := map[string]string{"description": "Service account", "memberOf": "0"}
		if s.owner != "" {
			attrs["managedBy"] = s.owner
		}
		add(s.sam, "service", s.class, nil, s.uac, day(700+int(hash32(s.sam)%300)), ptr(day(int(hash32("l"+s.sam)%3))), attrs)
	}
	for _, a := range accts {
		res.Accounts = append(res.Accounts, a.rec)
	}

	groupRef := func(cn string) Ref {
		return Ref{Kind: "group", System: DemoADSystem, ExternalID: adGUID("group:" + cn)}
	}
	acctRef := map[string]Ref{}
	for _, a := range accts {
		acctRef[a.rec.Username] = Ref{Kind: "account", System: DemoADSystem, ExternalID: a.rec.ExternalID}
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].cn < groups[j].cn })
	groupStats := &ClassStats{Attributes: map[string]AttrStat{}}
	for _, g := range groups {
		desc := "CN=" + g.cn + ",OU=Groups," + adDomain
		res.Groups = append(res.Groups, GroupRecord{System: DemoADSystem, ExternalID: groupRef(g.cn).ExternalID, Name: g.cn,
			Kind: "security_group", Privileged: g.privileged, Description: &desc})
		for _, m := range g.members {
			res.Edges = append(res.Edges, EdgeRecord{Src: acctRef[m], Dst: groupRef(g.cn), Relation: "member_of"})
		}
		groupStats.Total++
	}
	for _, a := range []string{"objectGUID", "cn", "groupType", "member", "managedBy"} {
		groupStats.Attributes[a] = AttrStat{Present: groupStats.Total, Distinct: groupStats.Total}
	}
	// Memberships in groups outside the base DNs (OU=Old Groups is not in scope).
	for _, m := range [][2]string{{"jdoe.old", "Legacy-Contractors"}, {"temp.contractor1", "Old-VPN"},
		{samName("Hollis", "Brightwater"), "Old-VPN"}} {
		res.Edges = append(res.Edges, EdgeRecord{Src: acctRef[m[0]],
			Dst: Ref{Kind: "group", System: DemoADSystem, ExternalID: "CN=" + m[1] + ",OU=Old Groups," + adDomain}, Relation: "member_of"})
	}
	res.Stats = StatsFromAccounts(res.Accounts, func(a *AccountRecord) string {
		if a.Kind == "service" {
			return "service"
		}
		return "user"
	})
	res.Stats.Classes["group"] = groupStats
	gmsa := 0
	for _, a := range accts {
		if a.class == "msDS-GroupManagedServiceAccount" {
			gmsa++
		}
	}
	if gmsa > 0 {
		res.Stats.Classes["msDS-GroupManagedServiceAccount"] = &ClassStats{Total: gmsa, Attributes: map[string]AttrStat{}}
	}
	return res
}

// StatsFromAccounts computes per-class attribute fill counts from the
// accounts' mapped attributes. classOf assigns each account a class.
func StatsFromAccounts(accts []AccountRecord, classOf func(*AccountRecord) string) *DiscoveryStats {
	st := &DiscoveryStats{Classes: map[string]*ClassStats{}}
	distinct := map[string]map[string]map[string]bool{}
	for i := range accts {
		a := &accts[i]
		cls := classOf(a)
		cs := st.Classes[cls]
		if cs == nil {
			cs = &ClassStats{Attributes: map[string]AttrStat{}}
			st.Classes[cls] = cs
			distinct[cls] = map[string]map[string]bool{}
		}
		cs.Total++
		for k, v := range a.Attributes {
			if v == "" {
				continue
			}
			s := cs.Attributes[k]
			s.Present++
			cs.Attributes[k] = s
			if distinct[cls][k] == nil {
				distinct[cls][k] = map[string]bool{}
			}
			distinct[cls][k][v] = true
		}
	}
	for cls, attrs := range distinct {
		for k, vals := range attrs {
			s := st.Classes[cls].Attributes[k]
			s.Distinct = len(vals)
			st.Classes[cls].Attributes[k] = s
		}
	}
	return st
}
