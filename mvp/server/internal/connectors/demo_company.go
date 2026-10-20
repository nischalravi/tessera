package connectors

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// The demo company: "Larkspur Labs" (larkspur.example), about 60 employees,
// 25 service accounts / API keys and 6 AI agents across Workday, Okta, AWS,
// GitHub and Snowflake, with 90 days of synthetic usage. Every name is invented.
//
// The model builds one DiscoveryResult per system; each demo connector simply
// returns its slice. Real connectors replace these one system at a time.
//
// The construction order and every random draw mirror the original Python
// model exactly (see PyRandom), so seed 7 yields the same company, ids and
// timestamps as before the Go port.

// Domain is the demo company's email domain.
const Domain = "larkspur.example"

// Systems lists the demo systems in connector order.
var Systems = []string{"workday", "okta", "aws", "github", "snowflake"}

var firstNames = []string{
	"Rosalind", "Caspian", "Mireille", "Kofi", "Alice", "Tomas", "Ingrid", "Rafael", "Sana", "Bastian",
	"Yara", "Callum", "Lena", "Marcus", "Oren", "Talia", "Joaquin", "Freya", "Idris", "Hana",
	"Wren", "Anika", "Desmond", "Ottilie", "Kenji", "Dmitri", "Teodor", "Esme", "Rohan", "Linnea",
	"Bram", "Ayasha", "Cyrus", "Delphine", "Femi", "Greer", "Priya", "Ilya", "Juno", "Leif",
	"Nikhil", "Odessa", "Pascal", "Quinn", "Hollis", "Soren", "Thandiwe", "Ulric", "Vesna", "Wim",
	"Xiomara", "Yusuf", "Zora", "Anders", "Beatrix", "Mei", "Dalia", "Emeric", "Zainab", "Marisol",
}

var lastNames = []string{
	"Okafor", "Bellweather", "Ramaswamy", "Lindqvist", "Achterberg", "Mensah", "Castellanos", "Haverford",
	"Quillfeather", "Ostrowski", "Quennell", "Delacroix", "Nakamura-Reyes", "Ferreira", "Abernathy",
	"Kowalczyk", "Mokoena", "Sorensen", "Whitlock", "Iyer", "Marchetti", "Oyelaran", "Pemberton",
	"Rasmussen", "Szabo", "Thornbury", "Valdivia", "Winslow", "Zeller", "Arkwright",
}

type orgTeam struct {
	dept, team string
	size       int
	titles     []string
}

// The first member of each team is its lead.
var org = []orgTeam{
	{"Executive", "exec", 3, []string{"Chief Executive Officer", "Chief Technology Officer", "Chief Financial Officer"}},
	{"Engineering", "backend", 7, []string{"Engineering Manager, Backend", "Senior Software Engineer", "Software Engineer"}},
	{"Engineering", "frontend", 5, []string{"Engineering Manager, Frontend", "Frontend Engineer"}},
	{"Engineering", "platform", 6, []string{"Platform Lead", "Site Reliability Engineer", "Platform Engineer"}},
	{"Data", "data", 7, []string{"Head of Data", "Data Engineer", "Analytics Engineer", "Data Scientist"}},
	{"Security", "security", 3, []string{"Head of Security", "Security Engineer"}},
	{"Finance", "finance", 8, []string{"Financial Controller", "AP Specialist", "Accountant", "FP&A Analyst"}},
	{"Sales", "sales", 10, []string{"VP Sales", "Account Executive", "Sales Development Rep", "Sales Ops Analyst"}},
	{"Support", "support", 7, []string{"Support Lead", "Support Engineer", "Customer Success Manager"}},
	{"People", "people", 4, []string{"Head of People", "HR Business Partner", "Recruiter"}},
}

type teamSlot struct {
	team string
	i    int
}

// Names pinned to specific roles so the demo tells a story.
var pinned = map[teamSlot][2]string{
	{"exec", 0}: {"Rosalind", "Haverford"}, {"exec", 1}: {"Caspian", "Arkwright"},
	{"exec", 2}: {"Mireille", "Delacroix"}, {"backend", 0}: {"Kofi", "Mensah"},
	{"backend", 1}: {"Alice", "Okafor"}, {"platform", 0}: {"Ingrid", "Lindqvist"},
	{"platform", 1}: {"Marcus", "Bellweather"}, {"platform", 2}: {"Oren", "Whitlock"},
	{"data", 0}: {"Sana", "Iyer"}, {"data", 1}: {"Dmitri", "Ostrowski"},
	{"security", 0}: {"Thandiwe", "Mokoena"}, {"finance", 0}: {"Beatrix", "Pemberton"},
	{"finance", 1}: {"Priya", "Ramaswamy"}, {"finance", 2}: {"Tomas", "Szabo"},
	{"finance", 3}: {"Linnea", "Sorensen"}, {"sales", 0}: {"Rafael", "Valdivia"},
	{"sales", 1}: {"Hollis", "Brightwater"}, {"support", 0}: {"Yara", "Castellanos"},
	{"support", 1}: {"Callum", "Ferreira"}, {"people", 0}: {"Esme", "Thornbury"},
}

// terminated people and how many days ago they left.
var terminated = map[string]int{"Hollis Brightwater": 35, "Dmitri Ostrowski": 50, "Oren Whitlock": 20}

// Person is one employee of the demo company.
type Person struct {
	EID, First, Last, Dept, Team, Title string
	Lead                                bool
	ManagerEID                          string
	Status                              string
	HiredAt                             time.Time
	TerminatedAt                        *time.Time
}

// Name is "First Last".
func (p *Person) Name() string { return p.First + " " + p.Last }

// Email is first.last@larkspur.example.
func (p *Person) Email() string {
	return strings.ToLower(p.First) + "." + strings.ReplaceAll(strings.ToLower(p.Last), " ", "") + "@" + Domain
}

func (p *Person) gh() string {
	last := strings.ToLower(p.Last)
	if r := []rune(last); len(r) > 5 {
		last = string(r[:5])
	}
	return strings.ToLower(p.First) + "-" + last
}

func (p *Person) sf() string {
	return strings.ToUpper(p.First) + "_" + strings.ReplaceAll(strings.ToUpper(p.Last), "-", "_")
}

func (p *Person) ref() *IdentityRef { return &IdentityRef{ExternalID: p.EID} }

type permMeta struct{ privileged bool }

// DemoCompany is the deterministic fictional company behind the demo connectors.
type DemoCompany struct {
	rng        *PyRandom
	Now        time.Time
	R          map[string]*DiscoveryResult
	Usage      map[string][]*UsageRecord
	HrisEvents []*HrisEventRecord
	People     []*Person
	byName     map[string]*Person

	children         map[Ref][]Ref
	identityAccounts map[string][]Ref
	identityType     map[string]string
	identityOrder    []string
	permMeta         map[Ref]permMeta
	unused           map[[2]string]bool
	dormant          map[string]int

	wdGroups map[string]Ref
	wdAcct   map[string]Ref
	okta     map[string]Ref
	oktaAcct map[string]Ref
	aws      map[string]Ref
	awsPerms map[string]Ref
	gh       map[string]Ref
	ghRepos  []string
	ghAcct   map[string]Ref
	sf       map[string]Ref
	sfAcct   map[string]Ref
}

// NewDemoCompany builds the company for a seed; "now" is truncated to midnight.
func NewDemoCompany(seed uint64, now time.Time) *DemoCompany {
	now = now.UTC()
	c := &DemoCompany{
		rng:              NewPyRandom(seed),
		Now:              time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC),
		R:                map[string]*DiscoveryResult{},
		Usage:            map[string][]*UsageRecord{},
		byName:           map[string]*Person{},
		children:         map[Ref][]Ref{},
		identityAccounts: map[string][]Ref{},
		identityType:     map[string]string{},
		permMeta:         map[Ref]permMeta{},
		unused:           map[[2]string]bool{},
		dormant:          map[string]int{},
	}
	for _, s := range Systems {
		c.R[s] = &DiscoveryResult{}
	}
	c.buildPeople()
	c.buildWorkday()
	c.buildOkta()
	c.buildAWS()
	c.buildGitHub()
	c.buildSnowflake()
	c.buildNHIs()
	c.buildAgents()
	c.buildUsage()
	c.buildHrisEvents()
	return c
}

var (
	companyMu    sync.Mutex
	companyCache = map[string]*DemoCompany{}
)

// GetCompany returns the (cached) company for a seed and the day of now.
func GetCompany(seed uint64, now time.Time) *DemoCompany {
	key := fmt.Sprintf("%d/%s", seed, timeutil.Date(now))
	companyMu.Lock()
	defer companyMu.Unlock()
	if c, ok := companyCache[key]; ok {
		return c
	}
	c := NewDemoCompany(seed, now)
	companyCache[key] = c
	return c
}

// ---------------------------------------------------------------- helpers

func sp(s string) *string { return &s }

func tp(t time.Time) *time.Time { return &t }

func (c *DemoCompany) daysAgo(n float64) time.Time { return timeutil.DaysAgo(c.Now, n) }

func (c *DemoCompany) resource(system, xid, name, kind string, env *string, tags ...string) {
	if tags == nil {
		tags = []string{}
	}
	c.R[system].Resources = append(c.R[system].Resources, ResourceRecord{system, xid, name, kind, env, tags})
}

func (c *DemoCompany) perm(system, action, resXID string, privileged bool) Ref {
	xid := action + "@" + resXID
	ref := Ref{"perm", system, xid}
	if _, ok := c.permMeta[ref]; !ok {
		c.R[system].Permissions = append(c.R[system].Permissions, PermissionRecord{system, xid, action, resXID, privileged})
		c.permMeta[ref] = permMeta{privileged}
	}
	return ref
}

func (c *DemoCompany) group(system, xid, name, kind string, privileged, requestable bool, desc *string) Ref {
	if name == "" {
		name = xid
	}
	c.R[system].Groups = append(c.R[system].Groups, GroupRecord{system, xid, name, kind, privileged, requestable, desc})
	return Ref{"group", system, xid}
}

func (c *DemoCompany) edge(src, dst Ref, relation, system string) {
	if system == "" {
		system = dst.System
	}
	c.R[system].Edges = append(c.R[system].Edges, EdgeRecord{Src: src, Dst: dst, Relation: relation})
	c.children[src] = append(c.children[src], dst)
}

func (c *DemoCompany) grant(g Ref, perms ...Ref) {
	for _, p := range perms {
		c.edge(g, p, "grants", "")
	}
}

func (c *DemoCompany) account(system, xid, username, ownerEID, kind, status string, created *time.Time) Ref {
	var ident *IdentityRef
	if ownerEID != "" {
		ident = &IdentityRef{ExternalID: ownerEID}
	}
	if created == nil {
		created = tp(c.daysAgo(float64(c.rng.RandInt(120, 900))))
	}
	var lastLogin *time.Time
	if status == "active" {
		lastLogin = tp(c.daysAgo(c.rng.Random() * 3))
	}
	c.R[system].Accounts = append(c.R[system].Accounts, AccountRecord{system, xid, username, ident, kind, status, created, lastLogin, nil})
	ref := Ref{"account", system, xid}
	if ownerEID != "" {
		c.identityAccounts[ownerEID] = append(c.identityAccounts[ownerEID], ref)
	}
	return ref
}

func (c *DemoCompany) member(acct Ref, groups ...Ref) {
	for _, g := range groups {
		c.edge(acct, g, "member_of", acct.System)
	}
}

func (c *DemoCompany) setType(xid, t string) {
	if _, ok := c.identityType[xid]; !ok {
		c.identityOrder = append(c.identityOrder, xid)
	}
	c.identityType[xid] = t
}

func (c *DemoCompany) team(team string) []*Person {
	var out []*Person
	for _, p := range c.People {
		if p.Team == team {
			out = append(out, p)
		}
	}
	return out
}

// P returns the person with the given full name.
func (c *DemoCompany) P(name string) *Person { return c.byName[name] }

// ------------------------------------------------------------------ build

func (c *DemoCompany) buildPeople() {
	pinnedFirst := map[string]bool{}
	for _, n := range pinned {
		pinnedFirst[n[0]] = true
	}
	var firsts []string
	for _, f := range firstNames {
		if !pinnedFirst[f] {
			firsts = append(firsts, f)
		}
	}
	c.rng.ShuffleStrings(firsts)
	n := 1001
	leads := map[string]*Person{}
	for _, t := range org {
		for i := 0; i < t.size; i++ {
			var first, last string
			if pn, ok := pinned[teamSlot{t.team, i}]; ok {
				first, last = pn[0], pn[1]
			} else {
				first, firsts = firsts[len(firsts)-1], firsts[:len(firsts)-1]
				last = lastNames[c.rng.ChoiceIndex(len(lastNames))]
			}
			var title string
			if i == 0 {
				title = t.titles[0]
			} else {
				pool := t.titles[1:]
				if len(pool) == 0 {
					pool = t.titles
				}
				title = pool[c.rng.ChoiceIndex(len(pool))]
			}
			if t.team == "exec" {
				title = t.titles[i]
			}
			p := &Person{EID: fmt.Sprintf("emp-%d", n), First: first, Last: last, Dept: t.dept, Team: t.team,
				Title: title, Lead: i == 0, Status: "active", HiredAt: c.daysAgo(float64(c.rng.RandInt(150, 2200)))}
			n++
			if i == 0 {
				leads[t.team] = p
			}
			c.People = append(c.People, p)
			c.byName[p.Name()] = p
		}
	}
	ceo, cto, cfo := c.P("Rosalind Haverford"), c.P("Caspian Arkwright"), c.P("Mireille Delacroix")
	execFor := map[string]*Person{"Engineering": cto, "Data": cto, "Security": cto, "Finance": cfo}
	for _, p := range c.People {
		switch {
		case p.Team == "exec":
			if p != ceo {
				p.ManagerEID = ceo.EID
			}
		case p.Lead:
			if m, ok := execFor[p.Dept]; ok {
				p.ManagerEID = m.EID
			} else {
				p.ManagerEID = ceo.EID
			}
		default:
			p.ManagerEID = leads[p.Team].EID
		}
		if d, ok := terminated[p.Name()]; ok {
			p.Status = "terminated"
			p.TerminatedAt = tp(c.daysAgo(float64(d)))
		}
		c.setType(p.EID, "human")
	}
}

func (c *DemoCompany) buildWorkday() {
	wd := c.R["workday"]
	for _, p := range c.People {
		var mgr *IdentityRef
		if p.ManagerEID != "" {
			mgr = &IdentityRef{ExternalID: p.ManagerEID}
		}
		wd.Identities = append(wd.Identities, IdentityRecord{
			ExternalID: p.EID, Name: p.Name(), Type: "human", Email: sp(p.Email()), Department: sp(p.Dept),
			Title: sp(p.Title), Status: p.Status, Manager: mgr, HiredAt: tp(p.HiredAt), TerminatedAt: p.TerminatedAt,
		})
	}
	prod := sp("prod")
	c.resource("workday", "supplier-payments", "Supplier Payments", "business_process", prod, "payments", "financial")
	c.resource("workday", "payroll", "Payroll", "business_process", prod, "payroll", "pii", "financial")
	c.resource("workday", "worker-records", "Worker Records", "dataset", prod, "pii", "hr")
	pc := c.perm("workday", "payments:create", "supplier-payments", false)
	pa := c.perm("workday", "payments:approve", "supplier-payments", false)
	pr := c.perm("workday", "payroll:run", "payroll", true)
	pv := c.perm("workday", "payroll:view", "payroll", false)
	wv := c.perm("workday", "workers:view", "worker-records", false)
	we := c.perm("workday", "workers:edit", "worker-records", true)
	gClerk := c.group("workday", "sg-ap-clerk", "AP Clerk", "security_group", false, false, sp("Create supplier payments"))
	gAppr := c.group("workday", "sg-ap-approver", "AP Approver", "security_group", false, false, sp("Approve supplier payments"))
	gPayroll := c.group("workday", "sg-payroll-admin", "Payroll Administrator", "security_group", true, false, nil)
	gHRBP := c.group("workday", "sg-hr-partner", "HR Partner", "security_group", false, false, nil)
	gMgr := c.group("workday", "sg-manager-ss", "Manager Self-Service", "security_group", false, false, nil)
	c.grant(gClerk, pc)
	c.grant(gAppr, pa)
	c.grant(gPayroll, pr, pv)
	c.grant(gHRBP, wv, we)
	c.grant(gMgr, wv)
	c.wdGroups = map[string]Ref{"clerk": gClerk, "approver": gAppr, "payroll": gPayroll, "hrbp": gHRBP, "mgr": gMgr}
	c.wdAcct = map[string]Ref{}
	for _, p := range c.People {
		status := "disabled"
		if p.Status == "active" {
			status = "active"
		}
		a := c.account("workday", p.EID, p.EID, p.EID, "user", status, tp(p.HiredAt))
		c.wdAcct[p.EID] = a
		if p.Lead {
			c.member(a, gMgr)
		}
	}
	fin := c.team("finance")
	// Priya holds both clerk and approver -> SoD violation
	c.member(c.wdAcct[c.P("Priya Ramaswamy").EID], gClerk, gAppr)
	c.member(c.wdAcct[c.P("Tomas Szabo").EID], gClerk)
	c.member(c.wdAcct[c.P("Linnea Sorensen").EID], gAppr)
	c.member(c.wdAcct[fin[4].EID], gClerk)
	c.member(c.wdAcct[c.P("Mireille Delacroix").EID], gAppr)
	c.member(c.wdAcct[fin[0].EID], gAppr, gPayroll)
	for _, p := range c.team("people") {
		c.member(c.wdAcct[p.EID], gHRBP)
	}
	c.member(c.wdAcct[c.team("people")[1].EID], gPayroll)
}

func (c *DemoCompany) buildOkta() {
	c.resource("okta", "tenant", "larkspur.okta.example", "idp_tenant", sp("prod"), "identity")
	sa := c.perm("okta", "okta:SuperAdmin", "tenant", true)
	ua := c.perm("okta", "okta:UserAdmin", "tenant", true)
	c.okta = map[string]Ref{}
	for _, g := range []string{"everyone", "engineering", "eng-backend", "eng-frontend", "eng-platform", "data-team",
		"security-team", "finance", "sales", "support", "people-ops", "executives"} {
		name := g
		if g == "everyone" {
			name = "Everyone"
		}
		c.okta[g] = c.group("okta", g, name, "group", false, false, nil)
	}
	c.okta["okta-super-admins"] = c.group("okta", "okta-super-admins", "okta-super-admins", "group", true, false, sp("Okta Super Administrators"))
	c.okta["okta-helpdesk"] = c.group("okta", "okta-helpdesk", "okta-helpdesk", "group", true, false, nil)
	c.grant(c.okta["okta-super-admins"], sa)
	c.grant(c.okta["okta-helpdesk"], ua)
	teamGroups := map[string][]string{
		"exec": {"executives"}, "backend": {"engineering", "eng-backend"},
		"frontend": {"engineering", "eng-frontend"}, "platform": {"engineering", "eng-platform"},
		"data": {"data-team"}, "security": {"security-team"}, "finance": {"finance"}, "sales": {"sales"},
		"support": {"support"}, "people": {"people-ops"},
	}
	c.oktaAcct = map[string]Ref{}
	for _, p := range c.People {
		status := "active"
		if p.Status == "terminated" && p.Name() != "Oren Whitlock" { // Oren's Okta account was missed
			status = "disabled"
		}
		a := c.account("okta", "00u"+p.EID[4:], p.Email(), p.EID, "user", status, tp(p.HiredAt))
		c.oktaAcct[p.EID] = a
		groups := []Ref{c.okta["everyone"]}
		for _, g := range teamGroups[p.Team] {
			groups = append(groups, c.okta[g])
		}
		c.member(a, groups...)
	}
	c.member(c.oktaAcct[c.P("Thandiwe Mokoena").EID], c.okta["okta-super-admins"])
	c.member(c.oktaAcct[c.P("Ingrid Lindqvist").EID], c.okta["okta-super-admins"])
	c.member(c.oktaAcct[c.team("security")[1].EID], c.okta["okta-helpdesk"])
	c.member(c.oktaAcct[c.team("support")[2].EID], c.okta["okta-helpdesk"])
}

func (c *DemoCompany) buildAWS() {
	prod, staging := sp("prod"), sp("staging")
	R := func(xid, name, kind string, env *string, tags ...string) {
		c.resource("aws", xid, name, kind, env, tags...)
	}
	R("s3:customer-pii", "s3://customer-pii", "s3_bucket", prod, "pii")
	R("s3:app-logs", "s3://app-logs", "s3_bucket", prod)
	R("s3:finance-reports", "s3://finance-reports", "s3_bucket", prod, "financial")
	R("s3:ml-artifacts", "s3://ml-artifacts", "s3_bucket", staging)
	R("s3:terraform-state", "s3://terraform-state", "s3_bucket", prod, "infra")
	R("rds:orders-db", "rds/orders-db", "rds_instance", prod, "pii")
	R("ec2:prod-fleet", "ec2/prod-fleet", "ec2_fleet", prod)
	R("acct:prod", "aws-account/larkspur-prod", "aws_account", prod)
	R("acct:staging", "aws-account/larkspur-staging", "aws_account", staging)
	R("kms:pii-key", "kms/pii-key", "kms_key", prod, "pii")
	ap := map[string]Ref{}
	p := func(name, action, res string, priv bool) { ap[name] = c.perm("aws", action, res, priv) }
	p("get_pii", "s3:GetObject", "s3:customer-pii", false)
	p("put_pii", "s3:PutObject", "s3:customer-pii", false)
	p("del_pii", "s3:DeleteObject", "s3:customer-pii", true)
	p("get_logs", "s3:GetObject", "s3:app-logs", false)
	p("put_logs", "s3:PutObject", "s3:app-logs", false)
	p("get_fin", "s3:GetObject", "s3:finance-reports", false)
	p("put_fin", "s3:PutObject", "s3:finance-reports", false)
	p("get_ml", "s3:GetObject", "s3:ml-artifacts", false)
	p("put_ml", "s3:PutObject", "s3:ml-artifacts", false)
	p("get_tf", "s3:GetObject", "s3:terraform-state", false)
	p("put_tf", "s3:PutObject", "s3:terraform-state", true)
	p("rds_conn", "rds:Connect", "rds:orders-db", false)
	p("rds_mod", "rds:ModifyDBInstance", "rds:orders-db", true)
	p("ec2_desc", "ec2:DescribeInstances", "ec2:prod-fleet", false)
	p("ec2_term", "ec2:TerminateInstances", "ec2:prod-fleet", true)
	p("admin_prod", "iam:*", "acct:prod", true)
	p("admin_stg", "iam:*", "acct:staging", true)
	p("iam_read", "iam:GetAccountAuthorizationDetails", "acct:prod", false)
	p("ce", "ce:GetCostAndUsage", "acct:prod", false)
	p("kms", "kms:Decrypt", "kms:pii-key", false)
	c.awsPerms = ap
	role := func(x string, priv, req bool, d string) Ref {
		var desc *string
		if d != "" {
			desc = sp(d)
		}
		return c.group("aws", "role/"+x, x, "role", priv, req, desc)
	}
	c.aws = map[string]Ref{}
	c.aws["DevAdmin"] = role("DevAdmin", true, false, "Developer admin on staging (legacy: also reads customer-pii)")
	c.aws["ProdReadOnly"] = role("ProdReadOnly", false, false, "Read-only access to prod")
	c.aws["ProdAdmin"] = role("ProdAdmin", true, true, "Full admin on the prod account")
	c.aws["BreakGlassAdmin"] = role("BreakGlassAdmin", true, true, "Emergency admin (JIT only)")
	c.aws["DataEngineer"] = role("DataEngineer", false, false, "Data platform access")
	c.aws["BillingAdmin"] = role("BillingAdmin", false, false, "Cost and finance reporting")
	c.aws["SecurityAudit"] = role("SecurityAudit", false, false, "Security read-only audit")
	c.aws["CIDeployRole"] = role("CIDeployRole", true, false, "Assumed by CI to deploy infrastructure")
	c.aws["SREAgentRole"] = role("SREAgentRole", false, false, "Assumed by the SRE on-call agent")
	A := c.aws
	c.grant(A["DevAdmin"], ap["admin_stg"], ap["get_ml"], ap["put_ml"], ap["get_pii"], ap["get_logs"])
	c.grant(A["ProdReadOnly"], ap["ec2_desc"], ap["get_logs"], ap["rds_conn"])
	c.grant(A["ProdAdmin"], ap["admin_prod"], ap["ec2_term"], ap["rds_mod"], ap["del_pii"], ap["put_tf"], ap["get_tf"], ap["ec2_desc"])
	c.grant(A["BreakGlassAdmin"], ap["admin_prod"])
	c.grant(A["DataEngineer"], ap["get_pii"], ap["put_pii"], ap["get_ml"], ap["put_ml"], ap["kms"], ap["rds_conn"])
	c.grant(A["BillingAdmin"], ap["ce"], ap["get_fin"], ap["put_fin"])
	c.grant(A["SecurityAudit"], ap["iam_read"], ap["get_logs"], ap["ec2_desc"], ap["get_tf"])
	c.grant(A["CIDeployRole"], ap["put_tf"], ap["get_tf"], ap["ec2_term"], ap["put_ml"], ap["get_ml"])
	c.edge(A["SREAgentRole"], A["ProdReadOnly"], "maps_to", "")
	// SAML federation: Okta groups -> AWS roles
	for _, m := range []struct {
		g     string
		roles []string
	}{
		{"engineering", []string{"DevAdmin", "ProdReadOnly"}}, {"eng-platform", []string{"ProdAdmin"}},
		{"data-team", []string{"DataEngineer"}}, {"finance", []string{"BillingAdmin"}},
		{"security-team", []string{"SecurityAudit", "ProdReadOnly"}},
	} {
		for _, r := range m.roles {
			c.edge(c.okta[m.g], A[r], "maps_to", "aws")
		}
	}
}

func (c *DemoCompany) ghPerm(a, r string) Ref {
	return c.perm("github", "repo:"+a, "repo:"+r, a == "admin")
}

func (c *DemoCompany) buildGitHub() {
	type repo struct {
		name string
		env  *string
		tags []string
	}
	repos := []repo{
		{"payments-service", sp("prod"), []string{"payments"}}, {"web-app", sp("prod"), nil}, {"mobile-app", sp("prod"), nil},
		{"infra-terraform", sp("prod"), []string{"infra"}}, {"data-pipelines", sp("prod"), nil},
		{"ml-models", sp("staging"), nil}, {"docs-site", nil, nil},
	}
	for _, r := range repos {
		c.resource("github", "repo:"+r.name, "larkspur/"+r.name, "repository", r.env, r.tags...)
		c.ghRepos = append(c.ghRepos, r.name)
	}
	c.resource("github", "org", "github.com/larkspur", "org", sp("prod"))
	orgAdmin := c.perm("github", "org:admin", "org", true)
	c.gh = map[string]Ref{}
	for _, t := range []string{"backend", "frontend", "platform", "data", "security", "all-engineers"} {
		c.gh[t] = c.group("github", "team/"+t, t, "team", false, false, nil)
	}
	c.gh["org-owners"] = c.group("github", "team/org-owners", "org-owners", "team", true, false, nil)
	T := c.gh
	gp := c.ghPerm
	var reads []Ref
	for _, r := range c.ghRepos {
		reads = append(reads, gp("read", r))
	}
	c.grant(T["all-engineers"], reads...)
	c.grant(T["backend"], gp("write", "payments-service"), gp("write", "web-app"))
	c.grant(T["frontend"], gp("write", "web-app"), gp("write", "mobile-app"), gp("write", "docs-site"))
	plat := []Ref{gp("admin", "infra-terraform")}
	for _, r := range c.ghRepos {
		plat = append(plat, gp("write", r))
	}
	c.grant(T["platform"], plat...)
	c.grant(T["data"], gp("write", "data-pipelines"), gp("write", "ml-models"))
	c.grant(T["security"], gp("admin", "payments-service"), gp("read", "infra-terraform"))
	c.grant(T["org-owners"], orgAdmin)
	c.ghAcct = map[string]Ref{}
	eng := map[string]bool{"backend": true, "frontend": true, "platform": true, "data": true, "security": true}
	for _, p := range c.People {
		if !eng[p.Team] && p.Name() != "Caspian Arkwright" {
			continue
		}
		// GitHub accounts are not deprovisioned when people leave.
		a := c.account("github", p.gh(), p.gh(), p.EID, "user", "active", tp(p.HiredAt))
		c.ghAcct[p.EID] = a
		teams := []Ref{T["all-engineers"]}
		if t, ok := T[p.Team]; ok {
			teams = append(teams, t)
		}
		c.member(a, teams...)
	}
	for _, n := range []string{"Caspian Arkwright", "Ingrid Lindqvist", "Kofi Mensah"} {
		c.member(c.ghAcct[c.P(n).EID], T["org-owners"])
	}
}

func (c *DemoCompany) buildSnowflake() {
	for _, db := range []struct {
		name string
		tags []string
	}{{"CUSTOMERS", []string{"pii"}}, {"FINANCE", []string{"financial"}}, {"EVENTS", nil}, {"MARKETING", nil}} {
		c.resource("snowflake", "db:"+db.name, "snowflake/"+db.name, "database", sp("prod"), db.tags...)
	}
	c.resource("snowflake", "account", "snowflake/LARKSPUR_SF", "warehouse_account", sp("prod"))
	spm := func(a, r string, priv bool) Ref { return c.perm("snowflake", "snowflake:"+a, "db:"+r, priv) }
	acctadmin := c.perm("snowflake", "snowflake:ACCOUNTADMIN", "account", true)
	c.sf = map[string]Ref{}
	for _, r := range []string{"ANALYST", "PII_READER", "DATA_ENGINEER", "FINANCE_ANALYST", "LOADER", "REPORTING"} {
		c.sf[r] = c.group("snowflake", "role/"+r, r, "role", false, false, nil)
	}
	c.sf["ACCOUNTADMIN"] = c.group("snowflake", "role/ACCOUNTADMIN", "ACCOUNTADMIN", "role", true, true, nil)
	c.sf["SYSADMIN"] = c.group("snowflake", "role/SYSADMIN", "SYSADMIN", "role", true, false, nil)
	S := c.sf
	c.grant(S["ANALYST"], spm("SELECT", "EVENTS", false), spm("SELECT", "MARKETING", false))
	c.grant(S["PII_READER"], spm("SELECT", "CUSTOMERS", false))
	c.grant(S["DATA_ENGINEER"], spm("INSERT", "EVENTS", false), spm("INSERT", "CUSTOMERS", false), spm("INSERT", "MARKETING", false))
	c.grant(S["FINANCE_ANALYST"], spm("SELECT", "FINANCE", false))
	c.grant(S["LOADER"], spm("INSERT", "EVENTS", false), spm("INSERT", "CUSTOMERS", false))
	c.grant(S["REPORTING"], spm("SELECT", "EVENTS", false), spm("SELECT", "FINANCE", false))
	c.grant(S["ACCOUNTADMIN"], acctadmin)
	var own []Ref
	for _, d := range []string{"CUSTOMERS", "FINANCE", "EVENTS", "MARKETING"} {
		own = append(own, spm("OWNERSHIP", d, true))
	}
	c.grant(S["SYSADMIN"], own...)
	// role hierarchy
	c.edge(S["DATA_ENGINEER"], S["ANALYST"], "maps_to", "")
	c.edge(S["DATA_ENGINEER"], S["PII_READER"], "maps_to", "")
	c.edge(S["ACCOUNTADMIN"], S["SYSADMIN"], "maps_to", "")
	c.sfAcct = map[string]Ref{}
	sfuser := func(p *Person, roles ...string) {
		a := c.account("snowflake", p.sf(), p.sf(), p.EID, "user", "active", tp(p.HiredAt))
		c.sfAcct[p.EID] = a
		for _, r := range roles {
			c.member(a, S[r])
		}
	}
	for _, p := range c.team("data") {
		sfuser(p, "DATA_ENGINEER")
	}
	for _, p := range c.team("finance")[:5] {
		sfuser(p, "FINANCE_ANALYST")
	}
	for _, p := range c.team("sales")[:6] {
		sfuser(p, "ANALYST")
	}
	for _, p := range c.team("support")[:3] {
		sfuser(p, "ANALYST", "PII_READER")
	}
	sfuser(c.P("Mireille Delacroix"), "FINANCE_ANALYST", "ANALYST")
	sfuser(c.P("Kofi Mensah"), "ANALYST")
	// standing ACCOUNTADMIN for two data folks (one never uses it)
	c.member(c.sfAcct[c.P("Sana Iyer").EID], S["ACCOUNTADMIN"])
	c.member(c.sfAcct[c.team("data")[2].EID], S["ACCOUNTADMIN"])
}

// ------------------------------------------------------- non-human identities

func (c *DemoCompany) nhi(xid, name, system, owner, desc, kind string) string {
	var ownerRef *IdentityRef
	if owner != "" {
		ownerRef = &IdentityRef{ExternalID: c.P(owner).EID}
	}
	c.R[system].Identities = append(c.R[system].Identities, IdentityRecord{
		ExternalID: xid, Name: name, Type: "service", Title: sp(kind), Status: "active", Owner: ownerRef, Description: sp(desc),
	})
	c.setType(xid, "service")
	return xid
}

func (c *DemoCompany) secret(system string, acct Ref, kind, name string, age float64, lastUsed float64) {
	c.R[system].Secrets = append(c.R[system].Secrets, SecretRecord{
		System: system, ExternalID: acct.ExternalID + "/" + name, Account: acct, Kind: kind, Name: name,
		CreatedAt: c.daysAgo(age), LastUsedAt: tp(c.daysAgo(lastUsed)),
	})
}

func (c *DemoCompany) buildNHIs() {
	A, S, O, ap := c.aws, c.sf, c.okta, c.awsPerms
	awsNHIs := []struct {
		name, owner, desc string
		roles, perms      []Ref
		keyAge, lastUsed  float64
	}{
		{"svc-ci-deployer", "Ingrid Lindqvist", "CI/CD pipeline deployer", []Ref{A["CIDeployRole"]}, nil, 412, 0.1},
		{"svc-backup-agent", "Dmitri Ostrowski", "Nightly RDS/S3 backup job", nil, []Ref{ap["get_pii"], ap["rds_conn"], ap["put_logs"]}, 230, 0.5},
		{"svc-legacy-etl", "", "Legacy ETL from the 2022 data platform", nil, []Ref{ap["get_pii"], ap["get_fin"], ap["kms"]}, 780, 128},
		{"svc-log-shipper", "Thandiwe Mokoena", "Ships logs to the SIEM", nil, []Ref{ap["put_logs"], ap["get_logs"]}, 31, 0.1},
		{"svc-cost-exporter", "Beatrix Pemberton", "Exports cost data to finance", nil, []Ref{ap["ce"], ap["put_fin"]}, 95, 1},
		{"svc-terraform", "Ingrid Lindqvist", "Terraform Cloud runner", nil, []Ref{ap["admin_prod"], ap["put_tf"]}, 160, 2},
		{"svc-monitoring", "Marcus Bellweather", "Metrics collector", nil, []Ref{ap["ec2_desc"]}, 60, 0.1},
		{"svc-lambda-orders", "Kofi Mensah", "Orders Lambda execution identity", nil, []Ref{ap["rds_conn"]}, 12, 0.1},
		{"svc-data-export", "Oren Whitlock", "Ad-hoc customer export for a 2025 audit", nil, []Ref{ap["get_pii"], ap["put_fin"]}, 340, 74},
	}
	for _, n := range awsNHIs {
		xid := c.nhi("nhi-aws-"+n.name, n.name, "aws", n.owner, n.desc, "AWS IAM user")
		a := c.account("aws", "iam-user/"+n.name, n.name, xid, "service", "active", nil)
		for _, r := range n.roles {
			c.edge(a, r, "member_of", "aws")
		}
		for _, p := range n.perms {
			c.edge(a, p, "direct_grant", "aws")
		}
		key := strings.ReplaceAll(strings.ToUpper(n.name), "-", "")
		if len(key) > 12 {
			key = key[:12]
		}
		c.secret("aws", a, "access_key", "AKIA"+key, n.keyAge, n.lastUsed)
		if n.lastUsed > 60 {
			c.dormant[xid] = int(n.lastUsed)
		}
	}
	gp := c.ghPerm
	allRepos := func(a string) []Ref {
		var out []Ref
		for _, r := range c.ghRepos {
			out = append(out, gp(a, r))
		}
		return out
	}
	ghNHIs := []struct {
		name, owner, desc, kind string
		perms                   []Ref
		age, lastUsed           float64
	}{
		{"release-bot", "Ingrid Lindqvist", "GitHub App that cuts releases", "github_app", allRepos("write"), 45, 0.2},
		{"infra-deploy-key", "", "Deploy key on infra-terraform", "deploy_key", []Ref{gp("write", "infra-terraform")}, 610, 3},
		{"jenkins-pat", "Oren Whitlock", "Personal access token used by legacy Jenkins", "pat",
			[]Ref{gp("admin", "payments-service"), gp("write", "web-app")}, 300, 0.5},
		{"dependabot-svc", "Thandiwe Mokoena", "Dependency update automation", "github_app", allRepos("read"), 20, 0.1},
		{"docs-publisher", "", "Publishes docs-site on merge", "deploy_key", []Ref{gp("write", "docs-site")}, 20, 1},
	}
	for _, n := range ghNHIs {
		xid := c.nhi("nhi-gh-"+n.name, n.name, "github", n.owner, n.desc, "GitHub "+strings.ReplaceAll(n.kind, "_", " "))
		a := c.account("github", "bot/"+n.name, n.name, xid, "service", "active", nil)
		for _, p := range n.perms {
			c.edge(a, p, "direct_grant", "github")
		}
		c.secret("github", a, n.kind, n.name+"-token", n.age, n.lastUsed)
	}
	sfNHIs := []struct {
		name, owner, desc string
		roles             []string
		age, lastUsed     float64
	}{
		{"FIVETRAN_LOADER", "Sana Iyer", "Fivetran ingestion", []string{"LOADER"}, 70, 0.1},
		{"DBT_RUNNER", "Sana Iyer", "dbt transformations", []string{"DATA_ENGINEER"}, 200, 0.1},
		{"LOOKER_SVC", "Dmitri Ostrowski", "Looker BI connection", []string{"ANALYST", "PII_READER"}, 400, 0.2},
		{"TABLEAU_LEGACY", "", "Retired Tableau server", []string{"REPORTING"}, 900, 150},
		{"REVERSE_ETL_SVC", "Rafael Valdivia", "Syncs customer segments to CRM", []string{"PII_READER"}, 120, 0.5},
	}
	for _, n := range sfNHIs {
		xid := c.nhi("nhi-sf-"+strings.ToLower(n.name), n.name, "snowflake", n.owner, n.desc, "Snowflake service user")
		a := c.account("snowflake", "svc/"+n.name, n.name, xid, "service", "active", nil)
		for _, r := range n.roles {
			c.member(a, S[r])
		}
		c.secret("snowflake", a, "keypair", n.name+"_rsa", n.age, n.lastUsed)
		if n.lastUsed > 60 {
			c.dormant[xid] = int(n.lastUsed)
		}
	}
	oktaNHIs := []struct {
		name, owner, desc string
		groups            []Ref
		age               float64
	}{
		{"scim-provisioner", "Thandiwe Mokoena", "SCIM provisioning token", []Ref{O["okta-super-admins"]}, 88},
		{"hr-sync-token", "Esme Thornbury", "Workday -> Okta HR sync", []Ref{O["okta-helpdesk"]}, 140},
		{"old-migration-token", "", "Token from the 2023 IdP migration", []Ref{O["okta-super-admins"]}, 700},
	}
	for _, n := range oktaNHIs {
		xid := c.nhi("nhi-okta-"+n.name, n.name, "okta", n.owner, n.desc, "Okta API token")
		a := c.account("okta", "svc/"+n.name, n.name, xid, "api_key", "active", nil)
		c.member(a, n.groups...)
		lu := 0.3
		if n.name == "old-migration-token" {
			lu = 200
		}
		c.secret("okta", a, "api_token", n.name, n.age, lu)
		if lu > 60 {
			c.dormant[xid] = int(lu)
		}
	}
	wdNHIs := []struct {
		name, owner, desc string
		groups            []Ref
		age               float64
	}{
		{"ISU_Okta_Sync", "Esme Thornbury", "Integration user for Okta sync", []Ref{c.wdGroups["hrbp"]}, 365},
		{"ISU_Payroll_Export", "Beatrix Pemberton", "Payroll export to bank", []Ref{c.wdGroups["payroll"]}, 500},
		{"ISU_Expense_Bot", "Hollis Brightwater", "Expense report automation", []Ref{c.wdGroups["clerk"]}, 260},
	}
	for _, n := range wdNHIs {
		xid := c.nhi("nhi-wd-"+strings.ToLower(n.name), n.name, "workday", n.owner, n.desc, "Workday integration user")
		a := c.account("workday", "isu/"+n.name, n.name, xid, "service", "active", nil)
		c.member(a, n.groups...)
		c.secret("workday", a, "password", n.name+"-password", n.age, 1)
	}
}

// ------------------------------------------------------------ AI agents

func (c *DemoCompany) buildAgents() {
	S, A := c.sf, c.aws
	gp := c.ghPerm
	type deleg struct {
		principal string
		scopes    []string
	}
	agents := []struct {
		xid, name, owner, desc string
		delegations            []deleg
		wire                   func(Ref)
		system                 string
		keyAge                 float64
	}{
		{"agent-support-copilot", "Support Copilot", "Yara Castellanos", "Drafts replies to customer tickets using account history",
			[]deleg{{"Yara Castellanos", []string{"tickets:read", "customers:read"}},
				{"Callum Ferreira", []string{"tickets:read", "customers:read", "tickets:reply"}}},
			func(a Ref) { c.member(a, S["PII_READER"]) }, "snowflake", 25},
		{"agent-code-review", "Code Review Bot", "Kofi Mensah", "Reviews pull requests and suggests fixes",
			[]deleg{{"Alice Okafor", []string{"github:pull_request:comment", "github:repo:read"}}},
			func(a Ref) {
				for _, r := range c.ghRepos {
					c.edge(a, gp("read", r), "direct_grant", "github")
				}
				c.edge(a, gp("write", "web-app"), "direct_grant", "github")
			}, "github", 40},
		{"agent-finance-recon", "Finance Recon Agent", "Beatrix Pemberton", "Reconciles supplier invoices and prepares payments",
			[]deleg{{"Beatrix Pemberton", []string{"workday:payments:create", "snowflake:query:FINANCE"}}},
			func(a Ref) { c.member(a, c.wdGroups["clerk"]) }, "workday", 60},
		{"agent-data-analyst", "Data Analyst Agent", "Sana Iyer", "Answers ad-hoc analytics questions in Slack",
			[]deleg{{"Sana Iyer", []string{"snowflake:query"}}, {"Rafael Valdivia", []string{"snowflake:query:MARKETING"}}},
			func(a Ref) { c.member(a, S["ANALYST"], S["PII_READER"]) }, "snowflake", 100},
		{"agent-sre-oncall", "SRE On-call Agent", "Marcus Bellweather", "Triages alerts and gathers diagnostics from prod",
			[]deleg{{"Marcus Bellweather", []string{"aws:ec2:describe", "aws:logs:read"}}},
			func(a Ref) { c.member(a, A["SREAgentRole"]) }, "aws", 15},
		{"agent-sales-research", "Sales Research Agent", "Hollis Brightwater", "Enriches leads and summarizes accounts before calls",
			[]deleg{{"Hollis Brightwater", []string{"snowflake:query:MARKETING", "crm:read"}}},
			func(a Ref) { c.member(a, S["ANALYST"], S["REPORTING"]) }, "snowflake", 210},
	}
	oktaAgents := c.group("okta", "ai-agents", "ai-agents", "group", false, false, sp("Registered AI agent identities"))
	for _, ag := range agents {
		c.R["okta"].Identities = append(c.R["okta"].Identities, IdentityRecord{
			ExternalID: ag.xid, Name: ag.name, Type: "ai_agent", Title: sp("AI agent"), Status: "active",
			Owner: &IdentityRef{ExternalID: c.P(ag.owner).EID}, Description: sp(ag.desc),
		})
		c.setType(ag.xid, "ai_agent")
		oa := c.account("okta", "agent/"+ag.xid, ag.xid+"@agents."+Domain, ag.xid, "agent", "active", nil)
		c.member(oa, oktaAgents)
		sysAcct := c.account(ag.system, "agent/"+ag.xid, ag.xid, ag.xid, "agent", "active", nil)
		ag.wire(sysAcct)
		c.secret(ag.system, sysAcct, "api_token", ag.xid+"-key", ag.keyAge, 0.1)
		for _, d := range ag.delegations {
			c.R["okta"].Delegations = append(c.R["okta"].Delegations, DelegationRecord{
				Agent: IdentityRef{ExternalID: ag.xid}, Principal: IdentityRef{ExternalID: c.P(d.principal).EID}, Scopes: d.scopes,
			})
		}
	}
}

// ---------------------------------------------------------------- usage

type reach struct {
	perm, acct Ref
}

// reachable returns perm refs reachable from an identity's accounts (model
// level, ignoring status) with the account each is first reached through.
func (c *DemoCompany) reachable(eid string) []reach {
	var out []reach
	got := map[Ref]bool{}
	for _, acct := range c.identityAccounts[eid] {
		stack := []Ref{acct}
		seen := map[Ref]bool{}
		for len(stack) > 0 {
			cur := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, nxt := range c.children[cur] {
				if seen[nxt] {
					continue
				}
				seen[nxt] = true
				if nxt.Kind == "perm" {
					if !got[nxt] {
						got[nxt] = true
						out = append(out, reach{nxt, acct})
					}
				} else {
					stack = append(stack, nxt)
				}
			}
		}
	}
	return out
}

func (c *DemoCompany) buildUsage() {
	rng := c.rng
	alice := c.P("Alice Okafor").EID
	for _, x := range []string{"s3:GetObject@s3:customer-pii", "iam:*@acct:staging", "s3:PutObject@s3:ml-artifacts"} {
		c.unused[[2]string{alice, x}] = true
	}
	// Legacy DevAdmin grant to customer-pii: no engineer actually uses it -> role-level trim
	for _, t := range []string{"backend", "frontend", "platform"} {
		for _, p := range c.team(t) {
			c.unused[[2]string{p.EID, "s3:GetObject@s3:customer-pii"}] = true
		}
	}
	c.unused[[2]string{c.team("data")[2].EID, "snowflake:ACCOUNTADMIN@account"}] = true
	c.unused[[2]string{c.P("Priya Ramaswamy").EID, "payments:approve@supplier-payments"}] = true

	type idp struct {
		eid    string
		person *Person
	}
	var ids []idp
	for _, p := range c.People {
		ids = append(ids, idp{p.EID, p})
	}
	for _, x := range c.identityOrder {
		if c.identityType[x] != "human" {
			ids = append(ids, idp{x, nil})
		}
	}
	for _, id := range ids {
		perms := c.reachable(id.eid)
		if len(perms) == 0 {
			continue
		}
		itype := c.identityType[id.eid]
		lastActive := 0
		if id.person != nil && id.person.Status == "terminated" {
			lastActive = terminated[id.person.Name()]
		}
		if d, ok := c.dormant[id.eid]; ok {
			lastActive = d
		}
		var activity float64
		if itype == "human" {
			activity = rng.Uniform(0.25, 0.7)
		} else {
			activity = rng.Uniform(0.7, 1.0)
		}
		for _, pr := range perms {
			privileged := c.permMeta[pr.perm].privileged
			if c.unused[[2]string{id.eid, pr.perm.ExternalID}] {
				continue
			}
			roll := rng.Random()
			pUnused := 0.25
			if privileged {
				pUnused = 0.55
			}
			if itype != "human" {
				pUnused *= 0.5
			}
			if roll < pUnused {
				continue // granted, never used
			}
			windowEnd := lastActive
			var days []int
			if roll < pUnused+0.1 && itype == "human" {
				windowEnd = max(windowEnd, rng.RandInt(62, 85)) // used once, long ago
				days = []int{rng.RandInt(windowEnd, 89)}
			} else {
				rate := activity
				if privileged {
					rate *= 0.3
				}
				for d := windowEnd; d < 90; d++ {
					if rng.Random() < rate {
						days = append(days, d)
					}
				}
			}
			hi := 12
			if itype != "human" {
				hi = 40
			}
			for _, d := range days {
				cnt := rng.RandInt(1, hi)
				acct := pr.acct
				c.Usage[pr.perm.System] = append(c.Usage[pr.perm.System], &UsageRecord{
					Identity: IdentityRef{ExternalID: id.eid}, Permission: pr.perm, Day: c.daysAgo(float64(d)), Count: cnt, Account: &acct,
				})
			}
		}
	}
}

// ------------------------------------------------------------ HRIS feed

func (c *DemoCompany) buildHrisEvents() {
	marcus := c.P("Marcus Bellweather")
	mover := c.team("support")[3]
	c.HrisEvents = []*HrisEventRecord{
		{"wd-evt-9001", "leaver", marcus.ref(), c.Now,
			ojson.Object{{Key: "reason", Value: "Resignation"}, {Key: "last_day", Value: timeutil.Date(c.Now)}}},
		{"wd-evt-9002", "mover", mover.ref(), c.Now.Add(48 * time.Hour),
			ojson.Object{{Key: "from_department", Value: "Support"}, {Key: "to_department", Value: "Sales"}, {Key: "from_team", Value: "support"},
				{Key: "to_team", Value: "sales"}, {Key: "new_title", Value: "Account Executive"}}},
		{"wd-evt-9003", "joiner", nil, c.Now.Add(72 * time.Hour),
			ojson.Object{{Key: "name", Value: "Noor Achterberg"}, {Key: "email", Value: "noor.achterberg@" + Domain}, {Key: "department", Value: "Data"},
				{Key: "team", Value: "data"}, {Key: "title", Value: "Analytics Engineer"}, {Key: "manager_external_id", Value: c.P("Sana Iyer").EID}}},
	}
	for _, p := range c.People {
		if p.Status == "terminated" {
			c.HrisEvents = append(c.HrisEvents, &HrisEventRecord{
				"wd-evt-term-" + p.EID, "leaver", p.ref(), *p.TerminatedAt,
				ojson.Object{{Key: "reason", Value: "Voluntary"}, {Key: "historical", Value: true}},
			})
		}
	}
}
