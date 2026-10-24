package successfactors

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// The fields asked of each entity. Nothing else is read: no date of birth,
// national id, compensation or bank details ever leave SuccessFactors.
const (
	selUser   = "userId,username,displayName,email,title,department,status,hireDate"
	selEmp    = "userId,personIdExternal,startDate,endDate"
	selJob    = "userId,seqNumber,startDate,endDate,department,jobTitle,managerId,location,costCenter,company,departmentNav/name"
	selPerson = "personIdExternal,personalInfoNav/firstName,personalInfoNav/lastName"
)

type oUser struct {
	UserID, Username, DisplayName, Email, Title, Department, Status, HireDate flex
}

type oEmp struct {
	UserID, PersonIDExternal, StartDate, EndDate flex
}

type oJob struct {
	UserID, SeqNumber, StartDate, EndDate, Department, JobTitle, ManagerID, Location, CostCenter, Company flex
	DepartmentNav                                                                                         struct{ Name flex } `json:"departmentNav"`
}

type oPerson struct {
	PersonIDExternal flex
	PersonalInfoNav  struct {
		Results []struct{ FirstName, LastName flex } `json:"results"`
	} `json:"personalInfoNav"`
}

func (j *oJob) deptName() string {
	if j.DepartmentNav.Name != "" {
		return string(j.DepartmentNav.Name)
	}
	return string(j.Department)
}

// noManager is the value SuccessFactors puts in managerId when there is none.
const noManager = "NO_MANAGER"

// snapshot is one read: users, the latest employment and the current job per
// user id, and the names of people without a User row.
type snapshot struct {
	users map[string]*oUser
	emps  map[string]*oEmp
	jobs  map[string]*oJob
	names map[string]string // person id -> display name (PerPerson)
}

func (c *Connector) jobFilter(from, to time.Time) (string, error) {
	f := "startDate le " + odataTime(to) + " and endDate ge " + odataTime(from)
	if c.cfg.LegalEntity != "" {
		lit, err := odataString(c.cfg.LegalEntity)
		if err != nil {
			return "", err
		}
		f += " and company eq " + lit
	}
	return f, nil
}

// readUsers, readEmployments, readPeople fill st; readJobs is shared with the
// event read (from, to is the effective window asked for).
func (c *Connector) readUsers(ctx context.Context, st *snapshot) error {
	q := url.Values{"$select": {selUser}}
	return wrap("users", listAll(ctx, c, "User", q, func(u oUser) error {
		if u.UserID != "" && len(u.UserID) <= 128 {
			st.users[string(u.UserID)] = &u
		}
		return nil
	}))
}

func (c *Connector) readEmployments(ctx context.Context, st *snapshot) error {
	q := url.Values{"$select": {selEmp}}
	return wrap("employments", listAll(ctx, c, "EmpEmployment", q, func(e oEmp) error {
		if e.UserID == "" || len(e.UserID) > 128 || len(e.PersonIDExternal) > 128 {
			return nil
		}
		// a rehire leaves several rows: the latest start is the current employment
		if prev := st.emps[string(e.UserID)]; prev != nil {
			p, n := parseTime(string(prev.StartDate)), parseTime(string(e.StartDate))
			if p != nil && (n == nil || n.Before(*p)) {
				return nil
			}
		}
		st.emps[string(e.UserID)] = &e
		return nil
	}))
}

func (c *Connector) readPeople(ctx context.Context, st *snapshot) error {
	q := url.Values{"$select": {selPerson}, "$expand": {"personalInfoNav"}}
	err := listAll(ctx, c, "PerPerson", q, func(p oPerson) error {
		if p.PersonIDExternal == "" || len(p.PersonalInfoNav.Results) == 0 {
			return nil
		}
		n := p.PersonalInfoNav.Results[len(p.PersonalInfoNav.Results)-1]
		if name := strings.TrimSpace(string(n.FirstName) + " " + string(n.LastName)); name != "" {
			st.names[string(p.PersonIDExternal)] = name
		}
		return nil
	})
	// Without the role-based permission to read PerPerson the names of people
	// who have no User row (leavers) fall back to their ids; the rest still reads.
	if s := connsync.Status(err); s == 403 || s == 404 {
		return nil
	}
	return wrap("people", err)
}

// readJobs reads the job rows effective between from and to.
func (c *Connector) readJobs(ctx context.Context, from, to time.Time, each func(oJob)) error {
	f, err := c.jobFilter(from, to)
	if err != nil {
		return err
	}
	q := url.Values{"$select": {selJob}, "$expand": {"departmentNav"}, "$filter": {f}}
	return wrap("jobs", listAll(ctx, c, "EmpJob", q, func(j oJob) error {
		if j.UserID != "" && len(j.UserID) <= 128 {
			each(j)
		}
		return nil
	}))
}

func wrap(what string, err error) error {
	if err != nil {
		return fmt.Errorf("successfactors: %s: %w", what, err)
	}
	return nil
}

func (c *Connector) read(ctx context.Context, now time.Time) (*snapshot, error) {
	st := &snapshot{users: map[string]*oUser{}, emps: map[string]*oEmp{}, jobs: map[string]*oJob{}, names: map[string]string{}}
	if err := c.readUsers(ctx, st); err != nil {
		return nil, err
	}
	if err := c.readEmployments(ctx, st); err != nil {
		return nil, err
	}
	err := c.readJobs(ctx, now, now, func(j oJob) {
		// concurrent rows (a rare data error, or a global assignment): the highest sequence wins
		if prev := st.jobs[string(j.UserID)]; prev == nil || j.SeqNumber > prev.SeqNumber {
			st.jobs[string(j.UserID)] = &j
		}
	})
	if err != nil {
		return nil, err
	}
	if err := c.readPeople(ctx, st); err != nil {
		return nil, err
	}
	return st, nil
}

// Discover implements connectors.Connector: a full read of the people.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	now := c.now().UTC()
	st, err := c.read(ctx, now)
	if err != nil {
		return nil, err
	}
	return c.build(st, now), nil
}

var slugRE = regexp.MustCompile(`[^a-z0-9]+`)

// teamSlug is the team name the joiner / mover flow keys birthright access on:
// the department's name, lower case.
func teamSlug(name string) string {
	return strings.Trim(slugRE.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

func strp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// person is one user id as the build sees it.
type person struct {
	userID, personID           string
	user                       *oUser
	emp                        *oEmp
	job                        *oJob
	hire, end                  *time.Time
	hired, terminated          bool
	name, email, title, deptID string
}

// people lists the persons of a snapshot in user id order, with what is true on
// the day now.
func (c *Connector) people(st *snapshot, now time.Time) []*person {
	seen := map[string]bool{}
	var ids []string
	for id := range st.emps {
		seen[id] = true
		ids = append(ids, id)
	}
	for id := range st.users {
		if !seen[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var out []*person
	for _, id := range ids {
		p := &person{userID: id, user: st.users[id], emp: st.emps[id], job: st.jobs[id]}
		if c.cfg.LegalEntity != "" && p.job == nil {
			continue // another legal entity (or no job in this one)
		}
		p.personID = id
		switch {
		case p.emp != nil:
			p.hire, p.end = parseTime(string(p.emp.StartDate)), parseTime(string(p.emp.EndDate))
			if p.emp.PersonIDExternal != "" {
				p.personID = string(p.emp.PersonIDExternal)
			}
		case p.user != nil:
			p.hire = parseTime(string(p.user.HireDate))
		}
		p.hired = p.hire == nil || !p.hire.After(now)
		switch {
		case p.end != nil:
			p.terminated = !p.end.After(now)
		case p.emp == nil && p.user != nil && (strings.EqualFold(string(p.user.Status), "inactive") || strings.EqualFold(string(p.user.Status), "f")):
			p.terminated = true
		}
		if p.user != nil {
			p.name, p.email, p.title = string(p.user.DisplayName), string(p.user.Email), string(p.user.Title)
		}
		if p.name == "" {
			p.name = st.names[p.personID]
		}
		if p.name == "" {
			p.name = p.personID
		}
		if p.job != nil && p.job.JobTitle != "" {
			p.title = string(p.job.JobTitle)
		}
		out = append(out, p)
	}
	return out
}

func (c *Connector) build(st *snapshot, now time.Time) *connectors.DiscoveryResult {
	res := &connectors.DiscoveryResult{}
	ps := c.people(st, now)
	xidOf := map[string]string{}
	for _, p := range ps {
		xidOf[p.userID] = p.personID
	}
	managerOf := func(p *person) string {
		if p.job == nil || p.job.ManagerID == "" || string(p.job.ManagerID) == noManager || string(p.job.ManagerID) == p.userID {
			return ""
		}
		if x := xidOf[string(p.job.ManagerID)]; x != "" {
			return x
		}
		return string(p.job.ManagerID)
	}
	seenIdent, seenAcct, seenGroup := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range ps {
		if !p.hired {
			continue // not a person yet: only the pending joiner event exists
		}
		status, acctStatus := "active", "active"
		var termAt *time.Time
		if p.terminated {
			status, acctStatus, termAt = "terminated", "disabled", p.end
		}
		dept, deptCode := "", ""
		if p.job != nil {
			dept, deptCode = p.job.deptName(), string(p.job.Department)
		}
		if dept == "" && p.user != nil {
			dept = string(p.user.Department)
		}
		if c.cfg.EmitIdentities && !seenIdent[p.personID] {
			seenIdent[p.personID] = true
			rec := connectors.IdentityRecord{ExternalID: p.personID, Name: p.name, Type: "human", Email: strp(p.email),
				Department: strp(dept), Title: strp(p.title), Status: status, HiredAt: p.hire, TerminatedAt: termAt}
			if m := managerOf(p); m != "" && m != p.personID {
				rec.Manager = &connectors.IdentityRef{ExternalID: m}
			}
			res.Identities = append(res.Identities, rec)
		}
		if seenAcct[p.userID] {
			continue
		}
		seenAcct[p.userID] = true
		username := p.userID
		if p.user != nil && p.user.Username != "" {
			username = string(p.user.Username)
		}
		attrs := map[string]string{}
		put := func(k, v string) {
			if v != "" {
				attrs[k] = v
			}
		}
		put("user_id", p.userID)
		put("person_id", p.personID)
		put("work_email", p.email)
		put("status", status)
		put("title", p.title)
		put("department", dept)
		put("manager", managerOf(p))
		if p.hire != nil {
			put("hire_date", p.hire.Format("2006-01-02"))
		}
		if p.end != nil {
			put("termination_date", p.end.Format("2006-01-02"))
		}
		if p.job != nil {
			put("location", string(p.job.Location))
			put("cost_center", string(p.job.CostCenter))
			put("legal_entity", string(p.job.Company))
		}
		res.Accounts = append(res.Accounts, connectors.AccountRecord{System: System, ExternalID: p.userID, Username: username,
			Identity: &connectors.IdentityRef{ExternalID: p.personID, Email: p.email}, Kind: "user", Status: acctStatus,
			CreatedAt: p.hire, Attributes: attrs})
		if p.terminated || deptCode == "" || len(deptCode) > 128 {
			continue
		}
		gx := "dept:" + deptCode
		if !seenGroup[gx] {
			seenGroup[gx] = true
			name := dept
			if name == "" {
				name = deptCode
			}
			res.Groups = append(res.Groups, connectors.GroupRecord{System: System, ExternalID: gx, Name: name, Kind: "department"})
		}
		res.Edges = append(res.Edges, connectors.EdgeRecord{Relation: "member_of",
			Src: connectors.Ref{Kind: "account", System: System, ExternalID: p.userID},
			Dst: connectors.Ref{Kind: "group", System: System, ExternalID: gx}})
	}
	return res
}

// Probe is what a readiness probe learns from one small read: how many users
// the first page held and which fields came back (names only, never values).
type Probe struct {
	Users  int
	Fields []string
}

var errNoRows = errors.New("successfactors: the User read returned no rows")

// Probe reads one bounded page of User with the connector's own selection. A
// refused credential is a *connsync.StatusError (401 or 403).
func (c *Connector) Probe(ctx context.Context, limit int) (Probe, error) {
	if limit < 1 || limit > 500 {
		limit = 500
	}
	q := url.Values{"$select": {selUser}, "$top": {fmt.Sprint(limit)}}
	var page odPage[map[string]any]
	if _, err := c.api.GetJSON(ctx, c.entityURL("User", q), nil, &page); err != nil {
		return Probe{}, err
	}
	out := Probe{Users: len(page.D.Results)}
	if out.Users == 0 {
		return out, errNoRows
	}
	seen := map[string]bool{}
	for _, row := range page.D.Results {
		for k := range row {
			if !strings.HasPrefix(k, "__") && !seen[k] {
				seen[k] = true
				out.Fields = append(out.Fields, k)
			}
		}
	}
	sort.Strings(out.Fields)
	return out, nil
}

// ErrNoRows reports whether err is the empty-read error of Probe.
func ErrNoRows(err error) bool { return errors.Is(err, errNoRows) }
