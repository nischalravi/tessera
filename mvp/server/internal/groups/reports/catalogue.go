// Package reports is the groups report catalogue (design
// docs/design/groups-grouper-parity.md §10.7; issue #57, GR-14): saved,
// parameterized queries from a fixed list (there is no free SQL), run on
// demand or on a schedule, delivered as CSV or JSON.
//
// A report never shows more than the person it runs for may see. Every row is
// filtered by the privileges of that subject: the caller for a run by hand, the
// user who saved the report (with what they hold when it runs) for a scheduled
// run. The stored output of a run can be read back only by that user or a
// tenant admin.
package reports

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/gov"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Limits.
const (
	// MaxRows bounds a report; a longer one is cut and says so (never silently).
	MaxRows = 10000
	// KeepRuns is how many runs of a report are kept.
	KeepRuns   = 10
	MaxName    = 200
	MaxReports = 100
)

// Kinds of the catalogue.
const (
	GroupMembers         = "group_members"
	GroupsOfPerson       = "groups_of_person"
	FolderPrivileges     = "folder_privileges"
	GroupsWithoutOwners  = "groups_without_owners"
	PolicyDirectMembers  = "policy_direct_exceptions"
	AttestationStatus    = "attestation_status"
	DeprovisioningBlog   = "deprovisioning_backlog"
	BasisInPolicy        = "basis_groups_in_policy"
	LoaderFailsafeLog    = "loader_failsafe_history"
	ProvisioningDriftLog = "provisioning_drift"
)

// Param describes one parameter of a report.
type Param struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // group | folder | identity | integer | enum
	Required bool   `json:"required"`
	Values   string `json:"values,omitempty"` // for an enum: the allowed values
}

// Def is one report of the catalogue.
type Def struct {
	Kind        string   `json:"kind"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Params      []Param  `json:"params"`
	Columns     []string `json:"columns"`
	// Needs is the privilege the subject must hold on the report's object (when it names one).
	Needs string `json:"needs,omitempty"`
	// Available is false for a report whose data arrives with a later part of the groups work.
	Available   bool   `json:"available"`
	ArrivesWith string `json:"arrives_with,omitempty"`
}

var catalogue = []Def{
	{Kind: GroupMembers, Title: "Members of a group", Description: "Direct or effective members with source and dates.",
		Params:  []Param{{Name: "group", Type: "group", Required: true}, {Name: "filter", Type: "enum", Values: "effective|direct"}},
		Columns: []string{"identity_id", "name", "email", "status", "membership", "source", "enabled_from", "disabled_at"}, Needs: "read", Available: true},
	{Kind: GroupsOfPerson, Title: "Groups of a person", Description: "The groups an identity is in, directly or through another group.",
		Params:  []Param{{Name: "identity", Type: "identity", Required: true}},
		Columns: []string{"group", "membership", "status"}, Needs: "view", Available: true},
	{Kind: FolderPrivileges, Title: "Privileges in a folder", Description: "The privilege rows on a folder.",
		Params:  []Param{{Name: "folder", Type: "folder", Required: true}},
		Columns: []string{"privilege", "holder_type", "holder", "applies_to", "scope", "source"}, Needs: "stem_admin", Available: true},
	{Kind: GroupsWithoutOwners, Title: "Groups without owners", Description: "Groups with no admin holder and no data owner.",
		Params:  []Param{{Name: "folder", Type: "folder"}},
		Columns: []string{"group", "folder", "status"}, Needs: "view", Available: true},
	{Kind: PolicyDirectMembers, Title: "Policy groups with many direct members", Description: "Policy groups whose direct identity members exceed a limit.",
		Params:  []Param{{Name: "limit", Type: "integer"}},
		Columns: []string{"group", "direct_members"}, Needs: "view", Available: true},
	{Kind: AttestationStatus, Title: "Attestation status", Description: "The latest periodic attestation of each group.",
		Params:  []Param{{Name: "folder", Type: "folder"}},
		Columns: []string{"group", "status", "started_at", "due_at", "population", "undecided", "overdue"}, Needs: "view", Available: true},
	{Kind: DeprovisioningBlog, Title: "Deprovisioning backlog", Description: "Open deprovisioning items per folder and their age.",
		Params:  []Param{{Name: "folder", Type: "folder"}},
		Columns: []string{"folder", "identity", "mode", "opened_at", "age_days", "due_at"}, Needs: "stem_admin", Available: true},
	{Kind: BasisInPolicy, Title: "Basis groups referenced directly by policy", Description: "A Deployment Guide anti-pattern.",
		Columns: []string{}, Available: false, ArrivesWith: "GR-7 (object types) and GR-9 (policy groups)"},
	{Kind: LoaderFailsafeLog, Title: "Loader failsafe history", Description: "Loader runs held by their failsafe.",
		Columns: []string{}, Available: false, ArrivesWith: "GR-10 (loaders)"},
	{Kind: ProvisioningDriftLog, Title: "Provisioning drift", Description: "Provisioning operations that ended in drift.",
		Columns: []string{}, Available: false, ArrivesWith: "GR-11 (provisioning)"},
}

// Catalogue lists the reports.
func Catalogue() []Def {
	out := make([]Def, len(catalogue))
	for i, d := range catalogue {
		d.Params = slices.Clone(d.Params)
		if d.Params == nil {
			d.Params = []Param{}
		}
		out[i] = d
	}
	return out
}

func defOf(kind string) (*Def, error) {
	for i := range catalogue {
		if catalogue[i].Kind == kind {
			return &catalogue[i], nil
		}
	}
	return nil, gov.Invalid("unknown_report", "%q is not a report of the catalogue", kind)
}

// Params are the parameters of a report; which are used depends on its kind.
type Params struct {
	Group    string `json:"group,omitempty"`
	Folder   string `json:"folder,omitempty"`
	Identity int64  `json:"identity,omitempty"`
	Filter   string `json:"filter,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

// Env is one run's context: the transaction, the clock and the subject the
// report is for (its checker filters every row).
type Env struct {
	Tx      *store.TenantTx
	Now     time.Time
	Checker *privs.Checker
	Engine  *engine.Engine
}

func (e Env) eng() *engine.Engine {
	if e.Engine != nil {
		return e.Engine
	}
	return engine.New(0)
}

// Result is the output of a run: rows of strings under columns.
type Result struct {
	Kind      string     `json:"kind"`
	Columns   []string   `json:"columns"`
	Rows      [][]string `json:"rows"`
	Truncated bool       `json:"truncated"`
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func uuidRE(s string) bool { return uuidPattern.MatchString(s) }

// mustUUID parses a stored user id; a damaged one is the nil UUID, which no user has.
func mustUUID(s string) uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// Validate checks the parameters against the report's definition: required
// ones are present and no parameter that the report does not take is.
func Validate(kind string, p *Params) error {
	d, err := defOf(kind)
	if err != nil {
		return err
	}
	if !d.Available {
		return gov.Conflict("report_unavailable", "%s arrives with %s", kind, d.ArrivesWith)
	}
	has := map[string]bool{"group": p.Group != "", "folder": p.Folder != "", "identity": p.Identity != 0, "filter": p.Filter != "", "limit": p.Limit != 0}
	takes := map[string]bool{}
	for _, pr := range d.Params {
		takes[pr.Name] = true
		if pr.Required && !has[pr.Name] {
			return gov.Invalid("invalid_params", "%s needs %s", kind, pr.Name)
		}
	}
	for name, set := range has {
		if set && !takes[name] {
			return gov.Invalid("invalid_params", "%s does not take %s", kind, name)
		}
	}
	for field, v := range map[string]string{"group": p.Group, "folder": p.Folder} {
		if v != "" && !uuidRE(v) {
			return gov.Invalid("invalid_params", "%s is an id (a UUID)", field)
		}
	}
	if p.Identity < 0 {
		return gov.Invalid("invalid_params", "identity is an identity id")
	}
	if p.Filter != "" && p.Filter != "direct" && p.Filter != "effective" {
		return gov.Invalid("invalid_params", "filter is direct or effective")
	}
	if p.Limit < 0 || p.Limit > 1_000_000 {
		return gov.Invalid("invalid_params", "limit is 0 to 1000000")
	}
	return nil
}

// Authorize checks, before any row is read, the privilege a report's object
// needs: it is a 403 for a subject who may not see what the report is about.
func Authorize(ck *privs.Checker, kind string, p Params) error {
	switch kind {
	case GroupMembers:
		return ck.Require(privs.GroupObject(store.GroupID(p.Group)), privs.Read)
	case FolderPrivileges:
		return ck.Require(privs.FolderObject(store.FolderID(p.Folder)), privs.StemAdmin)
	}
	return nil
}

// Run produces a report for the checker's subject.
func Run(e Env, kind string, p Params) (*Result, error) {
	if err := Validate(kind, &p); err != nil {
		return nil, err
	}
	if err := Authorize(e.Checker, kind, p); err != nil {
		return nil, err
	}
	d, _ := defOf(kind)
	res := &Result{Kind: kind, Columns: slices.Clone(d.Columns), Rows: [][]string{}}
	var err error
	switch kind {
	case GroupMembers:
		err = e.groupMembers(res, p)
	case GroupsOfPerson:
		err = e.groupsOfPerson(res, p)
	case FolderPrivileges:
		err = e.folderPrivileges(res, p)
	case GroupsWithoutOwners:
		err = e.withoutOwners(res, p)
	case PolicyDirectMembers:
		err = e.policyDirect(res, p)
	case AttestationStatus:
		err = e.attestationStatus(res, p)
	case DeprovisioningBlog:
		err = e.deprovBacklog(res, p)
	}
	if err != nil {
		return nil, err
	}
	sortRows(res.Rows) // the same data gives the same output, and the same rows survive a cut
	if len(res.Rows) > MaxRows {
		res.Rows, res.Truncated = res.Rows[:MaxRows], true
	}
	return res, nil
}

// ---------------------------------------------------------------- the reports

func day(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (e Env) liveGroup(id string) (*store.NativeGroup, error) {
	g, err := e.Tx.GrpGroup(store.GroupID(id))
	if errors.Is(err, store.ErrNotFound) {
		return nil, gov.NotFound("no such group")
	}
	return g, err
}

func (e Env) groupMembers(res *Result, p Params) error {
	g, err := e.liveGroup(p.Group)
	if err != nil {
		return err
	}
	list := store.MembersListID(e.Tx.Tenant())
	people, _, err := e.Tx.IdentityMap()
	if err != nil {
		return err
	}
	row := func(id int64, membership, source string, from, to *time.Time) {
		var name, email, status string
		if i := people[id]; i != nil {
			name, email, status = i.Name, deref(i.Email), i.Status
		}
		res.Rows = append(res.Rows, []string{strconv.FormatInt(id, 10), name, email, status, membership, source, day(from), day(to)})
	}
	if p.Filter == "direct" {
		for off := 0; len(res.Rows) <= MaxRows; off += 1000 {
			rows, err := e.Tx.GrpDirect(store.GrpDirectFilter{Group: g.ID, List: list, MemberType: store.MemberIdentity, Limit: 1000, Offset: off})
			if err != nil {
				return err
			}
			for _, m := range rows {
				row(*m.MemberIdentity, "direct", m.Source, m.EnabledFrom, m.DisabledAt)
			}
			if len(rows) < 1000 {
				break
			}
		}
		return nil
	}
	for off := 0; len(res.Rows) <= MaxRows; off += 1000 {
		rows, err := e.Tx.GrpEffectiveList(g.ID, list, 1000, off)
		if err != nil {
			return err
		}
		for _, m := range rows {
			if ok, err := e.Tx.GrpDirectIdentityActive(g.ID, list, m.Identity, e.Now); err != nil {
				return err
			} else if ok {
				d, err := e.Tx.GrpDirectFind(g.ID, list, store.MemberIdentity, strconv.FormatInt(m.Identity, 10))
				if err != nil {
					return err
				}
				row(m.Identity, "direct", d.Source, d.EnabledFrom, d.DisabledAt)
			} else {
				row(m.Identity, "nested", "nested", nil, nil)
			}
		}
		if len(rows) < 1000 {
			break
		}
	}
	return nil
}

func (e Env) groupsOfPerson(res *Result, p Params) error {
	if _, err := e.Tx.Identity(p.Identity); errors.Is(err, store.ErrNotFound) {
		return gov.NotFound("no such identity")
	} else if err != nil {
		return err
	}
	list := store.MembersListID(e.Tx.Tenant())
	direct, err := e.Tx.GrpDirectIdentityGroups(list, p.Identity, e.Now)
	if err != nil {
		return err
	}
	isDirect := map[store.GroupID]bool{}
	for _, id := range direct {
		isDirect[id] = true
	}
	eff, err := e.Tx.GrpEffectiveGroupsOf(p.Identity, list)
	if err != nil {
		return err
	}
	for _, id := range eff {
		g, err := e.Tx.GrpGroup(id)
		if err != nil {
			return err
		}
		// a group the subject may not view is not named, whatever it says about the person
		if ok, err := e.Checker.Has(privs.GroupObject(g.ID), privs.View); err != nil {
			return err
		} else if !ok {
			continue
		}
		how := "nested"
		if isDirect[id] {
			how = "direct"
		}
		res.Rows = append(res.Rows, []string{g.Name, how, g.Status})
	}
	sortRows(res.Rows)
	return nil
}

func (e Env) folderPrivileges(res *Result, p Params) error {
	f, err := e.Tx.GrpFolder(store.FolderID(p.Folder))
	if errors.Is(err, store.ErrNotFound) {
		return gov.NotFound("no such folder")
	}
	if err != nil {
		return err
	}
	rows, err := e.Tx.GrpPrivilegesOf(string(privs.Folder), string(f.ID))
	if err != nil {
		return err
	}
	for _, r := range rows {
		holder := ""
		switch r.HolderType {
		case store.HolderIdentity:
			holder = strconv.FormatInt(*r.HolderIdentity, 10)
			if i, err := e.Tx.Identity(*r.HolderIdentity); err == nil {
				holder = i.Name
			}
		case store.HolderGroup:
			holder = string(*r.HolderGroup)
			if g, err := e.Tx.GrpGroup(*r.HolderGroup); err == nil {
				holder = g.Name
			}
		}
		res.Rows = append(res.Rows, []string{r.Privilege, r.HolderType, holder, r.AppliesTo, r.Scope, r.Source})
	}
	sortRows(res.Rows)
	return nil
}

// viewable lists the live groups the subject may view, optionally below a
// folder, ordered by name.
func (e Env) viewable(folder string) ([]*store.NativeGroup, error) {
	var all []*store.NativeGroup
	if folder != "" {
		f, err := e.Tx.GrpFolder(store.FolderID(folder))
		if errors.Is(err, store.ErrNotFound) {
			return nil, gov.NotFound("no such folder")
		}
		if err != nil {
			return nil, err
		}
		if all, err = e.Tx.GrpGroupsBelow(f.Name); err != nil {
			return nil, err
		}
	} else {
		var err error
		if all, err = e.Tx.GrpGroupsAll(); err != nil {
			return nil, err
		}
	}
	var out []*store.NativeGroup
	for _, g := range all {
		if g.Status == store.GroupDeleted {
			continue
		}
		if ok, err := e.Checker.Has(privs.GroupObject(g.ID), privs.View); err != nil {
			return nil, err
		} else if ok {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (e Env) folderName(id store.FolderID) string {
	if f, err := e.Tx.GrpFolder(id); err == nil {
		return f.Name
	}
	return string(id)
}

func (e Env) withoutOwners(res *Result, p Params) error {
	gs, err := e.viewable(p.Folder)
	if err != nil {
		return err
	}
	for _, g := range gs {
		if deref(g.DataOwner) != "" {
			continue
		}
		rows, err := e.Tx.GrpPrivilegesOf(string(privs.Group), string(g.ID))
		if err != nil {
			return err
		}
		owned := slices.ContainsFunc(rows, func(r *store.GrpPrivilege) bool {
			return r.Privilege == string(privs.Admin) && r.HolderType != store.HolderEveryone
		})
		if !owned {
			res.Rows = append(res.Rows, []string{g.Name, e.folderName(g.FolderID), g.Status})
		}
	}
	return nil
}

func (e Env) policyDirect(res *Result, p Params) error {
	limit := p.Limit
	if limit == 0 {
		limit = 10
	}
	gs, err := e.viewable("")
	if err != nil {
		return err
	}
	list := store.MembersListID(e.Tx.Tenant())
	for _, g := range gs {
		if g.Definition != store.DefinitionPolicy {
			continue
		}
		n, err := e.Tx.GrpDirectCount(store.GrpDirectFilter{Group: g.ID, List: list, MemberType: store.MemberIdentity})
		if err != nil {
			return err
		}
		if n > limit {
			res.Rows = append(res.Rows, []string{g.Name, strconv.Itoa(n)})
		}
	}
	return nil
}

func (e Env) attestationStatus(res *Result, p Params) error {
	gs, err := e.viewable(p.Folder)
	if err != nil {
		return err
	}
	visible := map[store.GroupID]*store.NativeGroup{}
	for _, g := range gs {
		visible[g.ID] = g
	}
	camps, err := e.Tx.GrpAttestCampaigns(store.GrpAttestFilter{Limit: 1000})
	if err != nil {
		return err
	}
	seen := map[store.GroupID]bool{}
	for _, c := range camps { // newest first
		g := visible[c.GroupID]
		if g == nil || c.Kind != store.AttestPeriodic || seen[c.GroupID] {
			continue
		}
		seen[c.GroupID] = true
		undecided := 0
		if c.ReviewCampaign != nil {
			if undecided, err = e.Tx.CountOpenItems(*c.ReviewCampaign); err != nil {
				return err
			}
		}
		overdue := "no"
		if c.Status == store.AttestOpen && e.Now.After(c.DueAt) {
			overdue = "yes"
		}
		res.Rows = append(res.Rows, []string{g.Name, c.Status, day(&c.StartedAt), day(&c.DueAt), strconv.Itoa(c.PopulationCount),
			strconv.Itoa(undecided), overdue})
	}
	sortRows(res.Rows)
	return nil
}

func (e Env) deprovBacklog(res *Result, p Params) error {
	items, err := e.Tx.GrpDeprovItems(store.GrpDeprovFilter{Status: store.DeprovOpen, FolderID: store.FolderID(p.Folder), Limit: 1000})
	if err != nil {
		return err
	}
	for _, it := range items {
		// the folders the subject administers only: the backlog names people
		if ok, err := e.Checker.Has(privs.FolderObject(it.FolderID), privs.StemAdmin); err != nil {
			return err
		} else if !ok {
			continue
		}
		who := strconv.FormatInt(it.Identity, 10)
		if i, err := e.Tx.Identity(it.Identity); err == nil {
			who = i.Name
		}
		age := int(e.Now.Sub(it.OpenedAt).Hours() / 24)
		res.Rows = append(res.Rows, []string{e.folderName(it.FolderID), who, it.Mode, day(&it.OpenedAt), strconv.Itoa(age), day(it.DueAt)})
	}
	sortRows(res.Rows)
	return nil
}

func sortRows(rows [][]string) {
	sort.SliceStable(rows, func(i, j int) bool { return slices.Compare(rows[i], rows[j]) < 0 })
}

// ---------------------------------------------------------------- output

// csvCell defuses a cell a spreadsheet would run as a formula.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// CSV renders the result as CSV: a header, then the rows, with formula-like
// cells prefixed by a quote.
func (r *Result) CSV() (string, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.Write(r.Columns); err != nil {
		return "", err
	}
	for _, row := range r.Rows {
		cells := make([]string, len(row))
		for i, c := range row {
			cells[i] = csvCell(c)
		}
		if err := w.Write(cells); err != nil {
			return "", err
		}
	}
	w.Flush()
	return b.String(), w.Error()
}

// JSON renders the result as JSON: kind, generated_at, columns, rows (arrays of strings), truncated.
func (r *Result) JSON(at time.Time) (string, error) {
	b, err := json.MarshalIndent(struct {
		Kind        string     `json:"kind"`
		GeneratedAt string     `json:"generated_at"`
		Columns     []string   `json:"columns"`
		Rows        [][]string `json:"rows"`
		Truncated   bool       `json:"truncated"`
	}{r.Kind, at.UTC().Format(time.RFC3339), r.Columns, r.Rows, r.Truncated}, "", "  ")
	return string(b) + "\n", err
}

// Render renders the result in a format (csv or json).
func (r *Result) Render(format string, at time.Time) (string, error) {
	switch format {
	case "csv":
		return r.CSV()
	case "json":
		return r.JSON(at)
	}
	return "", gov.Invalid("invalid_format", "format is csv or json")
}

// Digest is the SHA-256 of rendered output, as hex.
func Digest(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
