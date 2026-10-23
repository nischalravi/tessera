package perms

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/attrs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Grouper permission documents. The shape follows what Grouper's web services
// return for a permission assignment (role name, subject, permission name,
// action, disallowed, enabled and disabled times, limits), so the Grouper
// connector (GR-15) can hand over what it reads, and an export can be imported
// again. Names are full names: the role is a group's, the resource an attribute
// name's ("folder:definition:name"), a limit's the limit name's. The subject, when
// there is one, is an identity's external id.

// Doc is a permission document.
type Doc struct {
	Permissions []Entry `json:"permissions"`
}

// Entry is one permission assignment of a document.
type Entry struct {
	Role       string  `json:"role"`
	Subject    string  `json:"subject,omitempty"`
	Resource   string  `json:"resource"`
	Action     string  `json:"action"`
	Disallowed bool    `json:"disallowed,omitempty"`
	EnabledAt  string  `json:"enabled_at,omitempty"`
	DisabledAt string  `json:"disabled_at,omitempty"`
	Limits     []Limit `json:"limits,omitempty"`
}

// MaxImport bounds the entries of one import.
const MaxImport = 5000

func (e Entry) key() string {
	return strings.Join([]string{e.Role, e.Subject, e.Resource, e.Action}, "\x00")
}

// Export writes the tenant's permission assignments as a document, in a stable order.
func Export(tx *store.TenantTx) (*Doc, error) {
	s, err := Load(tx)
	if err != nil {
		return nil, err
	}
	doc := &Doc{Permissions: []Entry{}}
	xids := map[int64]string{}
	for _, a := range s.Assignments {
		e := Entry{Role: a.RoleName, Resource: a.Resource, Action: a.Action, Disallowed: a.Disallowed, Limits: a.Limits}
		if a.Subject != nil {
			xid, ok := xids[*a.Subject]
			if !ok {
				i, err := tx.Identity(*a.Subject)
				if err != nil {
					return nil, err
				}
				xid = i.ExternalID
				xids[*a.Subject] = xid
			}
			e.Subject = xid
		}
		if a.EnabledFrom != nil {
			e.EnabledAt = store.RT(*a.EnabledFrom)
		}
		if a.DisabledAt != nil {
			e.DisabledAt = store.RT(*a.DisabledAt)
		}
		slices.SortFunc(e.Limits, func(x, y Limit) int { return strings.Compare(x.Name, y.Name) })
		doc.Permissions = append(doc.Permissions, e)
	}
	slices.SortFunc(doc.Permissions, func(x, y Entry) int { return strings.Compare(x.key(), y.key()) })
	return doc, nil
}

// ImportResult says what an import did (or, for a refused one, found wrong).
type ImportResult struct {
	Created   int      `json:"created"`
	Replaced  int      `json:"replaced"`
	Unchanged int      `json:"unchanged"`
	Errors    []string `json:"errors,omitempty"`
}

// planned is an entry resolved against the tenant's data.
type planned struct {
	e          Entry
	owner      attrs.Owner
	name       *store.GrpAttrName
	action     string // action id
	from, to   *time.Time
	limitNames []*store.GrpAttrName
	limitDefs  []*store.GrpAttrDef
}

// Import applies a document: each entry becomes a permission assignment on its
// role (or on the role's membership of the subject), with its limits, through
// attrs.Assign, so each change writes its audit and change events in the
// caller's transaction. An entry that already holds is left alone, one that
// differs is replaced, and nothing in the document removes an assignment. The
// whole document is checked first: if any entry is wrong nothing is applied and
// the result lists every problem.
func Import(e attrs.Env, doc *Doc) (*ImportResult, error) {
	res := &ImportResult{}
	if len(doc.Permissions) == 0 {
		return res, nil
	}
	if len(doc.Permissions) > MaxImport {
		return nil, invalid("too_many", "an import holds at most %d permission assignments", MaxImport)
	}
	plan := make([]*planned, 0, len(doc.Permissions))
	seen := map[string]bool{}
	for i, en := range doc.Permissions {
		p, err := resolve(e.Tx, en)
		if err == nil && seen[en.key()] {
			err = errors.New("given twice")
		}
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("permissions[%d]: %s", i, oneLine(err.Error())))
			continue
		}
		seen[en.key()] = true
		plan = append(plan, p)
	}
	if len(res.Errors) > 0 {
		return res, nil
	}
	have, err := Load(e.Tx)
	if err != nil {
		return nil, err
	}
	for _, p := range plan {
		old, err := findHeld(e.Tx, have, p)
		if err != nil {
			return nil, err
		}
		if old != nil && sameAs(old, p) {
			res.Unchanged++
			continue
		}
		if old != nil {
			if _, err := attrs.Unassign(e, old.ID); err != nil {
				return nil, err
			}
			res.Replaced++
		} else {
			res.Created++
		}
		if err := apply(e, p); err != nil {
			return nil, err
		}
	}
	_, err = e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: "groups.permissions.imported", LegacyActor: "groups",
		TargetType: "permissions", TargetID: "import", Detail: ojson.Object{{Key: "entries", Value: int64(len(plan))},
			{Key: "created", Value: int64(res.Created)}, {Key: "replaced", Value: int64(res.Replaced)},
			{Key: "unchanged", Value: int64(res.Unchanged)}}})
	return res, err
}

func parseTime(field, s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, fmt.Errorf("%s must be an RFC 3339 time", field)
	}
	t = t.UTC()
	return &t, nil
}

func resolve(tx *store.TenantTx, en Entry) (*planned, error) {
	p := &planned{e: en}
	g, err := tx.GrpGroupByName(en.Role)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("no role %q", en.Role)
	}
	if err != nil {
		return nil, err
	}
	p.owner = attrs.Owner{Type: store.AttrOwnerGroup, ID: string(g.ID)}
	if en.Subject != "" {
		i, err := tx.IdentityByExternalID(en.Subject)
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("no identity %q", en.Subject)
		}
		if err != nil {
			return nil, err
		}
		m, err := tx.GrpDirectFind(g.ID, store.MembersListID(tx.Tenant()), store.MemberIdentity, strconv.FormatInt(i.ID, 10))
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("identity %q is not a direct member of role %q", en.Subject, en.Role)
		}
		if err != nil {
			return nil, err
		}
		p.owner = attrs.Owner{Type: store.AttrOwnerMembership, ID: m.ID}
	}
	if p.name, err = attrs.NameByFullName(tx, en.Resource); err != nil {
		return nil, fmt.Errorf("no permission resource %q", en.Resource)
	}
	d, err := attrs.Def(tx, p.name.DefID)
	if err != nil {
		return nil, err
	}
	if d.AttrType != store.AttrTypePerm {
		return nil, fmt.Errorf("%q is not a permission resource (its definition is of type %s)", en.Resource, d.AttrType)
	}
	act := en.Action
	if act == "" {
		act = attrs.DefaultAction
	}
	a, err := tx.GrpAttrActionByName(d.ID, act)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%q has no action %q", en.Resource, act)
	}
	if err != nil {
		return nil, err
	}
	p.action = a.ID
	p.e.Action = a.Name
	if p.from, err = parseTime("enabled_at", en.EnabledAt); err != nil {
		return nil, err
	}
	if p.to, err = parseTime("disabled_at", en.DisabledAt); err != nil {
		return nil, err
	}
	for _, l := range en.Limits {
		if _, err := CompileLimit(l.Name, l.Values); err != nil {
			return nil, err
		}
		n, err := attrs.NameByFullName(tx, l.Name)
		if err != nil {
			return nil, fmt.Errorf("no limit %q", l.Name)
		}
		ld, err := attrs.Def(tx, n.DefID)
		if err != nil {
			return nil, err
		}
		if ld.AttrType != store.AttrTypeLimit {
			return nil, fmt.Errorf("%q is not a limit (its definition is of type %s)", l.Name, ld.AttrType)
		}
		p.limitNames, p.limitDefs = append(p.limitNames, n), append(p.limitDefs, ld)
	}
	return p, nil
}

// findHeld returns the loaded assignment that holds the same (owner, resource,
// action) as the plan, or nil.
func findHeld(tx *store.TenantTx, have *Set, p *planned) (*Assignment, error) {
	for _, a := range have.Assignments {
		if a.NameID != p.name.ID || a.ActionID != p.action {
			continue
		}
		if p.owner.Type == store.AttrOwnerGroup && a.Subject == nil && string(a.Role) == p.owner.ID {
			return a, nil
		}
		if p.owner.Type == store.AttrOwnerMembership && a.Subject != nil {
			m, err := tx.GrpDirectMembership(p.owner.ID)
			if err != nil {
				return nil, err
			}
			if a.Role == m.GroupID && m.MemberIdentity != nil && *m.MemberIdentity == *a.Subject {
				return a, nil
			}
		}
	}
	return nil, nil
}

func sameTime(a, b *time.Time) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Equal(*b)
}

func sameAs(a *Assignment, p *planned) bool {
	if a.Disallowed != p.e.Disallowed || !sameTime(a.EnabledFrom, p.from) || !sameTime(a.DisabledAt, p.to) {
		return false
	}
	norm := func(ls []Limit) []string {
		out := make([]string, len(ls))
		for i, l := range ls {
			vs := slices.Clone(l.Values)
			slices.Sort(vs)
			out[i] = l.Name + "=" + strings.Join(vs, "\x00")
		}
		slices.Sort(out)
		return out
	}
	return slices.Equal(norm(a.Limits), norm(p.e.Limits))
}

func apply(e attrs.Env, p *planned) error {
	as, err := attrs.Assign(e, attrs.AssignInput{Name: p.name.ID, Action: p.action, Owner: p.owner,
		Disallowed: p.e.Disallowed, EnabledFrom: p.from, DisabledAt: p.to})
	if err != nil {
		return err
	}
	for i, l := range p.e.Limits {
		vals := make([]json.RawMessage, len(l.Values))
		for j, v := range l.Values {
			if p.limitDefs[i].ValueType == store.AttrValueInteger {
				n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
				if err != nil {
					return invalid("invalid_limit", "limit %q takes integers, not %q", l.Name, v)
				}
				vals[j] = json.RawMessage(strconv.FormatInt(n, 10))
			} else {
				vals[j] = json.RawMessage(strconv.Quote(v))
			}
		}
		if _, err := attrs.Assign(e, attrs.AssignInput{Name: p.limitNames[i].ID,
			Owner: attrs.Owner{Type: store.AttrOwnerAssignment, ID: as.Assign.ID}, Values: vals}); err != nil {
			return err
		}
	}
	return nil
}
