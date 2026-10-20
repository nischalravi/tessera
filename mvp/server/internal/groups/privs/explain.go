package privs

import (
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Path is one way the subject holds a privilege on an object (design §7.2,
// "Explanations").
type Path struct {
	// Kind is role (a platform role gives it), identity, group or everyone: how
	// the holder of the row covers the subject.
	Kind string `json:"kind"`
	Role string `json:"role,omitempty"`
	// Row is the privilege row, absent for a role.
	Row *RowView `json:"row,omitempty"`
	// Via is how the row reaches the object: self, inherited_one,
	// inherited_sub or folder_stem_admin.
	Via string `json:"via,omitempty"`
	// OverFolder names the folder whose stem_admin gives the privilege (Via
	// folder_stem_admin).
	OverFolder string `json:"over_folder,omitempty"`
	// Holder names the identity or group holding the row.
	Holder string `json:"holder,omitempty"`
	Text   string `json:"text"`
}

// RowView is a privilege row with the names resolved.
type RowView struct {
	ID         string  `json:"id"`
	ObjectType string  `json:"object_type"`
	ObjectID   string  `json:"object_id"`
	ObjectName string  `json:"object_name"`
	Privilege  string  `json:"privilege"`
	HolderType string  `json:"holder_type"`
	HolderID   *string `json:"holder_id"`
	HolderName string  `json:"holder_name"`
	AppliesTo  string  `json:"applies_to"`
	Scope      string  `json:"scope"`
	Source     string  `json:"source"`
	CreatedBy  *string `json:"created_by"`
	GrantedBy  string  `json:"granted_by,omitempty"`
	CreatedAt  string  `json:"created_at"`
}

// Explanation is one privilege of the object and every path by which the
// subject holds it.
type Explanation struct {
	Privilege Privilege `json:"privilege"`
	Allowed   bool      `json:"allowed"`
	Paths     []Path    `json:"paths"`
}

// namer resolves the names a message shows.
type namer struct {
	tx *store.TenantTx
	c  *Checker
}

func (n namer) object(t string, id string) string {
	switch ObjectType(t) {
	case Folder:
		if f, err := n.c.folder(id); err == nil && f != nil {
			return rootName(f)
		}
	case Group:
		if g, err := n.tx.GrpGroup(store.GroupID(id)); err == nil {
			return g.Name
		}
	case AttrDef:
		if d, err := n.tx.GrpAttrDef(id); err == nil {
			return d.Name()
		}
	}
	return id
}

// rootName shows the tenant's root folder (whose name is empty) readably.
func rootName(f *store.Folder) string {
	if f.Name == "" {
		return "(root)"
	}
	return f.Name
}

func (n namer) identity(id int64) string {
	if i, err := n.tx.Identity(id); err == nil {
		return i.Name
	}
	return fmt.Sprintf("identity %d", id)
}

// who is the platform user that made a grant, as the console would show it.
func (n namer) who(by *string) string {
	if by == nil {
		return ""
	}
	if id, err := uuid.Parse(*by); err == nil {
		if u, err := n.tx.PlatformUser(id); err == nil {
			if u.Email != nil && *u.Email != "" {
				return *u.Email
			}
			return u.DisplayName
		}
	}
	return *by
}

// View resolves a stored row's names.
func (c *Checker) View(r *store.GrpPrivilege) *RowView {
	n := namer{c.tx, c}
	v := &RowView{ID: r.ID, ObjectType: r.ObjectType, ObjectID: r.ObjectID, ObjectName: n.object(r.ObjectType, r.ObjectID),
		Privilege: r.Privilege, HolderType: r.HolderType, AppliesTo: r.AppliesTo, Scope: r.Scope, Source: r.Source,
		CreatedBy: r.CreatedBy, GrantedBy: n.who(r.CreatedBy), CreatedAt: store.RT(r.CreatedAt)}
	switch r.HolderType {
	case store.HolderIdentity:
		id := fmt.Sprint(*r.HolderIdentity)
		v.HolderID, v.HolderName = &id, n.identity(*r.HolderIdentity)
	case store.HolderGroup:
		id := string(*r.HolderGroup)
		v.HolderID, v.HolderName = &id, n.object(string(Group), id)
	default:
		v.HolderName = "everyone"
	}
	return v
}

func upper(p string) string { return strings.ToUpper(p) }

// text writes one path as a sentence.
func (c *Checker) text(subject string, o Object, want Privilege, p Path) string {
	n := namer{c.tx, c}
	on := n.object(string(o.Type), o.ID)
	head := fmt.Sprintf("%s holds %s on `%s` because ", subject, upper(string(want)), on)
	if p.Kind == "role" {
		return head + fmt.Sprintf("the %s role holds it everywhere", p.Role)
	}
	r := p.Row
	var who string
	switch p.Kind {
	case CoverIdentity:
		who = "they hold"
	case CoverGroup:
		who = fmt.Sprintf("they are in `%s`, which holds", r.HolderName)
	default:
		who = "everyone holds"
	}
	what := fmt.Sprintf("%s on %s `%s`", upper(r.Privilege), r.ObjectType, r.ObjectName)
	switch p.Via {
	case ViaInheritedOne, ViaInheritedSub:
		what += fmt.Sprintf(" with scope `%s`", r.Scope)
	case ViaFolderStemAdm:
		what += fmt.Sprintf(", which covers everything below folder `%s`", p.OverFolder)
	}
	out := head + who + " " + what
	if r.GrantedBy != "" {
		out += fmt.Sprintf(" (granted by %s on %s)", r.GrantedBy, r.CreatedAt[:10])
	} else {
		out += fmt.Sprintf(" (%s, %s)", r.Source, r.CreatedAt[:10])
	}
	return out
}

// Explain lists, for every privilege that can be held on o, every path by which
// the subject holds it: a platform role, a row naming the subject's identity,
// a row held by a group the subject is in, a row held by everyone, each with
// how the row reaches the object (on it, or inherited from a folder with scope
// one or sub, or through stem_admin on a folder above). The result has an
// entry for each privilege of the object's type, held or not. An object that
// does not exist has no paths.
func (c *Checker) Explain(o Object) ([]Explanation, error) {
	n := namer{c.tx, c}
	subject := "The caller"
	if c.sub.Identity != nil {
		subject = n.identity(*c.sub.Identity)
	}
	var out []Explanation
	for _, want := range For(o.Type) {
		ex := Explanation{Privilege: want, Paths: []Path{}}
		if role := c.sub.roleFor(want); role != "" {
			p := Path{Kind: "role", Role: role}
			p.Text = c.text(subject, o, want, p)
			ex.Paths = append(ex.Paths, p)
		}
		cands, ok, err := c.candidates(o, want)
		if err != nil {
			return nil, err
		}
		if ok {
			for _, cd := range cands {
				kind, held, err := c.covers(cd.Row)
				if err != nil {
					return nil, err
				}
				if !held {
					continue
				}
				p := Path{Kind: kind, Via: cd.Via, Row: c.View(cd.Row)}
				if cd.Over != "" {
					p.OverFolder = n.object(string(Folder), cd.Over)
				}
				if kind != CoverEveryone {
					p.Holder = p.Row.HolderName
				}
				p.Text = c.text(subject, o, want, p)
				ex.Paths = append(ex.Paths, p)
			}
		}
		ex.Allowed = len(ex.Paths) > 0
		out = append(out, ex)
	}
	return out, nil
}
