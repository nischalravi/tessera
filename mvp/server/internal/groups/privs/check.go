package privs

import (
	"errors"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Object names the folder, group or attribute definition a privilege is held on.
type Object struct {
	Type ObjectType
	ID   string
}

// FolderObject, GroupObject and AttrDefObject build an Object.
func FolderObject(id store.FolderID) Object { return Object{Folder, string(id)} }

// GroupObject names a group.
func GroupObject(id store.GroupID) Object { return Object{Group, string(id)} }

// AttrDefObject names an attribute definition (GR-7).
func AttrDefObject(id string) Object { return Object{AttrDef, id} }

// Subject is who a check is for: the identity behind a signed-in platform user
// (design §7.2: platform users are linked to identities, so a signed-in admin's
// group privileges come from the identity's effective memberships) and the
// platform roles that apply on top of the privilege rows.
type Subject struct {
	// Identity is nil for a user without an identity link and for a machine
	// client: such a subject holds no identity or group privilege, only what
	// everyone holds and what its roles give.
	Identity *int64
	// TenantAdmin is an active tenant_admin role: Grouper's wheel group, which
	// implicitly holds every privilege.
	TenantAdmin bool
	// Auditor is an active auditor role: Grouper's read-only admin group, which
	// holds read, view and the *_attr_read privileges everywhere.
	Auditor bool
	// ViewerView is the viewer role where the tenant setting allows it: Grouper's
	// view-only admin group, which holds the view privileges everywhere.
	ViewerView bool
}

var (
	auditorGrants = []Privilege{Read, View, GroupAttrRead, StemView, StemAttrRead, AttrRead, AttrView, AttrDefAttrRead}
	viewerGrants  = []Privilege{View, StemView, AttrView}
)

// Roles that give a privilege without a row.
const (
	RoleTenantAdmin = "tenant_admin"
	RoleAuditor     = "auditor"
	RoleViewer      = "viewer"
)

// roleFor returns the platform role that gives the subject want, or "".
func (s Subject) roleFor(want Privilege) string {
	switch {
	case !Valid(want):
		return ""
	case s.TenantAdmin:
		return RoleTenantAdmin
	case s.Auditor && slices.ContainsFunc(auditorGrants, func(g Privilege) bool { return Implies(g, want) }):
		return RoleAuditor
	case s.ViewerView && slices.ContainsFunc(viewerGrants, func(g Privilege) bool { return Implies(g, want) }):
		return RoleViewer
	}
	return ""
}

// SeesAll reports whether the subject's roles give it the view privilege on
// every object of the type, so a listing needs no per-row check.
func (s Subject) SeesAll(t ObjectType) bool {
	switch t {
	case Folder:
		return s.roleFor(StemView) != ""
	case Group:
		return s.roleFor(View) != ""
	case AttrDef:
		return s.roleFor(AttrView) != ""
	}
	return false
}

// Checker answers privilege questions for one subject inside one transaction.
// It caches what it reads (folders, the rows of an object, the membership of
// each holder group), so the checks of one request share their lookups; make a
// new Checker per request.
type Checker struct {
	tx  *store.TenantTx
	now time.Time
	eng *engine.Engine
	sub Subject

	folders map[string]*store.Folder
	rows    map[Object][]*store.GrpPrivilege
	members map[string]bool
}

// NewChecker returns a Checker for sub at now. eng is the membership engine
// whose IsMember decides group holders (nil uses a default one).
func NewChecker(tx *store.TenantTx, now time.Time, eng *engine.Engine, sub Subject) *Checker {
	if eng == nil {
		eng = engine.New(0)
	}
	return &Checker{tx: tx, now: now, eng: eng, sub: sub, folders: map[string]*store.Folder{},
		rows: map[Object][]*store.GrpPrivilege{}, members: map[string]bool{}}
}

// Subject returns who the checker is for.
func (c *Checker) Subject() Subject { return c.sub }

func (c *Checker) folder(id string) (*store.Folder, error) {
	if f, ok := c.folders[id]; ok {
		return f, nil
	}
	f, err := c.tx.GrpFolder(store.FolderID(id))
	if errors.Is(err, store.ErrNotFound) {
		f, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.folders[id] = f
	return f, nil
}

func (c *Checker) rowsOf(o Object) ([]*store.GrpPrivilege, error) {
	if rs, ok := c.rows[o]; ok {
		return rs, nil
	}
	rs, err := c.tx.GrpPrivilegesOf(string(o.Type), o.ID)
	if err != nil {
		return nil, err
	}
	c.rows[o] = rs
	return rs, nil
}

// maxDepth bounds the walk up the folder tree (the parent links are acyclic,
// but a damaged tree must not loop).
const maxDepth = 256

// chain returns the folders above o, nearest first (the root last): the folders
// whose rows o can inherit. ok is false when o does not exist. An attribute
// definition lives in a folder (GR-7), so it inherits from that folder and the
// ones above it like a group does.
func (c *Checker) chain(o Object) (folders []*store.Folder, ok bool, err error) {
	var start *store.Folder
	switch o.Type {
	case AttrDef:
		d, err := c.tx.GrpAttrDef(o.ID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		if start, err = c.folder(string(d.FolderID)); err != nil || start == nil {
			return nil, false, err
		}
	case Group:
		g, err := c.tx.GrpGroup(store.GroupID(o.ID))
		if errors.Is(err, store.ErrNotFound) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		if start, err = c.folder(string(g.FolderID)); err != nil || start == nil {
			return nil, false, err
		}
	case Folder:
		f, err := c.folder(o.ID)
		if err != nil || f == nil {
			return nil, false, err
		}
		if f.ParentID == nil {
			return nil, true, nil
		}
		if start, err = c.folder(string(*f.ParentID)); err != nil || start == nil {
			return nil, false, err
		}
	default:
		return nil, true, nil
	}
	for f := start; f != nil && len(folders) < maxDepth; {
		folders = append(folders, f)
		if f.ParentID == nil {
			break
		}
		var err error
		if f, err = c.folder(string(*f.ParentID)); err != nil {
			return nil, false, err
		}
	}
	return folders, true, nil
}

// Ways a row reaches an object.
const (
	ViaSelf          = "self"              // the row sits on the object
	ViaInheritedOne  = "inherited_one"     // a folder row with scope one, from the object's parent folder
	ViaInheritedSub  = "inherited_sub"     // a folder row with scope sub, from an ancestor folder
	ViaFolderStemAdm = "folder_stem_admin" // stem_admin on an ancestor folder, which covers everything below it
)

// Candidate is a row that would give the privilege asked for if its holder is
// the subject.
type Candidate struct {
	Row *store.GrpPrivilege
	Via string
	// Over is the folder the stem_admin is held on (Via folder_stem_admin).
	Over string
}

func inherits(row *store.GrpPrivilege, t ObjectType, nearest bool) (via string, ok bool) {
	if row.AppliesTo != t.AppliesTo() {
		return "", false
	}
	switch {
	case row.Scope == "sub":
		return ViaInheritedSub, true
	case row.Scope == "one" && nearest:
		return ViaInheritedOne, true
	}
	return "", false
}

// candidates lists, without looking at who holds them, every row that gives
// want on o (design §7.2):
//
//	holders(o, p) = rows(object = o, applies_to = self, privilege in impliedBy(p))
//	              ∪ rows(object = F, applies_to = type(o), privilege in impliedBy(p))
//	                   for F = parent(o) with scope in {one, sub}
//	                   and F in ancestors(parent(o)) with scope = sub
//
// plus one rule the design's example (§7.2, "STEM_ADMIN on folder app:foo with
// scope sub gives UPDATE on a group below it") needs: whoever holds stem_admin
// on a folder, by a row on it or inherited from above, holds every privilege on
// the objects below that folder.
func (c *Checker) candidates(o Object, want Privilege) ([]Candidate, bool, error) {
	if !Valid(want) || ObjectOf(want) != o.Type {
		return nil, true, nil
	}
	chain, ok, err := c.chain(o)
	if err != nil || !ok {
		return nil, ok, err
	}
	by := ImpliedBy(want)
	var out []Candidate
	self, err := c.rowsOf(o)
	if err != nil {
		return nil, false, err
	}
	for _, r := range self {
		if r.AppliesTo == "self" && slices.Contains(by, Privilege(r.Privilege)) {
			out = append(out, Candidate{Row: r, Via: ViaSelf})
		}
	}
	for i, f := range chain {
		rs, err := c.rowsOf(FolderObject(f.ID))
		if err != nil {
			return nil, false, err
		}
		for _, r := range rs {
			if !slices.Contains(by, Privilege(r.Privilege)) {
				continue
			}
			if via, ok := inherits(r, o.Type, i == 0); ok {
				out = append(out, Candidate{Row: r, Via: via})
			}
		}
	}
	for k, f := range chain {
		// who holds stem_admin on f: its own rows, and folder rows from above it
		for j := k; j < len(chain); j++ {
			rs, err := c.rowsOf(FolderObject(chain[j].ID))
			if err != nil {
				return nil, false, err
			}
			for _, r := range rs {
				if Privilege(r.Privilege) != StemAdmin {
					continue
				}
				if j == k && r.AppliesTo == "self" {
					out = append(out, Candidate{Row: r, Via: ViaFolderStemAdm, Over: string(f.ID)})
				} else if j > k && r.AppliesTo == "folders" && (r.Scope == "sub" || (r.Scope == "one" && j == k+1)) {
					out = append(out, Candidate{Row: r, Via: ViaFolderStemAdm, Over: string(f.ID)})
				}
			}
		}
	}
	return out, true, nil
}

// Cover says how a holder covers the subject.
const (
	CoverIdentity = "identity" // the row names the subject's identity
	CoverGroup    = "group"    // the subject's identity is an effective member of the row's group
	CoverEveryone = "everyone" // the row is held by everyone
)

// covers reports whether the row's holder is the subject, and how.
func (c *Checker) covers(r *store.GrpPrivilege) (string, bool, error) {
	switch r.HolderType {
	case store.HolderEveryone:
		return CoverEveryone, true, nil
	case store.HolderIdentity:
		if c.sub.Identity != nil && r.HolderIdentity != nil && *r.HolderIdentity == *c.sub.Identity {
			return CoverIdentity, true, nil
		}
	case store.HolderGroup:
		if c.sub.Identity == nil || r.HolderGroup == nil {
			return "", false, nil
		}
		g := string(*r.HolderGroup)
		m, ok := c.members[g]
		if !ok {
			var err error
			// IsMember re-checks the direct rows' own dates, so a membership that
			// has ended counts as ended even if the time wheel has not run yet; a
			// disabled or deleted holder group is empty
			m, err = c.eng.IsMember(c.tx, c.now, *r.HolderGroup, store.MembersListID(c.tx.Tenant()), *c.sub.Identity)
			if err != nil {
				return "", false, err
			}
			c.members[g] = m
		}
		return CoverGroup, m, nil
	}
	return "", false, nil
}

// Has reports whether the subject holds want on o. An object that does not
// exist, or a privilege that does not belong to the object's type, is not held.
func (c *Checker) Has(o Object, want Privilege) (bool, error) {
	if c.sub.roleFor(want) != "" && ObjectOf(want) == o.Type {
		return true, nil
	}
	cands, ok, err := c.candidates(o, want)
	if err != nil || !ok {
		return false, err
	}
	for _, cd := range cands {
		if _, held, err := c.covers(cd.Row); err != nil {
			return false, err
		} else if held {
			return true, nil
		}
	}
	return false, nil
}

// HasAny reports whether the subject holds at least one of the privileges.
func (c *Checker) HasAny(o Object, want ...Privilege) (bool, error) {
	for _, p := range want {
		if ok, err := c.Has(o, p); err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

// DeniedError is the refusal of Require: the subject lacks the privilege.
type DeniedError struct {
	Object    Object
	Privilege Privilege
}

func (e *DeniedError) Error() string {
	return "privs: " + string(e.Privilege) + " is required on " + string(e.Object.Type) + " " + e.Object.ID
}

// Require returns a *DeniedError unless the subject holds want on o.
func (c *Checker) Require(o Object, want Privilege) error {
	ok, err := c.Has(o, want)
	if err != nil {
		return err
	}
	if !ok {
		return &DeniedError{Object: o, Privilege: want}
	}
	return nil
}

// RequireAny is Require for "one of": the error names the first privilege.
func (c *Checker) RequireAny(o Object, want ...Privilege) error {
	ok, err := c.HasAny(o, want...)
	if err != nil {
		return err
	}
	if !ok && len(want) > 0 {
		return &DeniedError{Object: o, Privilege: want[0]}
	}
	return nil
}
