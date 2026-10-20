package plan

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
)

// Live is the part of the server's state a plan is diffed against: every
// folder and group (by name), the direct members of the groups the plan
// changes, and the privilege rows of the objects the plan grants on.
type Live struct {
	Folders map[string]*LiveFolder // by folded name; the root has name ""
	Groups  map[string]*LiveGroup  // by folded name
	byID    map[string]*LiveGroup
	// Members are the direct member keys that count now (MemberRef.Key), by group id.
	Members map[string]map[string]bool
	// Privs are the privilege rows by object id.
	Privs map[string][]LivePriv
}

// LiveFolder is a folder as the server has it.
type LiveFolder struct {
	ID, Name, DisplayName, Description string
}

// LiveGroup is a group as the server has it.
type LiveGroup struct {
	ID, Name, Type, Definition string
}

// LivePriv is a privilege row.
type LivePriv struct {
	Privilege, HolderType, HolderID, AppliesTo, Scope string
}

// NewLive returns an empty state (for a plan against nothing, and for tests).
func NewLive() *Live {
	return &Live{Folders: map[string]*LiveFolder{}, Groups: map[string]*LiveGroup{}, byID: map[string]*LiveGroup{},
		Members: map[string]map[string]bool{}, Privs: map[string][]LivePriv{}}
}

// AddFolder records a folder.
func (l *Live) AddFolder(f LiveFolder) { l.Folders[naming.Fold(f.Name)] = &f }

// AddGroup records a group.
func (l *Live) AddGroup(g LiveGroup) {
	l.Groups[naming.Fold(g.Name)] = &g
	l.byID[g.ID] = &g
}

type folderRow struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_extension"`
	Description string `json:"description"`
}

type groupRow struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Definition string `json:"definition"`
}

type memberRow struct {
	Type       string  `json:"type"`
	IdentityID *int64  `json:"identity_id"`
	GroupID    *string `json:"group_id"`
	Active     bool    `json:"active"`
}

type privRowView struct {
	Privilege  string  `json:"privilege"`
	HolderType string  `json:"holder_type"`
	HolderID   *string `json:"holder_id"`
	AppliesTo  string  `json:"applies_to"`
	Scope      string  `json:"scope"`
}

// LoadCatalog reads every folder and group the caller may see.
func LoadCatalog(ctx context.Context, c Client) (*Live, error) {
	l := NewLive()
	folders, err := listAll[folderRow](ctx, c, "/api/groups/folders", nil)
	if err != nil {
		return nil, err
	}
	for _, f := range folders {
		l.AddFolder(LiveFolder{ID: f.ID, Name: f.Name, DisplayName: f.DisplayName, Description: f.Description})
	}
	groups, err := listAll[groupRow](ctx, c, "/api/groups/native", nil)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		l.AddGroup(LiveGroup{ID: g.ID, Name: g.Name, Type: g.Type, Definition: g.Definition})
	}
	return l, nil
}

// Load reads the catalog, then the direct members of the groups spec lists
// members for and the privilege rows of the objects it grants on (only those
// that exist: the others have nothing yet).
func Load(ctx context.Context, c Client, spec *Spec) (*Live, error) {
	l, err := LoadCatalog(ctx, c)
	if err != nil {
		return nil, err
	}
	for _, g := range spec.Groups {
		if len(g.Members.Add) == 0 && len(g.Members.Remove) == 0 {
			continue
		}
		if lg := l.Groups[naming.Fold(g.Name)]; lg != nil {
			if err := l.loadMembers(ctx, c, lg.ID); err != nil {
				return nil, err
			}
		}
	}
	for _, p := range spec.Privileges {
		o, err := ParseObject(p.Object)
		if err != nil {
			continue // Validate reports it
		}
		if id := l.objectID(o); id != "" {
			if err := l.loadPrivs(ctx, c, o.Type, id); err != nil {
				return nil, err
			}
		}
	}
	return l, nil
}

func (l *Live) objectID(o ObjectRef) string {
	if o.Type == "folder" {
		if f := l.Folders[naming.Fold(o.Name)]; f != nil {
			return f.ID
		}
		return ""
	}
	if g := l.Groups[naming.Fold(o.Name)]; g != nil {
		return g.ID
	}
	return ""
}

func (l *Live) loadMembers(ctx context.Context, c Client, group string) error {
	rows, err := listAll[memberRow](ctx, c, "/api/groups/"+url.PathEscape(group)+"/members", url.Values{"filter": {"direct"}})
	if err != nil {
		return err
	}
	set := map[string]bool{}
	for _, m := range rows {
		if !m.Active {
			continue
		}
		switch {
		case m.IdentityID != nil:
			set["identity:"+strconv.FormatInt(*m.IdentityID, 10)] = true
		case m.GroupID != nil:
			if g := l.byID[*m.GroupID]; g != nil {
				set["group:"+naming.Fold(g.Name)] = true
			}
		}
	}
	l.Members[group] = set
	return nil
}

func (l *Live) loadPrivs(ctx context.Context, c Client, typ, id string) error {
	path := "/api/groups/" + url.PathEscape(id) + "/privileges"
	if typ == "folder" {
		path = "/api/groups/folders/" + url.PathEscape(id) + "/privileges"
	}
	var out struct {
		Items []privRowView `json:"items"`
	}
	if _, err := call(ctx, c, http.MethodGet, path, nil, &out, nil); err != nil {
		return err
	}
	for _, r := range out.Items {
		p := LivePriv{Privilege: r.Privilege, HolderType: r.HolderType, AppliesTo: r.AppliesTo, Scope: r.Scope}
		if r.HolderID != nil {
			p.HolderID = *r.HolderID
		}
		l.Privs[id] = append(l.Privs[id], p)
	}
	return nil
}

// FindGroup returns the group with the name, or nil.
func (l *Live) FindGroup(name string) *LiveGroup { return l.Groups[naming.Fold(name)] }

// FindFolder returns the folder with the name, or nil.
func (l *Live) FindFolder(name string) *LiveFolder { return l.Folders[naming.Fold(name)] }

// GroupByID returns the group with the id, or nil.
func (l *Live) GroupByID(id string) *LiveGroup { return l.byID[id] }
