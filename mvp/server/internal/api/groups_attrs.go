package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/attrs"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Attribute framework, object types and services (issue #50, GR-7; design
// docs/design/groups-grouper-parity.md §10.9, §10.11). Every route needs
// groups.read or groups.write to be reached, and then the privileges of the
// attribute definition (attr_*) and of the object an assignment sits on (see
// attrs/access.go): a refusal is 403 privilege_required.
//
//	GET    /api/groups/attr-defs?folder=&scope=one|sub&q=&type=       attr_view (filtered)
//	POST   /api/groups/attr-defs                                      create on the folder
//	GET|PATCH|DELETE /api/groups/attr-defs/{id}                       attr_view | attr_admin
//	GET|POST /api/groups/attr-defs/{id}/actions                       attr_view | attr_admin
//	DELETE /api/groups/attr-defs/{id}/actions/{action_id}             attr_admin
//	PUT    /api/groups/attr-defs/{id}/actions/{action_id}/implies     {implies: [action ids]}  attr_admin
//	GET|POST /api/groups/attr-defs/{id}/privileges, DELETE .../{privilege_id}, GET .../privileges/effective
//	GET    /api/groups/attr-names?def=&q=                             attr_view
//	POST   /api/groups/attr-names                                     {def, extension, ...}  attr_admin
//	GET|PATCH|DELETE /api/groups/attr-names/{id}                      attr_view | attr_admin
//	PUT    /api/groups/attr-names/{id}/implies                        {implies: [name ids]}  attr_admin
//	GET    /api/groups/attr-assignments?owner_type=&owner=&def=&name=&effective=   attr_read + the owner's read privilege (filtered)
//	POST   /api/groups/attr-assignments                               {name, action, owner_type, owner, values, ...}
//	GET|PATCH|DELETE /api/groups/attr-assignments/{id}
//	PUT    /api/groups/attr-assignments/{id}/values                   {values: [...]}
//	GET    /api/groups/object-types                                   the vocabulary
//	GET|PUT /api/groups/{id}/object-types, /api/groups/folders/{id}/object-types   {types: [...]}
//	GET    /api/groups/services                                       the services the caller can use
//
// Floating values are JSON strings ("12.5"), never numbers. A cycle in the
// implications is 409 {"error":"cycle","path":[...]}; deleting a definition,
// name or action that assignments use is 409 attr_*_in_use.
func (s *Server) registerGroupsAttrRoutes() {
	G, P, PU, PA, D := http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete
	canRead, canWrite := need(auth.PermGroupsRead), need(auth.PermGroupsWrite)
	// literal paths first: /api/groups/{id} would also match "services" and "object-types"
	s.handle(G, "/api/groups/object-types", read, canRead, s.rd(s.getObjectTypeVocabulary))
	s.handle(G, "/api/groups/services", read, canRead, s.rd(s.listGrpServices))
	s.handle(G, "/api/groups/attr-defs", read, canRead, s.rd(s.listAttrDefs))
	s.handle(P, "/api/groups/attr-defs", write, canWrite, s.rd(s.createAttrDef))
	s.handle(G, "/api/groups/attr-defs/{id}", read, canRead, s.rd(s.getAttrDef))
	s.handle(PA, "/api/groups/attr-defs/{id}", write, canWrite, s.rd(s.patchAttrDef))
	s.handle(D, "/api/groups/attr-defs/{id}", write, canWrite, s.rd(s.deleteAttrDef))
	s.handle(G, "/api/groups/attr-defs/{id}/actions", read, canRead, s.rd(s.listAttrActions))
	s.handle(P, "/api/groups/attr-defs/{id}/actions", write, canWrite, s.rd(s.createAttrAction))
	s.handle(D, "/api/groups/attr-defs/{id}/actions/{action_id}", write, canWrite, s.rd(s.deleteAttrAction))
	s.handle(PU, "/api/groups/attr-defs/{id}/actions/{action_id}/implies", write, canWrite, s.rd(s.setAttrActionImplies))
	h := s.privHandlers(privs.AttrDef)
	base := "/api/groups/attr-defs/{id}/privileges"
	s.handle(G, base, read, canRead, s.rd(h.list))
	s.handle(P, base, write, canWrite, s.rd(h.grant))
	s.handle(G, base+"/effective", read, canRead, s.rd(h.effective))
	s.handle(D, base+"/{privilege_id}", write, canWrite, s.rd(h.revoke))
	s.handle(G, "/api/groups/attr-names", read, canRead, s.rd(s.listAttrNames))
	s.handle(P, "/api/groups/attr-names", write, canWrite, s.rd(s.createAttrName))
	s.handle(G, "/api/groups/attr-names/{id}", read, canRead, s.rd(s.getAttrName))
	s.handle(PA, "/api/groups/attr-names/{id}", write, canWrite, s.rd(s.patchAttrName))
	s.handle(D, "/api/groups/attr-names/{id}", write, canWrite, s.rd(s.deleteAttrName))
	s.handle(PU, "/api/groups/attr-names/{id}/implies", write, canWrite, s.rd(s.setAttrNameImplies))
	s.handle(G, "/api/groups/attr-assignments", read, canRead, s.rd(s.listAttrAssigns))
	s.handle(P, "/api/groups/attr-assignments", write, canWrite, s.rd(s.createAttrAssign))
	s.handle(G, "/api/groups/attr-assignments/{id}", read, canRead, s.rd(s.getAttrAssign))
	s.handle(PA, "/api/groups/attr-assignments/{id}", write, canWrite, s.rd(s.patchAttrAssign))
	s.handle(D, "/api/groups/attr-assignments/{id}", write, canWrite, s.rd(s.deleteAttrAssign))
	s.handle(PU, "/api/groups/attr-assignments/{id}/values", write, canWrite, s.rd(s.setAttrAssignValues))
	s.handle(G, "/api/groups/{id}/object-types", read, canRead, s.rd(s.getGroupObjectTypes))
	s.handle(PU, "/api/groups/{id}/object-types", write, canWrite, s.rd(s.putGroupObjectTypes))
	s.handle(G, "/api/groups/folders/{id}/object-types", read, canRead, s.rd(s.getFolderObjectTypes))
	s.handle(PU, "/api/groups/folders/{id}/object-types", write, canWrite, s.rd(s.putFolderObjectTypes))
}

// ---------------------------------------------------------------- helpers

// attrDefFor loads a definition (404) and requires the privilege on it (403).
func (s *Server) attrDefFor(r *http.Request, ck *privs.Checker, id string, p privs.Privilege) (*store.GrpAttrDef, error) {
	d, err := attrs.Def(store.TxFrom(r.Context()), id)
	if err != nil {
		return nil, grpErr(err)
	}
	return d, grpErr(ck.Require(privs.AttrDefObject(d.ID), p))
}

func attrPathID(p *params, key, what string) (string, error) {
	id := p.path[key]
	if !idRE.MatchString(id) {
		return "", grpNotFound(what)
	}
	return id, nil
}

// pageOf runs fetch in chunks and keeps the rows keep accepts until offset and
// limit count accepted rows (like visible, for a test that is not one privilege).
func pageOf[T any](limit, offset int, fetch func(limit, offset int) ([]T, error), keep func(T) (bool, error)) ([]T, error) {
	const chunk = 500
	out := []T{}
	skip := offset
	for raw := 0; len(out) < limit; raw += chunk {
		rows, err := fetch(chunk, raw)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			ok, err := keep(row)
			switch {
			case err != nil:
				return nil, err
			case !ok:
			case skip > 0:
				skip--
			case len(out) < limit:
				out = append(out, row)
			}
		}
		if len(rows) < chunk {
			break
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- views

type attrDefView struct {
	ID               string   `json:"id"`
	FolderID         string   `json:"folder_id"`
	Name             string   `json:"name"`
	Extension        string   `json:"extension"`
	DisplayExtension string   `json:"display_extension"`
	Description      string   `json:"description"`
	AttrType         string   `json:"attr_type"`
	ValueType        string   `json:"value_type"`
	MultiAssign      bool     `json:"multi_assign"`
	MultiValued      bool     `json:"multi_valued"`
	AssignTo         []string `json:"assign_to"`
	System           bool     `json:"system"`
	CreatedAt        string   `json:"created_at"`
	CreatedBy        *string  `json:"created_by"`
	Version          int64    `json:"version"`
}

func viewAttrDef(d *store.GrpAttrDef) attrDefView {
	return attrDefView{ID: d.ID, FolderID: string(d.FolderID), Name: d.Name(), Extension: d.Extension, DisplayExtension: d.DisplayExtension,
		Description: d.Description, AttrType: d.AttrType, ValueType: d.ValueType, MultiAssign: d.MultiAssign, MultiValued: d.MultiValued,
		AssignTo: slices.Clone(d.AssignTo), System: d.System, CreatedAt: store.RT(d.CreatedAt), CreatedBy: d.CreatedBy, Version: d.Version}
}

type attrNameView struct {
	ID               string   `json:"id"`
	DefID            string   `json:"def_id"`
	Name             string   `json:"name"`
	Extension        string   `json:"extension"`
	DisplayExtension string   `json:"display_extension"`
	Description      string   `json:"description"`
	Implies          []string `json:"implies"`
	ImpliesAll       []string `json:"implies_all"`
	CreatedAt        string   `json:"created_at"`
}

func viewAttrName(tx *store.TenantTx, d *store.GrpAttrDef, n *store.GrpAttrName) (attrNameView, error) {
	direct, all, err := attrs.Implied(tx, store.ImpliesNames, n.ID)
	if err != nil {
		return attrNameView{}, err
	}
	return attrNameView{ID: n.ID, DefID: n.DefID, Name: attrs.NameFullName(d, n), Extension: n.Extension,
		DisplayExtension: n.DisplayExtension, Description: n.Description, Implies: direct, ImpliesAll: all, CreatedAt: store.RT(n.CreatedAt)}, nil
}

type attrActionView struct {
	ID          string   `json:"id"`
	DefID       string   `json:"def_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Implies     []string `json:"implies"`
	ImpliesAll  []string `json:"implies_all"`
	CreatedAt   string   `json:"created_at"`
}

func viewAttrAction(tx *store.TenantTx, a *store.GrpAttrAction) (attrActionView, error) {
	direct, all, err := attrs.Implied(tx, store.ImpliesActions, a.ID)
	if err != nil {
		return attrActionView{}, err
	}
	return attrActionView{ID: a.ID, DefID: a.DefID, Name: a.Name, Description: a.Description, Implies: direct, ImpliesAll: all,
		CreatedAt: store.RT(a.CreatedAt)}, nil
}

type attrAssignView struct {
	ID          string  `json:"id"`
	DefID       string  `json:"def_id"`
	Def         string  `json:"def"`
	NameID      string  `json:"name_id"`
	Name        string  `json:"name"`
	ActionID    string  `json:"action_id"`
	Action      string  `json:"action"`
	OwnerType   string  `json:"owner_type"`
	Owner       string  `json:"owner"`
	Disallowed  bool    `json:"disallowed"`
	EnabledFrom *string `json:"enabled_from"`
	DisabledAt  *string `json:"disabled_at"`
	// Active says the assignment counts at this moment (its dates, and not a disallow).
	Active bool `json:"active"`
	// Values are JSON strings, integers and member ids; a floating value is a string.
	Values    []any   `json:"values"`
	CreatedAt string  `json:"created_at"`
	CreatedBy *string `json:"created_by"`
	Version   int64   `json:"version"`
}

// assignViewer builds assignment views, caching the definitions, names and
// actions of one request.
type assignViewer struct {
	tx   *store.TenantTx
	now  time.Time
	defs map[string]*store.GrpAttrDef
	nms  map[string]*store.GrpAttrName
	acts map[string]*store.GrpAttrAction
}

func newAssignViewer(tx *store.TenantTx, now time.Time) *assignViewer {
	return &assignViewer{tx: tx, now: now, defs: map[string]*store.GrpAttrDef{}, nms: map[string]*store.GrpAttrName{},
		acts: map[string]*store.GrpAttrAction{}}
}

func (v *assignViewer) def(id string) (*store.GrpAttrDef, error) {
	if d, ok := v.defs[id]; ok {
		return d, nil
	}
	d, err := attrs.Def(v.tx, id)
	if err != nil {
		return nil, err
	}
	v.defs[id] = d
	return d, nil
}

func (v *assignViewer) view(a *store.GrpAttrAssign, values []*store.GrpAttrValue) (attrAssignView, error) {
	d, err := v.def(a.DefID)
	if err != nil {
		return attrAssignView{}, err
	}
	n, ok := v.nms[a.NameID]
	if !ok {
		if n, err = attrs.Name(v.tx, a.NameID); err != nil {
			return attrAssignView{}, err
		}
		v.nms[a.NameID] = n
	}
	ac, ok := v.acts[a.ActionID]
	if !ok {
		if ac, err = attrs.Action(v.tx, a.ActionID); err != nil {
			return attrAssignView{}, err
		}
		v.acts[a.ActionID] = ac
	}
	if values == nil {
		if values, err = v.tx.GrpAttrValuesOf(a.ID); err != nil {
			return attrAssignView{}, err
		}
	}
	out := attrAssignView{ID: a.ID, DefID: d.ID, Def: d.Name(), NameID: n.ID, Name: attrs.NameFullName(d, n), ActionID: ac.ID,
		Action: ac.Name, OwnerType: a.OwnerType, Owner: a.OwnerID, Disallowed: a.Disallowed, Active: attrs.Active(a, v.now),
		Values: make([]any, len(values)), CreatedAt: store.RT(a.CreatedAt), CreatedBy: a.CreatedBy, Version: a.Version}
	for i, val := range values {
		out.Values[i] = attrs.JSON(val)
	}
	if a.EnabledFrom != nil {
		t := store.RT(*a.EnabledFrom)
		out.EnabledFrom = &t
	}
	if a.DisabledAt != nil {
		t := store.RT(*a.DisabledAt)
		out.DisabledAt = &t
	}
	return out, nil
}

// ---------------------------------------------------------------- definitions

func (s *Server) listAttrDefs(r *http.Request, p *params) (int, any, error) {
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	folder, _ := p.query("folder")
	if err := grpBodyID("folder", folder); err != nil {
		return 0, nil, err
	}
	q, err := queryStr(p, "q", 255)
	if err != nil {
		return 0, nil, err
	}
	typ, _ := p.query("type")
	if typ != "" && !slices.Contains(attrs.AttrTypes, typ) {
		return 0, nil, badRequest("invalid_type", "type is one of "+strings.Join(attrs.AttrTypes, ", "))
	}
	filter := store.GrpAttrDefFilter{Q: q, AttrType: typ}
	scope, _ := p.query("scope")
	if folder != "" {
		f, err := store.TxFrom(r.Context()).GrpFolder(store.FolderID(folder))
		if errors.Is(err, store.ErrNotFound) {
			return 0, nil, grpNotFound("folder")
		}
		if err != nil {
			return 0, nil, err
		}
		switch scope {
		case "", "one":
			filter.FolderID = f.ID
		case "sub":
			filter.Prefix = f.Name
		default:
			return 0, nil, badRequest("invalid_scope", "scope is one or sub")
		}
	}
	tx := store.TxFrom(r.Context())
	// browse and search show only what the caller may view (attr_view)
	ds, err := visible(s.grpChecker(r), privs.AttrDef, limit, offset, func(l, o int) ([]*store.GrpAttrDef, error) {
		f := filter
		f.Limit, f.Offset = l, o
		return tx.GrpAttrDefs(f)
	}, func(d *store.GrpAttrDef) privs.Object { return privs.AttrDefObject(d.ID) }, privs.AttrView)
	if err != nil {
		return 0, nil, grpErr(err)
	}
	items := make([]attrDefView, len(ds))
	for i, d := range ds {
		items[i] = viewAttrDef(d)
	}
	return http.StatusOK, listBody{items, limit, offset}, nil
}

func (s *Server) createAttrDef(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		Folder           string   `json:"folder"`
		Extension        string   `json:"extension"`
		DisplayExtension string   `json:"display_extension"`
		Description      string   `json:"description"`
		AttrType         string   `json:"attr_type"`
		ValueType        string   `json:"value_type"`
		MultiAssign      bool     `json:"multi_assign"`
		MultiValued      bool     `json:"multi_valued"`
		AssignTo         []string `json:"assign_to"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if !idRE.MatchString(in.Folder) {
		return 0, nil, badRequest("invalid_folder", "folder must be a folder id")
	}
	if _, err := s.grpFolderFor(r, s.grpChecker(r), in.Folder, privs.Create); err != nil {
		return 0, nil, err
	}
	var out *store.GrpAttrDef
	err := s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = attrs.CreateDef(e.Attrs(), attrs.DefInput{Folder: store.FolderID(in.Folder), Extension: in.Extension,
			DisplayExtension: in.DisplayExtension, Description: in.Description, AttrType: in.AttrType, ValueType: in.ValueType,
			MultiAssign: in.MultiAssign, MultiValued: in.MultiValued, AssignTo: in.AssignTo})
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, viewAttrDef(out), nil
}

func (s *Server) getAttrDef(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "attribute definition")
	if err != nil {
		return 0, nil, err
	}
	d, err := s.attrDefFor(r, s.grpChecker(r), id, privs.AttrView)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, viewAttrDef(d), nil
}

func (s *Server) patchAttrDef(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "attribute definition")
	if err != nil {
		return 0, nil, err
	}
	if _, err := s.attrDefFor(r, s.grpChecker(r), id, privs.AttrAdmin); err != nil {
		return 0, nil, err
	}
	var in struct {
		DisplayExtension *string   `json:"display_extension"`
		Description      *string   `json:"description"`
		MultiAssign      *bool     `json:"multi_assign"`
		MultiValued      *bool     `json:"multi_valued"`
		AssignTo         *[]string `json:"assign_to"`
		Version          *int64    `json:"version"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out *store.GrpAttrDef
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = attrs.UpdateDef(e.Attrs(), id, attrs.DefUpdate{DisplayExtension: in.DisplayExtension, Description: in.Description,
			MultiAssign: in.MultiAssign, MultiValued: in.MultiValued, AssignTo: in.AssignTo, Version: in.Version})
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, viewAttrDef(out), nil
}

func (s *Server) deleteAttrDef(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "attribute definition")
	if err != nil {
		return 0, nil, err
	}
	if _, err := s.attrDefFor(r, s.grpChecker(r), id, privs.AttrAdmin); err != nil {
		return 0, nil, err
	}
	err = s.grpWrite(r, func(e model.Env) error { return attrs.DeleteDef(e.Attrs(), id) })
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"id": id, "deleted": true}, nil
}

// ---------------------------------------------------------------- actions

func (s *Server) listAttrActions(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "attribute definition")
	if err != nil {
		return 0, nil, err
	}
	d, err := s.attrDefFor(r, s.grpChecker(r), id, privs.AttrView)
	if err != nil {
		return 0, nil, err
	}
	tx := store.TxFrom(r.Context())
	as, err := tx.GrpAttrActionsOf(d.ID)
	if err != nil {
		return 0, nil, err
	}
	items := make([]attrActionView, len(as))
	for i, a := range as {
		if items[i], err = viewAttrAction(tx, a); err != nil {
			return 0, nil, err
		}
	}
	return http.StatusOK, map[string]any{"def_id": d.ID, "items": items}, nil
}

func (s *Server) createAttrAction(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "attribute definition")
	if err != nil {
		return 0, nil, err
	}
	if _, err := s.attrDefFor(r, s.grpChecker(r), id, privs.AttrAdmin); err != nil {
		return 0, nil, err
	}
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out *store.GrpAttrAction
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = attrs.CreateAction(e.Attrs(), id, in.Name, in.Description)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	v, err := viewAttrAction(store.TxFrom(r.Context()), out)
	return http.StatusCreated, v, err
}

// actionOf loads the path's action (404) of the path's definition and requires
// attr_admin on the definition (403).
func (s *Server) actionOf(r *http.Request, p *params) (*store.GrpAttrAction, error) {
	id, err := grpPathID(p, "attribute definition")
	if err != nil {
		return nil, err
	}
	aid, err := attrPathID(p, "action_id", "attribute action")
	if err != nil {
		return nil, err
	}
	d, err := s.attrDefFor(r, s.grpChecker(r), id, privs.AttrAdmin)
	if err != nil {
		return nil, err
	}
	a, err := attrs.Action(store.TxFrom(r.Context()), aid)
	if err != nil {
		return nil, grpErr(err)
	}
	if a.DefID != d.ID {
		return nil, grpNotFound("attribute action")
	}
	return a, nil
}

func (s *Server) deleteAttrAction(r *http.Request, p *params) (int, any, error) {
	a, err := s.actionOf(r, p)
	if err != nil {
		return 0, nil, err
	}
	err = s.grpWrite(r, func(e model.Env) error { return attrs.DeleteAction(e.Attrs(), a.ID) })
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"id": a.ID, "deleted": true}, nil
}

func impliesBody(r *http.Request) ([]string, error) {
	var in struct {
		Implies []string `json:"implies"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return nil, err
	}
	for _, id := range in.Implies {
		if !idRE.MatchString(id) {
			return nil, badRequest("invalid_implies", "implies is a list of ids")
		}
	}
	return in.Implies, nil
}

func (s *Server) setAttrActionImplies(r *http.Request, p *params) (int, any, error) {
	a, err := s.actionOf(r, p)
	if err != nil {
		return 0, nil, err
	}
	implies, err := impliesBody(r)
	if err != nil {
		return 0, nil, err
	}
	var out *store.GrpAttrAction
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = attrs.SetActionImplies(e.Attrs(), a.ID, implies)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	v, err := viewAttrAction(store.TxFrom(r.Context()), out)
	return http.StatusOK, v, err
}

// ---------------------------------------------------------------- names

func (s *Server) listAttrNames(r *http.Request, p *params) (int, any, error) {
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	def, _ := p.query("def")
	if err := grpBodyID("def", def); err != nil {
		return 0, nil, err
	}
	q, err := queryStr(p, "q", 255)
	if err != nil {
		return 0, nil, err
	}
	ck := s.grpChecker(r)
	tx := store.TxFrom(r.Context())
	if def != "" { // one definition's names: one check
		if _, err := s.attrDefFor(r, ck, def, privs.AttrView); err != nil {
			return 0, nil, err
		}
	}
	// the names of every definition the caller may view (attr_view)
	view := newAssignViewer(tx, s.clock())
	ns, err := pageOf(limit, offset, func(l, o int) ([]*store.GrpAttrName, error) {
		return tx.GrpAttrNames(def, q, l, o)
	}, func(n *store.GrpAttrName) (bool, error) {
		return ck.Has(privs.AttrDefObject(n.DefID), privs.AttrView)
	})
	if err != nil {
		return 0, nil, grpErr(err)
	}
	items := make([]attrNameView, len(ns))
	for i, n := range ns {
		d, err := view.def(n.DefID)
		if err != nil {
			return 0, nil, grpErr(err)
		}
		if items[i], err = viewAttrName(tx, d, n); err != nil {
			return 0, nil, err
		}
	}
	return http.StatusOK, listBody{items, limit, offset}, nil
}

func (s *Server) createAttrName(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		Def              string `json:"def"`
		Extension        string `json:"extension"`
		DisplayExtension string `json:"display_extension"`
		Description      string `json:"description"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if !idRE.MatchString(in.Def) {
		return 0, nil, badRequest("invalid_def", "def must be the id of an attribute definition")
	}
	d, err := s.attrDefFor(r, s.grpChecker(r), in.Def, privs.AttrAdmin)
	if err != nil {
		return 0, nil, err
	}
	var out *store.GrpAttrName
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = attrs.CreateName(e.Attrs(), attrs.NameInput{Def: in.Def, Extension: in.Extension,
			DisplayExtension: in.DisplayExtension, Description: in.Description})
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	v, err := viewAttrName(store.TxFrom(r.Context()), d, out)
	return http.StatusCreated, v, err
}

// nameFor loads the path's name (404) and requires the privilege on its definition (403).
func (s *Server) nameFor(r *http.Request, p *params, priv privs.Privilege) (*store.GrpAttrName, *store.GrpAttrDef, error) {
	id, err := grpPathID(p, "attribute name")
	if err != nil {
		return nil, nil, err
	}
	n, err := attrs.Name(store.TxFrom(r.Context()), id)
	if err != nil {
		return nil, nil, grpErr(err)
	}
	d, err := s.attrDefFor(r, s.grpChecker(r), n.DefID, priv)
	return n, d, err
}

func (s *Server) getAttrName(r *http.Request, p *params) (int, any, error) {
	n, d, err := s.nameFor(r, p, privs.AttrView)
	if err != nil {
		return 0, nil, err
	}
	v, err := viewAttrName(store.TxFrom(r.Context()), d, n)
	return http.StatusOK, v, err
}

func (s *Server) patchAttrName(r *http.Request, p *params) (int, any, error) {
	n, d, err := s.nameFor(r, p, privs.AttrAdmin)
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		DisplayExtension *string `json:"display_extension"`
		Description      *string `json:"description"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out *store.GrpAttrName
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = attrs.UpdateName(e.Attrs(), n.ID, in.DisplayExtension, in.Description)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	v, err := viewAttrName(store.TxFrom(r.Context()), d, out)
	return http.StatusOK, v, err
}

func (s *Server) deleteAttrName(r *http.Request, p *params) (int, any, error) {
	n, _, err := s.nameFor(r, p, privs.AttrAdmin)
	if err != nil {
		return 0, nil, err
	}
	err = s.grpWrite(r, func(e model.Env) error { return attrs.DeleteName(e.Attrs(), n.ID) })
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"id": n.ID, "deleted": true}, nil
}

func (s *Server) setAttrNameImplies(r *http.Request, p *params) (int, any, error) {
	n, d, err := s.nameFor(r, p, privs.AttrAdmin)
	if err != nil {
		return 0, nil, err
	}
	implies, err := impliesBody(r)
	if err != nil {
		return 0, nil, err
	}
	var out *store.GrpAttrName
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = attrs.SetNameImplies(e.Attrs(), n.ID, implies)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	v, err := viewAttrName(store.TxFrom(r.Context()), d, out)
	return http.StatusOK, v, err
}

// ---------------------------------------------------------------- assignments

// parseOwner validates an owner named in a body or query: its type, and its id
// by what the type is (a UUID, or an identity id).
func parseOwner(typ, id string) (attrs.Owner, error) {
	if !slices.Contains(attrs.OwnerTypes, typ) {
		return attrs.Owner{}, badRequest("invalid_owner_type", "owner_type is one of "+strings.Join(attrs.OwnerTypes, ", "))
	}
	if typ == store.AttrOwnerIdentity {
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil || n < 1 {
			return attrs.Owner{}, badRequest("invalid_owner", "an identity owner is an identity id")
		}
		return attrs.Owner{Type: typ, ID: strconv.FormatInt(n, 10)}, nil
	}
	if !idRE.MatchString(id) {
		return attrs.Owner{}, badRequest("invalid_owner", "owner must be the id of the "+typ)
	}
	return attrs.Owner{Type: typ, ID: id}, nil
}

func parseTimePtr(field string, s *string) (*time.Time, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil, badRequest("invalid_"+field, field+" must be an RFC 3339 time")
	}
	t = t.UTC()
	return &t, nil
}

func (s *Server) listAttrAssigns(r *http.Request, p *params) (int, any, error) {
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	ownerType, _ := p.query("owner_type")
	ownerID, _ := p.query("owner")
	def, _ := p.query("def")
	name, _ := p.query("name")
	if err := errors.Join(grpBodyID("def", def), grpBodyID("name", name)); err != nil {
		return 0, nil, firstErrOf(err)
	}
	filter := store.GrpAttrAssignFilter{DefID: def, NameID: name}
	if (ownerType == "") != (ownerID == "") {
		return 0, nil, badRequest("invalid_owner", "give owner_type and owner together")
	}
	if ownerType != "" {
		o, err := parseOwner(ownerType, ownerID)
		if err != nil {
			return 0, nil, err
		}
		filter.OwnerType, filter.OwnerID = o.Type, o.ID
	}
	eff := p.queryOptBool("effective")
	tx := store.TxFrom(r.Context())
	ck := s.grpChecker(r)
	if eff != nil && *eff {
		if ownerType == "" {
			return 0, nil, badRequest("invalid_owner", "effective needs owner_type and owner")
		}
		return s.effectiveAttrs(r, tx, ck, attrs.Owner{Type: filter.OwnerType, ID: filter.OwnerID})
	}
	view := newAssignViewer(tx, s.clock())
	rows, err := pageOf(limit, offset, func(l, o int) ([]*store.GrpAttrAssign, error) {
		f := filter
		f.Limit, f.Offset = l, o
		return tx.GrpAttrAssigns(f)
	}, func(a *store.GrpAttrAssign) (bool, error) {
		d, err := view.def(a.DefID)
		if err != nil {
			return false, err
		}
		return attrs.CanRead(ck, tx, d, attrs.OwnerOf(a))
	})
	if err != nil {
		return 0, nil, grpErr(err)
	}
	items := make([]attrAssignView, len(rows))
	for i, a := range rows {
		if items[i], err = view.view(a, nil); err != nil {
			return 0, nil, grpErr(err)
		}
	}
	return http.StatusOK, listBody{items, limit, offset}, nil
}

func firstErrOf(err error) error {
	type multi interface{ Unwrap() []error }
	if m, ok := err.(multi); ok {
		for _, e := range m.Unwrap() {
			if e != nil {
				return e
			}
		}
	}
	return err
}

type effectiveNameView struct {
	NameID  string `json:"name_id"`
	Name    string `json:"name"`
	Via     string `json:"via"`
	Implied bool   `json:"implied"`
}

// effectiveAttrs answers effective=true: the names the owner has, by assignment
// and by implication, that the caller may read.
func (s *Server) effectiveAttrs(r *http.Request, tx *store.TenantTx, ck *privs.Checker, o attrs.Owner) (int, any, error) {
	names, err := attrs.Effective(tx, o, s.clock())
	if err != nil {
		return 0, nil, grpErr(err)
	}
	items := []effectiveNameView{}
	for _, n := range names {
		name, err := attrs.Name(tx, n.NameID)
		if err != nil {
			return 0, nil, grpErr(err)
		}
		d, err := attrs.Def(tx, name.DefID)
		if err != nil {
			return 0, nil, grpErr(err)
		}
		if ok, err := attrs.CanRead(ck, tx, d, o); err != nil {
			return 0, nil, err
		} else if !ok {
			continue
		}
		items = append(items, effectiveNameView{NameID: n.NameID, Name: attrs.NameFullName(d, name), Via: n.Via, Implied: n.Implied})
	}
	return http.StatusOK, map[string]any{"owner_type": o.Type, "owner": o.ID, "effective": true, "items": items}, nil
}

func (s *Server) createAttrAssign(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		Name        string            `json:"name"`
		Action      string            `json:"action"`
		OwnerType   string            `json:"owner_type"`
		Owner       string            `json:"owner"`
		Disallowed  bool              `json:"disallowed"`
		EnabledFrom *string           `json:"enabled_from"`
		DisabledAt  *string           `json:"disabled_at"`
		Values      []json.RawMessage `json:"values"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	tx := store.TxFrom(r.Context())
	var name *store.GrpAttrName
	var err error
	if idRE.MatchString(in.Name) {
		name, err = attrs.Name(tx, in.Name)
	} else {
		name, err = attrs.NameByFullName(tx, in.Name)
	}
	if err != nil {
		return 0, nil, grpErr(err)
	}
	d, err := attrs.Def(tx, name.DefID)
	if err != nil {
		return 0, nil, grpErr(err)
	}
	owner, err := parseOwner(in.OwnerType, in.Owner)
	if err != nil {
		return 0, nil, err
	}
	from, err := parseTimePtr("enabled_from", in.EnabledFrom)
	if err != nil {
		return 0, nil, err
	}
	to, err := parseTimePtr("disabled_at", in.DisabledAt)
	if err != nil {
		return 0, nil, err
	}
	action := in.Action
	if action != "" && !idRE.MatchString(action) { // an action may be named
		a, err := tx.GrpAttrActionByName(d.ID, action)
		if errors.Is(err, store.ErrNotFound) {
			return 0, nil, grpNotFound("attribute action")
		}
		if err != nil {
			return 0, nil, err
		}
		action = a.ID
	}
	if err := attrs.RequireAssign(s.grpChecker(r), tx, d, owner); err != nil {
		return 0, nil, grpErr(err)
	}
	var out *attrs.Assigned
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = attrs.Assign(e.Attrs(), attrs.AssignInput{Name: name.ID, Action: action, Owner: owner,
			Disallowed: in.Disallowed, EnabledFrom: from, DisabledAt: to, Values: in.Values})
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	v, err := newAssignViewer(tx, s.clock()).view(out.Assign, out.Values)
	return http.StatusCreated, v, err
}

// assignFor loads the path's assignment (404) and its definition.
func (s *Server) assignFor(r *http.Request, p *params) (*store.GrpAttrAssign, *store.GrpAttrDef, error) {
	id, err := grpPathID(p, "attribute assignment")
	if err != nil {
		return nil, nil, err
	}
	tx := store.TxFrom(r.Context())
	a, err := attrs.AssignByID(tx, id)
	if err != nil {
		return nil, nil, grpErr(err)
	}
	d, err := attrs.Def(tx, a.DefID)
	return a, d, grpErr(err)
}

func (s *Server) getAttrAssign(r *http.Request, p *params) (int, any, error) {
	a, d, err := s.assignFor(r, p)
	if err != nil {
		return 0, nil, err
	}
	tx := store.TxFrom(r.Context())
	if err := attrs.RequireRead(s.grpChecker(r), tx, d, attrs.OwnerOf(a)); err != nil {
		return 0, nil, grpErr(err)
	}
	v, err := newAssignViewer(tx, s.clock()).view(a, nil)
	return http.StatusOK, v, grpErr(err)
}

func (s *Server) patchAttrAssign(r *http.Request, p *params) (int, any, error) {
	a, d, err := s.assignFor(r, p)
	if err != nil {
		return 0, nil, err
	}
	tx := store.TxFrom(r.Context())
	if err := attrs.RequireChange(s.grpChecker(r), tx, d, attrs.OwnerOf(a)); err != nil {
		return 0, nil, grpErr(err)
	}
	var in struct {
		Disallowed  *bool   `json:"disallowed"`
		EnabledFrom *string `json:"enabled_from"`
		DisabledAt  *string `json:"disabled_at"`
		Version     *int64  `json:"version"`
	}
	// null clears a date, absent leaves it: decode the dates as raw JSON
	var raw map[string]json.RawMessage
	if err := decodeBody(r, &raw, false); err != nil {
		return 0, nil, err
	}
	up := attrs.AssignUpdate{}
	for k, v := range raw {
		switch k {
		case "disallowed":
			if err := json.Unmarshal(v, &in.Disallowed); err != nil {
				return 0, nil, badRequest("invalid_body", "disallowed is a boolean")
			}
		case "enabled_from", "disabled_at":
			var sp *string
			if err := json.Unmarshal(v, &sp); err != nil {
				return 0, nil, badRequest("invalid_"+k, k+" is an RFC 3339 time or null")
			}
			t, err := parseTimePtr(k, sp)
			if err != nil {
				return 0, nil, err
			}
			if k == "enabled_from" {
				up.EnabledFrom, up.ClearEnabledFrom = t, t == nil
			} else {
				up.DisabledAt, up.ClearDisabledAt = t, t == nil
			}
		case "version":
			if err := json.Unmarshal(v, &in.Version); err != nil {
				return 0, nil, badRequest("invalid_body", "version is an integer")
			}
		default:
			return 0, nil, badRequest("invalid_body", "unknown field "+strconv.Quote(k))
		}
	}
	up.Disallowed, up.Version = in.Disallowed, in.Version
	var out *attrs.Assigned
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = attrs.UpdateAssign(e.Attrs(), a.ID, up)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	v, err := newAssignViewer(tx, s.clock()).view(out.Assign, out.Values)
	return http.StatusOK, v, grpErr(err)
}

func (s *Server) deleteAttrAssign(r *http.Request, p *params) (int, any, error) {
	a, d, err := s.assignFor(r, p)
	if err != nil {
		return 0, nil, err
	}
	if err := attrs.RequireUnassign(s.grpChecker(r), store.TxFrom(r.Context()), d, attrs.OwnerOf(a)); err != nil {
		return 0, nil, grpErr(err)
	}
	var removed int
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		removed, err = attrs.Unassign(e.Attrs(), a.ID)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"id": a.ID, "removed": removed}, nil
}

func (s *Server) setAttrAssignValues(r *http.Request, p *params) (int, any, error) {
	a, d, err := s.assignFor(r, p)
	if err != nil {
		return 0, nil, err
	}
	tx := store.TxFrom(r.Context())
	if err := attrs.RequireChange(s.grpChecker(r), tx, d, attrs.OwnerOf(a)); err != nil {
		return 0, nil, grpErr(err)
	}
	var in struct {
		Values []json.RawMessage `json:"values"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out *attrs.Assigned
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = attrs.SetValues(e.Attrs(), a.ID, in.Values)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	v, err := newAssignViewer(tx, s.clock()).view(out.Assign, out.Values)
	return http.StatusOK, v, grpErr(err)
}

// ---------------------------------------------------------------- object types and services

func (s *Server) getObjectTypeVocabulary(r *http.Request, _ *params) (int, any, error) {
	d, n, err := attrs.Builtin(store.TxFrom(r.Context()))
	if err != nil {
		return 0, nil, grpErr(err)
	}
	return http.StatusOK, map[string]any{"group": attrs.ObjectTypeVocabulary(store.AttrOwnerGroup),
		"folder": attrs.ObjectTypeVocabulary(store.AttrOwnerFolder), "definition": attrs.ObjectTypesFullName,
		"created": d != nil && n != nil, "lint_rules": []string{attrs.RulePolicyDirectMembers, attrs.RuleBundleDirectMembers,
			attrs.RuleMissingDataOwner, attrs.RuleServiceNoPolicy}}, nil
}

type objectTypesBody struct {
	ObjectType string          `json:"object_type"`
	ObjectID   string          `json:"object_id"`
	Types      []string        `json:"types"`
	Vocabulary []string        `json:"vocabulary"`
	Lint       []attrs.Finding `json:"lint"`
}

func (s *Server) objectTypesOf(r *http.Request, o attrs.Owner, lint func() ([]attrs.Finding, error)) (objectTypesBody, error) {
	types, err := attrs.ObjectTypesOf(store.TxFrom(r.Context()), o)
	if err != nil {
		return objectTypesBody{}, grpErr(err)
	}
	if types == nil {
		types = []string{}
	}
	out := objectTypesBody{ObjectType: o.Type, ObjectID: o.ID, Types: types, Vocabulary: attrs.ObjectTypeVocabulary(o.Type), Lint: []attrs.Finding{}}
	if lint != nil {
		fs, err := lint()
		if err != nil {
			return out, grpErr(err)
		}
		if fs != nil {
			out.Lint = fs
		}
	}
	return out, nil
}

func (s *Server) getGroupObjectTypes(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	ck := s.grpChecker(r)
	g, err := s.grpGroupFor(r, ck, id, privs.View)
	if err != nil {
		return 0, nil, err
	}
	// the lint findings count members, so they need read
	canLint, err := ck.Has(privs.GroupObject(g.ID), privs.Read)
	if err != nil {
		return 0, nil, err
	}
	var lint func() ([]attrs.Finding, error)
	if canLint {
		lint = func() ([]attrs.Finding, error) { return attrs.LintGroup(store.TxFrom(r.Context()), g) }
	}
	out, err := s.objectTypesOf(r, attrs.Owner{Type: store.AttrOwnerGroup, ID: string(g.ID)}, lint)
	return http.StatusOK, out, err
}

func (s *Server) getFolderObjectTypes(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "folder")
	if err != nil {
		return 0, nil, err
	}
	f, err := s.grpFolderFor(r, s.grpChecker(r), id, privs.StemView)
	if err != nil {
		return 0, nil, err
	}
	out, err := s.objectTypesOf(r, attrs.Owner{Type: store.AttrOwnerFolder, ID: string(f.ID)},
		func() ([]attrs.Finding, error) { return attrs.LintFolder(store.TxFrom(r.Context()), f) })
	return http.StatusOK, out, err
}

// putObjectTypes replaces an owner's object types. The caller has been checked.
func (s *Server) putObjectTypes(r *http.Request, o attrs.Owner) (int, any, error) {
	var in struct {
		Types []string `json:"types"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.Types == nil {
		return 0, nil, badRequest("invalid_types", "types is a list (empty removes the object types)")
	}
	tx := store.TxFrom(r.Context())
	err := s.grpWrite(r, func(e model.Env) error {
		if len(in.Types) > 0 {
			if err := e.EnsureObjectTypes(); err != nil {
				return err
			}
		} else if d, n, err := attrs.Builtin(tx); err != nil || d == nil || n == nil {
			return err // nothing to remove
		}
		_, err := attrs.SetObjectTypes(e.Attrs(), o, in.Types)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	out, err := s.objectTypesOf(r, o, nil)
	return http.StatusOK, out, err
}

func (s *Server) putGroupObjectTypes(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	g, err := s.grpGroupFor(r, s.grpChecker(r), id, privs.GroupAttrUpdate)
	if err != nil {
		return 0, nil, err
	}
	return s.putObjectTypes(r, attrs.Owner{Type: store.AttrOwnerGroup, ID: string(g.ID)})
}

func (s *Server) putFolderObjectTypes(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "folder")
	if err != nil {
		return 0, nil, err
	}
	f, err := s.grpFolderFor(r, s.grpChecker(r), id, privs.StemAttrUpdate)
	if err != nil {
		return 0, nil, err
	}
	return s.putObjectTypes(r, attrs.Owner{Type: store.AttrOwnerFolder, ID: string(f.ID)})
}

type serviceView struct {
	Folder folderView         `json:"folder"`
	Groups []serviceGroupView `json:"groups"`
}

type serviceGroupView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

// listGrpServices is "Services I can use" (G-48): the service folders whose
// policy groups the caller's identity belongs to.
func (s *Server) listGrpServices(r *http.Request, _ *params) (int, any, error) {
	ck := s.grpChecker(r)
	items := []serviceView{}
	if id := ck.Subject().Identity; id != nil {
		svcs, err := attrs.ServicesFor(ck, store.TxFrom(r.Context()), s.cfg.GroupsEngine, s.clock(), *id)
		if err != nil {
			return 0, nil, grpErr(err)
		}
		for _, sv := range svcs {
			v := serviceView{Folder: viewFolder(sv.Folder), Groups: make([]serviceGroupView, len(sv.Groups))}
			for i, g := range sv.Groups {
				v.Groups[i] = serviceGroupView{ID: string(g.ID), Name: g.Name, DisplayName: g.DisplayName}
			}
			items = append(items, v)
		}
	}
	return http.StatusOK, map[string]any{"items": items}, nil
}
