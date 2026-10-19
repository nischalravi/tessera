package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Native groups, folder and group CRUD (issue #44, GR-1; design
// docs/design/groups-grouper-parity.md §10.11). Every route needs groups.admin,
// which only tenant_admin holds until GR-4 adds the per-object privileges.
//
//	GET    /api/groups/folders?parent=&scope=one|sub&q=&limit=&offset=
//	POST   /api/groups/folders                   {parent, extension, display_extension, description, data_owner}
//	GET|PATCH|DELETE /api/groups/folders/{id}
//	POST   /api/groups/folders/{id}/move         {parent}
//	POST   /api/groups/folders/{id}/copy         {parent, extension}
//	GET    /api/groups/native?folder=&scope=&q=&type=&deleted=&limit=&offset=
//	POST   /api/groups                           {folder, extension, display_extension, description, type, ...}
//	GET|PATCH|DELETE /api/groups/{id}
//	POST   /api/groups/{id}/move                 {folder}
//	POST   /api/groups/{id}/copy                 {folder, extension}
//	POST   /api/groups/{id}/restore
//
// GET /api/groups already lists the connected-system groups, so the native
// list is GET /api/groups/native. Answers are 404 for an unknown id, 409
// {"error": code, "detail": msg} for a name or state conflict and 422 for an
// invalid name or field.
func (s *Server) registerGroupsFolderRoutes() {
	G, P, PA, D := http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete
	perm := need(auth.PermGroupsAdmin)
	// literal paths first: /api/groups/{id} would also match "folders" and "native"
	s.handle(G, "/api/groups/folders", read, perm, s.rd(s.listGrpFolders))
	s.handle(P, "/api/groups/folders", write, perm, s.rd(s.createGrpFolder))
	s.handle(G, "/api/groups/folders/{id}", read, perm, s.rd(s.getGrpFolder))
	s.handle(PA, "/api/groups/folders/{id}", write, perm, s.rd(s.patchGrpFolder))
	s.handle(D, "/api/groups/folders/{id}", write, perm, s.rd(s.deleteGrpFolder))
	s.handle(P, "/api/groups/folders/{id}/move", write, perm, s.rd(s.moveGrpFolder))
	s.handle(P, "/api/groups/folders/{id}/copy", write, perm, s.rd(s.copyGrpFolder))
	s.handle(G, "/api/groups/native", read, perm, s.rd(s.listGrpGroups))
	s.handle(P, "/api/groups", write, perm, s.rd(s.createGrpGroup))
	s.handle(G, "/api/groups/{id}", read, perm, s.rd(s.getGrpGroup))
	s.handle(PA, "/api/groups/{id}", write, perm, s.rd(s.patchGrpGroup))
	s.handle(D, "/api/groups/{id}", write, perm, s.rd(s.deleteGrpGroup))
	s.handle(P, "/api/groups/{id}/move", write, perm, s.rd(s.moveGrpGroup))
	s.handle(P, "/api/groups/{id}/copy", write, perm, s.rd(s.copyGrpGroup))
	s.handle(P, "/api/groups/{id}/restore", write, perm, s.rd(s.restoreGrpGroup))
}

// ---------------------------------------------------------------- views

type folderView struct {
	ID               string  `json:"id"`
	ParentID         *string `json:"parent_id"`
	Extension        string  `json:"extension"`
	DisplayExtension string  `json:"display_extension"`
	Name             string  `json:"name"`
	DisplayName      string  `json:"display_name"`
	Description      string  `json:"description"`
	IDIndex          int64   `json:"id_index"`
	DataOwner        *string `json:"data_owner"`
	ManagedBy        string  `json:"managed_by"`
	CreatedAt        string  `json:"created_at"`
	CreatedBy        *string `json:"created_by"`
	Version          int64   `json:"version"`
}

func viewFolder(f *store.Folder) folderView {
	var parent *string
	if f.ParentID != nil {
		p := string(*f.ParentID)
		parent = &p
	}
	return folderView{ID: string(f.ID), ParentID: parent, Extension: f.Extension, DisplayExtension: f.DisplayExtension,
		Name: f.Name, DisplayName: f.DisplayName, Description: f.Description, IDIndex: f.IDIndex, DataOwner: f.DataOwner,
		ManagedBy: string(f.ManagedBy), CreatedAt: store.RT(f.CreatedAt), CreatedBy: f.CreatedBy, Version: f.Version}
}

type groupView struct {
	ID                string  `json:"id"`
	FolderID          string  `json:"folder_id"`
	Extension         string  `json:"extension"`
	DisplayExtension  string  `json:"display_extension"`
	Name              string  `json:"name"`
	DisplayName       string  `json:"display_name"`
	Description       string  `json:"description"`
	IDIndex           int64   `json:"id_index"`
	Type              string  `json:"type"`
	Definition        string  `json:"definition"`
	ManagedBy         string  `json:"managed_by"`
	DataOwner         *string `json:"data_owner"`
	MemberDescription *string `json:"member_description"`
	Status            string  `json:"status"`
	Requestable       bool    `json:"requestable"`
	CreatedAt         string  `json:"created_at"`
	CreatedBy         *string `json:"created_by"`
	Version           int64   `json:"version"`
}

func viewGroup(g *store.NativeGroup) groupView {
	return groupView{ID: string(g.ID), FolderID: string(g.FolderID), Extension: g.Extension, DisplayExtension: g.DisplayExtension,
		Name: g.Name, DisplayName: g.DisplayName, Description: g.Description, IDIndex: g.IDIndex, Type: string(g.Kind),
		Definition: string(g.Definition), ManagedBy: string(g.ManagedBy), DataOwner: g.DataOwner,
		MemberDescription: g.MemberDescription, Status: g.Status, Requestable: g.Requestable,
		CreatedAt: store.RT(g.CreatedAt), CreatedBy: g.CreatedBy, Version: g.Version}
}

type listBody struct {
	Items  any `json:"items"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// ---------------------------------------------------------------- helpers

// grpErr maps the model's refusals to the readiness-style JSON errors.
func grpErr(err error) error {
	var me *model.Error
	if !errors.As(err, &me) {
		return err
	}
	status := map[model.Kind]int{model.NotFound: http.StatusNotFound, model.Conflict: http.StatusConflict,
		model.Invalid: http.StatusUnprocessableEntity}[me.Kind]
	return &readiness.Error{Status: status, Code: me.Code, Msg: me.Msg, Extra: me.Extra}
}

func grpNotFound(what string) error {
	return &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such " + what}
}

// grpPathID validates the {id} path segment as a UUID.
func grpPathID(p *params, what string) (string, error) {
	id := p.path["id"]
	if !idRE.MatchString(id) {
		return "", grpNotFound(what)
	}
	return id, nil
}

// grpBodyID validates a UUID in a body or query field ("" stays "").
func grpBodyID(field, v string) error {
	if v != "" && !idRE.MatchString(v) {
		return badRequest("invalid_"+field, field+" must be a UUID")
	}
	return nil
}

func (s *Server) grpEnv(r *http.Request, c *store.TenantTx, now time.Time) model.Env {
	env := model.Env{Tx: c, Now: now}
	if pr := principal(r); pr.UserID != nil {
		u := pr.UserID.String()
		env.By = &u
	}
	return env
}

// grpWrite runs fn in the request's write transaction with a model.Env.
func (s *Server) grpWrite(r *http.Request, fn func(e model.Env) error) error {
	return grpErr(s.write(r, func(c *store.TenantTx, now time.Time) error { return fn(s.grpEnv(r, c, now)) }))
}

// grpRead builds a read-only model.Env.
func (s *Server) grpRead(r *http.Request) model.Env {
	return model.Env{Tx: store.TxFrom(r.Context()), Now: s.clock()}
}

// pageParams reads limit (1..500, default 100) and offset (>= 0).
func pageParams(p *params) (limit, offset int, err error) {
	limit = 100
	for name, dst := range map[string]*int{"limit": &limit, "offset": &offset} {
		raw, ok := p.query(name)
		if !ok {
			continue
		}
		n, e := strconv.Atoi(raw)
		if e != nil || n < 0 || (name == "limit" && (n < 1 || n > 500)) {
			return 0, 0, badRequest("invalid_"+name, name+" is out of range (limit 1 to 500, offset 0 or more)")
		}
		*dst = n
	}
	return limit, offset, nil
}

func queryStr(p *params, name string, max int) (string, error) {
	v, _ := p.query(name)
	if len(v) > max {
		return "", badRequest("invalid_"+name, name+" is too long")
	}
	return v, nil
}

// ---------------------------------------------------------------- folders

func (s *Server) listGrpFolders(r *http.Request, p *params) (int, any, error) {
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	parent, _ := p.query("parent")
	q, err := queryStr(p, "q", 255)
	if err != nil {
		return 0, nil, err
	}
	if err := grpBodyID("parent", parent); err != nil {
		return 0, nil, err
	}
	scope, _ := p.query("scope")
	fs, err := s.grpRead(r).ListFolders(model.FolderQuery{Parent: store.FolderID(parent), Scope: scope, Q: q, Limit: limit, Offset: offset})
	if err != nil {
		return 0, nil, grpErr(err)
	}
	items := make([]folderView, len(fs))
	for i, f := range fs {
		items[i] = viewFolder(f)
	}
	return http.StatusOK, listBody{items, limit, offset}, nil
}

func (s *Server) getGrpFolder(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "folder")
	if err != nil {
		return 0, nil, err
	}
	f, err := s.grpRead(r).Folder(store.FolderID(id))
	if err != nil {
		return 0, nil, grpErr(err)
	}
	return http.StatusOK, viewFolder(f), nil
}

func (s *Server) createGrpFolder(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		Parent           string `json:"parent"`
		Extension        string `json:"extension"`
		DisplayExtension string `json:"display_extension"`
		Description      string `json:"description"`
		DataOwner        string `json:"data_owner"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if err := grpBodyID("parent", in.Parent); err != nil {
		return 0, nil, err
	}
	var out *store.Folder
	err := s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = e.CreateFolder(model.CreateFolderInput{Parent: store.FolderID(in.Parent), Extension: in.Extension,
			DisplayExtension: in.DisplayExtension, Description: in.Description, DataOwner: in.DataOwner})
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, viewFolder(out), nil
}

func (s *Server) patchGrpFolder(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "folder")
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Extension        *string `json:"extension"`
		DisplayExtension *string `json:"display_extension"`
		Description      *string `json:"description"`
		DataOwner        *string `json:"data_owner"`
		Version          *int64  `json:"version"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out *store.Folder
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = e.UpdateFolder(store.FolderID(id), model.UpdateFolderInput{Extension: in.Extension,
			DisplayExtension: in.DisplayExtension, Description: in.Description, DataOwner: in.DataOwner, Version: in.Version})
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, viewFolder(out), nil
}

func (s *Server) deleteGrpFolder(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "folder")
	if err != nil {
		return 0, nil, err
	}
	if err := s.grpWrite(r, func(e model.Env) error { return e.DeleteFolder(store.FolderID(id)) }); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"id": id, "deleted": true}, nil
}

func (s *Server) moveGrpFolder(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "folder")
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Parent string `json:"parent"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.Parent == "" {
		return 0, nil, badRequest("invalid_parent", "parent is required")
	}
	if err := grpBodyID("parent", in.Parent); err != nil {
		return 0, nil, err
	}
	var out *store.Folder
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = e.MoveFolder(store.FolderID(id), store.FolderID(in.Parent))
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, viewFolder(out), nil
}

func (s *Server) copyGrpFolder(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "folder")
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Parent    string `json:"parent"`
		Extension string `json:"extension"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.Parent == "" {
		return 0, nil, badRequest("invalid_parent", "parent is required")
	}
	if err := grpBodyID("parent", in.Parent); err != nil {
		return 0, nil, err
	}
	var out *store.Folder
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = e.CopyFolder(store.FolderID(id), model.CopyInput{Parent: store.FolderID(in.Parent), Extension: in.Extension})
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, viewFolder(out), nil
}

// ---------------------------------------------------------------- groups

func (s *Server) listGrpGroups(r *http.Request, p *params) (int, any, error) {
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
	scope, _ := p.query("scope")
	typ, _ := p.query("type")
	deleted, _ := p.query("deleted")
	if deleted != "" && deleted != "true" && deleted != "false" {
		return 0, nil, badRequest("invalid_deleted", "deleted is true or false")
	}
	gs, err := s.grpRead(r).ListGroups(model.GroupQuery{Folder: store.FolderID(folder), Scope: scope, Q: q,
		Kind: store.GroupKind(typ), IncludeDeleted: deleted == "true", Limit: limit, Offset: offset})
	if err != nil {
		return 0, nil, grpErr(err)
	}
	items := make([]groupView, len(gs))
	for i, g := range gs {
		items[i] = viewGroup(g)
	}
	return http.StatusOK, listBody{items, limit, offset}, nil
}

func (s *Server) getGrpGroup(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	g, err := s.grpRead(r).Group(store.GroupID(id))
	if err != nil {
		return 0, nil, grpErr(err)
	}
	return http.StatusOK, viewGroup(g), nil
}

func (s *Server) createGrpGroup(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		Folder            string `json:"folder"`
		Extension         string `json:"extension"`
		DisplayExtension  string `json:"display_extension"`
		Description       string `json:"description"`
		Type              string `json:"type"`
		DataOwner         string `json:"data_owner"`
		MemberDescription string `json:"member_description"`
		Requestable       bool   `json:"requestable"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.Folder == "" {
		return 0, nil, badRequest("invalid_folder", "folder is required")
	}
	if err := grpBodyID("folder", in.Folder); err != nil {
		return 0, nil, err
	}
	var out *store.NativeGroup
	err := s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = e.CreateGroup(model.CreateGroupInput{Folder: store.FolderID(in.Folder), Extension: in.Extension,
			DisplayExtension: in.DisplayExtension, Description: in.Description, Kind: store.GroupKind(in.Type),
			DataOwner: in.DataOwner, MemberDescription: in.MemberDescription, Requestable: in.Requestable})
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, viewGroup(out), nil
}

func (s *Server) patchGrpGroup(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Extension         *string `json:"extension"`
		DisplayExtension  *string `json:"display_extension"`
		Description       *string `json:"description"`
		DataOwner         *string `json:"data_owner"`
		MemberDescription *string `json:"member_description"`
		Requestable       *bool   `json:"requestable"`
		Status            *string `json:"status"`
		Version           *int64  `json:"version"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out *store.NativeGroup
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = e.UpdateGroup(store.GroupID(id), model.UpdateGroupInput{Extension: in.Extension,
			DisplayExtension: in.DisplayExtension, Description: in.Description, DataOwner: in.DataOwner,
			MemberDescription: in.MemberDescription, Requestable: in.Requestable, Status: in.Status, Version: in.Version})
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, viewGroup(out), nil
}

func (s *Server) deleteGrpGroup(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	if err := s.grpWrite(r, func(e model.Env) error { return e.DeleteGroup(store.GroupID(id)) }); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"id": id, "deleted": true}, nil
}

func (s *Server) restoreGrpGroup(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	var out *store.NativeGroup
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = e.RestoreGroup(store.GroupID(id))
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, viewGroup(out), nil
}

func (s *Server) moveGrpGroup(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Folder string `json:"folder"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.Folder == "" {
		return 0, nil, badRequest("invalid_folder", "folder is required")
	}
	if err := grpBodyID("folder", in.Folder); err != nil {
		return 0, nil, err
	}
	var out *store.NativeGroup
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = e.MoveGroup(store.GroupID(id), store.FolderID(in.Folder))
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, viewGroup(out), nil
}

func (s *Server) copyGrpGroup(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Folder    string `json:"folder"`
		Extension string `json:"extension"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.Folder == "" {
		return 0, nil, badRequest("invalid_folder", "folder is required")
	}
	if err := grpBodyID("folder", in.Folder); err != nil {
		return 0, nil, err
	}
	var out *store.NativeGroup
	err = s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = e.CopyGroup(store.GroupID(id), model.CopyInput{Parent: store.FolderID(in.Folder), Extension: in.Extension})
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, viewGroup(out), nil
}
