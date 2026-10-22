package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Native groups, folder and group CRUD (issue #44, GR-1; design
// docs/design/groups-grouper-parity.md §10.11). A route needs groups.read or
// groups.write to be reached, and then the privilege its folder or group asks
// for (GR-4, issue #47; groups_privs.go): a refusal is 403 privilege_required.
//
//	list folders and groups   only those the caller may view (stem_view, view)
//	GET a folder              stem_view         GET a group       view
//	create a folder           create on the parent folder
//	create a group            create on the folder (and read on a composite's factors)
//	edit, delete a folder     stem_admin        edit, delete, restore a group   admin
//	move                      stem_admin / admin on the object, create on the destination
//	copy                      stem_admin / read on the source, create on the destination
//
//	GET    /api/groups/folders?parent=&scope=one|sub&q=&limit=&offset=
//	POST   /api/groups/folders                   {parent, extension, display_extension, description, data_owner}
//	GET|PATCH|DELETE /api/groups/folders/{id}    DELETE ?recursive=true deletes the whole tree (below)
//	GET    /api/groups/folders/{id}/delete-plan  what a recursive delete removes and what blocks it
//	POST   /api/groups/folders/{id}/move         {parent}
//	POST   /api/groups/folders/{id}/copy         {parent, extension}
//	GET    /api/groups/native?folder=&scope=&q=&type=&deleted=&limit=&offset=
//	POST   /api/groups                           {folder, extension, display_extension, description, type, ...}
//	GET|PATCH|DELETE /api/groups/{id}
//	POST   /api/groups/{id}/move                 {folder}
//	POST   /api/groups/{id}/copy                 {folder, extension}
//	POST   /api/groups/{id}/restore
//	POST   /api/groups/{id}/purge                permanently delete a group that is already deleted (admin)
//
// GET /api/groups already lists the connected-system groups, so the native
// list is GET /api/groups/native. Answers are 404 for an unknown id, 409
// {"error": code, "detail": msg} for a name or state conflict and 422 for an
// invalid name or field.
func (s *Server) registerGroupsFolderRoutes() {
	G, P, PA, D := http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete
	canRead, canWrite := need(auth.PermGroupsRead), need(auth.PermGroupsWrite)
	// literal paths first: /api/groups/{id} would also match "folders" and "native"
	s.handle(G, "/api/groups/folders", read, canRead, s.rd(s.listGrpFolders))
	s.handle(P, "/api/groups/folders", write, canWrite, s.rd(s.createGrpFolder))
	s.handle(G, "/api/groups/folders/{id}", read, canRead, s.rd(s.getGrpFolder))
	s.handle(PA, "/api/groups/folders/{id}", write, canWrite, s.rd(s.patchGrpFolder))
	// phased: a recursive delete may file a change request, which opens its own transaction
	s.handle(D, "/api/groups/folders/{id}", phased, canWrite, s.rd(s.deleteGrpFolder))
	s.handle(G, "/api/groups/folders/{id}/delete-plan", read, canRead, s.rd(s.getGrpFolderDeletePlan))
	s.handle(P, "/api/groups/folders/{id}/move", write, canWrite, s.rd(s.moveGrpFolder))
	s.handle(P, "/api/groups/folders/{id}/copy", write, canWrite, s.rd(s.copyGrpFolder))
	s.handle(G, "/api/groups/native", read, canRead, s.rd(s.listGrpGroups))
	s.handle(P, "/api/groups", write, canWrite, s.rd(s.createGrpGroup))
	s.handle(G, "/api/groups/{id}", read, canRead, s.rd(s.getGrpGroup))
	s.handle(PA, "/api/groups/{id}", write, canWrite, s.rd(s.patchGrpGroup))
	s.handle(D, "/api/groups/{id}", write, canWrite, s.rd(s.deleteGrpGroup))
	s.handle(P, "/api/groups/{id}/move", write, canWrite, s.rd(s.moveGrpGroup))
	s.handle(P, "/api/groups/{id}/copy", write, canWrite, s.rd(s.copyGrpGroup))
	s.handle(P, "/api/groups/{id}/restore", write, canWrite, s.rd(s.restoreGrpGroup))
	s.handle(P, "/api/groups/{id}/purge", write, canWrite, s.rd(s.purgeGrpGroup))
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
	ID               string  `json:"id"`
	FolderID         string  `json:"folder_id"`
	Extension        string  `json:"extension"`
	DisplayExtension string  `json:"display_extension"`
	Name             string  `json:"name"`
	DisplayName      string  `json:"display_name"`
	Description      string  `json:"description"`
	IDIndex          int64   `json:"id_index"`
	Type             string  `json:"type"`
	Definition       string  `json:"definition"`
	CompositeOp      *string `json:"composite_op"`
	// who deleted it, when and why, while it is deleted
	DeletedBy         *string   `json:"deleted_by,omitempty"`
	DeletedAt         *string   `json:"deleted_at,omitempty"`
	DeletedReason     *string   `json:"deleted_reason,omitempty"`
	DeletedWithFolder *string   `json:"deleted_with_folder,omitempty"`
	Factors           *[]string `json:"factors,omitempty"` // composites, on single-group answers
	ManagedBy         string    `json:"managed_by"`
	DataOwner         *string   `json:"data_owner"`
	MemberDescription *string   `json:"member_description"`
	Status            string    `json:"status"`
	EnabledFrom       *string   `json:"enabled_from"`
	DisabledAt        *string   `json:"disabled_at"`
	Requestable       bool      `json:"requestable"`
	EffectiveCount    int64     `json:"effective_count"`
	EffectiveVersion  int64     `json:"effective_version"`
	// RecomputeState is clean, pending (a queued recompute is running: the
	// members are stale) or failed.
	RecomputeState string  `json:"recompute_state"`
	CreatedAt      string  `json:"created_at"`
	CreatedBy      *string `json:"created_by"`
	Version        int64   `json:"version"`
}

func viewGroup(g *store.NativeGroup) groupView {
	v := groupView{ID: string(g.ID), FolderID: string(g.FolderID), Extension: g.Extension, DisplayExtension: g.DisplayExtension,
		Name: g.Name, DisplayName: g.DisplayName, Description: g.Description, IDIndex: g.IDIndex, Type: string(g.Kind),
		Definition: string(g.Definition), ManagedBy: string(g.ManagedBy), DataOwner: g.DataOwner,
		MemberDescription: g.MemberDescription, Status: g.Status, Requestable: g.Requestable,
		EffectiveCount: g.EffectiveCount, EffectiveVersion: g.EffectiveVersion, RecomputeState: g.RecomputeState,
		CreatedAt: store.RT(g.CreatedAt), CreatedBy: g.CreatedBy, Version: g.Version}
	if g.CompositeOp != nil {
		op := string(*g.CompositeOp)
		v.CompositeOp = &op
	}
	if g.Status == store.GroupDeleted && g.DeletedAt != nil {
		at, by, why, with := store.RT(*g.DeletedAt), g.DeletedBy, g.DeletedReason, g.DeletedWithFolder
		v.DeletedAt, v.DeletedBy = &at, &by
		if why != "" {
			v.DeletedReason = &why
		}
		if with != "" {
			v.DeletedWithFolder = &with
		}
	}
	if g.EnabledFrom != nil {
		s := store.RT(*g.EnabledFrom)
		v.EnabledFrom = &s
	}
	if g.DisabledAt != nil {
		s := store.RT(*g.DisabledAt)
		v.DisabledAt = &s
	}
	return v
}

// viewGroupFull is viewGroup plus a composite's factors.
func viewGroupFull(e model.Env, g *store.NativeGroup) (groupView, error) {
	v := viewGroup(g)
	if g.Definition != store.DefinitionBasic {
		fs, err := e.Factors(g.ID)
		if err != nil {
			return v, err
		}
		out := groupIDStrings(fs)
		v.Factors = &out
	}
	return v, nil
}

func groupIDStrings(ids []store.GroupID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
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
		return privErr(err)
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
	pr := principal(r)
	env := model.Env{Tx: c, Now: now, Engine: s.cfg.GroupsEngine, ByIdentity: pr.IdentityID,
		TenantAdmin: pr.ActiveRoles.Has(auth.RoleTenantAdmin), Guard: s.cfg.GroupsRules.Guard()}
	if pr.UserID != nil {
		u := pr.UserID.String()
		env.By = &u
	}
	if r.Method != http.MethodGet {
		env.ByDisplay = s.actorLabel(r, c)
	}
	return env
}

// actorLabel is the acting person as it is kept with what they delete: the name of the identity their user is
// linked to (else the user's own name), and "(tenant admin)" for that role.
func (s *Server) actorLabel(r *http.Request, c *store.TenantTx) string {
	pr := principal(r)
	name := pr.Display
	if pr.IdentityID != nil {
		if i, err := c.Identity(*pr.IdentityID); err == nil && i.Name != "" {
			name = i.Name
		}
	}
	if name == "" {
		name = "a user"
	}
	if pr.ActiveRoles.Has(auth.RoleTenantAdmin) {
		name += " (tenant admin)"
	}
	return name
}

const maxReason = 500

// deleteReason is the optional body of a delete: why. required says the route refuses without one.
func deleteReason(r *http.Request, required bool) (string, error) {
	var in struct {
		Reason string `json:"reason"`
	}
	if err := decodeBody(r, &in, true); err != nil {
		return "", err
	}
	in.Reason = strings.TrimSpace(in.Reason)
	switch {
	case len(in.Reason) > maxReason:
		return "", badRequest("invalid_reason", "reason is at most 500 characters")
	case required && in.Reason == "":
		return "", badRequest("reason_required", "say why in reason")
	}
	return in.Reason, nil
}

// grpWrite runs fn in the request's write transaction with a model.Env.
func (s *Server) grpWrite(r *http.Request, fn func(e model.Env) error) error {
	return grpErr(s.write(r, func(c *store.TenantTx, now time.Time) error { return fn(s.grpEnv(r, c, now)) }))
}

// grpRead builds a read-only model.Env.
func (s *Server) grpRead(r *http.Request) model.Env {
	return model.Env{Tx: store.TxFrom(r.Context()), Now: s.clock(), Engine: s.cfg.GroupsEngine}
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
	e := s.grpRead(r)
	// browse and search show only what the caller may view (stem_view)
	fs, err := visible(s.grpChecker(r), privs.Folder, limit, offset, func(l, o int) ([]*store.Folder, error) {
		return e.ListFolders(model.FolderQuery{Parent: store.FolderID(parent), Scope: scope, Q: q, Limit: l, Offset: o})
	}, func(f *store.Folder) privs.Object { return privs.FolderObject(f.ID) }, privs.StemView)
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
	f, err := s.grpFolderFor(r, s.grpChecker(r), id, privs.StemView)
	if err != nil {
		return 0, nil, err
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
	if _, err := s.grpFolderOrRoot(r, s.grpChecker(r), in.Parent, privs.Create); err != nil {
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
	if _, err := s.grpFolderFor(r, s.grpChecker(r), id, privs.StemAdmin); err != nil {
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

func (s *Server) moveGrpFolder(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "folder")
	if err != nil {
		return 0, nil, err
	}
	ck := s.grpChecker(r)
	if _, err := s.grpFolderFor(r, ck, id, privs.StemAdmin); err != nil {
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
	if _, err := s.grpFolderFor(r, ck, in.Parent, privs.Create); err != nil { // the destination
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
	ck := s.grpChecker(r)
	// a copy takes the groups below the folder with it, so it needs stem_admin on the source
	if _, err := s.grpFolderFor(r, ck, id, privs.StemAdmin); err != nil {
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
	if _, err := s.grpFolderFor(r, ck, in.Parent, privs.Create); err != nil {
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
	e := s.grpRead(r)
	// browse and search show only what the caller may view (GRP-7387)
	gs, err := visible(s.grpChecker(r), privs.Group, limit, offset, func(l, o int) ([]*store.NativeGroup, error) {
		return e.ListGroups(model.GroupQuery{Folder: store.FolderID(folder), Scope: scope, Q: q,
			Kind: store.GroupKind(typ), IncludeDeleted: deleted == "true", Limit: l, Offset: o})
	}, func(g *store.NativeGroup) privs.Object { return privs.GroupObject(g.ID) }, privs.View)
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
	g, err := s.grpGroupFor(r, s.grpChecker(r), id, privs.View)
	if err != nil {
		return 0, nil, err
	}
	v, err := viewGroupFull(s.grpRead(r), g)
	return http.StatusOK, v, err
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
		// a composite group: definition "composite" with an operator and its factors
		Definition  string   `json:"definition"`
		CompositeOp string   `json:"composite_op"`
		Factors     []string `json:"factors"`
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
	factors, err := grpFactorIDs(in.Factors)
	if err != nil {
		return 0, nil, err
	}
	ck := s.grpChecker(r)
	if _, err := s.grpFolderFor(r, ck, in.Folder, privs.Create); err != nil {
		return 0, nil, err
	}
	if err := s.requireReadOn(r, ck, factors); err != nil {
		return 0, nil, err
	}
	var out groupView
	err = s.grpWrite(r, func(e model.Env) error {
		g, err := e.CreateGroup(model.CreateGroupInput{Folder: store.FolderID(in.Folder), Extension: in.Extension,
			DisplayExtension: in.DisplayExtension, Description: in.Description, Kind: store.GroupKind(in.Type),
			DataOwner: in.DataOwner, MemberDescription: in.MemberDescription, Requestable: in.Requestable,
			Definition: store.Definition(in.Definition), Op: store.CompositeOp(in.CompositeOp), Factors: factors})
		if err != nil {
			return err
		}
		out, err = viewGroupFull(e, g)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, out, nil
}

// grpFactorIDs validates the factor ids of a composite body.
func grpFactorIDs(in []string) ([]store.GroupID, error) {
	out := make([]store.GroupID, len(in))
	for i, f := range in {
		if !idRE.MatchString(f) {
			return nil, badRequest("invalid_factors", "factors must be group ids (UUIDs)")
		}
		out[i] = store.GroupID(f)
	}
	return out, nil
}

// grpTime parses an optional RFC 3339 field; clear is true for "" (remove the date).
func grpTime(field string, v *string) (t *time.Time, clear bool, err error) {
	if v == nil {
		return nil, false, nil
	}
	if *v == "" {
		return nil, true, nil
	}
	p, perr := time.Parse(time.RFC3339, *v)
	if perr != nil {
		return nil, false, badRequest("invalid_"+field, field+" must be an RFC 3339 time, or empty to clear it")
	}
	p = p.UTC()
	return &p, false, nil
}

func (s *Server) patchGrpGroup(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	if _, err := s.grpGroupFor(r, s.grpChecker(r), id, privs.Admin); err != nil {
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
		EnabledFrom       *string `json:"enabled_from"` // RFC 3339; "" removes it
		DisabledAt        *string `json:"disabled_at"`
		Version           *int64  `json:"version"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	from, clearFrom, err := grpTime("enabled_from", in.EnabledFrom)
	if err != nil {
		return 0, nil, err
	}
	to, clearTo, err := grpTime("disabled_at", in.DisabledAt)
	if err != nil {
		return 0, nil, err
	}
	var out groupView
	err = s.grpWrite(r, func(e model.Env) error {
		g, err := e.UpdateGroup(store.GroupID(id), model.UpdateGroupInput{Extension: in.Extension,
			DisplayExtension: in.DisplayExtension, Description: in.Description, DataOwner: in.DataOwner,
			MemberDescription: in.MemberDescription, Requestable: in.Requestable, Status: in.Status,
			EnabledFrom: from, DisabledAt: to, ClearEnabledFrom: clearFrom, ClearDisabledAt: clearTo, Version: in.Version})
		if err != nil {
			return err
		}
		out, err = viewGroupFull(e, g)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

func (s *Server) deleteGrpGroup(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	if _, err := s.grpGroupFor(r, s.grpChecker(r), id, privs.Admin); err != nil {
		return 0, nil, err
	}
	reason, err := deleteReason(r, false)
	if err != nil {
		return 0, nil, err
	}
	if err := s.grpWrite(r, func(e model.Env) error { e.Reason = reason; return e.DeleteGroup(store.GroupID(id)) }); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"id": id, "deleted": true}, nil
}

func (s *Server) purgeGrpGroup(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	if _, err := s.grpGroupFor(r, s.grpChecker(r), id, privs.Admin); err != nil {
		return 0, nil, err
	}
	reason, err := deleteReason(r, true)
	if err != nil {
		return 0, nil, err
	}
	if err := s.grpWrite(r, func(e model.Env) error { e.Reason = reason; return e.PurgeGroup(store.GroupID(id)) }); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"id": id, "purged": true}, nil
}

func (s *Server) restoreGrpGroup(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	if _, err := s.grpGroupFor(r, s.grpChecker(r), id, privs.Admin); err != nil {
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
	ck := s.grpChecker(r)
	if _, err := s.grpGroupFor(r, ck, id, privs.Admin); err != nil {
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
	if _, err := s.grpFolderFor(r, ck, in.Folder, privs.Create); err != nil { // the destination
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
	ck := s.grpChecker(r)
	if _, err := s.grpGroupFor(r, ck, id, privs.Read); err != nil {
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
	if _, err := s.grpFolderFor(r, ck, in.Folder, privs.Create); err != nil {
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
