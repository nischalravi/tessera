package api

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Flat-file import for disconnected applications (issue #105):
//
//	GET  /api/flatfile/apps                       the apps and their saved column mappings
//	PUT  /api/flatfile/apps/{system}/mapping      {name, owner, accounts{...}, entitlements{...}}: save a mapping
//	POST /api/flatfile/apps/{system}/uploads      the CSV as the body; ?kind=accounts|entitlements&filename=
//	GET  /api/flatfile/uploads[?system=]          upload history, newest first
//	GET  /api/flatfile/uploads/{upload_id}        one upload with its per-row errors and its delta
//	GET  /api/flatfile/tasks[?status=]            manual fulfilment tasks
//	POST /api/flatfile/tasks/{task_id}/close      {reason}: close a task by hand
//
// Saving a mapping needs flatfile.manage and a fresh phishing-resistant
// sign-in (it decides how a file becomes access in the graph); an upload needs
// flatfile.upload; closing a task by hand needs flatfile.close_tasks and the
// same sign-in. An upload with any invalid row is answered 422 with every bad
// row, and recorded in the history (nothing else changes).
//
// The upload takes the file as bytes and hands them to flatfile.Apply, which
// is all a later SFTP drop has to call; no SFTP server is built here.

func (s *Server) registerFlatfileRoutes() {
	const G, P, U = http.MethodGet, http.MethodPost, http.MethodPut
	s.handle(G, "/api/flatfile/apps", read, need(auth.PermGraphRead), s.rd(s.listFlatApps))
	s.handle(U, "/api/flatfile/apps/{system}/mapping", write, needStepUp(auth.PermFlatfileManage, auth.StepUpPolicy), s.rd(s.putFlatMapping))
	s.handle(P, "/api/flatfile/apps/{system}/uploads", write, Route{Perm: auth.PermFlatfileUpload, BodyType: flatBodyType}, s.uploadFlatFile)
	s.handle(G, "/api/flatfile/uploads", read, need(auth.PermGraphRead), s.rd(s.listFlatUploads))
	s.handle(G, "/api/flatfile/uploads/{upload_id}", read, need(auth.PermGraphRead), s.rd(s.getFlatUpload))
	s.handle(G, "/api/flatfile/tasks", read, need(auth.PermGraphRead), s.rd(s.listFlatTasks))
	s.handle(P, "/api/flatfile/tasks/{task_id}/close", write, needStepUp(auth.PermFlatfileCloseTasks, auth.StepUpPolicy), s.rd(s.closeFlatTask))
}

func flatSystem(p *params) (string, error) {
	sys := p.path["system"]
	if !flatfile.ValidSystem(sys) {
		return "", errStatus(http.StatusNotFound, "app not found")
	}
	return sys, nil
}

func (s *Server) listFlatApps(r *http.Request, _ *params) (int, any, error) {
	rows, err := store.TxFrom(r.Context()).FlatMappings()
	if err != nil {
		return 0, nil, err
	}
	apps := make([]flatfile.MappingView, 0, len(rows))
	for _, m := range rows {
		v, err := flatfile.ViewMapping(m)
		if err != nil {
			return 0, nil, err
		}
		apps = append(apps, v)
	}
	return http.StatusOK, map[string]any{"apps": apps}, nil
}

type flatMappingInput struct {
	Name         string                    `json:"name"`
	Owner        string                    `json:"owner"`
	Accounts     flatfile.AccountCols      `json:"accounts"`
	Entitlements *flatfile.EntitlementCols `json:"entitlements"`
}

func (s *Server) putFlatMapping(r *http.Request, p *params) (int, any, error) {
	sys, err := flatSystem(p)
	if err != nil {
		return 0, nil, err
	}
	var in flatMappingInput
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	m := &flatfile.Mapping{System: sys, Name: in.Name, Owner: in.Owner, Accounts: in.Accounts, Entitlements: in.Entitlements}
	var fe *flatfile.FieldError
	if err := m.Validate(); errors.As(err, &fe) {
		return 0, nil, badRequest("invalid_mapping", fe.Error())
	}
	c, now := store.TxFrom(r.Context()), s.clock()
	_, err = c.FlatMapping(sys)
	created := errors.Is(err, store.ErrNotFound)
	if err != nil && !created {
		return 0, nil, err
	}
	if created {
		// a new app may not take over a system another source already feeds
		if err := flatSystemFree(c, sys); err != nil {
			return 0, nil, err
		}
	}
	row, err := m.ToStore()
	if err != nil {
		return 0, nil, err
	}
	row.UpdatedBy, row.UpdatedAt = actor(r), now
	if err := c.PutFlatMapping(row); err != nil {
		return 0, nil, err
	}
	ents := ojson.Object{}
	if m.Entitlements != nil {
		ents = ojson.Object{{Key: "account_id", Value: m.Entitlements.AccountID}, {Key: "entitlement", Value: m.Entitlements.Entitlement},
			{Key: "name", Value: m.Entitlements.Name}, {Key: "privileged", Value: m.Entitlements.Privileged}}
	}
	a := m.Accounts
	if err := c.Audit(now, actor(r), "flatfile.mapping_saved", ojson.Object{{Key: "system", Value: sys}, {Key: "name", Value: row.Name},
		{Key: "owner", Value: row.Owner}, {Key: "created", Value: created},
		{Key: "accounts", Value: ojson.Object{{Key: "account_id", Value: a.AccountID}, {Key: "username", Value: a.Username},
			{Key: "email", Value: a.Email}, {Key: "identity_id", Value: a.IdentityID}, {Key: "status", Value: a.Status}}},
		{Key: "entitlements", Value: ents}}); err != nil {
		return 0, nil, err
	}
	saved, err := c.FlatMapping(sys)
	if err != nil {
		return 0, nil, err
	}
	v, err := flatfile.ViewMapping(saved)
	if err != nil {
		return 0, nil, err
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	return status, v, nil
}

// flatSystemFree refuses a system a connection or an existing source owns.
func flatSystemFree(c *store.TenantTx, system string) error {
	conns, err := c.Connections()
	if err != nil {
		return err
	}
	for _, x := range conns {
		if x.System == system {
			return errStatus(http.StatusConflict, "a connection already feeds the system "+system)
		}
	}
	n, err := c.CountSystem(system)
	if err != nil {
		return err
	}
	if n.Accounts+n.Groups+n.Resources+n.Permissions > 0 || system == "tessera" {
		return errStatus(http.StatusConflict, "the system "+system+" already has data from another source")
	}
	return nil
}

// flatBodyType is the media type of an upload. authorize lets this one
// through besides JSON for this route; the handler refuses JSON here, which
// is not a file.
const flatBodyType = "text/csv"

func (s *Server) uploadFlatFile(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	sys, err := flatSystem(p)
	if err != nil {
		return nil, err
	}
	kind := p.queryOptLiteral("kind", []string{flatfile.KindAccounts, flatfile.KindEntitlements})
	filename := ""
	if f := p.queryOptStr("filename"); f != nil {
		filename = *f
	}
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	if kind == nil {
		return nil, badRequest("invalid_kind", "kind is required: accounts or entitlements")
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != flatBodyType {
			return nil, errStatus(http.StatusUnsupportedMediaType, "send the file as "+flatBodyType)
		}
	}
	if utf8.RuneCountInString(filename) > 255 {
		return nil, badRequest("invalid_filename", "filename is at most 255 characters")
	}
	// one byte over the limit is enough to know the file is too large
	raw, err := io.ReadAll(io.LimitReader(r.Body, flatfile.MaxBytes+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errBodyTooLarge
		}
		return nil, errBodyUnreadable
	}
	res, err := flatfile.Apply(store.TxFrom(r.Context()), s.clock(), flatfile.Input{System: sys, Kind: *kind,
		Source: flatfile.SourceAPI, Filename: filename, Raw: raw, By: actor(r)})
	var fe *flatfile.Error
	switch {
	case errors.Is(err, flatfile.ErrNoMapping):
		return nil, errStatus(http.StatusNotFound, "app not found: save its column mapping first")
	case errors.As(err, &fe):
		return nil, badRequest(fe.Code, fe.Msg)
	case err != nil:
		return nil, err
	}
	tasks := make([]flatfile.TaskView, len(res.Confirmed))
	for i, t := range res.Confirmed {
		tasks[i] = flatfile.ViewTask(t)
	}
	errs := res.Errors
	truncated := len(errs) > flatfile.MaxStoredErrors
	if truncated {
		errs = errs[:flatfile.MaxStoredErrors]
	}
	body := flatfile.UploadDetail{UploadView: flatfile.ViewUpload(res.Upload), Errors: flatfile.ViewErrors(errs),
		ErrorsTruncated: truncated, Changes: flatfile.ViewChanges(res.Changes)}
	out := map[string]any{"upload": body, "confirmed_tasks": tasks}
	if res.Upload.Status == store.FlatUploadRejected {
		// 422, but the transaction commits: the rejected upload is history
		return statusBody{http.StatusUnprocessableEntity, out}, nil
	}
	return statusBody{http.StatusCreated, out}, nil
}

func (s *Server) listFlatUploads(r *http.Request, p *params) (int, any, error) {
	system := p.queryOptStr("system")
	if err := validated(p, nil); err != nil {
		return 0, nil, err
	}
	sys := ""
	if system != nil {
		if !flatfile.ValidSystem(*system) {
			return 0, nil, badRequest("invalid_system", "system is not a valid app name")
		}
		sys = *system
	}
	rows, err := store.TxFrom(r.Context()).FlatUploads(sys)
	if err != nil {
		return 0, nil, err
	}
	out := make([]flatfile.UploadView, len(rows))
	for i, u := range rows {
		out[i] = flatfile.ViewUpload(u)
	}
	return http.StatusOK, map[string]any{"uploads": out}, nil
}

func (s *Server) getFlatUpload(r *http.Request, p *params) (int, any, error) {
	id := p.path["upload_id"]
	if !idRE.MatchString(id) {
		return 0, nil, errStatus(http.StatusNotFound, "upload not found")
	}
	c := store.TxFrom(r.Context())
	u, err := c.FlatUpload(id)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil, errStatus(http.StatusNotFound, "upload not found")
	}
	if err != nil {
		return 0, nil, err
	}
	d, err := flatfile.ViewDetail(c, u)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, d, nil
}

func (s *Server) listFlatTasks(r *http.Request, p *params) (int, any, error) {
	status := p.queryOptLiteral("status", []string{store.FlatTaskOpen, store.FlatTaskConfirmed, store.FlatTaskClosed})
	if err := validated(p, nil); err != nil {
		return 0, nil, err
	}
	st := ""
	if status != nil {
		st = *status
	}
	rows, err := store.TxFrom(r.Context()).FlatTasks(st)
	if err != nil {
		return 0, nil, err
	}
	out := make([]flatfile.TaskView, len(rows))
	for i, t := range rows {
		out[i] = flatfile.ViewTask(t)
	}
	return http.StatusOK, map[string]any{"tasks": out}, nil
}

func (s *Server) closeFlatTask(r *http.Request, p *params) (int, any, error) {
	id := p.path["task_id"]
	if !idRE.MatchString(id) {
		return 0, nil, errStatus(http.StatusNotFound, "task not found")
	}
	var in struct {
		Reason string `json:"reason"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	reason := strings.TrimSpace(in.Reason)
	if n := utf8.RuneCountInString(reason); n < 10 || n > 500 {
		return 0, nil, badRequest("invalid_reason", "reason is required: 10 to 500 characters")
	}
	t, err := flatfile.CloseTask(store.TxFrom(r.Context()), s.clock(), actor(r), id, reason)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return 0, nil, errStatus(http.StatusNotFound, "task not found")
	case errors.Is(err, flatfile.ErrTaskNotOpen):
		return 0, nil, errStatus(http.StatusConflict, flatfile.ErrTaskNotOpen.Msg)
	case err != nil:
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"task": flatfile.ViewTask(t)}, nil
}
