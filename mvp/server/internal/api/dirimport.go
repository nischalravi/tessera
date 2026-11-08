package api

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Directory CSV import and the create and edit forms of manual-source objects (issue #915):
//
//	GET  /api/directory/imports/sources      the manual sources and the columns their files carry
//	POST /api/directory/imports/plan         the CSV as the body; ?target=people|accounts|entitlements&system=&name=&filename=
//	                                         a dry run: adds, changes, removals, every bad row, the deletion guard's view
//	POST /api/directory/imports/apply        the same file, applied (directory.import and a fresh sign-in)
//	PUT  /api/directory/manual/records       {target, system, name, fields}: create or edit one object of a manual source
//	GET  /api/directory/manual/lookup        ?target=&id=: who owns an object, and its fields when a manual source does
//
// A file is loaded into a manual source, a system the admin names, never into one a connector owns. It goes
// through the ingest path connectors use (identity and account correlation, authoritative attributes, the
// deletion guard), and removals reach only rows the same source imported before. A plan is read-only and
// needs the permission; applying one also needs step-up, and records the domain event "directory.import"
// in the same transaction. A file with an invalid row is answered 422 with every bad row and changes nothing.

func (s *Server) registerDirectoryImportRoutes() {
	const G, P, U = http.MethodGet, http.MethodPost, http.MethodPut
	s.handle(G, "/api/directory/imports/sources", read, need(auth.PermGraphRead), s.rd(s.listManualSources))
	s.handle(P, "/api/directory/imports/plan", write, Route{Perm: auth.PermDirectoryImport, BodyType: flatBodyType}, s.planDirImport).answersRead = true
	s.handle(P, "/api/directory/imports/apply", write, Route{Perm: auth.PermDirectoryImport, BodyType: flatBodyType,
		Authn: stepUpPolicy()}, s.applyDirImport)
	s.handle(U, "/api/directory/manual/records", write, needStepUp(auth.PermDirectoryImport, auth.StepUpPolicy), s.rd(s.putManualRecord))
	s.handle(G, "/api/directory/manual/lookup", read, need(auth.PermGraphRead), s.rd(s.manualLookup))
}

func stepUpPolicy() *auth.AuthnRequirement {
	r := auth.StepUpPolicy
	return &r
}

// dirImportPaths are the routes that take a file of up to flatfile.DirectoryLimits.MaxBytes.
var dirImportPaths = map[string]bool{"/api/directory/imports/plan": true, "/api/directory/imports/apply": true}

// dirImportBodyCap is the request cap of those routes: the file limit and room for the headers of a
// chunked body, so a file one byte over is answered file_too_large and not cut off.
const dirImportBodyCap = 5<<20 + 64<<10

type manualSourceView struct {
	System         string   `json:"system"`
	Name           string   `json:"name"`
	People         int      `json:"people"`
	Accounts       int      `json:"accounts"`
	Entitlements   int      `json:"entitlements"`
	AccountColumns []string `json:"account_columns"`
}

func (s *Server) listManualSources(r *http.Request, _ *params) (int, any, error) {
	rows, err := flatfile.ManualSources(store.TxFrom(r.Context()))
	if err != nil {
		return 0, nil, err
	}
	out := make([]manualSourceView, len(rows))
	for i, m := range rows {
		out[i] = manualSourceView{System: m.System, Name: m.Name, People: m.People, Accounts: m.Accounts, Entitlements: m.Entitle,
			AccountColumns: m.AccountColumns}
	}
	return http.StatusOK, map[string]any{"sources": out, "limits": map[string]int{
		"max_bytes": flatfile.DirectoryLimits.MaxBytes, "max_rows": flatfile.DirectoryLimits.MaxRows},
		"columns": map[string]any{
			flatfile.TargetPeople:       map[string]any{"all": flatfile.PeopleColumns, "required": flatfile.PeopleRequired},
			flatfile.TargetAccounts:     map[string]any{"all": flatfile.AccountColumns, "required": flatfile.AccountRequired},
			flatfile.TargetEntitlements: map[string]any{"all": flatfile.EntitlementColumns, "required": flatfile.EntitlementRequired},
		}}, nil
}

// importTarget and importSource read the query of a plan or an apply.
func importQuery(p *params) (*string, *string, string, string) {
	target := p.queryOptLiteral("target", []string{flatfile.TargetPeople, flatfile.TargetAccounts, flatfile.TargetEntitlements})
	system := p.queryOptStr("system")
	name, filename := "", ""
	if n := p.queryOptStr("name"); n != nil {
		name = strings.TrimSpace(*n)
	}
	if f := p.queryOptStr("filename"); f != nil {
		filename = *f
	}
	return target, system, name, filename
}

// reservedSystems are the systems the configured (legacy) connectors write to without a connection row: an
// import may not name one, even before the connector's first sync has put data there.
func (s *Server) reservedSystems() (map[string]bool, error) {
	conns, err := s.cfg.Connectors(s.clock())
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(conns))
	for _, c := range conns {
		out[c.System()] = true
	}
	return out, nil
}

func (s *Server) readImport(r *http.Request, p *params) (flatfile.ImportInput, error) {
	var in flatfile.ImportInput
	target, system, name, filename := importQuery(p)
	if err := validated(p, nil); err != nil {
		return in, err
	}
	if target == nil {
		return in, badRequest("invalid_target", "target is required: people, accounts or entitlements")
	}
	if system == nil || !flatfile.ValidSystem(*system) {
		return in, badRequest("invalid_system", "system is required: the manual source, 1 to 63 lower-case letters, digits, '.', '_' or '-'")
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != flatBodyType {
			return in, errStatus(http.StatusUnsupportedMediaType, "send the file as "+flatBodyType)
		}
	}
	if utf8.RuneCountInString(filename) > 255 || utf8.RuneCountInString(name) > 100 {
		return in, badRequest("invalid_filename", "filename is at most 255 characters and name at most 100")
	}
	// one byte over the limit is enough to know the file is too large
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(flatfile.DirectoryLimits.MaxBytes)+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return in, errBodyTooLarge
		}
		return in, errBodyUnreadable
	}
	reserved, err := s.reservedSystems()
	if err != nil {
		return in, err
	}
	return flatfile.ImportInput{System: *system, Name: name, Target: *target, Filename: filename, Raw: raw, By: actor(r), ByUser: userID(r), Reserved: reserved}, nil
}

const (
	maxPlanErrors  = 200
	maxPlanChanges = 500
)

type planView struct {
	System           string                 `json:"system"`
	Target           string                 `json:"target"`
	Rows             int                    `json:"rows"`
	Added            int                    `json:"added"`
	Changed          int                    `json:"changed"`
	Removed          int                    `json:"removed"`
	Unchanged        int                    `json:"unchanged"`
	Errors           []flatfile.RowError    `json:"errors"`
	ErrorCount       int                    `json:"error_count"`
	ErrorsTruncated  bool                   `json:"errors_truncated"`
	Changes          []flatfile.Change      `json:"changes"`
	ChangesTruncated bool                   `json:"changes_truncated"`
	Guard            *flatfile.GuardPreview `json:"guard"`
	Claims           []flatfile.Claim       `json:"claims"`
}

func viewPlan(pl *flatfile.Plan) planView {
	errs, chs := pl.Errors, pl.Changes
	v := planView{System: pl.System, Target: pl.Kind, Rows: pl.RowsTotal, Added: pl.Added, Changed: pl.Changed, Removed: pl.Removed,
		Unchanged: pl.Unchanged, ErrorCount: len(errs), Guard: pl.Guard, Claims: pl.Claims}
	if v.Claims == nil {
		v.Claims = []flatfile.Claim{}
	}
	if v.ErrorsTruncated = len(errs) > maxPlanErrors; v.ErrorsTruncated {
		errs = errs[:maxPlanErrors]
	}
	if v.ChangesTruncated = len(chs) > maxPlanChanges; v.ChangesTruncated {
		chs = chs[:maxPlanChanges]
	}
	v.Errors, v.Changes = flatfile.ViewErrors(errs), flatfile.ViewChanges(chs)
	return v
}

func importError(err error) error {
	var fe *flatfile.Error
	if errors.As(err, &fe) {
		if fe.Code == "system_not_manual" {
			return errStatus(http.StatusConflict, fe.Msg)
		}
		return badRequest(fe.Code, fe.Msg)
	}
	return err
}

func (s *Server) planDirImport(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	in, err := s.readImport(r, p)
	if err != nil {
		return nil, err
	}
	pl, err := flatfile.PlanImport(store.TxFrom(r.Context()), s.clock(), in)
	if err != nil {
		return nil, importError(err)
	}
	return statusBody{http.StatusOK, map[string]any{"plan": viewPlan(pl), "valid": len(pl.Errors) == 0}}, nil
}

func (s *Server) applyDirImport(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	in, err := s.readImport(r, p)
	if err != nil {
		return nil, err
	}
	return s.finishImport(flatfile.ApplyImport(store.TxFrom(r.Context()), s.clock(), in))
}

func (s *Server) finishImport(res *flatfile.ImportOutcome, err error) (any, error) {
	if err != nil {
		return nil, importError(err)
	}
	body := map[string]any{"plan": viewPlan(res.Plan)}
	if len(res.Plan.Errors) > 0 {
		// 422, but the transaction commits: the refused file is in the audit ledger
		body["error"], body["detail"] = "invalid_file", "the file has rows that cannot be imported; nothing was changed"
		return statusBody{http.StatusUnprocessableEntity, body}, nil
	}
	body["status"] = "applied"
	if res.Held > 0 {
		// what happened: the removals the deletion guard held are not applied (as the groups routes answer)
		body["status"] = "partially_applied"
		if res.Held == res.Plan.Removed {
			body["status"] = "held"
		}
		body["applied"], body["held"], body["hold_id"] = res.Plan.Removed-res.Held, res.Held, res.HoldID
		body["message"] = fmt.Sprintf("Removed %d of %d: %d held for approval", res.Plan.Removed-res.Held, res.Plan.Removed, res.Held)
	}
	if res.HeldRestores > 0 {
		// restores of people the source ended wait for a second admin too; say so, with their own hold
		body["held_reactivations"], body["reactivation_hold_id"] = res.HeldRestores, res.RestoreHoldID
		note := fmt.Sprintf("%d restore(s) held for approval", res.HeldRestores)
		if res.Held == 0 {
			body["status"], body["held"], body["hold_id"] = "partially_applied", res.HeldRestores, res.RestoreHoldID
			if res.Plan.Added == 0 && res.Plan.Removed == 0 && res.Plan.Changed <= res.HeldRestores {
				// every change in the file was a restore the guard held: nothing applied
				body["status"] = "held"
			}
			body["message"] = note
		} else {
			body["message"] = fmt.Sprintf("%v; %s", body["message"], note)
		}
	}
	return statusBody{http.StatusCreated, body}, nil
}

type manualRecordBody struct {
	Target string            `json:"target"`
	System string            `json:"system"`
	Name   string            `json:"name"`
	Fields map[string]string `json:"fields"`
}

func (s *Server) putManualRecord(r *http.Request, _ *params) (int, any, error) {
	var b manualRecordBody
	if err := decodeBody(r, &b, false); err != nil {
		return 0, nil, err
	}
	switch {
	case !flatfile.ValidTarget(b.Target):
		return 0, nil, badRequest("invalid_target", "target must be people, accounts or entitlements")
	case !flatfile.ValidSystem(b.System):
		return 0, nil, badRequest("invalid_system", "system is the manual source, 1 to 63 lower-case letters, digits, '.', '_' or '-'")
	case len(b.Fields) == 0 || len(b.Fields) > 16:
		return 0, nil, badRequest("invalid_fields", "fields holds the values of one object")
	case utf8.RuneCountInString(b.Name) > 100:
		return 0, nil, badRequest("invalid_name", "name is at most 100 characters")
	}
	for k, v := range b.Fields {
		if utf8.RuneCountInString(v) > flatfile.MaxCellRunes || len(k) > 64 {
			return 0, nil, badRequest("invalid_fields", "a value is too long")
		}
	}
	reserved, err := s.reservedSystems()
	if err != nil {
		return 0, nil, err
	}
	res, err := flatfile.UpsertRecord(store.TxFrom(r.Context()), s.clock(), flatfile.RecordInput{System: b.System, Name: strings.TrimSpace(b.Name),
		Target: b.Target, Fields: b.Fields, By: actor(r), ByUser: userID(r), Reserved: reserved})
	out, err := s.finishImport(res, err)
	if err != nil {
		return 0, nil, err
	}
	sb := out.(statusBody)
	if sb.status == http.StatusCreated {
		sb.status = http.StatusOK
	}
	return sb.status, sb.body, nil
}

// manualLookup says who owns an object: managed is false for an object a connector (or any source but a
// manual one) owns; for one a manual source owns it carries the source and the fields a form edits.
func (s *Server) manualLookup(r *http.Request, p *params) (int, any, error) {
	target := p.queryOptLiteral("target", []string{flatfile.TargetPeople, flatfile.TargetAccounts, flatfile.TargetEntitlements})
	id := p.queryInt("id", 0, i64(1), nil)
	if err := validated(p, nil); err != nil {
		return 0, nil, err
	}
	if target == nil {
		return 0, nil, badRequest("invalid_target", "target is required")
	}
	c := store.TxFrom(r.Context())
	var system, key, kind string
	switch *target {
	case flatfile.TargetPeople:
		i, err := c.Identity(id)
		if err != nil {
			return 0, nil, notFoundIf(err)
		}
		key, kind = i.ExternalID, store.ImportPeople
		if system, err = c.ImportRecordSource(kind, key); err != nil {
			return 0, nil, err
		}
	case flatfile.TargetEntitlements:
		g, err := c.Group(id)
		if err != nil {
			return 0, nil, notFoundIf(err)
		}
		system, key, kind = g.System, g.ExternalID, store.ImportEntitlements
	default:
		a, err := c.Account(id)
		if err != nil {
			return 0, nil, notFoundIf(err)
		}
		system, key = a.System, a.ExternalID
	}
	out := map[string]any{"target": *target, "managed": false, "system": system}
	if system == "" && *target != flatfile.TargetPeople {
		return http.StatusOK, out, nil
	}
	var data string
	switch {
	case *target == flatfile.TargetAccounts:
		if _, err := c.FlatMapping(system); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return http.StatusOK, map[string]any{"target": *target, "managed": false, "system": system}, nil
			}
			return 0, nil, err
		}
		recs, err := c.FlatRecords(system, flatfile.KindAccounts)
		if err != nil {
			return 0, nil, err
		}
		for _, x := range recs {
			if x.Key == key {
				data = x.Data
			}
		}
	default:
		if system == "" {
			return http.StatusOK, out, nil
		}
		recs, err := c.ImportRecords(system, kind)
		if err != nil {
			return 0, nil, err
		}
		for _, x := range recs {
			if x.Key == key {
				data = x.Data
			}
		}
	}
	if data == "" {
		return http.StatusOK, out, nil
	}
	out["managed"], out["fields"] = true, flatfile.RecordFields(data)
	return http.StatusOK, out, nil
}

// userID is the signed-in platform user's id, "" for a caller that is no user (an API client).
func userID(r *http.Request) string {
	if id := actorUser(r); id != nil {
		return *id
	}
	return ""
}
