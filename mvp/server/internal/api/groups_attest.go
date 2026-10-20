package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/attest"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/deprov"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/inbox"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Group attestation, the groups Inbox and deprovisioning (issue #57, GR-14;
// design docs/design/groups-grouper-parity.md §10.4, §10.5). Every route asks
// the route's permission and then the privilege on the object, as the other
// group routes do.
//
// Attestation (a membership campaign of the certification engine; its population
// is frozen when it starts):
//
//	GET|PUT|DELETE /api/groups/{id}/attestation                     the group's settings (admin); a group takes its folder's
//	GET|PUT|DELETE /api/groups/folders/{id}/attestation             a folder's settings (stem_admin)
//	GET  /api/groups/{id}/attestation/campaigns                     the group's campaigns (admin)
//	POST /api/groups/{id}/attestation/campaigns                     start one now (admin)
//	GET  /api/groups/attestation/campaigns/{campaign_id}            items with usage context, progress, proof of the frozen population (admin or reviewer group)
//	POST /api/groups/attestation/campaigns/{campaign_id}/items/{item_id}/decision   {decision: keep|revoke, comment} (admin or reviewer group)
//
// The Inbox:
//
//	GET  /api/groups/inbox/tasks[?status=&kind=]                       the tasks the caller administers or is assigned
//	POST /api/groups/inbox/tasks/{task_id}/close                    {status: done|dismissed}
//
// Deprovisioning:
//
//	GET|PUT /api/groups/deprovisioning/settings                     {affiliations, veto_enabled} (groups.admin)
//	GET|PUT|DELETE /api/groups/folders/{id}/deprovisioning          a folder's mode {mode: notify|auto_after|auto_now, days} (stem_admin)
//	GET  /api/groups/deprovisioning/items[?status=&folder=]         open work in the folders the caller administers
//	POST /api/groups/deprovisioning/items/{item_id}/resolve         {action: remove|dismiss, reason} (stem_admin on the folder)
func (s *Server) registerGroupsGovRoutes() {
	G, P, PU, D := http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete
	canRead, canWrite, admin := need(auth.PermGroupsRead), need(auth.PermGroupsWrite), need(auth.PermGroupsAdmin)
	for _, typ := range []privs.ObjectType{privs.Folder, privs.Group} {
		base := "/api/groups/{id}"
		if typ == privs.Folder {
			base = "/api/groups/folders/{id}"
		}
		h := attestHandlers{s, s.privHandlers(typ)}
		s.handle(G, base+"/attestation", read, canRead, s.rd(h.getSettings))
		s.handle(PU, base+"/attestation", write, canWrite, s.rd(h.putSettings))
		s.handle(D, base+"/attestation", write, canWrite, s.rd(h.deleteSettings))
	}
	s.handle(G, "/api/groups/{id}/attestation/campaigns", read, canRead, s.rd(s.listAttestations))
	s.handle(P, "/api/groups/{id}/attestation/campaigns", write, canWrite, s.rd(s.startAttestation))
	s.handle(G, "/api/groups/attestation/campaigns/{campaign_id}", read, canRead, s.rd(s.getAttestation))
	s.handle(P, "/api/groups/attestation/campaigns/{campaign_id}/items/{item_id}/decision", write, canWrite, s.rd(s.decideAttestation))

	s.handle(G, "/api/groups/inbox/tasks", read, canRead, s.rd(s.listInbox))
	s.handle(P, "/api/groups/inbox/tasks/{task_id}/close", write, canWrite, s.rd(s.closeTask))

	s.handle(G, "/api/groups/deprovisioning/settings", read, admin, s.rd(s.getDeprovSettings))
	s.handle(PU, "/api/groups/deprovisioning/settings", write, admin, s.rd(s.putDeprovSettings))
	s.handle(G, "/api/groups/folders/{id}/deprovisioning", read, canRead, s.rd(s.getDeprovFolder))
	s.handle(PU, "/api/groups/folders/{id}/deprovisioning", write, canWrite, s.rd(s.putDeprovFolder))
	s.handle(D, "/api/groups/folders/{id}/deprovisioning", write, canWrite, s.rd(s.deleteDeprovFolder))
	s.handle(G, "/api/groups/deprovisioning/items", read, canRead, s.rd(s.listDeprovItems))
	s.handle(P, "/api/groups/deprovisioning/items/{item_id}/resolve", write, canWrite, s.rd(s.resolveDeprovItem))
}

// ---------------------------------------------------------------- shared

// govSubject says who the request's principal is, for the packages of GR-14.
func (s *Server) attestEnv(r *http.Request, c *store.TenantTx, now time.Time, ck *privs.Checker) attest.Env {
	pr := principal(r)
	e := attest.Env{Tx: c, Now: now, Checker: ck, Engine: s.cfg.GroupsEngine, ByIdentity: pr.IdentityID,
		TenantAdmin: pr.ActiveRoles.Has(auth.RoleTenantAdmin)}
	if pr.UserID != nil {
		e.By = pr.UserID.String()
	}
	return e
}

func (s *Server) deprovEnv(r *http.Request, c *store.TenantTx, now time.Time, ck *privs.Checker) deprov.Env {
	pr := principal(r)
	e := deprov.Env{Tx: c, Now: now, Checker: ck, Engine: s.cfg.GroupsEngine, ByIdentity: pr.IdentityID,
		TenantAdmin: pr.ActiveRoles.Has(auth.RoleTenantAdmin)}
	if pr.UserID != nil {
		e.By = pr.UserID.String()
	}
	return e
}

// grpPathUUID validates a path segment as a UUID (404 otherwise).
func grpPathUUID(p *params, name, what string) (string, error) {
	id := p.path[name]
	if !idRE.MatchString(id) {
		return "", grpNotFound(what)
	}
	return id, nil
}

// queryEnum reads an optional query value that must be one of values.
func queryEnum(p *params, name string, values ...string) (string, error) {
	v, ok := p.query(name)
	if !ok || v == "" {
		return "", nil
	}
	for _, w := range values {
		if v == w {
			return v, nil
		}
	}
	return "", badRequest("invalid_"+name, name+" is one of "+strings.Join(values, ", "))
}

// ---------------------------------------------------------------- attestation settings

type attestHandlers struct {
	s *Server
	p privHandlers
}

func (h attestHandlers) getSettings(r *http.Request, p *params) (int, any, error) {
	ck := h.s.grpChecker(r)
	o, err := h.p.object(r, p, ck, h.p.admin())
	if err != nil {
		return 0, nil, err
	}
	v, err := attest.Get(store.TxFrom(r.Context()), string(o.Type), o.ID)
	if err != nil {
		return 0, nil, grpErr(err)
	}
	return http.StatusOK, v, nil
}

func (h attestHandlers) putSettings(r *http.Request, p *params) (int, any, error) {
	ck := h.s.grpChecker(r)
	o, err := h.p.object(r, p, ck, h.p.admin())
	if err != nil {
		return 0, nil, err
	}
	var in attest.Settings
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out *attest.View
	err = grpErr(h.s.write(r, func(c *store.TenantTx, now time.Time) (err error) {
		out, err = attest.Put(h.s.attestEnv(r, c, now, ck), string(o.Type), o.ID, in)
		return err
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

func (h attestHandlers) deleteSettings(r *http.Request, p *params) (int, any, error) {
	ck := h.s.grpChecker(r)
	o, err := h.p.object(r, p, ck, h.p.admin())
	if err != nil {
		return 0, nil, err
	}
	err = grpErr(h.s.write(r, func(c *store.TenantTx, now time.Time) error {
		return attest.Delete(h.s.attestEnv(r, c, now, ck), string(o.Type), o.ID)
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"owner_type": string(o.Type), "owner_id": o.ID, "deleted": true}, nil
}

// ---------------------------------------------------------------- campaigns

func (s *Server) listAttestations(r *http.Request, p *params) (int, any, error) {
	ck := s.grpChecker(r)
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	g, err := s.grpGroupFor(r, ck, id, privs.Admin)
	if err != nil {
		return 0, nil, err
	}
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	rows, err := store.TxFrom(r.Context()).GrpAttestCampaigns(store.GrpAttestFilter{Group: g.ID, Limit: limit, Offset: offset})
	if err != nil {
		return 0, nil, err
	}
	items := make([]attest.CampaignView, 0, len(rows))
	for _, c := range rows {
		items = append(items, attest.ViewOf(c))
	}
	return http.StatusOK, map[string]any{"group_id": id, "items": items}, nil
}

func (s *Server) startAttestation(r *http.Request, p *params) (int, any, error) {
	ck := s.grpChecker(r)
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	g, err := s.grpGroupFor(r, ck, id, privs.Admin)
	if err != nil {
		return 0, nil, err
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return 0, nil, err
	}
	var out attest.CampaignView
	err = grpErr(s.write(r, func(c *store.TenantTx, now time.Time) error {
		camp, _, err := attest.Start(s.attestEnv(r, c, now, ck), g.ID, attest.StartInput{})
		if err != nil {
			return err
		}
		out = attest.ViewOf(camp)
		return nil
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, out, nil
}

func (s *Server) getAttestation(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathUUID(p, "campaign_id", "attestation")
	if err != nil {
		return 0, nil, err
	}
	c := store.TxFrom(r.Context())
	v, items, verified, err := attest.Campaign(s.attestEnv(r, c, s.clock(), s.grpChecker(r)), id)
	if err != nil {
		return 0, nil, grpErr(err)
	}
	return http.StatusOK, map[string]any{"campaign": v, "items": items, "population_verified": verified}, nil
}

func (s *Server) decideAttestation(r *http.Request, p *params) (int, any, error) {
	cid, err := grpPathUUID(p, "campaign_id", "attestation")
	if err != nil {
		return 0, nil, err
	}
	iid, err := grpPathUUID(p, "item_id", "item")
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Decision string  `json:"decision"`
		Comment  *string `json:"comment"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.Comment != nil && len(*in.Comment) > 1000 {
		return 0, nil, badRequest("invalid_comment", "comment is at most 1000 characters")
	}
	ck := s.grpChecker(r)
	var out *attest.ItemView
	err = grpErr(s.write(r, func(c *store.TenantTx, now time.Time) (err error) {
		out, err = attest.Decide(s.attestEnv(r, c, now, ck), principal(r).User(), cid, iid, in.Decision, in.Comment)
		return err
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

// ---------------------------------------------------------------- Inbox

type taskView struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Title      string          `json:"title"`
	Detail     json.RawMessage `json:"detail"`
	ObjectType string          `json:"object_type"`
	ObjectID   string          `json:"object_id"`
	Subject    *int64          `json:"subject_identity_id,omitempty"`
	Assignee   *int64          `json:"assignee_identity_id,omitempty"`
	Status     string          `json:"status"`
	DueAt      *time.Time      `json:"due_at,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	ClosedAt   *time.Time      `json:"closed_at,omitempty"`
}

func viewTask(t *store.GrpTask) taskView {
	return taskView{ID: t.ID, Kind: t.Kind, Title: t.Title, Detail: json.RawMessage(t.Detail), ObjectType: t.ObjectType, ObjectID: t.ObjectID,
		Subject: t.Subject, Assignee: t.Assignee, Status: t.Status, DueAt: t.DueAt, CreatedAt: t.CreatedAt, ClosedAt: t.ClosedAt}
}

func (s *Server) listInbox(r *http.Request, p *params) (int, any, error) {
	status, err := queryEnum(p, "status", store.TaskOpen, store.TaskDone, store.TaskDismissed)
	if err != nil {
		return 0, nil, err
	}
	kind, err := queryEnum(p, "kind", store.TaskDeprovisioning, store.TaskRule, store.TaskMicroCertification, store.TaskAttestation,
		store.TaskAttestationOverdue)
	if err != nil {
		return 0, nil, err
	}
	if status == "" {
		status = store.TaskOpen
	}
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	rows, err := inbox.List(store.TxFrom(r.Context()), s.grpChecker(r), store.GrpTaskFilter{Status: status, Kind: kind}, limit, offset)
	if err != nil {
		return 0, nil, grpErr(err)
	}
	items := make([]taskView, 0, len(rows))
	for _, t := range rows {
		items = append(items, viewTask(t))
	}
	return http.StatusOK, map[string]any{"items": items}, nil
}

func (s *Server) closeTask(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathUUID(p, "task_id", "task")
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Status string `json:"status"`
	}
	if err := decodeBody(r, &in, true); err != nil {
		return 0, nil, err
	}
	if in.Status == "" {
		in.Status = store.TaskDone
	}
	ck := s.grpChecker(r)
	by := ""
	if pr := principal(r); pr.UserID != nil {
		by = pr.UserID.String()
	}
	var out taskView
	err = grpErr(s.write(r, func(c *store.TenantTx, now time.Time) error {
		t, err := inbox.Close(c, ck, now, id, in.Status, by)
		if err != nil {
			return err
		}
		out = viewTask(t)
		return nil
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

// ---------------------------------------------------------------- deprovisioning

func (s *Server) getDeprovSettings(r *http.Request, _ *params) (int, any, error) {
	v, err := deprov.LoadSettings(store.TxFrom(r.Context()))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, v, nil
}

func (s *Server) putDeprovSettings(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		Affiliations []string `json:"affiliations"`
		VetoEnabled  *bool    `json:"veto_enabled"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	for _, a := range in.Affiliations {
		if err := grpBodyID("affiliations", a); err != nil {
			return 0, nil, err
		}
	}
	if in.Affiliations == nil {
		in.Affiliations = []string{}
	}
	veto := in.VetoEnabled == nil || *in.VetoEnabled
	var out deprov.Settings
	err := grpErr(s.write(r, func(c *store.TenantTx, now time.Time) (err error) {
		out, err = deprov.SaveSettings(s.deprovEnv(r, c, now, s.grpChecker(r)), deprov.Settings{Affiliations: in.Affiliations, VetoEnabled: veto})
		return err
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

func (s *Server) getDeprovFolder(r *http.Request, p *params) (int, any, error) {
	ck := s.grpChecker(r)
	id, err := grpPathID(p, "folder")
	if err != nil {
		return 0, nil, err
	}
	f, err := s.grpFolderFor(r, ck, id, privs.StemAdmin)
	if err != nil {
		return 0, nil, err
	}
	m, _, err := deprov.ModeOf(store.TxFrom(r.Context()), f.ID)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, m, nil
}

func (s *Server) putDeprovFolder(r *http.Request, p *params) (int, any, error) {
	ck := s.grpChecker(r)
	id, err := grpPathID(p, "folder")
	if err != nil {
		return 0, nil, err
	}
	f, err := s.grpFolderFor(r, ck, id, privs.StemAdmin)
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Mode string `json:"mode"`
		Days int    `json:"days"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out deprov.FolderMode
	err = grpErr(s.write(r, func(c *store.TenantTx, now time.Time) (err error) {
		out, err = deprov.SetFolder(s.deprovEnv(r, c, now, ck), f.ID, in.Mode, in.Days)
		return err
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

func (s *Server) deleteDeprovFolder(r *http.Request, p *params) (int, any, error) {
	ck := s.grpChecker(r)
	id, err := grpPathID(p, "folder")
	if err != nil {
		return 0, nil, err
	}
	f, err := s.grpFolderFor(r, ck, id, privs.StemAdmin)
	if err != nil {
		return 0, nil, err
	}
	err = grpErr(s.write(r, func(c *store.TenantTx, now time.Time) error {
		return deprov.DeleteFolder(s.deprovEnv(r, c, now, ck), f.ID)
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"folder_id": id, "deleted": true}, nil
}

func (s *Server) listDeprovItems(r *http.Request, p *params) (int, any, error) {
	status, err := queryEnum(p, "status", store.DeprovOpen, store.DeprovRemoved, store.DeprovDismissed)
	if err != nil {
		return 0, nil, err
	}
	folder, err := queryStr(p, "folder", 36)
	if err != nil {
		return 0, nil, err
	}
	if err := grpBodyID("folder", folder); err != nil {
		return 0, nil, err
	}
	if status == "" {
		status = store.DeprovOpen
	}
	var identity int64
	if v, ok := p.query("identity"); ok && v != "" {
		if identity, err = strconv.ParseInt(v, 10, 64); err != nil || identity < 1 {
			return 0, nil, badRequest("invalid_identity", "identity is an identity id")
		}
	}
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	items, err := deprov.List(store.TxFrom(r.Context()), s.grpChecker(r), store.GrpDeprovFilter{Status: status, FolderID: store.FolderID(folder),
		Identity: identity}, limit, offset)
	if err != nil {
		return 0, nil, grpErr(err)
	}
	return http.StatusOK, map[string]any{"items": items}, nil
}

func (s *Server) resolveDeprovItem(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathUUID(p, "item_id", "deprovisioning item")
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	ck := s.grpChecker(r)
	var out deprov.ItemView
	err = grpErr(s.write(r, func(c *store.TenantTx, now time.Time) error {
		it, err := deprov.Resolve(s.deprovEnv(r, c, now, ck), id, in.Action, in.Reason)
		if err != nil {
			return err
		}
		out = deprov.ViewOf(c, it)
		return nil
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}
