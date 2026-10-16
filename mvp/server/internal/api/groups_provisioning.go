package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/provisioning"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Group provisioning (issue #54, GR-11; design docs/design/groups-grouper-parity.md
// §9.2). Every route needs groups.admin, which only tenant_admin holds until GR-4.
//
//	GET    /api/groups/provisioners                              the provisioners
//	POST   /api/groups/provisioners                              {name, target_type, config, secret?, connection_id?, full_schedule?, failsafe?} (starts in adopt mode)
//	GET    /api/groups/provisioners/{id}                         one, with its last runs, op counts and event lag
//	PATCH  /api/groups/provisioners/{id}                         {version, name?, config?, secret?, mode?, connection_id?, full_schedule?, failsafe?}
//	DELETE /api/groups/provisioners/{id}                         removes it, its marks, ownership records, runs and ops (the target is not touched)
//	GET    /api/groups/provisioners/{id}/marks                   the marks, with the names of what they mark
//	PUT    /api/groups/provisioners/{id}/marks                   {object_type, object_id, scope?, include?, metadata?}
//	DELETE /api/groups/provisioners/{id}/marks/{mark_type}/{object}
//	POST   /api/groups/provisioners/{id}/sync                    {approve_failsafe?} asks for a full sync; the runner starts it (202)
//	GET    /api/groups/provisioners/{id}/runs                    the runs, newest first
//	GET    /api/groups/provisioners/{id}/ops?run=&status=        the ops, newest first
//	GET    /api/groups/provisioners/{id}/groups                  the groups it owns on the target, and their status
//	POST   /api/groups/provisioners/{id}/diagnose?group=&identity=  why a group or identity will or will not be provisioned, and the ops a sync would run
//
// Credentials go in "secret" ({"bind_password"}, {"token"} or {"signing_secret"}
// by target type), are sealed with the KEK and never come back: a provisioner
// shows only the names of the credentials it has (secret_keys_set).
//
// A new provisioner is in adopt mode: its first full sync records what exists
// on the target and what a sync would change, and changes nothing. It becomes
// active (mode PATCH) only after such a run has completed; dry_run records the
// plan and applies nothing; paused does nothing.
func (s *Server) registerGroupsProvisioningRoutes() {
	G, P, PU, PA, D := http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete
	perm := need(auth.PermGroupsAdmin)
	s.handle(G, "/api/groups/provisioners", read, perm, s.rd(s.listProvisioners))
	s.handle(P, "/api/groups/provisioners", write, perm, s.rd(s.createProvisioner))
	s.handle(G, "/api/groups/provisioners/{id}", read, perm, s.rd(s.getProvisioner))
	s.handle(PA, "/api/groups/provisioners/{id}", write, perm, s.rd(s.updateProvisioner))
	s.handle(D, "/api/groups/provisioners/{id}", write, perm, s.rd(s.deleteProvisioner))
	s.handle(G, "/api/groups/provisioners/{id}/marks", read, perm, s.rd(s.listProvMarks))
	s.handle(PU, "/api/groups/provisioners/{id}/marks", write, perm, s.rd(s.putProvMark))
	s.handle(D, "/api/groups/provisioners/{id}/marks/{mark_type}/{object}", write, perm, s.rd(s.deleteProvMark))
	s.handle(P, "/api/groups/provisioners/{id}/sync", write, perm, s.rd(s.requestProvSync))
	s.handle(G, "/api/groups/provisioners/{id}/runs", read, perm, s.rd(s.listProvRuns))
	s.handle(G, "/api/groups/provisioners/{id}/ops", read, perm, s.rd(s.listProvOps))
	s.handle(G, "/api/groups/provisioners/{id}/groups", read, perm, s.rd(s.listProvGroups))
	s.handle(P, "/api/groups/provisioners/{id}/diagnose", phased, perm, s.diagnoseProvisioner).answersRead = true
}

// ---------------------------------------------------------------- views

type provisionerView struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	TargetType   string          `json:"target_type"`
	ConnectionID *string         `json:"connection_id"`
	Config       json.RawMessage `json:"config"`
	// SecretKeysSet names the credentials that are stored, never their values.
	SecretKeysSet []string        `json:"secret_keys_set"`
	Mode          string          `json:"mode"`
	FullSchedule  string          `json:"full_schedule"`
	Failsafe      json.RawMessage `json:"failsafe"`
	NeedsFull     bool            `json:"needs_full_sync"`
	ApproveNext   bool            `json:"failsafe_approved_for_next_sync"`
	CreatedBy     *string         `json:"created_by"`
	CreatedAt     string          `json:"created_at"`
	UpdatedAt     string          `json:"updated_at"`
	Version       int64           `json:"version"`
}

func (s *Server) viewProvisioner(c *store.TenantTx, p *store.Provisioner) provisionerView {
	v := provisionerView{ID: p.ID, Name: p.Name, TargetType: p.TargetType, ConnectionID: p.ConnectionID, Config: p.Config,
		SecretKeysSet: s.cfg.Provisioning.SecretKeysSet(c.Tenant(), p), Mode: p.Mode, FullSchedule: p.FullSchedule, Failsafe: p.Failsafe,
		NeedsFull: p.NeedsFull, ApproveNext: p.ApproveNext, CreatedAt: store.RT(p.CreatedAt), UpdatedAt: store.RT(p.UpdatedAt), Version: p.Version}
	if v.SecretKeysSet == nil {
		v.SecretKeysSet = []string{}
	}
	if p.CreatedBy != "" {
		v.CreatedBy = &p.CreatedBy
	}
	return v
}

type runView struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Mode       string          `json:"mode"`
	Status     string          `json:"status"`
	FromSeq    int64           `json:"from_seq"`
	ToSeq      int64           `json:"to_seq"`
	Summary    json.RawMessage `json:"summary"`
	Error      *string         `json:"error"`
	StartedAt  string          `json:"started_at"`
	FinishedAt *string         `json:"finished_at"`
}

func viewRun(r *store.SyncRun) runView {
	v := runView{ID: r.ID, Kind: r.Kind, Mode: r.Mode, Status: r.Status, FromSeq: r.FromSeq, ToSeq: r.ToSeq, Summary: r.Summary,
		StartedAt: store.RT(r.StartedAt), FinishedAt: rtPtr(r.FinishedAt)}
	if r.Error != "" {
		v.Error = &r.Error
	}
	return v
}

type opView struct {
	ID          string          `json:"id"`
	RunID       *string         `json:"run_id"`
	Op          string          `json:"op"`
	Group       string          `json:"object_ref"`
	GroupID     *string         `json:"group_id"`
	PayloadHash string          `json:"payload_hash"`
	Detail      json.RawMessage `json:"detail"`
	CauseSeq    *int64          `json:"cause_seq"`
	Status      string          `json:"status"`
	Attempts    int             `json:"attempts"`
	Error       *string         `json:"error"`
	PlannedAt   string          `json:"planned_at"`
	AppliedAt   *string         `json:"applied_at"`
	VerifiedAt  *string         `json:"verified_at"`
}

func viewOp(o *store.SyncOp) opView {
	v := opView{ID: o.ID, Op: o.Op, Group: o.ObjectRef, PayloadHash: o.PayloadHash, Detail: o.Detail, CauseSeq: o.CauseSeq, Status: o.Status,
		Attempts: o.Attempts, PlannedAt: store.RT(o.PlannedAt), AppliedAt: rtPtr(o.AppliedAt), VerifiedAt: rtPtr(o.VerifiedAt)}
	if o.RunID != "" {
		v.RunID = &o.RunID
	}
	if o.GroupID != "" {
		v.GroupID = &o.GroupID
	}
	if o.Error != "" {
		v.Error = &o.Error
	}
	return v
}

// provErr maps the provisioning package's refusals to the JSON errors.
func provErr(err error) error {
	var dup *provisioning.DuplicateError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &dup):
		return &readiness.Error{Status: http.StatusConflict, Code: "name_taken", Msg: dup.Error()}
	case errors.Is(err, provisioning.ErrConfig):
		return badRequest("invalid_provisioner", err.Error())
	case errors.Is(err, provisioning.ErrReviewRequired):
		return &readiness.Error{Status: http.StatusConflict, Code: "review_required", Msg: err.Error()}
	case errors.Is(err, provisioning.ErrPaused):
		return &readiness.Error{Status: http.StatusConflict, Code: "provisioner_paused", Msg: "the provisioner is paused"}
	case errors.Is(err, store.ErrVersionConflict):
		return &readiness.Error{Status: http.StatusConflict, Code: "version_conflict",
			Msg: "the provisioner changed since it was read; reload it and retry"}
	case errors.Is(err, store.ErrNotFound):
		return grpNotFound("provisioner")
	}
	return err
}

func provID(p *params) (string, error) { return grpPathID(p, "provisioner") }

// ---------------------------------------------------------------- provisioners

func (s *Server) listProvisioners(r *http.Request, _ *params) (int, any, error) {
	c := store.TxFrom(r.Context())
	ps, err := c.Provisioners()
	if err != nil {
		return 0, nil, err
	}
	items := make([]provisionerView, len(ps))
	for i, p := range ps {
		items[i] = s.viewProvisioner(c, p)
	}
	return http.StatusOK, map[string]any{"items": items}, nil
}

type createProvBody struct {
	Name         string            `json:"name"`
	TargetType   string            `json:"target_type"`
	ConnectionID *string           `json:"connection_id"`
	Config       json.RawMessage   `json:"config"`
	Secret       map[string]string `json:"secret"`
	FullSchedule string            `json:"full_schedule"`
	Failsafe     json.RawMessage   `json:"failsafe"`
}

func (s *Server) createProvisioner(r *http.Request, _ *params) (int, any, error) {
	var in createProvBody
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out provisionerView
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		p, err := s.cfg.Provisioning.Create(c, now, actor(r), provisioning.CreateInput{Name: in.Name, TargetType: in.TargetType,
			ConnectionID: in.ConnectionID, Config: in.Config, Secret: in.Secret, FullSchedule: in.FullSchedule, Failsafe: in.Failsafe})
		if err != nil {
			return err
		}
		out = s.viewProvisioner(c, p)
		return nil
	})
	if err != nil {
		return 0, nil, provErr(err)
	}
	return http.StatusCreated, out, nil
}

func (s *Server) getProvisioner(r *http.Request, p *params) (int, any, error) {
	id, err := provID(p)
	if err != nil {
		return 0, nil, err
	}
	c := store.TxFrom(r.Context())
	pr, err := c.Provisioner(id)
	if err != nil {
		return 0, nil, provErr(err)
	}
	out := map[string]any{"provisioner": s.viewProvisioner(c, pr)}
	counts, err := c.SyncOpCounts(id)
	if err != nil {
		return 0, nil, err
	}
	out["op_counts"] = counts
	runs := map[string]any{}
	for _, kind := range []string{store.RunFull, store.RunIncremental} {
		run, err := c.LastSyncRun(id, kind)
		switch {
		case errors.Is(err, store.ErrNotFound):
			runs[kind] = nil
		case err != nil:
			return 0, nil, err
		default:
			runs[kind] = viewRun(run)
		}
	}
	out["last_runs"] = runs
	if lag, err := events.Lag(c, provisioning.Consumer(id)); err == nil {
		out["event_lag"] = lag
	} else {
		return 0, nil, err
	}
	marks, err := c.ProvMarks(id)
	if err != nil {
		return 0, nil, err
	}
	out["marks"] = len(marks)
	return http.StatusOK, out, nil
}

type updateProvBody struct {
	Version      *int64            `json:"version"`
	Name         *string           `json:"name"`
	ConnectionID *string           `json:"connection_id"`
	Config       json.RawMessage   `json:"config"`
	Secret       map[string]string `json:"secret"`
	Mode         *string           `json:"mode"`
	FullSchedule *string           `json:"full_schedule"`
	Failsafe     json.RawMessage   `json:"failsafe"`
}

func (s *Server) updateProvisioner(r *http.Request, p *params) (int, any, error) {
	id, err := provID(p)
	if err != nil {
		return 0, nil, err
	}
	var in updateProvBody
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.Version == nil {
		return 0, nil, badRequest("invalid_version", "version is required: the version you read")
	}
	var out provisionerView
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		pr, err := s.cfg.Provisioning.Update(c, now, actor(r), id, provisioning.UpdateInput{Version: *in.Version, Name: in.Name,
			ConnectionID: in.ConnectionID, Config: in.Config, Secret: in.Secret, Mode: in.Mode, FullSchedule: in.FullSchedule, Failsafe: in.Failsafe})
		if err != nil {
			return err
		}
		out = s.viewProvisioner(c, pr)
		return nil
	})
	if err != nil {
		return 0, nil, provErr(err)
	}
	return http.StatusOK, out, nil
}

func (s *Server) deleteProvisioner(r *http.Request, p *params) (int, any, error) {
	id, err := provID(p)
	if err != nil {
		return 0, nil, err
	}
	err = s.write(r, func(c *store.TenantTx, now time.Time) error { return s.cfg.Provisioning.Delete(c, now, actor(r), id) })
	if err != nil {
		return 0, nil, provErr(err)
	}
	return http.StatusOK, map[string]any{"id": id, "deleted": true}, nil
}

// ---------------------------------------------------------------- marks

type markView struct {
	ObjectType string          `json:"object_type"`
	ObjectID   string          `json:"object_id"`
	Name       string          `json:"name"`
	Scope      string          `json:"scope"`
	Include    bool            `json:"include"`
	Metadata   json.RawMessage `json:"metadata"`
}

func viewMark(c *store.TenantTx, m *store.ProvMark) markView {
	v := markView{ObjectType: m.ObjectType, ObjectID: m.ObjectID, Scope: m.Scope, Include: m.Include, Metadata: m.Metadata}
	if m.ObjectType == "group" {
		if g, err := c.GrpGroup(store.GroupID(m.ObjectID)); err == nil {
			v.Name = g.Name
		}
	} else if f, err := c.GrpFolder(store.FolderID(m.ObjectID)); err == nil {
		v.Name = f.Name
	}
	return v
}

func (s *Server) listProvMarks(r *http.Request, p *params) (int, any, error) {
	id, err := provID(p)
	if err != nil {
		return 0, nil, err
	}
	c := store.TxFrom(r.Context())
	if _, err := c.Provisioner(id); err != nil {
		return 0, nil, provErr(err)
	}
	ms, err := c.ProvMarks(id)
	if err != nil {
		return 0, nil, err
	}
	items := make([]markView, len(ms))
	for i, m := range ms {
		items[i] = viewMark(c, m)
	}
	return http.StatusOK, map[string]any{"items": items}, nil
}

func (s *Server) putProvMark(r *http.Request, p *params) (int, any, error) {
	id, err := provID(p)
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		ObjectType string          `json:"object_type"`
		ObjectID   string          `json:"object_id"`
		Scope      string          `json:"scope"`
		Include    *bool           `json:"include"`
		Metadata   json.RawMessage `json:"metadata"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if err := grpBodyID("object_id", in.ObjectID); err != nil || in.ObjectID == "" {
		return 0, nil, badRequest("invalid_object_id", "object_id must be the UUID of a folder or a group")
	}
	include := in.Include == nil || *in.Include
	var out markView
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		m, err := s.cfg.Provisioning.SetMark(c, now, actor(r), id, provisioning.MarkInput{ObjectType: in.ObjectType, ObjectID: in.ObjectID,
			Scope: in.Scope, Include: include, Metadata: in.Metadata})
		if err != nil {
			return err
		}
		out = viewMark(c, m)
		return nil
	})
	if err != nil {
		return 0, nil, provErr(err)
	}
	return http.StatusOK, out, nil
}

func (s *Server) deleteProvMark(r *http.Request, p *params) (int, any, error) {
	id, err := provID(p)
	if err != nil {
		return 0, nil, err
	}
	typ, object := p.path["mark_type"], p.path["object"]
	if (typ != "folder" && typ != "group") || !idRE.MatchString(object) {
		return 0, nil, grpNotFound("mark")
	}
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		return s.cfg.Provisioning.RemoveMark(c, now, actor(r), id, typ, object)
	})
	if err != nil {
		return 0, nil, provErr(err)
	}
	return http.StatusOK, map[string]any{"object_type": typ, "object_id": object, "deleted": true}, nil
}

// ---------------------------------------------------------------- sync, runs, ops

func (s *Server) requestProvSync(r *http.Request, p *params) (int, any, error) {
	id, err := provID(p)
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		ApproveFailsafe bool `json:"approve_failsafe"`
	}
	if err := decodeBody(r, &in, true); err != nil {
		return 0, nil, err
	}
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		return s.cfg.Provisioning.RequestFull(c, now, actor(r), id, in.ApproveFailsafe)
	})
	if err != nil {
		return 0, nil, provErr(err)
	}
	return http.StatusAccepted, map[string]any{"queued": true, "kind": store.RunFull, "approve_failsafe": in.ApproveFailsafe}, nil
}

func (s *Server) listProvRuns(r *http.Request, p *params) (int, any, error) {
	id, err := provID(p)
	if err != nil {
		return 0, nil, err
	}
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	c := store.TxFrom(r.Context())
	if _, err := c.Provisioner(id); err != nil {
		return 0, nil, provErr(err)
	}
	runs, err := c.SyncRuns(id, limit, offset)
	if err != nil {
		return 0, nil, err
	}
	items := make([]runView, len(runs))
	for i, run := range runs {
		items[i] = viewRun(run)
	}
	return http.StatusOK, listBody{Items: items, Limit: limit, Offset: offset}, nil
}

var opStatuses = map[string]bool{store.OpPlanned: true, store.OpApplied: true, store.OpVerified: true, store.OpFailed: true,
	store.OpDrift: true, store.OpSkipped: true}

func (s *Server) listProvOps(r *http.Request, p *params) (int, any, error) {
	id, err := provID(p)
	if err != nil {
		return 0, nil, err
	}
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	run, _ := p.query("run")
	status, _ := p.query("status")
	if err := grpBodyID("run", run); err != nil {
		return 0, nil, err
	}
	if status != "" && !opStatuses[status] {
		return 0, nil, badRequest("invalid_status", "status is planned, applied, verified, failed, drift or skipped")
	}
	c := store.TxFrom(r.Context())
	if _, err := c.Provisioner(id); err != nil {
		return 0, nil, provErr(err)
	}
	ops, err := c.SyncOps(id, store.SyncOpFilter{RunID: run, Status: status, Limit: limit, Offset: offset})
	if err != nil {
		return 0, nil, err
	}
	items := make([]opView, len(ops))
	for i, o := range ops {
		items[i] = viewOp(o)
	}
	return http.StatusOK, listBody{Items: items, Limit: limit, Offset: offset}, nil
}

func (s *Server) listProvGroups(r *http.Request, p *params) (int, any, error) {
	id, err := provID(p)
	if err != nil {
		return 0, nil, err
	}
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	c := store.TxFrom(r.Context())
	if _, err := c.Provisioner(id); err != nil {
		return 0, nil, provErr(err)
	}
	gs, err := c.SyncGroups(id, limit, offset)
	if err != nil {
		return 0, nil, err
	}
	type view struct {
		GroupID        string  `json:"group_id"`
		TargetID       string  `json:"target_id"`
		TargetName     string  `json:"target_name"`
		Status         string  `json:"status"`
		StateHash      string  `json:"state_hash"`
		LastReadAt     *string `json:"last_read_at"`
		LastVerifiedAt *string `json:"last_verified_at"`
	}
	items := make([]view, len(gs))
	for i, g := range gs {
		items[i] = view{GroupID: g.GroupID, TargetID: g.TargetID, TargetName: g.TargetName, Status: g.Status, StateHash: g.StateHash,
			LastReadAt: rtPtr(g.LastReadAt), LastVerifiedAt: rtPtr(g.LastVerifiedAt)}
	}
	return http.StatusOK, listBody{Items: items, Limit: limit, Offset: offset}, nil
}

// diagnoseProvisioner explains a group (and optionally an identity) and shows the
// ops a sync would run. It reads the target and applies nothing.
func (s *Server) diagnoseProvisioner(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := provID(p)
	if err != nil {
		return nil, err
	}
	group, _ := p.query("group")
	if group == "" || !idRE.MatchString(group) {
		return nil, badRequest("invalid_group", "group must be the UUID of a group")
	}
	var identity int64
	if raw, ok := p.query("identity"); ok && raw != "" {
		identity, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || identity < 1 {
			return nil, badRequest("invalid_identity", "identity must be an identity id")
		}
	}
	d, err := s.cfg.Provisioning.Diagnose(r.Context(), p.scope.Tenant, id, group, identity)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, grpNotFound("provisioner or group")
		}
		return nil, provErr(err)
	}
	return d, nil
}
