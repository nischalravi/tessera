package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/loaders"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Group loaders (issue #53, GR-10; design docs/design/groups-grouper-parity.md
// §9.1): loaders fill native groups from a source and hold a run that trips a
// failsafe. A route needs a role permission and then a privilege on the
// loader's target folder (GR-4). Reading is groups.read and stem_view (the
// definition itself, the runs' detail and the unresolved subjects need
// stem_admin); configuring and running need groups.loader.admin and stem_admin.
//
//	GET    /api/groups/loaders?limit=&offset=                 the loaders whose folder the caller may view
//	POST   /api/groups/loaders                                {name, type, config, target_folder, ...}: STEP_UP_POLICY
//	GET    /api/groups/loaders/{id}
//	PATCH  /api/groups/loaders/{id}                           the fields to change: STEP_UP_POLICY
//	POST   /api/groups/loaders/{id}/run                       {kind: full|incremental|preview}
//	GET    /api/groups/loaders/{id}/runs?limit=&offset=
//	GET    /api/groups/loaders/{id}/runs/{run_id}             with the plan and the downstream impact
//	POST   /api/groups/loaders/{id}/runs/{run_id}/approve     apply a held run as computed: STEP_UP_POLICY
//	POST   /api/groups/loaders/{id}/runs/{run_id}/reject      discard it: STEP_UP_POLICY
//	GET    /api/groups/loaders/{id}/unresolved?limit=&offset=
//	GET    /api/groups/loader-tasks                           the Inbox tasks of held runs (type loader_held)
//
// Creating or changing a loader that runs a SQL query does not apply at once:
// the route answers 202 with an admin change request (groups.loader.save) that
// a second admin approves (Phase 0 admin-change workflow, GRP-6311). Loaders of
// the other types are saved directly. A run answers 200 with the run, 502
// loader_run_failed (with the run) when the source could not be read or the
// plan could not be applied.
func (s *Server) registerGroupsLoaderRoutes() {
	G, P, PA := http.MethodGet, http.MethodPost, http.MethodPatch
	canRead := need(auth.PermGroupsRead)
	adm := need(auth.PermGroupsLoaderAdmin)
	cfgStepUp := needStepUp(auth.PermGroupsLoaderAdmin, auth.StepUpPolicy)
	// literal paths before /api/groups/{id}
	s.handle(G, "/api/groups/loaders", read, canRead, s.rd(s.listGrpLoaders))
	s.handle(P, "/api/groups/loaders", phased, cfgStepUp, s.rd(s.createGrpLoader))
	s.handle(G, "/api/groups/loader-tasks", read, canRead, s.rd(s.listLoaderTasks))
	s.handle(G, "/api/groups/loaders/{id}", read, canRead, s.rd(s.getGrpLoader))
	s.handle(PA, "/api/groups/loaders/{id}", phased, cfgStepUp, s.rd(s.patchGrpLoader))
	s.handle(P, "/api/groups/loaders/{id}/run", phased, adm, s.rd(s.runGrpLoader))
	s.handle(G, "/api/groups/loaders/{id}/runs", read, canRead, s.rd(s.listLoaderRuns))
	s.handle(G, "/api/groups/loaders/{id}/runs/{run_id}", read, canRead, s.rd(s.getLoaderRun))
	s.handle(P, "/api/groups/loaders/{id}/runs/{run_id}/approve", phased, cfgStepUp, s.rd(s.decideLoaderRun(true)))
	s.handle(P, "/api/groups/loaders/{id}/runs/{run_id}/reject", phased, cfgStepUp, s.rd(s.decideLoaderRun(false)))
	s.handle(G, "/api/groups/loaders/{id}/unresolved", read, canRead, s.rd(s.listLoaderUnresolved))
}

// ---------------------------------------------------------------- views

type loaderJobView struct {
	State             string         `json:"state"`
	NextFullAt        *string        `json:"next_full_at"`
	NextIncrementalAt *string        `json:"next_incremental_at"`
	LagSeconds        *int64         `json:"lag_seconds"`
	LastRun           *loaderRunView `json:"last_run"`
}

type loaderView struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Type              string          `json:"type"`
	ConnectionID      *string         `json:"connection_id"`
	Config            json.RawMessage `json:"config"`
	TargetFolderID    string          `json:"target_folder_id"`
	TargetFolder      string          `json:"target_folder"`
	NameTemplate      string          `json:"name_template"`
	OnMissingGroup    string          `json:"on_missing_group"`
	AndGroupID        *string         `json:"and_group_id"`
	Schedule          string          `json:"schedule"`
	IncrementalSecs   *int64          `json:"incremental_secs"`
	Failsafe          json.RawMessage `json:"failsafe"`
	Status            string          `json:"status"`
	HasSecret         bool            `json:"has_secret"`
	RequiresApproval  bool            `json:"requires_approval"`
	LastFullAt        *string         `json:"last_full_at"`
	LastIncrementalAt *string         `json:"last_incremental_at"`
	CreatedBy         *string         `json:"created_by"`
	CreatedAt         string          `json:"created_at"`
	UpdatedAt         string          `json:"updated_at"`
	Version           int64           `json:"version"`
	Job               *loaderJobView  `json:"job"`
}

// viewLoader renders a loader. The definition (config, failsafe) is only for
// those who administer its folder: full says the caller does.
func viewLoader(tx *store.TenantTx, l *store.GrpLoader, now time.Time, full bool) (loaderView, error) {
	v := loaderView{ID: l.ID, Name: l.Name, Type: l.Type, ConnectionID: l.ConnectionID, TargetFolderID: string(l.TargetFolder),
		NameTemplate: l.NameTemplate, OnMissingGroup: l.OnMissingGroup, Schedule: l.Schedule, IncrementalSecs: l.IncrementalSecs,
		Status: l.Status, HasSecret: len(l.SecretEnc) > 0, RequiresApproval: loaders.NeedsSecondApprover(l.Type), LastFullAt: rtPtr(l.LastFullAt),
		LastIncrementalAt: rtPtr(l.LastIncrAt), CreatedBy: l.CreatedBy, CreatedAt: store.RT(l.CreatedAt),
		UpdatedAt: store.RT(l.UpdatedAt), Version: l.Version}
	if l.AndGroup != nil {
		g := string(*l.AndGroup)
		v.AndGroupID = &g
	}
	if f, err := tx.GrpFolder(l.TargetFolder); err == nil {
		v.TargetFolder = f.Name
	} else if !errors.Is(err, store.ErrNotFound) {
		return v, err
	}
	if full {
		v.Config, v.Failsafe = json.RawMessage(l.Config), json.RawMessage(l.Failsafe)
	}
	st, err := loaders.StatusOf(tx, l, now)
	if err != nil {
		return v, err
	}
	job := &loaderJobView{State: st.State}
	if !st.NextFull.IsZero() {
		s := store.RT(st.NextFull)
		job.NextFullAt = &s
	}
	if !st.NextIncremental.IsZero() {
		s := store.RT(st.NextIncremental)
		job.NextIncrementalAt = &s
	}
	if st.LagSeconds >= 0 {
		job.LagSeconds = &st.LagSeconds
	}
	if st.LastRun != nil {
		rv := loaderViewRun(st.LastRun, false)
		job.LastRun = &rv
	}
	v.Job = job
	return v, nil
}

type loaderRunView struct {
	ID              string          `json:"id"`
	LoaderID        string          `json:"loader_id"`
	Kind            string          `json:"kind"`
	Status          string          `json:"status"`
	StartedAt       string          `json:"started_at"`
	FinishedAt      *string         `json:"finished_at"`
	SourceRows      *int64          `json:"source_rows"`
	GroupsSeen      *int64          `json:"groups_seen"`
	Adds            *int64          `json:"adds"`
	Removes         *int64          `json:"removes"`
	Unresolved      *int64          `json:"unresolved"`
	FailsafeTripped json.RawMessage `json:"failsafe_tripped"`
	SourceHash      *string         `json:"source_hash"`
	Error           *string         `json:"error"`
	RequestedBy     *string         `json:"requested_by"`
	DecidedBy       *string         `json:"decided_by"`
	DecidedAt       *string         `json:"decided_at"`
	Impact          json.RawMessage `json:"impact,omitempty"`
	Plan            json.RawMessage `json:"plan,omitempty"`
}

func rawOrNil(s *string) json.RawMessage {
	if s == nil {
		return json.RawMessage("null")
	}
	return json.RawMessage(*s)
}

// loaderViewRun renders a run; detail adds the plan and the downstream impact.
func loaderViewRun(r *store.GrpLoaderRun, detail bool) loaderRunView {
	v := loaderRunView{ID: r.ID, LoaderID: r.LoaderID, Kind: r.Kind, Status: r.Status, StartedAt: store.RT(r.StartedAt),
		FinishedAt: rtPtr(r.FinishedAt), SourceRows: r.SourceRows, GroupsSeen: r.GroupsSeen, Adds: r.Adds, Removes: r.Removes,
		Unresolved: r.Unresolved, FailsafeTripped: rawOrNil(r.FailsafeTripped), SourceHash: r.SourceHash, Error: r.Error,
		RequestedBy: r.RequestedBy, DecidedBy: r.DecidedBy, DecidedAt: rtPtr(r.DecidedAt)}
	if detail {
		v.Impact, v.Plan = rawOrNil(r.Impact), rawOrNil(r.Plan)
	}
	return v
}

// ---------------------------------------------------------------- authorization

func (s *Server) loaderActor(r *http.Request) loaders.Actor {
	pr := principal(r)
	a := loaders.Actor{Identity: pr.IdentityID, TenantAdmin: pr.ActiveRoles.Has(auth.RoleTenantAdmin)}
	if pr.UserID != nil {
		u := pr.UserID.String()
		a.By = &u
	}
	return a
}

// loaderFor loads a loader (404) and requires the privilege on its target
// folder (403), in the request's transaction.
func (s *Server) loaderFor(r *http.Request, ck *privs.Checker, id string, p privs.Privilege) (*store.GrpLoader, error) {
	l, err := store.TxFrom(r.Context()).GrpLoader(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, grpNotFound("loader")
	}
	if err != nil {
		return nil, err
	}
	return l, grpErr(ck.Require(privs.FolderObject(l.TargetFolder), p))
}

// loaderForPhased is loaderFor for a phased route, which has no request
// transaction: it reads in one of its own.
func (s *Server) loaderForPhased(ctx context.Context, r *http.Request, p *params, id string, priv privs.Privilege) (*store.GrpLoader, error) {
	var l *store.GrpLoader
	err := p.scope.Read(ctx, func(c *store.TenantTx) error {
		var err error
		if l, err = c.GrpLoader(id); errors.Is(err, store.ErrNotFound) {
			return grpNotFound("loader")
		} else if err != nil {
			return err
		}
		ck := privs.NewChecker(c, s.clock(), s.cfg.GroupsEngine, s.grpSubject(r))
		return grpErr(ck.Require(privs.FolderObject(l.TargetFolder), priv))
	})
	return l, err
}

// ---------------------------------------------------------------- reads

func (s *Server) listGrpLoaders(r *http.Request, p *params) (int, any, error) {
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	tx, ck := store.TxFrom(r.Context()), s.grpChecker(r)
	all, err := tx.GrpLoaders()
	if err != nil {
		return 0, nil, err
	}
	// the loaders whose folder the caller may view
	var shown []*store.GrpLoader
	for _, l := range all {
		ok, err := ck.Has(privs.FolderObject(l.TargetFolder), privs.StemView)
		if err != nil {
			return 0, nil, grpErr(err)
		}
		if ok {
			shown = append(shown, l)
		}
	}
	if offset > len(shown) {
		offset = len(shown)
	}
	shown = shown[offset:min(len(shown), offset+limit)]
	now := s.clock()
	items := make([]loaderView, 0, len(shown))
	for _, l := range shown {
		admin, err := ck.Has(privs.FolderObject(l.TargetFolder), privs.StemAdmin)
		if err != nil {
			return 0, nil, grpErr(err)
		}
		v, err := viewLoader(tx, l, now, admin)
		if err != nil {
			return 0, nil, err
		}
		items = append(items, v)
	}
	return http.StatusOK, listBody{items, limit, offset}, nil
}

func (s *Server) getGrpLoader(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "loader")
	if err != nil {
		return 0, nil, err
	}
	ck := s.grpChecker(r)
	l, err := s.loaderFor(r, ck, id, privs.StemView)
	if err != nil {
		return 0, nil, err
	}
	admin, err := ck.Has(privs.FolderObject(l.TargetFolder), privs.StemAdmin)
	if err != nil {
		return 0, nil, grpErr(err)
	}
	v, err := viewLoader(store.TxFrom(r.Context()), l, s.clock(), admin)
	return http.StatusOK, v, err
}

type runListBody struct {
	Items  []loaderRunView `json:"items"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
	Total  int             `json:"total"`
}

func (s *Server) listLoaderRuns(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "loader")
	if err != nil {
		return 0, nil, err
	}
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	l, err := s.loaderFor(r, s.grpChecker(r), id, privs.StemView)
	if err != nil {
		return 0, nil, err
	}
	tx := store.TxFrom(r.Context())
	rows, err := tx.GrpLoaderRuns(l.ID, limit, offset)
	if err != nil {
		return 0, nil, err
	}
	total, err := tx.GrpLoaderRunCount(l.ID)
	if err != nil {
		return 0, nil, err
	}
	out := runListBody{Items: make([]loaderRunView, len(rows)), Limit: limit, Offset: offset, Total: total}
	for i, x := range rows {
		out.Items[i] = loaderViewRun(x, false)
	}
	return http.StatusOK, out, nil
}

func (s *Server) getLoaderRun(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "loader")
	if err != nil {
		return 0, nil, err
	}
	l, err := s.loaderFor(r, s.grpChecker(r), id, privs.StemAdmin)
	if err != nil {
		return 0, nil, err
	}
	rid := p.path["run_id"]
	if !idRE.MatchString(rid) {
		return 0, nil, grpNotFound("run")
	}
	run, err := store.TxFrom(r.Context()).GrpLoaderRun(rid)
	if errors.Is(err, store.ErrNotFound) || (err == nil && run.LoaderID != l.ID) {
		return 0, nil, grpNotFound("run")
	}
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, loaderViewRun(run, true), nil
}

type unresolvedView struct {
	Source     string          `json:"source"`
	Identifier string          `json:"identifier"`
	FirstSeen  string          `json:"first_seen"`
	LastSeen   string          `json:"last_seen"`
	Groups     json.RawMessage `json:"groups"`
}

func (s *Server) listLoaderUnresolved(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "loader")
	if err != nil {
		return 0, nil, err
	}
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	l, err := s.loaderFor(r, s.grpChecker(r), id, privs.StemAdmin)
	if err != nil {
		return 0, nil, err
	}
	tx := store.TxFrom(r.Context())
	rows, err := tx.GrpLoaderUnresolved(l.ID, limit, offset)
	if err != nil {
		return 0, nil, err
	}
	total, err := tx.GrpLoaderUnresolvedCount(l.ID)
	if err != nil {
		return 0, nil, err
	}
	items := make([]unresolvedView, len(rows))
	for i, u := range rows {
		items[i] = unresolvedView{Source: u.Source, Identifier: u.Identifier, FirstSeen: store.RT(u.FirstSeen),
			LastSeen: store.RT(u.LastSeen), Groups: json.RawMessage(u.Groups)}
	}
	return http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset, "total": total}, nil
}

// loaderTask is an Inbox task of a held run.
type loaderTask struct {
	Type            string          `json:"type"`
	RunID           string          `json:"run_id"`
	LoaderID        string          `json:"loader_id"`
	LoaderName      string          `json:"loader_name"`
	TargetFolder    string          `json:"target_folder"`
	HeldAt          string          `json:"held_at"`
	Adds            *int64          `json:"adds"`
	Removes         *int64          `json:"removes"`
	Unresolved      *int64          `json:"unresolved"`
	FailsafeTripped json.RawMessage `json:"failsafe_tripped"`
	Impact          json.RawMessage `json:"impact"`
}

// listLoaderTasks lists the held runs as Inbox tasks of type loader_held, for
// those who administer the loader's folder (its owners).
func (s *Server) listLoaderTasks(r *http.Request, p *params) (int, any, error) {
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	tx, ck := store.TxFrom(r.Context()), s.grpChecker(r)
	held, err := tx.GrpLoaderHeldRuns()
	if err != nil {
		return 0, nil, err
	}
	var shown []loaderTask
	for _, run := range held {
		l, err := tx.GrpLoader(run.LoaderID)
		if err != nil {
			return 0, nil, err
		}
		ok, err := ck.Has(privs.FolderObject(l.TargetFolder), privs.StemAdmin)
		if err != nil {
			return 0, nil, grpErr(err)
		}
		if !ok {
			continue
		}
		t := loaderTask{Type: "loader_held", RunID: run.ID, LoaderID: l.ID, LoaderName: l.Name, HeldAt: store.RT(run.StartedAt),
			Adds: run.Adds, Removes: run.Removes, Unresolved: run.Unresolved, FailsafeTripped: rawOrNil(run.FailsafeTripped),
			Impact: rawOrNil(run.Impact)}
		if f, err := tx.GrpFolder(l.TargetFolder); err == nil {
			t.TargetFolder = f.Name
		}
		shown = append(shown, t)
	}
	if offset > len(shown) {
		offset = len(shown)
	}
	shown = shown[offset:min(len(shown), offset+limit)]
	if shown == nil {
		shown = []loaderTask{}
	}
	return http.StatusOK, listBody{shown, limit, offset}, nil
}

// ---------------------------------------------------------------- configuration

// loaderBody is a create: the whole definition, and the credential of a CSV
// URL (a bearer token, sealed; never returned).
type loaderBody struct {
	loaders.Spec
	Secret string `json:"secret"`
}

// approvalAnswer is the 202 of a change that needs a second person.
func approvalAnswer(ch *store.AdminChange, loaderID string) map[string]any {
	return map[string]any{"status": "pending_approval", "change_request_id": ch.ID.String(), "type": ch.Type,
		"loader_id": emptyToNil(loaderID), "expires_at": store.RT(ch.ExpiresAt),
		"detail": "a second admin must approve this change (POST /api/admin/change-requests/{id}/approve) before the loader is saved"}
}

func emptyToNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Server) createGrpLoader(r *http.Request, p *params) (int, any, error) {
	var in loaderBody
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	ctx := r.Context()
	if loaders.NeedsSecondApprover(in.Type) {
		// validate and authorize now; the second approver applies it
		err := p.scope.Read(ctx, func(c *store.TenantTx) error {
			if err := s.requireFolder(r, c, in.TargetFolder); err != nil {
				return err
			}
			l, err := loaders.Validate(c, in.Spec, nil)
			if err != nil {
				return grpErr(err)
			}
			return s.checkLoaderSecret(l, in.Secret, true)
		})
		if err != nil {
			return 0, nil, err
		}
		ch, err := s.submitLoaderChange(ctx, r, "", nil, in.Spec, in.Secret)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, approvalAnswer(ch, ""), nil
	}
	var out loaderView
	err := p.scope.Write(ctx, func(c *store.TenantTx) error {
		if err := s.requireFolder(r, c, in.TargetFolder); err != nil {
			return err
		}
		now := s.clock()
		l, err := loaders.Create(s.loaderSaveEnv(r, c, now), in.Spec, in.Secret)
		if err != nil {
			return grpErr(err)
		}
		out, err = viewLoader(c, l, now, true)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, out, nil
}

// requireFolder asks for stem_admin on the folder a loader targets (the
// folder must exist: an unknown one is 422, not a hint that it does not).
func (s *Server) requireFolder(r *http.Request, c *store.TenantTx, folder string) error {
	if err := grpBodyID("target_folder", folder); err != nil {
		return err
	}
	if folder == "" {
		return badRequest("invalid_target_folder", "target_folder is required")
	}
	ck := privs.NewChecker(c, s.clock(), s.cfg.GroupsEngine, s.grpSubject(r))
	f, err := c.GrpFolder(store.FolderID(folder))
	if errors.Is(err, store.ErrNotFound) {
		return badRequest("unknown_folder", "no such target folder")
	}
	if err != nil {
		return err
	}
	return grpErr(ck.Require(privs.FolderObject(f.ID), privs.StemAdmin))
}

// checkLoaderSecret refuses a credential the loader does not take, a missing one a
// new loader needs and a connection string that is not acceptable here (the
// second administrator should never approve what cannot run). The credential is
// not stored by this call.
func (s *Server) checkLoaderSecret(l *store.GrpLoader, secret string, create bool) error {
	use := loaders.SecretPolicy(l.Type, json.RawMessage(l.Config))
	switch {
	case secret == "" && create && use == loaders.SecretRequired:
		return badRequest("secret_required", "a "+l.Type+" loader needs its credential (secret)")
	case secret == "":
		return nil
	case use == loaders.SecretNone:
		return badRequest("secret_not_used", "a "+l.Type+" loader with this config takes no secret")
	}
	return grpErr(loaders.CheckSecret(l.Type, json.RawMessage(l.Config), secret, s.cfg.Env == config.Prod))
}

func (s *Server) loaderSaveEnv(r *http.Request, c *store.TenantTx, now time.Time) loaders.SaveEnv {
	pr := principal(r)
	e := loaders.SaveEnv{Tx: c, Now: now, Sealer: s.cfg.Sealer, Prod: s.cfg.Env == config.Prod}
	if pr.UserID != nil {
		u := pr.UserID.String()
		e.By = &u
	}
	return e
}

// submitLoaderChange files the groups.loader.save request of a SQL loader.
func (s *Server) submitLoaderChange(ctx context.Context, r *http.Request, loaderID string, version *int64, spec loaders.Spec, secret string) (*store.AdminChange, error) {
	body := map[string]any{"spec": spec}
	if loaderID != "" {
		body["loader_id"] = loaderID
		if version != nil {
			body["version"] = *version
		}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return s.admin.SubmitChecked(ctx, principal(r), admin.SubmitInput{Type: admin.TypeGroupLoaderSave, Payload: payload, ClientSecret: secret})
}

// loaderPatch changes the fields that are present. incremental_secs 0 clears
// it; and_group and connection_id "" clear theirs.
type loaderPatch struct {
	Name            *string           `json:"name"`
	ConnectionID    *string           `json:"connection_id"`
	Config          json.RawMessage   `json:"config"`
	TargetFolder    *string           `json:"target_folder"`
	NameTemplate    *string           `json:"name_template"`
	OnMissingGroup  *string           `json:"on_missing_group"`
	AndGroup        *string           `json:"and_group"`
	Schedule        *string           `json:"schedule"`
	IncrementalSecs *int64            `json:"incremental_secs"`
	Failsafe        *loaders.Failsafe `json:"failsafe"`
	Status          *string           `json:"status"`
	Secret          *string           `json:"secret"`
	Version         *int64            `json:"version"`
}

func (b *loaderPatch) apply(spec *loaders.Spec) {
	if b.Name != nil {
		spec.Name = *b.Name
	}
	if b.ConnectionID != nil {
		spec.ConnectionID = *b.ConnectionID
	}
	if len(b.Config) > 0 {
		spec.Config = b.Config
	}
	if b.TargetFolder != nil {
		spec.TargetFolder = *b.TargetFolder
	}
	if b.NameTemplate != nil {
		spec.NameTemplate = *b.NameTemplate
	}
	if b.OnMissingGroup != nil {
		spec.OnMissingGroup = *b.OnMissingGroup
	}
	if b.AndGroup != nil {
		spec.AndGroup = *b.AndGroup
	}
	if b.Schedule != nil {
		spec.Schedule = *b.Schedule
	}
	if b.IncrementalSecs != nil {
		spec.IncrementalSecs = b.IncrementalSecs
		if *b.IncrementalSecs == 0 {
			spec.IncrementalSecs = nil
		}
	}
	if b.Failsafe != nil {
		spec.Failsafe = b.Failsafe
	}
	if b.Status != nil {
		spec.Status = *b.Status
	}
}

func (b *loaderPatch) empty() bool {
	return b.Name == nil && b.ConnectionID == nil && len(b.Config) == 0 && b.TargetFolder == nil && b.NameTemplate == nil &&
		b.OnMissingGroup == nil && b.AndGroup == nil && b.Schedule == nil && b.IncrementalSecs == nil && b.Failsafe == nil &&
		b.Status == nil && b.Secret == nil
}

// disableOnly is a change that only turns a loader off: it needs no second
// person, since switching a source off narrows what it does.
func (b *loaderPatch) disableOnly() bool {
	return b.Status != nil && *b.Status == store.LoaderDisabled && b.Name == nil && b.ConnectionID == nil &&
		len(b.Config) == 0 && b.TargetFolder == nil && b.NameTemplate == nil && b.OnMissingGroup == nil && b.AndGroup == nil &&
		b.Schedule == nil && b.IncrementalSecs == nil && b.Failsafe == nil && b.Secret == nil
}

func (s *Server) patchGrpLoader(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "loader")
	if err != nil {
		return 0, nil, err
	}
	var in loaderPatch
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.empty() {
		return 0, nil, badRequest("empty_patch", "name the fields to change")
	}
	ctx := r.Context()
	old, err := s.loaderForPhased(ctx, r, p, id, privs.StemAdmin)
	if err != nil {
		return 0, nil, err
	}
	spec, err := loaders.SpecOf(old)
	if err != nil {
		return 0, nil, err
	}
	in.apply(&spec)
	// moving a loader to another folder needs the right on that folder too
	if in.TargetFolder != nil && spec.TargetFolder != string(old.TargetFolder) {
		if err := p.scope.Read(ctx, func(c *store.TenantTx) error { return s.requireFolder(r, c, spec.TargetFolder) }); err != nil {
			return 0, nil, err
		}
	}
	if loaders.NeedsSecondApprover(old.Type) && !in.disableOnly() {
		secret := ""
		if in.Secret != nil {
			secret = *in.Secret
			if secret == "" {
				return 0, nil, badRequest("secret_required", "a credential cannot be cleared by a change that needs approval: send the new one")
			}
		}
		err := p.scope.Read(ctx, func(c *store.TenantTx) error {
			cur, err := c.GrpLoader(id)
			if err != nil {
				return err
			}
			if in.Version != nil && *in.Version != cur.Version {
				return &readiness.Error{Status: http.StatusConflict, Code: "version_conflict",
					Msg: "the loader changed since it was read; reload it and retry"}
			}
			l, err := loaders.Validate(c, spec, cur)
			if err != nil {
				return grpErr(err)
			}
			if secret == "" && loaders.SecretPolicy(l.Type, json.RawMessage(l.Config)) == loaders.SecretRequired && len(cur.SecretEnc) == 0 {
				return badRequest("secret_required", "a "+l.Type+" loader needs its credential (secret)")
			}
			return s.checkLoaderSecret(l, secret, false)
		})
		if err != nil {
			return 0, nil, err
		}
		version := in.Version
		if version == nil {
			v := old.Version
			version = &v
		}
		ch, err := s.submitLoaderChange(ctx, r, id, version, spec, secret)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, approvalAnswer(ch, id), nil
	}
	var out loaderView
	err = p.scope.Write(ctx, func(c *store.TenantTx) error {
		now := s.clock()
		l, err := loaders.Update(s.loaderSaveEnv(r, c, now), id, in.Version, spec, in.Secret)
		if err != nil {
			return grpErr(err)
		}
		out, err = viewLoader(c, l, now, true)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

// ---------------------------------------------------------------- runs

func (s *Server) runGrpLoader(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "loader")
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Kind string `json:"kind"`
	}
	if err := decodeBody(r, &in, true); err != nil {
		return 0, nil, err
	}
	if in.Kind == "" {
		in.Kind = store.RunFull
	}
	ctx := r.Context()
	if _, err := s.loaderForPhased(ctx, r, p, id, privs.StemAdmin); err != nil {
		return 0, nil, err
	}
	run, err := s.loaders.Run(ctx, p.scope.Tenant, id, in.Kind, s.loaderActor(r))
	if err != nil {
		return 0, nil, grpErr(err)
	}
	if run == nil {
		return http.StatusOK, map[string]any{"status": "no_changes"}, nil
	}
	if run.Status == store.RunFailed {
		return 0, nil, &readiness.Error{Status: http.StatusBadGateway, Code: "loader_run_failed",
			Msg: "the loader run failed: " + deref(run.Error), Extra: map[string]any{"run": loaderViewRun(run, true)}}
	}
	return http.StatusOK, loaderViewRun(run, true), nil
}

func (s *Server) decideLoaderRun(approve bool) rdFunc {
	return func(r *http.Request, p *params) (int, any, error) {
		id, err := grpPathID(p, "loader")
		if err != nil {
			return 0, nil, err
		}
		rid := p.path["run_id"]
		if !idRE.MatchString(rid) {
			return 0, nil, grpNotFound("run")
		}
		ctx := r.Context()
		if _, err := s.loaderForPhased(ctx, r, p, id, privs.StemAdmin); err != nil {
			return 0, nil, err
		}
		a := s.loaderActor(r)
		var run *store.GrpLoaderRun
		if approve {
			run, err = s.loaders.Approve(ctx, p.scope.Tenant, id, rid, a)
		} else {
			run, err = s.loaders.Reject(ctx, p.scope.Tenant, id, rid, a)
		}
		if err != nil {
			return 0, nil, grpErr(err)
		}
		return http.StatusOK, loaderViewRun(run, true), nil
	}
}
