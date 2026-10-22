package loaders

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// fetchTimeout bounds one read of a source (a SQL query has its own, shorter,
// timeout).
const fetchTimeout = 10 * time.Minute

// Service runs loaders. The zero Clock is the wall clock.
type Service struct {
	DB     *store.DB
	Engine *engine.Engine
	Clock  timeutil.Clock
	Sealer *seal.Sealer
	// HTTP is the SSRF-guarded client (internal/safehttp) a URL source uses.
	HTTP *http.Client
	// DataDir is the directory SQL and CSV files must be under
	// (TESSERA_LOADER_DATA_DIR); empty turns file sources off.
	DataDir string
	Log     *slog.Logger
}

func (s *Service) now() time.Time {
	if s.Clock == nil {
		return timeutil.System()
	}
	return s.Clock()
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// Actor is who started a run or decided a held one: the platform user (nil for
// the scheduler), the identity behind it and whether it is a tenant admin.
type Actor struct {
	By          *string
	Identity    *int64
	TenantAdmin bool
}

func (a Actor) env(tx *store.TenantTx, now time.Time, eng *engine.Engine) model.Env {
	return model.Env{Tx: tx, Now: now, By: a.By, Engine: eng, ByIdentity: a.Identity, TenantAdmin: a.TenantAdmin,
		Cause: store.CauseLoader}
}

// Compact drops the groups a plan leaves as they are, so a stored plan holds
// only what it changes.
func (p *Plan) Compact() *Plan {
	out := *p
	out.Groups = nil
	for i := range p.Groups {
		g := &p.Groups[i]
		if g.Create || g.Restore || g.Enable || len(g.Add) > 0 || len(g.Remove) > 0 || g.Missing {
			out.Groups = append(out.Groups, *g)
		}
	}
	return &out
}

func checkRunnable(l *store.GrpLoader, kind string) error {
	if kind == store.RunPreview {
		return nil
	}
	switch {
	case l.Status == store.LoaderDisabled:
		return conflict("loader_disabled", "the loader is disabled")
	case l.Status == store.LoaderHeld:
		return conflict("loader_held", "the loader has a held run: approve or reject it first")
	case kind == store.RunIncremental && l.IncrementalSecs == nil:
		return conflict("no_incremental", "the loader has no incremental feed")
	case kind == store.RunIncremental && l.LastFullAt == nil:
		return conflict("no_full_run", "run a full load before the first incremental one")
	}
	return nil
}

func (s *Service) open(l *store.GrpLoader) ([]byte, error) {
	if len(l.SecretEnc) == 0 {
		return nil, nil
	}
	if s.Sealer == nil {
		return nil, conflict("sealer_unavailable", "no key-encryption key is configured to open the loader's credential")
	}
	b, err := s.Sealer.Open(l.SecretEnc, seal.AAD(l.TenantID, "grp_loaders", "secret_enc", l.ID))
	if err != nil {
		return nil, errors.New("loaders: the loader's credential cannot be opened")
	}
	return b, nil
}

// errRunFailed marks a run whose plan could not be built or applied for a
// reason of the source or of the groups (a name clash, an invalid name): it is
// recorded as a failed run in a transaction of its own.
var errRunFailed = errors.New("loaders: run failed")

// Run reads the loader's source and, for a full or incremental run, applies
// the result in one transaction with its audit event, or holds it if a failsafe
// trips. A preview computes the same plan and applies nothing. The returned run
// is the one recorded; its Status is applied, held, previewed or failed. An
// incremental run whose feed has no changes records nothing and returns nil.
func (s *Service) Run(ctx context.Context, tenant tenancy.ID, loaderID, kind string, a Actor) (*store.GrpLoaderRun, error) {
	if kind != store.RunFull && kind != store.RunIncremental && kind != store.RunPreview {
		return nil, invalid("invalid_kind", "kind is full, incremental or preview")
	}
	var l *store.GrpLoader
	err := s.DB.ReadTenant(ctx, tenant, func(tx *store.TenantTx) error {
		var err error
		if l, err = tx.GrpLoader(loaderID); errors.Is(err, store.ErrNotFound) {
			return notFound("no such loader")
		} else if err != nil {
			return err
		}
		return checkRunnable(l, kind)
	})
	if err != nil {
		return nil, err
	}
	started := s.now()
	secret, err := s.open(l)
	if err != nil {
		return s.fail(ctx, tenant, l, kind, started, a, err)
	}
	src, err := SourceFor(l.Type)
	if err != nil {
		return s.fail(ctx, tenant, l, kind, started, a, invalid("loader_type_unavailable", "loader type %q is not available", l.Type))
	}
	stats := &SourceStats{}
	job := LoaderJob{Loader: l, Config: json.RawMessage(l.Config), Secret: secret,
		Env: Env{DB: s.DB, Tenant: tenant, Now: started, DataDir: s.DataDir, HTTP: s.HTTP}, Stats: stats}
	fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	var loaded []LoadedGroup
	var changes []GroupChange
	next := ""
	if kind == store.RunIncremental {
		cursor := ""
		if l.Cursor != nil {
			cursor = *l.Cursor
		}
		var ok bool
		if changes, next, ok, err = src.Changes(fctx, job, cursor); err == nil && !ok {
			return nil, conflict("no_incremental", "the loader's source has no incremental feed")
		}
		if err == nil && len(changes) == 0 {
			return nil, nil
		}
	} else {
		loaded, err = src.Full(fctx, job)
	}
	if err != nil {
		return s.fail(ctx, tenant, l, kind, started, a, err)
	}
	var run *store.GrpLoaderRun
	var failure error
	err = s.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		now := s.now()
		cur, err := tx.GrpLoader(l.ID)
		if err != nil {
			return err
		}
		if err := checkRunnable(cur, kind); err != nil {
			return err // it changed while the source was read
		}
		var plan *Plan
		if kind == store.RunIncremental {
			plan, err = BuildIncremental(tx, cur, changes)
			if plan != nil {
				plan.CursorAfter = &next
			}
		} else {
			plan, err = BuildFull(tx, cur, loaded)
		}
		var me *model.Error
		if errors.As(err, &me) {
			failure = err
			return errRunFailed
		}
		if err != nil {
			return err
		}
		fs, err := ParseFailsafe(cur.Failsafe)
		if err != nil {
			return err
		}
		trips := fs.Evaluate(plan, plan.Counts)
		run = &store.GrpLoaderRun{Kind: kind, StartedAt: started, FinishedAt: &now, RequestedBy: a.By,
			SourceRows: i64(stats.Rows), GroupsSeen: i64(len(plan.Groups)), Unresolved: i64(len(plan.Unresolved))}
		if stats.Hash != "" {
			run.SourceHash = &stats.Hash
		}
		run.Adds, run.Removes = i64(plan.Adds()), i64(plan.Removes())
		if kind == store.RunIncremental {
			run.CursorAfter = &next
		}
		if len(trips) > 0 {
			tj, err := json.Marshal(trips)
			if err != nil {
				return err
			}
			run.FailsafeTripped = strp(string(tj))
		}
		switch {
		case kind == store.RunPreview || len(trips) > 0:
			imp, err := ComputeImpact(tx, plan, now)
			if err != nil {
				return err
			}
			ij, err := json.Marshal(imp)
			if err != nil {
				return err
			}
			pj, err := json.Marshal(plan.Compact())
			if err != nil {
				return err
			}
			run.Impact, run.Plan = strp(string(ij)), strp(string(pj))
			run.Status = store.RunPreviewed
			if kind != store.RunPreview {
				run.Status = store.RunHeld
				if err := tx.SetGrpLoaderStatus(cur.ID, store.LoaderHeld, now); err != nil {
					return err
				}
			}
			if plan.Kind == store.RunFull && kind != store.RunPreview {
				if err := recordUnresolved(tx, cur.ID, plan, now, true); err != nil {
					return err
				}
			}
			if kind != store.RunPreview && plan.Kind == store.RunIncremental {
				if err := recordUnresolved(tx, cur.ID, plan, now, false); err != nil {
					return err
				}
			}
		default:
			env := a.env(tx, now, s.Engine)
			// the deletion guard (internal/deleteguard) sees the loader and counts this run as one batch
			env.CauseRef, env.Correlation = cur.ID, "loader:"+cur.ID+":"+now.UTC().Format(time.RFC3339Nano)
			res, err := ApplyPlan(env, cur, plan)
			if err != nil {
				var me *model.Error
				if errors.As(err, &me) {
					failure = err
					return errRunFailed
				}
				return err
			}
			run.Status, run.Adds, run.Removes = store.RunApplied, i64(res.Added), i64(res.Removed)
			if err := recordUnresolved(tx, cur.ID, plan, now, plan.Kind == store.RunFull); err != nil {
				return err
			}
			var cursor *string
			if kind == store.RunIncremental {
				cursor = &next
			}
			if err := tx.RecordGrpLoaderRan(cur.ID, kind, now, cursor); err != nil {
				return err
			}
		}
		run.LoaderID = cur.ID
		if err := tx.InsertGrpLoaderRun(run); err != nil {
			return err
		}
		return s.record(tx, now, cur, run, a, nil)
	})
	if errors.Is(err, errRunFailed) {
		return s.fail(ctx, tenant, l, kind, started, a, failure)
	}
	if err != nil {
		return nil, err
	}
	return run, nil
}

func i64(n int) *int64 { v := int64(n); return &v }

func strp(s string) *string { return &s }

// recordUnresolved lists the subjects a run could not resolve. A full run is
// the whole truth, so what it did not see again (resolved, or no longer named)
// leaves the list.
func recordUnresolved(tx *store.TenantTx, loaderID string, plan *Plan, now time.Time, prune bool) error {
	for _, u := range plan.Unresolved {
		gj, err := json.Marshal(u.Groups)
		if err != nil {
			return err
		}
		if err := tx.UpsertGrpLoaderUnresolved(&store.GrpLoaderUnresolved{LoaderID: loaderID, Source: u.Source,
			Identifier: u.Identifier, FirstSeen: now, LastSeen: now, Groups: string(gj)}); err != nil {
			return err
		}
	}
	if prune {
		_, err := tx.PruneGrpLoaderUnresolved(loaderID, now)
		return err
	}
	return nil
}

// record writes the audit event of a run, and its loader event (applied, held,
// approved, rejected), in the caller's transaction.
func (s *Service) record(tx *store.TenantTx, now time.Time, l *store.GrpLoader, run *store.GrpLoaderRun, a Actor, extra ojson.Object) error {
	action := "groups.loader.run." + run.Status
	detail := ojson.Object{{Key: "loader_id", Value: l.ID}, {Key: "name", Value: l.Name}, {Key: "run_id", Value: run.ID},
		{Key: "kind", Value: run.Kind}, {Key: "status", Value: run.Status}, {Key: "source_rows", Value: deref64(run.SourceRows)},
		{Key: "groups", Value: deref64(run.GroupsSeen)}, {Key: "adds", Value: deref64(run.Adds)},
		{Key: "removes", Value: deref64(run.Removes)}, {Key: "unresolved", Value: deref64(run.Unresolved)}}
	if run.FailsafeTripped != nil {
		// the audit ledger has no fractions: the limits are said in words
		var trips []Trip
		if err := json.Unmarshal([]byte(*run.FailsafeTripped), &trips); err != nil {
			return err
		}
		list := make([]ojson.Object, len(trips))
		for i, t := range trips {
			list[i] = ojson.Object{{Key: "rule", Value: t.Rule}, {Key: "group", Value: t.Group}, {Key: "detail", Value: t.Detail}}
		}
		detail = append(detail, ojson.KV{Key: "failsafe_tripped", Value: list})
	}
	if run.SourceHash != nil {
		detail = append(detail, ojson.KV{Key: "source_sha256", Value: *run.SourceHash})
	}
	if run.Error != nil {
		detail = append(detail, ojson.KV{Key: "error", Value: *run.Error})
	}
	detail = append(detail, extra...)
	if _, err := tx.RecordAudit(store.AuditRecord{At: now, Action: action, LegacyActor: "groups", TargetType: "loader",
		TargetID: l.ID, Detail: detail}); err != nil {
		return err
	}
	var typ string
	switch run.Status {
	case store.RunApplied:
		typ = events.LoaderRunApplied
	case store.RunHeld:
		typ = events.LoaderRunHeld
	case store.RunApproved:
		typ = events.LoaderRunApproved
	case store.RunRejected:
		typ = events.LoaderRunRejected
	default:
		return nil
	}
	ev := events.New(typ, l.ID, now, store.CauseLoader)
	ev.Data = events.Data(map[string]any{"run_id": run.ID, "kind": run.Kind, "adds": deref64(run.Adds),
		"removes": deref64(run.Removes), "groups": deref64(run.GroupsSeen), "unresolved": deref64(run.Unresolved)})
	return pit.Emit(tx, ev)
}

func deref64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// fail records a failed run in a transaction of its own and returns it. The
// message is the refusal's own text when it is one of ours; anything else is
// logged and recorded generically, so a driver's error never reaches the run.
func (s *Service) fail(ctx context.Context, tenant tenancy.ID, l *store.GrpLoader, kind string, started time.Time, a Actor, cause error) (*store.GrpLoaderRun, error) {
	msg := "the run failed; see the server log"
	var me *model.Error
	if errors.As(cause, &me) {
		msg = me.Code + ": " + me.Msg
	} else {
		s.log().Error("group loader run failed", "loader", l.ID, "err", cause)
	}
	if len(msg) > 500 {
		msg = msg[:500]
	}
	var run *store.GrpLoaderRun
	err := s.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		now := s.now()
		run = &store.GrpLoaderRun{LoaderID: l.ID, Kind: kind, StartedAt: started, FinishedAt: &now, Status: store.RunFailed,
			Error: &msg, RequestedBy: a.By}
		if err := tx.InsertGrpLoaderRun(run); err != nil {
			return err
		}
		return s.record(tx, now, l, run, a, nil)
	})
	if err != nil {
		return nil, err
	}
	return run, nil
}

// ApplyResult is what ApplyPlan did.
type ApplyResult struct {
	Added, Removed, Skipped, GroupsCreated int
	// Queued is true when the engine queued a recompute for some group (the
	// change is committed; its effective members follow).
	Queued bool
}

// ApplyPlan makes the groups match the plan, in env's transaction. It creates
// the groups the plan creates, restores deleted ones the source returns again,
// syncs the loader-owned members, and treats a group the source no longer
// returns as the loader says (empty it, disable it or delete it).
func ApplyPlan(env model.Env, l *store.GrpLoader, plan *Plan) (ApplyResult, error) {
	var res ApplyResult
	for i := range plan.Groups {
		gp := &plan.Groups[i]
		var g *store.NativeGroup
		var err error
		if gp.Create {
			g, err = env.CreateLoaderGroup(model.LoaderGroupInput{Folder: l.TargetFolder, Extension: gp.Extension,
				DisplayName: gp.DisplayName, Description: gp.Description, LoaderID: l.ID})
			res.GroupsCreated++
		} else if g, err = env.Group(store.GroupID(gp.GroupID)); err == nil && g.Status == store.GroupDeleted {
			if gp.Missing {
				continue // deleted since the plan was made: nothing left to do
			}
			g, err = env.RestoreGroup(g.ID)
		}
		if err != nil {
			return res, err
		}
		if gp.Enable && !gp.Missing && g.Status == store.GroupDisabled {
			// the source returns a group the loader had disabled
			a := store.GroupActive
			if g, err = env.UpdateGroup(g.ID, model.UpdateGroupInput{Status: &a}); err != nil {
				return res, err
			}
		}
		sync, err := env.LoaderSync(g, l.ID, gp.Add, gp.Remove)
		if err != nil {
			return res, err
		}
		res.Added, res.Removed, res.Skipped = res.Added+sync.Added, res.Removed+sync.Removed, res.Skipped+sync.Skipped
		res.Queued = res.Queued || sync.Outcome.Queued
		switch {
		case gp.Missing && gp.Action == "disable" && g.Status == store.GroupActive:
			d := store.GroupDisabled
			if _, err := env.UpdateGroup(g.ID, model.UpdateGroupInput{Status: &d}); err != nil {
				return res, err
			}
		case gp.Missing && gp.Action == "delete":
			if err := env.DeleteGroup(g.ID); err != nil {
				return res, err
			}
		case !gp.Missing && !gp.Create:
			// display-name sync (G-60): the source's text wins
			var in model.UpdateGroupInput
			changed := false
			if gp.DisplayName != "" && gp.DisplayName != g.DisplayExtension {
				in.DisplayExtension, changed = &gp.DisplayName, true
			}
			if gp.Description != "" && gp.Description != g.Description {
				in.Description, changed = &gp.Description, true
			}
			if changed {
				if _, err := env.UpdateGroup(g.ID, in); err != nil {
					return res, err
				}
			}
		}
	}
	return res, nil
}

// Approve applies a held run as it was computed, releases the loader and
// records the decision. The plan was computed when the run was held; what has
// changed since is not recomputed (a later run corrects it).
func (s *Service) Approve(ctx context.Context, tenant tenancy.ID, loaderID, runID string, a Actor) (*store.GrpLoaderRun, error) {
	return s.decide(ctx, tenant, loaderID, runID, a, true)
}

// Reject discards a held run and releases the loader. A rejected incremental
// run still advances the cursor (the next full run corrects the loader's
// groups); otherwise the same changes would be held again.
func (s *Service) Reject(ctx context.Context, tenant tenancy.ID, loaderID, runID string, a Actor) (*store.GrpLoaderRun, error) {
	return s.decide(ctx, tenant, loaderID, runID, a, false)
}

func (s *Service) decide(ctx context.Context, tenant tenancy.ID, loaderID, runID string, a Actor, approve bool) (*store.GrpLoaderRun, error) {
	if _, err := uuid.Parse(runID); err != nil {
		return nil, notFound("no such run")
	}
	var run *store.GrpLoaderRun
	err := s.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		now := s.now()
		l, err := tx.GrpLoader(loaderID)
		if errors.Is(err, store.ErrNotFound) {
			return notFound("no such loader")
		}
		if err != nil {
			return err
		}
		if run, err = tx.GrpLoaderRun(runID); errors.Is(err, store.ErrNotFound) || (err == nil && run.LoaderID != l.ID) {
			return notFound("no such run")
		} else if err != nil {
			return err
		}
		if run.Status != store.RunHeld || run.Plan == nil {
			return conflict("not_held", "the run is %s, not held", run.Status)
		}
		by := ""
		if a.By != nil {
			by = *a.By
		}
		status := store.RunRejected
		extra := ojson.Object{{Key: "decided_by", Value: by}}
		var cursor *string
		if run.Kind == store.RunIncremental {
			cursor = run.CursorAfter
		}
		if approve {
			status = store.RunApproved
			var plan Plan
			if err := json.Unmarshal([]byte(*run.Plan), &plan); err != nil {
				return err
			}
			env := a.env(tx, now, s.Engine)
			// an approved held run is an approved override: the deletion guard neither counts nor holds it
			env.CauseRef, env.Override = l.ID, true
			res, err := ApplyPlan(env, l, &plan)
			if err != nil {
				return err
			}
			run.Adds, run.Removes = i64(res.Added), i64(res.Removed)
			extra = append(extra, ojson.KV{Key: "queued", Value: res.Queued})
		}
		if err := tx.DecideGrpLoaderRun(run.ID, status, by, now); err != nil {
			return err
		}
		run.Status, run.DecidedBy, run.DecidedAt = status, &by, &now
		if l.Status == store.LoaderHeld {
			if err := tx.SetGrpLoaderStatus(l.ID, store.LoaderEnabled, now); err != nil {
				return err
			}
		}
		kind := run.Kind
		if err := tx.RecordGrpLoaderRan(l.ID, kind, now, cursor); err != nil {
			return err
		}
		return s.record(tx, now, l, run, a, extra)
	})
	if err != nil {
		return nil, err
	}
	return run, nil
}
