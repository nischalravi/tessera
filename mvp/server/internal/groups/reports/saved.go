package reports

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/gov"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// SaveInput is what a client saves.
type SaveInput struct {
	Name     string
	Kind     string
	Params   Params
	Format   string // csv (default) | json
	Schedule string // none (default) | daily | weekly | monthly
	Delivery string // store (default) | email
}

// Notifier tells a user a scheduled report is ready. It carries no report
// data: the report is fetched from Tessera, with the user's own access. The
// default writes a log line.
type Notifier func(ctx context.Context, to string, subject, body string) error

// SaveEnv is a save's context: the transaction, the clock, the saving platform
// user and the checker for what that user holds.
type SaveEnv struct {
	Tx      *store.TenantTx
	Now     time.Time
	By      string
	Checker *privs.Checker
}

func nextRun(schedule string, from time.Time) *time.Time {
	var t time.Time
	switch schedule {
	case "daily":
		t = from.AddDate(0, 0, 1)
	case "weekly":
		t = from.AddDate(0, 0, 7)
	case "monthly":
		t = from.AddDate(0, 1, 0)
	default:
		return nil
	}
	return &t
}

func (in *SaveInput) normalize() error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > MaxName {
		return gov.Invalid("invalid_name", "name is 1 to %d characters", MaxName)
	}
	if in.Format == "" {
		in.Format = "csv"
	}
	if in.Format != "csv" && in.Format != "json" {
		return gov.Invalid("invalid_format", "format is csv or json")
	}
	if in.Schedule == "" {
		in.Schedule = "none"
	}
	if in.Schedule != "none" && in.Schedule != "daily" && in.Schedule != "weekly" && in.Schedule != "monthly" {
		return gov.Invalid("invalid_schedule", "schedule is none, daily, weekly or monthly")
	}
	if in.Delivery == "" {
		in.Delivery = "store"
	}
	if in.Delivery != "store" && in.Delivery != "email" {
		return gov.Invalid("invalid_delivery", "delivery is store or email")
	}
	if in.Delivery == "email" && in.Schedule == "none" {
		return gov.Invalid("invalid_delivery", "email delivery goes with a schedule")
	}
	return Validate(in.Kind, &in.Params)
}

// emailOpen reports whether the tenant lets Tessera send email (the rules gate:
// off until a tenant admin turns it on).
func emailOpen(tx *store.TenantTx) (bool, error) {
	s, err := tx.GrpRuleSettings()
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil && s.EmailEnabled, err
}

// Save stores a new report. The saving user must be allowed to run it now
// (privilege checked at save and again each run), and email delivery needs the
// tenant's email gate open.
func Save(e SaveEnv, in SaveInput) (*store.GrpReport, error) {
	if e.By == "" {
		return nil, gov.Forbidden("report_needs_user", "a report runs with the privileges of the user who saves it, so a machine client cannot save one")
	}
	if err := in.normalize(); err != nil {
		return nil, err
	}
	if err := e.precheck(in.Kind, in.Params, in.Delivery); err != nil {
		return nil, err
	}
	mine, err := e.Tx.GrpReports(e.By)
	if err != nil {
		return nil, err
	}
	if len(mine) >= MaxReports {
		return nil, gov.Conflict("too_many_reports", "a user has at most %d saved reports", MaxReports)
	}
	params, _ := json.Marshal(in.Params)
	r := &store.GrpReport{Name: in.Name, Kind: in.Kind, Params: string(params), Format: in.Format, Schedule: in.Schedule, Delivery: in.Delivery,
		NextRunAt: nextRun(in.Schedule, e.Now), CreatedBy: e.By, CreatedAt: e.Now, UpdatedAt: e.Now}
	if err := e.Tx.InsertGrpReport(r); err != nil {
		return nil, err
	}
	return r, e.audit("groups.report.saved", r)
}

func (e SaveEnv) precheck(kind string, p Params, delivery string) error {
	if err := Authorize(e.Checker, kind, p); err != nil {
		return err
	}
	if delivery == "email" {
		if ok, err := emailOpen(e.Tx); err != nil {
			return err
		} else if !ok {
			return gov.Conflict("email_disabled", "email is off for this tenant: a tenant admin turns it on in the groups settings")
		}
	}
	return nil
}

func (e SaveEnv) audit(action string, r *store.GrpReport) error {
	_, err := e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: action, LegacyActor: "groups", TargetType: "report", TargetID: r.ID,
		Detail: ojson.Object{{Key: "report_id", Value: r.ID}, {Key: "name", Value: r.Name}, {Key: "kind", Value: r.Kind},
			{Key: "schedule", Value: r.Schedule}, {Key: "delivery", Value: r.Delivery}, {Key: "format", Value: r.Format}}})
	return err
}

// Own loads a report the user may manage: their own, or any for a tenant admin.
// Someone else's report is not found.
func Own(tx *store.TenantTx, id, by string, tenantAdmin bool) (*store.GrpReport, error) {
	r, err := tx.GrpReport(id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && r.CreatedBy != by && !tenantAdmin) {
		return nil, gov.NotFound("no such report")
	}
	return r, err
}

// Update replaces a report's name, parameters, format, schedule and delivery.
// The updating user becomes its owner: it runs with their privileges from now on.
func Update(e SaveEnv, r *store.GrpReport, in SaveInput) (*store.GrpReport, error) {
	if e.By == "" {
		return nil, gov.Forbidden("report_needs_user", "a report runs with the privileges of the user who saves it, so a machine client cannot save one")
	}
	in.Kind = r.Kind
	if err := in.normalize(); err != nil {
		return nil, err
	}
	if err := e.precheck(in.Kind, in.Params, in.Delivery); err != nil {
		return nil, err
	}
	params, _ := json.Marshal(in.Params)
	r.Name, r.Params, r.Format, r.Delivery, r.CreatedBy, r.UpdatedAt = in.Name, string(params), in.Format, in.Delivery, e.By, e.Now
	if in.Schedule != r.Schedule || r.NextRunAt == nil {
		r.NextRunAt = nextRun(in.Schedule, e.Now)
	}
	if in.Schedule == "none" {
		r.NextRunAt = nil
	}
	r.Schedule = in.Schedule
	if err := e.Tx.SaveGrpReport(r); err != nil {
		return nil, err
	}
	return r, e.audit("groups.report.updated", r)
}

// Delete removes a report and its runs.
func Delete(e SaveEnv, r *store.GrpReport) error {
	if err := e.Tx.DeleteGrpReport(r.ID); err != nil {
		return err
	}
	return e.audit("groups.report.deleted", r)
}

// ParamsOf decodes a stored report's parameters.
func ParamsOf(r *store.GrpReport) (Params, error) {
	var p Params
	dec := json.NewDecoder(strings.NewReader(r.Params))
	dec.DisallowUnknownFields()
	return p, dec.Decode(&p)
}

// RunSaved runs a report for the checker's subject and stores the output as a
// run. The run's owner is the report's owner: only they, or a tenant admin, can
// read it back. A run that fails (the privilege was lost) is stored as failed.
func RunSaved(e Env, r *store.GrpReport, by, trigger string) (*store.GrpReportRun, error) {
	run := &store.GrpReportRun{ReportID: r.ID, RanAt: e.Now, RanBy: by, Trigger: trigger, Format: r.Format, Status: "ok"}
	var out string
	p, err := ParamsOf(r)
	if err == nil {
		var res *Result
		if res, err = Run(e, r.Kind, p); err == nil {
			if out, err = res.Render(r.Format, e.Now); err == nil {
				run.RowCount, run.Truncated, run.Content, run.SHA256 = len(res.Rows), res.Truncated, out, Digest(out)
			}
		}
	}
	if err != nil {
		var ge *gov.Error
		var de *privs.DeniedError
		switch {
		case errors.As(err, &ge):
			run.Error = ge.Code
		case errors.As(err, &de):
			run.Error = "privilege_required: " + string(de.Privilege)
		default:
			return nil, err
		}
		run.Status, run.Content, run.SHA256 = "failed", "", ""
	}
	if err := e.Tx.InsertGrpReportRun(run); err != nil {
		return nil, err
	}
	if _, err := e.Tx.PruneGrpReportRuns(r.ID, KeepRuns); err != nil {
		return nil, err
	}
	r.LastRunAt = &e.Now
	if r.NextRunAt != nil && trigger == "schedule" {
		r.NextRunAt = nextRun(r.Schedule, e.Now)
	}
	if err := e.Tx.SaveGrpReport(r); err != nil {
		return nil, err
	}
	_, err = e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: "groups.report.ran", LegacyActor: "groups", TargetType: "report", TargetID: r.ID,
		Detail: ojson.Object{{Key: "report_id", Value: r.ID}, {Key: "run_id", Value: run.ID}, {Key: "kind", Value: r.Kind}, {Key: "trigger", Value: trigger},
			{Key: "status", Value: run.Status}, {Key: "rows", Value: run.RowCount}, {Key: "truncated", Value: run.Truncated},
			{Key: "sha256", Value: run.SHA256}, {Key: "error", Value: run.Error}}})
	return run, err
}

// ReadRun returns a stored run the user may read: the report's owner's, or a
// tenant admin's. Anyone else gets not found.
func ReadRun(tx *store.TenantTx, id, by string, tenantAdmin bool) (*store.GrpReportRun, *store.GrpReport, error) {
	run, err := tx.GrpReportRun(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, gov.NotFound("no such run")
	}
	if err != nil {
		return nil, nil, err
	}
	r, err := Own(tx, run.ReportID, by, tenantAdmin)
	if err != nil {
		return nil, nil, gov.NotFound("no such run")
	}
	// the run was made for run.RanBy: another tenant admin may read it, another user may not
	if run.RanBy != by && !tenantAdmin {
		return nil, nil, gov.NotFound("no such run")
	}
	return run, r, nil
}

// ---------------------------------------------------------------- the scheduler

// RunDue runs the scheduled reports that have come due, each as the user who
// owns it with what they hold now: a user who is gone or lost the privilege
// gets a failed run, never the data. It returns how many it ran.
func RunDue(tx *store.TenantTx, now time.Time, eng *engine.Engine, notify Notifier, log *slog.Logger) (int, error) {
	due, err := tx.GrpReportsDue(now, 20)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range due {
		sub, err := privs.SubjectOfUser(tx, r.CreatedBy, now)
		var run *store.GrpReportRun
		switch {
		case errors.Is(err, privs.ErrNoUser):
			run, err = failedRun(tx, now, r, "author_unavailable")
		case err != nil:
			return n, err
		default:
			env := Env{Tx: tx, Now: now, Checker: privs.NewChecker(tx, now, eng, sub), Engine: eng}
			run, err = RunSaved(env, r, r.CreatedBy, "schedule")
		}
		if err != nil {
			return n, err
		}
		n++
		if r.Delivery == "email" && run.Status == "ok" && notify != nil {
			if err := notifyOwner(tx, r, run, notify, log); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

func failedRun(tx *store.TenantTx, now time.Time, r *store.GrpReport, why string) (*store.GrpReportRun, error) {
	run := &store.GrpReportRun{ReportID: r.ID, RanAt: now, RanBy: r.CreatedBy, Trigger: "schedule", Status: "failed", Format: r.Format, Error: why}
	if err := tx.InsertGrpReportRun(run); err != nil {
		return nil, err
	}
	r.LastRunAt = &now
	r.NextRunAt = nextRun(r.Schedule, now)
	return run, tx.SaveGrpReport(r)
}

// notifyOwner tells the report's owner the run is ready, when the tenant's
// email gate is open and the owner has an address. The message holds no data.
func notifyOwner(tx *store.TenantTx, r *store.GrpReport, run *store.GrpReportRun, notify Notifier, log *slog.Logger) error {
	if ok, err := emailOpen(tx); err != nil || !ok {
		return err
	}
	sub, err := tx.PlatformUser(mustUUID(r.CreatedBy))
	if err != nil || sub.IdentityID == nil {
		return nil
	}
	i, err := tx.Identity(*sub.IdentityID)
	if err != nil || i.Email == nil || *i.Email == "" {
		return nil
	}
	if err := notify(tx.Context(), *i.Email, "Report ready: "+r.Name, "Your scheduled report is ready. Open Tessera, Groups, Reports to read it."); err != nil {
		log.Warn("report notification failed", "report", r.ID)
	}
	return nil
}

// ---------------------------------------------------------------- the job

// Runner is the reports' background job. It is started next to the other
// groups jobs in cmd/tessera.
type Runner struct {
	DB     *store.DB
	Engine *engine.Engine
	Clock  timeutil.Clock
	Log    *slog.Logger
	Notify Notifier
	// Tick is how often Loop passes (default 1 minute).
	Tick time.Duration
}

func (r *Runner) defaults() {
	if r.Tick <= 0 {
		r.Tick = time.Minute
	}
	if r.Log == nil {
		r.Log = slog.Default()
	}
	if r.Clock == nil {
		r.Clock = timeutil.System
	}
}

// Once runs one pass over every active tenant. An error in one tenant does
// not stop the others; the first is returned.
func (r *Runner) Once(ctx context.Context) error {
	r.defaults()
	ctx = audit.WithSystemActor(ctx, "groups.reports")
	tenants, err := r.DB.ActiveTenants(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, t := range tenants {
		due := false
		err := r.DB.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			rs, err := tx.GrpReportsDue(r.Clock(), 1)
			due = len(rs) > 0
			return err
		})
		if err == nil && due {
			err = r.DB.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
				_, err := RunDue(tx, r.Clock(), r.Engine, r.Notify, r.Log)
				return err
			})
		}
		if err != nil {
			r.Log.Error("group reports pass failed", "tenant", t.Slug, "err", err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

// Loop runs Once until ctx is done, sleeping Tick between passes.
func (r *Runner) Loop(ctx context.Context) {
	r.defaults()
	for {
		if err := r.Once(ctx); err != nil && ctx.Err() == nil {
			r.Log.Error("group reports failed", "err", err)
		}
		t := time.NewTimer(r.Tick)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
